"""
Scan report builder (Phase 7.1 + 7.2).

Loads a completed scan plus all of its child findings (ports, vulnerabilities,
web findings) into a single, format-agnostic `ScanReport` dataclass, then
exports that snapshot to JSON / CSV / HTML / PDF.

The dataclass is intentionally serializer-free — `to_json`, `to_csv`, `to_html`,
and `to_pdf` each render the same in-memory structure differently, so a future
format (Markdown, SARIF, …) only needs another renderer, not another loader.
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import Port, Scan, Vulnerability, WebFinding

# Bumped alongside the FastAPI app version. Surfaced inside every exported
# report so a stale download can be traced back to the tool version that wrote
# it.
TOOL_NAME = "CyberScanner"
TOOL_VERSION = "0.1.0"

# Ordered from worst to least bad — used as the canonical column order in
# summary tables and CSV rollups so two reports always sort the same way.
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info", "Unknown")

# Bundled Jinja2 templates live next to this module so packaging the backend
# (PyInstaller / Docker) doesn't need a separate data-file copy step.
_TEMPLATE_DIR = Path(__file__).parent / "templates"


# --- in-memory snapshot ----------------------------------------------------

@dataclass
class PortRow:
    port: int
    proto: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None


@dataclass
class VulnerabilityRow:
    cve_id: str
    severity: str
    cvss_score: float | None = None
    product: str | None = None
    version: str | None = None
    port: int | None = None
    proto: str = "tcp"
    description: str | None = None
    source: str = "local"


@dataclass
class WebFindingRow:
    finding_type: str
    severity: str
    url: str | None = None
    description: str | None = None
    evidence: str | None = None


@dataclass
class ScanReport:
    """Frozen snapshot of a scan, ready to be rendered to any export format.

    Build with `ScanReport.from_db(session, scan_id)`; render with `to_json`,
    `to_csv`, `to_html`, or `to_pdf`. None of the renderers touch the DB —
    they read only the fields on this object.
    """

    scan_id: str
    target_ip: str
    target_hostname: str | None
    scan_type: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    options: dict[str, Any] | None
    results: Any | None
    ports: list[PortRow] = field(default_factory=list)
    vulnerabilities: list[VulnerabilityRow] = field(default_factory=list)
    web_findings: list[WebFindingRow] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # ---- loading -----------------------------------------------------------

    @classmethod
    async def from_db(cls, session: AsyncSession, scan_id: str) -> "ScanReport | None":
        """Hydrate a report for `scan_id`, or return None if it doesn't exist."""
        scan = await session.get(Scan, scan_id)
        if scan is None:
            return None

        port_rows = (
            await session.execute(
                select(Port).where(Port.scan_id == scan_id).order_by(Port.port)
            )
        ).scalars().all()
        vuln_rows = (
            await session.execute(
                select(Vulnerability)
                .where(Vulnerability.scan_id == scan_id)
                .order_by(Vulnerability.cvss_score.desc().nullslast(), Vulnerability.cve_id)
            )
        ).scalars().all()
        web_rows = (
            await session.execute(
                select(WebFinding)
                .where(WebFinding.scan_id == scan_id)
                .order_by(WebFinding.finding_type, WebFinding.url)
            )
        ).scalars().all()

        return cls(
            scan_id=scan.id,
            target_ip=scan.target_ip,
            target_hostname=scan.target_hostname,
            scan_type=str(scan.scan_type),
            status=str(scan.status),
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            options=scan.options,
            results=scan.results,
            ports=[PortRow(p.port, p.proto, p.state, p.service, p.product,
                           p.version, p.banner) for p in port_rows],
            vulnerabilities=[VulnerabilityRow(
                cve_id=v.cve_id, severity=v.severity, cvss_score=v.cvss_score,
                product=v.product, version=v.version, port=v.port, proto=v.proto,
                description=v.description, source=v.source) for v in vuln_rows],
            web_findings=[WebFindingRow(
                finding_type=w.finding_type, severity=w.severity, url=w.url,
                description=w.description, evidence=w.evidence) for w in web_rows],
        )

    # ---- summary -----------------------------------------------------------

    def severity_counts(self) -> dict[str, int]:
        """Combined severity rollup across vulnerabilities + web findings.

        Always returns every label in SEVERITY_ORDER (zero when absent) so a
        dashboard / template can lay out a fixed set of cells without
        defensive `if key in dict` checks.
        """
        c: Counter[str] = Counter()
        for v in self.vulnerabilities:
            c[v.severity or "Unknown"] += 1
        for w in self.web_findings:
            c[w.severity or "Info"] += 1
        return {label: c.get(label, 0) for label in SEVERITY_ORDER}

    def summary(self) -> dict[str, Any]:
        """Headline numbers — open ports, finding counts, severity rollup."""
        open_ports = sum(1 for p in self.ports if p.state == "open")
        return {
            "open_ports": open_ports,
            "total_ports_recorded": len(self.ports),
            "vulnerabilities": len(self.vulnerabilities),
            "web_findings": len(self.web_findings),
            "severity": self.severity_counts(),
            "duration_seconds": self._duration_seconds(),
        }

    def _duration_seconds(self) -> float | None:
        if self.started_at and self.completed_at:
            return round((self.completed_at - self.started_at).total_seconds(), 3)
        return None

    # ---- JSON --------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Plain dict the JSON renderer (and any other future serializer) uses."""
        return {
            "report": {
                "tool": TOOL_NAME,
                "version": TOOL_VERSION,
                "generated_at": _iso(self.generated_at),
            },
            "scan": {
                "id": self.scan_id,
                "target_ip": self.target_ip,
                "target_hostname": self.target_hostname,
                "scan_type": self.scan_type,
                "status": self.status,
                "started_at": _iso(self.started_at),
                "completed_at": _iso(self.completed_at),
                "options": self.options,
                "results": self.results,
            },
            "summary": self.summary(),
            "ports": [asdict(p) for p in self.ports],
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "web_findings": [asdict(w) for w in self.web_findings],
        }

    def to_json(self, *, indent: int = 2) -> bytes:
        """Pretty-printed JSON as bytes (HTTP body / file write-ready)."""
        return json.dumps(self.to_dict(), indent=indent, default=str).encode("utf-8")

    # ---- CSV ---------------------------------------------------------------

    CSV_COLUMNS = (
        "finding_class",
        "finding_type",
        "port",
        "proto",
        "state",
        "service",
        "product",
        "version",
        "cve_id",
        "cvss_score",
        "severity",
        "url",
        "description",
        "source",
    )

    def to_csv(self) -> bytes:
        """Flat table: one row per finding across ports / vulns / web.

        A blank cell is more useful than a None placeholder in a spreadsheet,
        so the dict-writer is set with `restval=""`.
        """
        buf = io.StringIO(newline="")
        writer = csv.DictWriter(buf, fieldnames=self.CSV_COLUMNS, restval="",
                                extrasaction="ignore")
        writer.writeheader()

        for p in self.ports:
            writer.writerow({
                "finding_class": "port", "finding_type": "open_port",
                "port": p.port, "proto": p.proto, "state": p.state,
                "service": p.service or "", "product": p.product or "",
                "version": p.version or "", "severity": "Info",
                "description": p.banner or "",
            })
        for v in self.vulnerabilities:
            writer.writerow({
                "finding_class": "vuln", "finding_type": "cve",
                "port": v.port if v.port is not None else "",
                "proto": v.proto, "product": v.product or "",
                "version": v.version or "", "cve_id": v.cve_id,
                "cvss_score": v.cvss_score if v.cvss_score is not None else "",
                "severity": v.severity, "description": v.description or "",
                "source": v.source,
            })
        for w in self.web_findings:
            writer.writerow({
                "finding_class": "web", "finding_type": w.finding_type,
                "severity": w.severity, "url": w.url or "",
                "description": w.description or "",
            })

        return buf.getvalue().encode("utf-8")

    # ---- HTML / PDF --------------------------------------------------------

    def to_html(self) -> bytes:
        """Render the report as a standalone HTML document."""
        # Imported lazily so loading the reporter for CSV/JSON doesn't pay the
        # cost of pulling Jinja2 in.
        from jinja2 import Environment, FileSystemLoader, select_autoescape

        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        # Datetimes in the dataclass would otherwise stringify as
        # "2026-01-01 12:00:00+00:00"; the filter gives canonical ISO 8601.
        env.filters["iso"] = lambda v: _iso(v) or "—"
        template = env.get_template("report.html.j2")
        html = template.render(
            tool=TOOL_NAME,
            version=TOOL_VERSION,
            generated_at=_iso(self.generated_at),
            scan=self,
            summary=self.summary(),
            severity_order=SEVERITY_ORDER,
        )
        return html.encode("utf-8")

    def to_pdf(self) -> bytes:
        """Render to PDF by running the HTML output through WeasyPrint."""
        # Lazy import: WeasyPrint pulls in native libs (cairo, pango). Only
        # users who actually request a PDF should pay that cost.
        from weasyprint import HTML

        return HTML(string=self.to_html().decode("utf-8")).write_pdf()


# --- helpers ----------------------------------------------------------------

def _iso(value: datetime | None) -> str | None:
    """Format a datetime as ISO 8601 with explicit UTC `Z`. None passes through."""
    if value is None:
        return None
    if value.tzinfo is None:
        # Stored as naive UTC in the DB — re-attach the timezone before
        # serializing so consumers don't have to guess what zone it's in.
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
