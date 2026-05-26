"""
Vulnerability scanner (Phase 4).

Takes the (product, version) pairs that the port scanner extracts from service
banners and matches them against known CVEs:

    - Local matching: a curated offline dataset (scanner/data/cve_db.json),
      always available, no network needed.
    - NVD matching (optional): live queries to the NIST NVD 2.0 REST API.

Public surface:
    severity_from_score(score)                  -> str
    load_cve_db(path=None)                       -> list[dict]
    match_local(product, version, db=None)       -> list[dict]
    scan_local(port_results)                     -> list[VulnFinding]
    query_nvd(product, version, ...)             -> (list[dict], err)
    scan_nvd(port_results, ...)                  -> (list[VulnFinding], list[str])
    render_vuln_table(target, findings)
    save_vuln_scan(...)                          -> scan id (UUID string)
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from functools import lru_cache
from pathlib import Path

import httpx
from rich.console import Console
from rich.table import Table

_CVE_DB_PATH = Path(__file__).parent / "data" / "cve_db.json"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD throttles anonymous callers to ~5 requests / 30s; an API key raises this.
# We space sequential queries out by this many seconds to stay under the limit.
NVD_DEFAULT_DELAY = 6.0

SEVERITY_COLOR = {
    "Critical": "bold red",
    "High": "red",
    "Medium": "yellow",
    "Low": "cyan",
    "None": "dim",
    "Unknown": "dim",
}
# Render order — worst first.
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4, "Unknown": 5}


@dataclass
class VulnFinding:
    port: int
    proto: str
    product: str
    version: str
    cve_id: str
    cvss_score: float | None
    severity: str
    description: str
    source: str = "local"  # "local" | "nvd"


def severity_from_score(score: float | None) -> str:
    """Map a CVSS base score to its qualitative band (CVSS v3 cutoffs)."""
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "None"


# ----------------------------------------------------------------------------
# Version comparison
# ----------------------------------------------------------------------------
#
# Service versions aren't pure dotted integers — OpenSSL appends a letter
# (1.0.1f), OpenSSH a patch level (8.2p1). We turn each dot-separated component
# into a (number, letter-ordinal) pair so "1.0.1f" < "1.0.1g" and "8.2" < "8.3"
# both order correctly. This is intentionally simpler than PEP 440 / semver;
# it's accurate enough for the version ranges in the local CVE dataset.

def _version_key(version: str) -> list[tuple[int, int]]:
    parts: list[tuple[int, int]] = []
    for comp in re.split(r"[.\-_]", version.strip().lower()):
        if not comp:
            continue
        m = re.match(r"(\d+)([a-z]*)", comp)
        if not m:
            parts.append((0, 0))
            continue
        letter_val = 0
        for ch in m.group(2):
            letter_val = letter_val * 27 + (ord(ch) - ord("a") + 1)
        parts.append((int(m.group(1)), letter_val))
    return parts or [(0, 0)]


def _cmp_versions(a: str, b: str) -> int:
    ka, kb = _version_key(a), _version_key(b)
    n = max(len(ka), len(kb))
    ka += [(0, 0)] * (n - len(ka))
    kb += [(0, 0)] * (n - len(kb))
    return (ka > kb) - (ka < kb)


def _version_matches(version: str, affected: dict) -> bool:
    """True if `version` falls within an `affected` spec from the CVE dataset."""
    versions = affected.get("versions")
    if versions:
        if any(_cmp_versions(version, v) == 0 for v in versions):
            return True

    if "version_start" not in affected and "version_end" not in affected:
        return False

    start = affected.get("version_start")
    if start is not None:
        c = _cmp_versions(version, start)
        if affected.get("version_start_excluding"):
            if c <= 0:
                return False
        elif c < 0:
            return False

    end = affected.get("version_end")
    if end is not None:
        c = _cmp_versions(version, end)
        if affected.get("version_end_excluding"):
            if c >= 0:
                return False
        elif c > 0:
            return False

    return True


# ----------------------------------------------------------------------------
# Local CVE dataset matching
# ----------------------------------------------------------------------------

@lru_cache(maxsize=1)
def load_cve_db(path: str | None = None) -> tuple[dict, ...]:
    """Load and cache the local CVE dataset. Returns the list of CVE entries."""
    p = Path(path) if path else _CVE_DB_PATH
    with p.open(encoding="utf-8") as fh:
        data = json.load(fh)
    return tuple(data.get("cves", []))


def _product_matches(detected: str, entry: dict) -> bool:
    d = detected.strip().lower()
    names = {entry["product"].lower()}
    names.update(a.lower() for a in entry.get("aliases", []))
    return d in names


def match_local(product: str, version: str,
                db: tuple[dict, ...] | None = None) -> list[dict]:
    """Return the CVE entries whose product and version range match."""
    db = db if db is not None else load_cve_db()
    return [
        entry for entry in db
        if _product_matches(product, entry)
        and _version_matches(version, entry["affected"])
    ]


def scan_local(port_results) -> list[VulnFinding]:
    """Match every open port that has a product+version against the local DB."""
    db = load_cve_db()
    findings: list[VulnFinding] = []
    for r in port_results:
        if r.state != "open" or not r.product or not r.version:
            continue
        for entry in match_local(r.product, r.version, db):
            findings.append(VulnFinding(
                port=r.port,
                proto=r.proto,
                product=r.product,
                version=r.version,
                cve_id=entry["cve_id"],
                cvss_score=entry.get("cvss_score"),
                severity=severity_from_score(entry.get("cvss_score")),
                description=entry["description"],
                source="local",
            ))
    return findings


# ----------------------------------------------------------------------------
# Live NVD (NIST National Vulnerability Database) querying
# ----------------------------------------------------------------------------

def _keyword_version(version: str) -> str:
    """Reduce a banner version to its leading numeric form for NVD keyword
    search: "7.6p1" -> "7.6", "1.0.1f" -> "1.0.1", "2.4.49" -> "2.4.49"."""
    m = re.match(r"\d+(?:\.\d+)*", version.strip())
    return m.group(0) if m else version


def _nvd_score(metrics: dict) -> tuple[float | None, str | None]:
    """Pull a base score + severity out of an NVD metrics block.

    Prefers CVSS v3.1, then v3.0, then v2 (deriving the band ourselves for v2,
    which predates the qualitative severity ratings).
    """
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            sev = (data.get("baseSeverity") or "").title() or None
            return data.get("baseScore"), sev
    arr = metrics.get("cvssMetricV2")
    if arr:
        score = arr[0].get("cvssData", {}).get("baseScore")
        return score, severity_from_score(score)
    return None, None


async def query_nvd(
    product: str,
    version: str,
    *,
    results_per_page: int = 5,
    timeout: float = 20.0,
    api_key: str | None = None,
) -> tuple[list[dict], str | None]:
    """Keyword-search the NVD 2.0 API for a product+version.

    Returns (findings, error). NVD keyword search is fuzzy, so results are
    candidate matches, not a guarantee the running version is affected.

    Banner versions often carry a patch suffix (OpenSSH "7.6p1", OpenSSL
    "1.0.1f") that NVD's keyword index doesn't recognise, so we search on the
    leading numeric "major.minor[.patch]" form to get useful hits.
    """
    keyword = f"{product} {_keyword_version(version)}".strip()
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
    }
    headers = {"apiKey": api_key} if api_key else {}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(NVD_API_URL, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as e:
        return [], str(e)

    out: list[dict] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        descs = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descs if d.get("lang") == "en"), ""
        )
        score, sev = _nvd_score(cve.get("metrics", {}))
        out.append({
            "cve_id": cve.get("id", "?"),
            "cvss_score": score,
            "severity": sev or severity_from_score(score),
            "description": description,
        })
    return out, None


async def scan_nvd(
    port_results,
    *,
    api_key: str | None = None,
    delay: float = NVD_DEFAULT_DELAY,
) -> tuple[list[VulnFinding], list[str]]:
    """Query NVD for each distinct open (product, version). Sequential + spaced
    out to respect NVD rate limits. Returns (findings, errors)."""
    # Dedupe by (product, version); keep the first port each was seen on.
    seen: dict[tuple[str, str], object] = {}
    for r in port_results:
        if r.state != "open" or not r.product or not r.version:
            continue
        seen.setdefault((r.product.lower(), r.version), r)

    findings: list[VulnFinding] = []
    errors: list[str] = []
    items = list(seen.values())
    for i, r in enumerate(items):
        cves, err = await query_nvd(r.product, r.version, api_key=api_key)
        if err:
            errors.append(f"{r.product} {r.version}: {err}")
        for c in cves:
            findings.append(VulnFinding(
                port=r.port,
                proto=r.proto,
                product=r.product,
                version=r.version,
                cve_id=c["cve_id"],
                cvss_score=c["cvss_score"],
                severity=c["severity"],
                description=c["description"],
                source="nvd",
            ))
        if i < len(items) - 1:
            await asyncio.sleep(delay)
    return findings, errors


# ----------------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------------

def render_vuln_table(target: str, findings: list[VulnFinding],
                      *, console: Console | None = None) -> None:
    console = console or Console()
    if not findings:
        console.print(
            f"[green]No known vulnerabilities matched for {target}.[/green]"
        )
        return

    ordered = sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 9),
            -(f.cvss_score or 0.0),
            f.port,
        ),
    )

    table = Table(title=f"Vulnerabilities — {target}    {len(ordered)} finding(s)")
    table.add_column("Port", justify="right", style="cyan")
    table.add_column("Product")
    table.add_column("Version")
    table.add_column("CVE")
    table.add_column("CVSS", justify="right")
    table.add_column("Severity", style="bold")
    table.add_column("Src")
    table.add_column("Description", overflow="fold", max_width=52)

    counts: dict[str, int] = {}
    for f in ordered:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        color = SEVERITY_COLOR.get(f.severity, "white")
        score = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "-"
        table.add_row(
            f"{f.port}/{f.proto}",
            f.product,
            f.version,
            f.cve_id,
            score,
            f"[{color}]{f.severity}[/{color}]",
            f.source,
            f.description or "-",
        )
    console.print(table)

    summary = "  ".join(
        f"[{SEVERITY_COLOR.get(sev, 'white')}]{counts[sev]} {sev}[/{SEVERITY_COLOR.get(sev, 'white')}]"
        for sev in sorted(counts, key=lambda s: SEVERITY_ORDER.get(s, 9))
    )
    console.print(f"[dim]Summary:[/dim] {summary}")


# ----------------------------------------------------------------------------
# Persistence
# ----------------------------------------------------------------------------

async def save_vuln_scan(
    *,
    target_ip: str,
    port_spec: str,
    timeout: float,
    started_at: datetime,
    completed_at: datetime,
    port_results: list,
    findings: list[VulnFinding],
    target_hostname: str | None = None,
    used_nvd: bool = False,
) -> str:
    """Persist a vuln scan: one `scans` row (type=vuln) plus one
    `vulnerabilities` row per finding, linked by scan_id. Returns the scan id.
    """
    # Lazy import keeps this module DB-free for --no-save runs.
    from db.models import Scan, ScanStatus, ScanType, Vulnerability
    from db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        scan = Scan(
            target_ip=target_ip,
            target_hostname=target_hostname,
            scan_type=ScanType.vuln,
            status=ScanStatus.completed,
            started_at=started_at,
            completed_at=completed_at,
            options={"port_spec": port_spec, "timeout": timeout, "nvd": used_nvd},
            results=[asdict(r) for r in port_results],
        )
        session.add(scan)
        await session.flush()  # populate scan.id before we reference it

        for f in findings:
            session.add(Vulnerability(
                scan_id=scan.id,
                cve_id=f.cve_id,
                product=f.product,
                version=f.version,
                port=f.port,
                proto=f.proto,
                cvss_score=f.cvss_score,
                severity=f.severity,
                description=f.description,
                source=f.source,
            ))

        await session.commit()
        return scan.id
