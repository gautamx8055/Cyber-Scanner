"""
SQLAlchemy ORM models.
Phase 1: Scan model. Phase 4: Vulnerability model. Phase 5: WebFinding model.
Phase 6: Port model — normalizes scans.results into queryable per-port rows.
"""

import uuid
from datetime import datetime
from sqlalchemy import String, Text, DateTime, Enum as SAEnum, JSON, Integer, Float, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from db.session import Base
import enum


class ScanType(str, enum.Enum):
    port = "port"
    vuln = "vuln"
    web = "web"
    full = "full"


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_ip: Mapped[str] = mapped_column(String(255), nullable=False)
    target_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scan_type: Mapped[str] = mapped_column(
        SAEnum(ScanType, name="scan_type_enum"), nullable=False, default=ScanType.port
    )
    status: Mapped[str] = mapped_column(
        SAEnum(ScanStatus, name="scan_status_enum"), nullable=False, default=ScanStatus.queued
    )
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    options: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    results: Mapped[list | None] = mapped_column(JSON, nullable=True)

    def __repr__(self) -> str:
        return f"<Scan id={self.id} target={self.target_ip} status={self.status}>"


class Port(Base):
    """A single port result from a `port` (or `full`) scan.

    Mirrors the scanner's PortResult dataclass, normalized into its own table
    and linked to its parent Scan by scan_id (CASCADE delete). Replaces the
    JSON blob in Scan.results once the API persists scans this way.

    `state` is an nmap-style string: open / closed / filtered / open|filtered.
    """

    __tablename__ = "ports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    proto: Mapped[str] = mapped_column(String(8), nullable=False, default="tcp")
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    service: Mapped[str | None] = mapped_column(String(64), nullable=True)
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<Port {self.port}/{self.proto} {self.state} scan={self.scan_id}>"


class Vulnerability(Base):
    """A CVE matched against a service found during a scan.

    Linked to its parent Scan by scan_id. `source` records where the match
    came from: "local" (curated offline dataset) or "nvd" (live NVD API).
    """

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    proto: Mapped[str] = mapped_column(String(8), nullable=False, default="tcp")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="Unknown")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="local")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<Vulnerability {self.cve_id} {self.severity} scan={self.scan_id}>"


class WebFinding(Base):
    """A single web-security finding from a `web` scan.

    Covers every Phase 5 check; `finding_type` says which one produced it:
        ssl              TLS/certificate issue (expiry, self-signed, weak cipher)
        missing_header   a security response header was absent
        info_leak        a header leaked software/version info
        dir              a path the directory brute-forcer found (200/403/30x)
        open_redirect    a parameter redirected off-site to our canary
        xss              a payload was reflected unescaped in the response
        sqli             a SQL error was provoked by an injected quote
        subdomain        a brute-forced subdomain that resolves

    Linked to its parent Scan by scan_id (CASCADE delete). `severity` is a
    plain string (Critical/High/Medium/Low/Info) to match Vulnerability.
    """

    __tablename__ = "web_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="Info")
    url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<WebFinding {self.finding_type} {self.severity} scan={self.scan_id}>"
