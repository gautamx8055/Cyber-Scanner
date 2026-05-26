"""
SQLAlchemy ORM models.
Phase 1: Scan model. Phase 4: Vulnerability model. Remaining models in Phase 6.
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
