"""
SQLAlchemy ORM models.
Phase 1: Scan model only. Remaining models added in Phase 6.
"""

import uuid
from datetime import datetime
from sqlalchemy import String, Text, DateTime, Enum as SAEnum, JSON
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

    def __repr__(self) -> str:
        return f"<Scan id={self.id} target={self.target_ip} status={self.status}>"
