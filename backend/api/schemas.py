"""
Pydantic request/response schemas for the scans API (Phase 6.2).

These are deliberately separate from the SQLAlchemy ORM models in db/models.py:
the ORM classes describe how rows are *stored*, these describe what the HTTP API
*accepts and returns*. `from_attributes=True` lets a response model be built
straight from an ORM row, which is how FastAPI's response_model serializes them.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from db.models import ScanStatus, ScanType


# --- request bodies ---------------------------------------------------------

class ScanCreate(BaseModel):
    """Body for POST /api/scans — queue a new scan.

    The scan is persisted with status `queued`; it is not executed here
    (background execution lands in Task 6.3). `options` is free-form per
    scan_type, e.g. {"ports": "1-1000", "timeout": 1.0} for a port scan.
    """

    target: str = Field(..., min_length=1, max_length=255,
                        description="target IP or hostname")
    scan_type: ScanType = ScanType.port
    options: dict[str, Any] | None = None


# --- nested finding rows ----------------------------------------------------

class PortOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    port: int
    proto: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    cve_id: str
    product: str | None = None
    version: str | None = None
    port: int | None = None
    proto: str
    cvss_score: float | None = None
    severity: str
    description: str | None = None
    source: str


class WebFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_type: str
    severity: str
    url: str | None = None
    description: str | None = None
    evidence: str | None = None


# --- scan responses ---------------------------------------------------------

class ScanSummary(BaseModel):
    """One row in the GET /api/scans list — no heavy JSON or child rows."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    target_ip: str
    target_hostname: str | None = None
    scan_type: ScanType
    status: ScanStatus
    started_at: datetime
    completed_at: datetime | None = None


class ScanDetail(ScanSummary):
    """GET /api/scans/{id} — full record: options, results blob, child findings."""

    options: dict[str, Any] | None = None
    results: Any | None = None
    ports: list[PortOut] = []
    vulnerabilities: list[VulnerabilityOut] = []
    web_findings: list[WebFindingOut] = []


class ScanList(BaseModel):
    """Paginated envelope for GET /api/scans."""

    total: int
    limit: int
    offset: int
    items: list[ScanSummary]
