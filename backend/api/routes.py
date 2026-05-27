"""
Scans REST API (Phase 6.2).

CRUD over the `scans` resource. Creating a scan persists it with status
`queued` — actually running it as a background task lands in Task 6.3.
FastAPI serves interactive docs for every route below at /docs.
"""

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.events import hub
from api.executor import execute_scan
from api.schemas import (
    PortOut,
    ScanCreate,
    ScanDetail,
    ScanList,
    ScanSummary,
    VulnerabilityOut,
    WebFindingOut,
)
from db.models import Port, Scan, ScanStatus, Vulnerability, WebFinding
from db.session import AsyncSessionLocal, get_db
from scanner.dns_utils import is_ip_literal

router = APIRouter(prefix="/api", tags=["scans"])
ws_router = APIRouter(tags=["scans"])


def _to_detail(scan, *, ports, vulns, webs) -> ScanDetail:
    """Build a ScanDetail from an ORM scan plus its already-fetched children.

    The children are passed in explicitly rather than read off `scan` because
    the ORM models define no relationships yet — the API queries each child
    table by scan_id.
    """
    return ScanDetail(
        **ScanSummary.model_validate(scan).model_dump(),
        options=scan.options,
        results=scan.results,
        ports=[PortOut.model_validate(p) for p in ports],
        vulnerabilities=[VulnerabilityOut.model_validate(v) for v in vulns],
        web_findings=[WebFindingOut.model_validate(w) for w in webs],
    )


@router.post("/scans", response_model=ScanDetail, status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> ScanDetail:
    """Queue a scan and kick off its background execution.

    Returns immediately with the persisted `queued` scan; the executor runs it
    as a background task and streams progress over /ws/scan/{id}.
    """
    # Split target into ip / hostname without a DNS round-trip — the executor
    # resolves a hostname to a real IP when the scan actually runs.
    if is_ip_literal(body.target):
        target_ip, target_hostname = body.target, None
    else:
        target_ip, target_hostname = body.target, body.target

    scan = Scan(
        target_ip=target_ip,
        target_hostname=target_hostname,
        scan_type=body.scan_type,
        status=ScanStatus.queued,
        options=body.options,
    )
    db.add(scan)
    await db.flush()
    # Commit now so the row is durable before the background task looks it up.
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(execute_scan, scan.id)
    # Freshly queued: no child rows or results yet.
    return _to_detail(scan, ports=[], vulns=[], webs=[])


@router.get("/scans", response_model=ScanList)
async def list_scans(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(20, ge=1, le=100, description="page size (max 100)"),
    offset: int = Query(0, ge=0, description="rows to skip"),
) -> ScanList:
    """List scans newest-first, paginated."""
    total = await db.scalar(select(func.count()).select_from(Scan))
    rows = (
        await db.execute(
            select(Scan).order_by(Scan.started_at.desc()).limit(limit).offset(offset)
        )
    ).scalars().all()
    return ScanList(
        total=total or 0,
        limit=limit,
        offset=offset,
        items=[ScanSummary.model_validate(r) for r in rows],
    )


@router.get("/scans/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)) -> ScanDetail:
    """Full scan detail: columns, options/results JSON, and all child findings."""
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")

    ports = (
        await db.execute(select(Port).where(Port.scan_id == scan_id))
    ).scalars().all()
    vulns = (
        await db.execute(select(Vulnerability).where(Vulnerability.scan_id == scan_id))
    ).scalars().all()
    webs = (
        await db.execute(select(WebFinding).where(WebFinding.scan_id == scan_id))
    ).scalars().all()
    return _to_detail(scan, ports=ports, vulns=vulns, webs=webs)


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)) -> None:
    """Delete a scan; its ports / vulns / web findings cascade away with it."""
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    await db.delete(scan)


@ws_router.websocket("/ws/scan/{scan_id}")
async def scan_progress(websocket: WebSocket, scan_id: str) -> None:
    """Stream live progress for a scan.

    Sends a status snapshot first (so a client that connects late, or after the
    scan already finished, isn't left hanging), then forwards executor events
    until the scan reaches a terminal state.
    """
    await websocket.accept()
    queue = hub.subscribe(scan_id)
    try:
        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            current = ScanStatus(scan.status) if scan is not None else None

        if current is None:
            await websocket.send_json({"type": "error", "error": "scan not found"})
            return

        await websocket.send_json({"type": "status", "status": current.value})
        if current in (ScanStatus.completed, ScanStatus.failed):
            # Already finished — nothing further will be published.
            await websocket.send_json({"type": current.value, "status": current.value})
            return

        while True:
            event = await queue.get()
            await websocket.send_json(event)
            if event.get("type") in ("completed", "failed"):
                return
    except WebSocketDisconnect:
        pass
    finally:
        hub.unsubscribe(scan_id, queue)
