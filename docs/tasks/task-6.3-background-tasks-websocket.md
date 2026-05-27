# Task 6.3 — Background Tasks + WebSocket Live Updates

## What was built
`POST /api/scans` now *runs* the scan instead of just queuing it. The work
happens in a FastAPI **background task** so the POST returns immediately, and a
**WebSocket** at `/ws/scan/{id}` streams live progress while it runs.

### Flow
```
POST /api/scans ──► persist row (queued), commit, schedule background task ──► 201 (immediate)
                                                   │
        background task (own DB session): queued ► running ► completed / failed
                                                   │ publishes events ▼
client ── WS /ws/scan/{id} ──► status snapshot, then live events ──► completed/failed
```

### Files created / modified
- **new** `backend/api/events.py` — `ScanEventHub`: in-process pub/sub keyed by
  `scan_id` over `asyncio.Queue`s, plus a module singleton `hub`. `publish()` is
  best-effort and non-blocking (no subscribers = no-op).
- **new** `backend/api/executor.py` — `execute_scan(scan_id)`, the background
  entry point:
  - flips the row to `running`, reads inputs, releases the session;
  - resolves a hostname target to an IP (for port/vuln/full) off-thread;
  - dispatches on `scan_type` → `_run_port` / `_run_vuln` / `_run_web` /
    `_run_full`;
  - writes normalized child rows (`ports`, `vulnerabilities`, `web_findings`)
    into the **existing** scan;
  - streams `started` / `port` / `progress` / `vuln` / `finding` / `completed` /
    `failed` events via the hub;
  - marks `completed` (with a results summary) or `failed`.
- **modified** `backend/api/routes.py` — `create_scan` commits then
  `background_tasks.add_task(execute_scan, scan.id)`; new `ws_router` (no `/api`
  prefix) serves `/ws/scan/{id}` (status snapshot, then forwards hub events
  until terminal).
- **modified** `backend/main.py` — includes `ws_router`.

## Key concepts
- **WebSocket vs HTTP**: HTTP is request/response — the client must poll for
  updates. A WebSocket is a single long-lived, bidirectional connection; once
  `accept()`-ed, the server can *push* frames whenever it likes. That's why
  progress streams over WS rather than repeated `GET /scans/{id}`.
- **Background task + its own session**: the request's `get_db` session is
  committed and closed once the response is sent, so the task can't borrow it —
  `execute_scan` opens fresh `AsyncSessionLocal()` sessions. The POST handler
  commits the row explicitly *before* scheduling, so the task is guaranteed to
  find it (no read-before-write race).
- **Decoupled producer/consumer**: the executor doesn't know about WebSockets;
  it just `publish()`es to the hub. The WS route doesn't know about scanning; it
  just drains a queue. The DB row is the source of truth; the event stream is a
  best-effort live view, so a client that connects late gets a status snapshot
  first and never hangs.
- **Live port events**: `_scan_ports_live` fans out per-port coroutines under a
  semaphore and consumes them with `asyncio.as_completed`, emitting an event as
  each port resolves — which is what makes ports appear "live".
- **In-process only**: the hub lives in one worker's memory. Multiple uvicorn
  workers wouldn't share it — that's the Redis pub/sub swap in Phase 11.4.

## Scan options (per type, all optional)
- `port` / `vuln`: `ports` (`"1-1024"` default), `timeout`, `concurrency`;
  `vuln` also takes `nvd` (bool, uses `NVD_API_KEY` if set).
- `web`: `checks` (default all), `timeout`, `concurrency`, `wordlist`.
- `full`: runs port → vuln → web; a failing phase is recorded but doesn't abort
  the rest.

## How to run / test
```bash
docker compose up -d
# queue a scan; POST returns immediately with status "queued"
curl -X POST http://localhost:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"target":"127.0.0.1","scan_type":"port","options":{"ports":"1-1024"}}'
# watch it live (any WS client), then GET the final record
#   ws://localhost:8000/ws/scan/<id>
curl http://localhost:8000/api/scans/<id>
```

## Testing status
Verified end-to-end against the running container (WS client = `websockets`,
which ships with `uvicorn[standard]`):
- **Background port scan** (`127.0.0.1`): POST → **201 immediate `queued`**;
  status `running → completed`; open port **8000 persisted as a `Port` row**;
  summary `{ports_scanned: 21, open: 1}`.
- **Live WS streaming** (filtered `192.0.2.1`, ~2s): received
  `status(running) → progress 50/100/150/200 → completed` with real-time
  timestamps — progress genuinely streamed, not batched.
- **Web scan** (against the backend itself, `headers` check): `running →
  completed`, **6 `web_findings`** persisted (5 missing-header + 1 info_leak).
- **Vuln branch**: completes, persists open `Port` rows, 0 CVEs on localhost
  (no matching banner) — path exercised without error.

All scans created during testing were deleted afterward. Remaining open item
for Phase 6: **6.4** (add the backend service / health checks to docker-compose
— the container already runs there, so this is mostly formalizing it).
