# Task 6.2 — Core API Routes

## What was built
A REST API over the `scans` resource, served by FastAPI and auto-documented at
`/docs`. Four endpoints, all under the `/api` prefix:

| Method | Path | Purpose | Success code |
|---|---|---|---|
| POST | `/api/scans` | Queue a new scan | 201 |
| GET | `/api/scans` | List scans, newest-first, paginated | 200 |
| GET | `/api/scans/{id}` | Full scan detail + child findings | 200 |
| DELETE | `/api/scans/{id}` | Delete a scan (children cascade) | 204 |

### Scope note — queue vs. execute
`POST /api/scans` **persists** a scan with status `queued`; it does **not** run
it. Background execution (and DNS resolution of hostname targets) lands in
**Task 6.3**. The create handler splits the target into `target_ip` /
`target_hostname` with a cheap IP-literal check — no network call — and the
6.3 executor will resolve + overwrite `target_ip` when the scan actually runs.

## Files created / modified
- **new** `backend/api/schemas.py` — Pydantic v2 models:
  - `ScanCreate` (request: `target`, `scan_type`, optional `options`)
  - `ScanSummary` (list rows), `ScanDetail` (extends summary with `options`,
    `results`, and child lists), `ScanList` (paginated envelope:
    `total / limit / offset / items`)
  - `PortOut`, `VulnerabilityOut`, `WebFindingOut` (nested findings)
- **new** `backend/api/routes.py` — `APIRouter(prefix="/api")` with the four
  handlers + a `_to_detail()` helper.
- **modified** `backend/main.py` — `app.include_router(scans_router)`.

## Key concepts
- **Pydantic models vs ORM models**: the SQLAlchemy classes in `db/models.py`
  describe *storage*; the schemas in `api/schemas.py` describe the *HTTP
  contract*. `ConfigDict(from_attributes=True)` lets a response model be built
  straight from an ORM row, and `response_model=` makes FastAPI validate +
  serialize the output (and document it in the OpenAPI schema).
- **Validation for free**: typing `scan_type: ScanType` (a str-enum) makes
  FastAPI reject anything outside `port/vuln/web/full` with a 422; `target`'s
  `min_length=1` rejects empty strings. No hand-written checks.
- **Why children are queried, not lazy-loaded**: the ORM models define no
  `relationship()` yet, so `GET /{id}` queries `ports`, `vulnerabilities`, and
  `web_findings` by `scan_id` and assembles them in `_to_detail()`. Deleting a
  scan relies on the DB-level `ON DELETE CASCADE` (from the migrations), not an
  ORM cascade.
- **Pagination**: `limit` (1–100, default 20) + `offset` (≥0) as query params,
  with a `SELECT count(*)` for `total` so a client knows how many pages exist.
- **Async DB access**: handlers depend on `get_db()` (async session); it
  commits on clean exit, so POST/DELETE persist without an explicit commit.

## How to run / test
```bash
docker compose up -d                 # backend auto-reloads (uvicorn --reload)
open http://localhost:8000/docs      # interactive Swagger UI

# queue a scan
curl -X POST http://localhost:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com","scan_type":"web","options":{"checks":["tls"]}}'

# list / detail / delete
curl 'http://localhost:8000/api/scans?limit=5'
curl http://localhost:8000/api/scans/<id>
curl -X DELETE http://localhost:8000/api/scans/<id>
```

## Testing status
Exercised live against the running container:
- All 4 routes present in `/openapi.json`.
- POST → **201** `queued`; IP target → `target_hostname=null`, hostname target
  → both fields set; `options` round-trips.
- GET list → paginated envelope with correct `total`.
- GET detail of an existing `vuln` scan returned its `results` blob **and 7
  child `vulnerabilities`** (ports/web_findings empty, as expected).
- DELETE → **204**, subsequent GET → **404**.
- Validation: bad `scan_type` → **422**, empty `target` → **422**, unknown id
  → **404**.

Test scans created during verification were deleted; the DB is back to its
prior state. Nothing executes a queued scan yet — that's Task 6.3.
