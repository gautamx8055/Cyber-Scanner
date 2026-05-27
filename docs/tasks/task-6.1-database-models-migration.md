# Task 6.1 — Database Models + Alembic Migrations

## What was built
The `Port` ORM model — the last of the four Phase 6 models (`Scan`, `Port`,
`Vulnerability`, `WebFinding`) — plus the migration that creates its table.

`Scan` (Phase 1), `Vulnerability` (Phase 4) and `WebFinding` (Phase 5) already
existed, so this task only added the missing `Port` model and wired up the
remaining index. The full schema is now normalized: every scan finding lives in
its own table linked back to `scans.id`.

### `Port` model (`backend/db/models.py`)
Mirrors the scanner's `PortResult` dataclass (`port_scanner.py`) one-to-one,
normalized into a queryable row instead of a blob inside `scans.results`:

| Column | Type | Notes |
|---|---|---|
| `id` | String(36) | UUID primary key |
| `scan_id` | String(36) | FK → `scans.id`, `ON DELETE CASCADE`, indexed |
| `port` | Integer | not null |
| `proto` | String(8) | `tcp` / `udp`, default `tcp` |
| `state` | String(16) | nmap-style: `open` / `closed` / `filtered` / `open\|filtered` |
| `service` | String(64) | e.g. `PostgreSQL`, nullable |
| `product` | String(128) | parsed from banner, nullable |
| `version` | String(64) | parsed from banner, nullable |
| `banner` | Text | raw banner, nullable |
| `created_at` | DateTime | server default `now()` |

### Indexes (scan_id, target_ip, created_at)
- `scan_id` — **new** `ix_ports_scan_id` on `ports` (matches the existing
  `scan_id` indexes on `vulnerabilities` and `web_findings`).
- `target_ip` and the scan timestamp — **already present** on `scans`
  (`ix_scans_target_ip`, `ix_scans_started_at`) from the initial migration.
  The scans table tracks time as `started_at`/`completed_at`, so `started_at`
  is the indexed "created_at" for a scan; no redundant column was added.

## Files modified
- **modified** `backend/db/models.py` — added `Port`; refreshed the module
  docstring (it previously said "Port model lands in Phase 6").
- **new** `backend/alembic/versions/e5f6a7b8c9d0_add_ports_table.py` —
  `down_revision = c3d4e5f6a7b8` (web_findings), creates `ports` +
  `ix_ports_scan_id`, with a reversible `downgrade()`.
- **modified** `TODO.md`, `docs/PROJECT_PLAN.md` — checked off 6.1.

## Key concepts
- **ORM model → table**: a SQLAlchemy class with `Mapped[...]` columns is the
  Python-side mirror of a DB table; Alembic turns schema changes into versioned
  migration scripts rather than hand-edited tables.
- **Normalization**: per-port data moves out of the `scans.results` JSON blob
  into a real table you can index, join, and filter on. The JSON column stays
  for now; the API (6.2) will start writing `Port` rows.
- **CASCADE delete**: deleting a `Scan` deletes its child `ports` (and vulns,
  web findings) automatically via the FK — no orphan rows.
- **Migration chain**: linear `down_revision` links keep ordering deterministic;
  `1dce0a52 → 7b2a9f3c → a1b2c3d4 → c3d4e5f6 → e5f6a7b8`.

## How to run
```bash
# apply (inside the running backend container)
docker compose exec backend alembic upgrade head

# inspect the new table
docker compose exec db psql -U cyberscanner -d cyberscanner -c "\d ports"
```

## Testing status
Applied against the live Postgres container: head advanced
`c3d4e5f6a7b8 → e5f6a7b8c9d0`, `\d ports` shows all columns/types, the
`ix_ports_scan_id` index, and the CASCADE FK. Model import verified
(`from db.models import Port`). Migration confirmed reversible via a
`downgrade -1` → `upgrade head` round-trip (table dropped, then recreated).
Nothing writes `Port` rows yet — that lands with the API routes in Task 6.2.
