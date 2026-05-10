# Task 2.2 — Banner Grabbing, Service Detection, Persistence

## What was built
Extended the Phase 2.1 scanner with:
- Passive **banner grabbing** — read the first bytes a service sends
  immediately after the TCP handshake.
- A **service-name map** for well-known ports (22→SSH, 80→HTTP, ...).
- **Regex version extraction** — pull product + version out of banners.
- **Persistence** — save the full scan (metadata + per-port findings)
  into the existing `scans` PostgreSQL table.

## Files created / modified
- **modified** `backend/scanner/port_scanner.py`
  - `COMMON_SERVICES` — port → service-name lookup
  - `_grab_banner(sock)` — best-effort `recv()` from an open socket
  - `_parse_banner(banner)` — regex-extracts `(product, version)`
  - `save_scan_results(...)` — async SQLAlchemy insert into `scans`
- **modified** `backend/db/models.py` — added `results` JSON column on `Scan`
- **new** `backend/alembic/versions/7b2a9f3c4d5e_add_results_column_to_scans.py`
  — migration that adds the `results` column

## Key concepts

### What is a service banner?
Many network services announce themselves the instant you connect:

| Service | Example banner |
|---|---|
| SSH | `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.13` |
| FTP | `220 ProFTPD 1.3.6e Server` |
| SMTP | `220 mail.example.com ESMTP Postfix` |

Other services (HTTP, HTTPS, PostgreSQL, MySQL) stay silent until the
client sends a protocol-specific request — so our passive banner grab
will just time out for them and return `None`. That's fine; the scan
still records that the port is open.

### Regex version extraction
```python
_VERSION_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9]{2,})[/_\s]+([0-9][0-9A-Za-z.\-_]*)"
)
```
Matches `Name<sep>Version` where the separator is `/`, `_`, or
whitespace. `-` is intentionally **not** a separator, so on an SSH
banner like `SSH-2.0-OpenSSH_8.2p1` the match skips past the
`SSH-2.0-` prefix and lands on `OpenSSH_8.2p1` → `("OpenSSH", "8.2p1")`.

### Schema change → migration
Per the project rule, any DB schema change is done through an Alembic
migration rather than hand-edited SQL. The new migration adds a single
nullable `results` column to the existing `scans` table; the downgrade
drops it. Using a JSON column now is a deliberate shortcut — Phase 6
will normalize this into `ports`, `vulnerabilities`, and `web_findings`
tables.

### What gets saved
Each `ports` scan inserts one row into `scans`:

| column | value |
|---|---|
| `target_ip` | `127.0.0.1` |
| `scan_type` | `port` |
| `status` | `completed` |
| `started_at` / `completed_at` | UTC timestamps |
| `options` | `{"port_spec": "22,80,443", "timeout": 1.0}` |
| `results` | `[{"port": 22, "state": "closed", ...}, ...]` |

## How to run

Apply the new migration (once):

```bash
cd backend
alembic upgrade head
```

Run a scan and inspect the saved row:

```bash
python -m cli ports 127.0.0.1 -p 22,80,5432,8000
docker exec cyberscanner_db \
  psql -U cyberscanner -d cyberscanner \
  -c "SELECT id, target_ip, jsonb_array_length(results::jsonb) FROM scans ORDER BY started_at DESC LIMIT 1;"
```
