# Task 4.3 — Vulnerabilities Table + Persistence

## What was built
Persistence for the vulnerability engine, plus the `vuln` CLI subcommand that
ties Phase 4 together (port scan → version match → render → save).

- A **`vulnerabilities`** table, one row per matched CVE, linked to its parent
  scan (`CASCADE` delete).
- A **`vuln` CLI subcommand**: scans ports, matches CVEs (local + optional
  NVD), renders both tables, and persists everything.

## Files created / modified
- **modified** `backend/db/models.py` — `Vulnerability` ORM model
- **new** `backend/alembic/versions/a1b2c3d4e5f6_add_vulnerabilities_table.py`
  — migration creating the table + indexes
- **modified** `backend/scanner/vuln_scanner.py` — `save_vuln_scan(...)`:
  inserts one `scans` row (type=`vuln`) + one `vulnerabilities` row per finding
- **modified** `backend/cli.py` — `cmd_vuln()` + the `vuln` subparser
- **modified** `backend/alembic/env.py` — see "Migration runner fix" below

## Migration runner fix (prerequisite)
The fresh database had **no tables** and `alembic` couldn't run: `env.py`
rewrote the URL to a sync `psycopg2` driver that isn't installed (it imported
`async_engine_from_config` but never used it). Since the whole stack is async +
asyncpg, `env.py` now runs migrations through the asyncpg engine via
`connection.run_sync(...)` — no `psycopg2`, no extra dependency. After the fix,
`alembic upgrade head` created `scans` (from the Phase 1/2 migrations) and then
`vulnerabilities`.

## Schema
| column | type | notes |
|---|---|---|
| `id` | varchar(36) | UUID PK |
| `scan_id` | varchar(36) | FK → `scans.id`, `ON DELETE CASCADE`, indexed |
| `cve_id` | varchar(32) | e.g. `CVE-2014-0160`, indexed |
| `product` / `version` | varchar | the detected service |
| `port` / `proto` | int / varchar(8) | where it was found |
| `cvss_score` | float | nullable |
| `severity` | varchar(16) | Critical / High / Medium / Low / Unknown |
| `description` | text | short summary |
| `source` | varchar(16) | `local` or `nvd` |
| `created_at` | timestamp | `server_default now()` |

A vuln scan writes the port findings to `scans.results` (JSON, like a port
scan) **and** a normalized `vulnerabilities` row per CVE. Phase 6 will fully
normalize ports too.

## How to run
```bash
# one-time: apply migrations
docker-compose exec backend alembic upgrade head

# local-only CVE matching
docker-compose exec backend python -m cli vuln 127.0.0.1 -p 1-1000

# also query the live NVD API (rate-limited)
docker-compose exec backend python -m cli vuln scanme.nmap.org -p 22,80 --nvd

# inspect persisted findings
docker-compose exec db psql -U cyberscanner -d cyberscanner \
  -c "SELECT cve_id, product, version, severity, source FROM vulnerabilities ORDER BY cvss_score DESC;"
```

`vuln` flags: `-p/--ports`, `--timeout`, `-c/--concurrency`, `--nvd`,
`--show-closed`, `--no-save`.

## Note on testing
Matching needs a service that emits a version banner. Most HTTP/TLS services
stay silent on passive connect, so local testing used throwaway listeners that
emit known-vulnerable banners (OpenSSH 7.6p1, vsFTPd 2.3.4, Apache 2.4.49) —
the chain matched, sorted, rendered, and persisted 7 CVEs correctly.
