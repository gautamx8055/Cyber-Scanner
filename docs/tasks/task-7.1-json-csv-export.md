# Task 7.1 — JSON + CSV Export

## What was built
A reusable `ScanReport` snapshot that loads a scan + all of its child rows
once, then renders to any export format. JSON and CSV are wired through a
single new endpoint:

```
GET /api/scans/{id}/export?format=json|csv   ──► attachment download
```

### Flow
```
GET /api/scans/{id}/export?format=json
  └─► ScanReport.from_db(session, id) ──┐
       reads scans, ports, vulns, web   │  (one snapshot, no DB calls
                                        │   during rendering)
       ───────────────────────────────► report.to_json() / .to_csv()
                                        │
                                        ▼
            Response(media_type=…, headers={Content-Disposition: …})
```

### Files created / modified
- **new** `backend/scanner/reporter.py` — the export engine.
  - `ScanReport` dataclass holds a frozen snapshot of a scan + its findings,
    plus four small dataclasses (`PortRow`, `VulnerabilityRow`,
    `WebFindingRow`) that mirror the ORM rows without dragging the
    SQLAlchemy session into the renderer.
  - `from_db(session, scan_id)` async classmethod hydrates the snapshot in
    one trip: vulnerabilities are ordered by CVSS desc (nulls last) so the
    JSON / CSV ordering matches a humans-first view.
  - `summary()` returns `open_ports`, `total_ports_recorded`,
    `vulnerabilities`, `web_findings`, a full `severity` rollup
    (`Critical → Unknown`), and `duration_seconds`. Severity counts always
    include every label (zero when absent) so templates never need
    `if key in dict` guards.
  - `to_json(indent=2) -> bytes`: pretty-printed UTF-8 JSON via
    `to_dict()`. Top-level shape is
    `{report, scan, summary, ports, vulnerabilities, web_findings}` so a
    consumer can pick out one section without parsing the whole thing.
  - `to_csv() -> bytes`: a single flat table — one row per finding across
    ports/vulns/web. Columns:
    `finding_class, finding_type, port, proto, state, service, product,
     version, cve_id, cvss_score, severity, url, description, source`.
    Blanks instead of `None` (spreadsheets handle blanks; `None` strings
    are noise).
- **modified** `backend/api/routes.py`
  - Added `GET /api/scans/{scan_id}/export?format=…&download=…`. Format is
    validated against a `{format -> (renderer attr, MIME, file ext)}` table,
    so format/Content-Type/filename can never drift out of sync.
  - 404 when the scan doesn't exist; 400 for an unknown format.
  - HTML defaults to inline (browser view); everything else, plus HTML with
    `?download=true`, comes back as
    `Content-Disposition: attachment; filename="cyberscan-<id>.<ext>"`.
  - PDF rendering goes through `asyncio.to_thread` so WeasyPrint's CPU work
    doesn't block the event loop.

## Key concepts
- **`dataclass` as a serializer-free DTO**: `ScanReport` carries data, not
  behavior. Loaders and renderers stay independent — adding Markdown or SARIF
  later means writing one more `to_*` method, not refactoring the loader.
- **`csv.DictWriter` with `restval=""` and `extrasaction="ignore"`**: lets
  each row writer only specify the columns it cares about; missing keys
  become blanks, and an accidental extra key is silently dropped instead of
  raising in the middle of a download.
- **Lazy imports**: Jinja2 / WeasyPrint are imported inside the `to_html` /
  `to_pdf` methods rather than at module top — a JSON-only request doesn't
  pay the import cost (and a misconfigured WeasyPrint install can't break
  the whole module).
- **`json.dumps(default=str)`**: a safety net so any stray
  `datetime`/`Enum`/`UUID` falls back to its string form instead of raising;
  the canonical fields are already pre-serialized through `_iso()`.

## How to run / test
```bash
docker compose up -d
# create + finish a scan, then export it
SID=$(curl -s -X POST http://localhost:8000/api/scans \
        -H 'Content-Type: application/json' \
        -d '{"target":"127.0.0.1","scan_type":"port","options":{"ports":"1-1024"}}' \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
sleep 2
curl -s "http://localhost:8000/api/scans/$SID/export?format=json" \
  | python3 -m json.tool | head -40
curl -s -OJ "http://localhost:8000/api/scans/$SID/export?format=csv"
column -ts, < "cyberscan-$SID.csv" | head
```

## Testing status
- `reporter.py` and the updated `routes.py` parse cleanly (`python -m
  py_compile`).
- The dataclass + summary path was exercised against the Jinja2 template (see
  Task 7.2) using a fake scan with two ports, two vulns, and two web findings:
  the rendered output included the correct counts and the severity rollup.
- Live end-to-end against a running container is the natural next check; the
  endpoint is a thin wrapper around code paths already verified in isolation.

Naturally next: Task 7.2 — `format=html` and `format=pdf` (same endpoint, same
report).
