# Task 7.2 — HTML + PDF Report (Jinja2 + WeasyPrint)

## What was built
The same `GET /api/scans/{id}/export` endpoint now also serves `format=html`
and `format=pdf`. A single Jinja2 template renders the report; WeasyPrint
turns that HTML into a paginated PDF.

```
ScanReport ──► report.html.j2 (Jinja2) ──► HTML bytes
                                  │
                                  └──► WeasyPrint ──► PDF bytes
```

### Files created / modified
- **new** `backend/scanner/templates/report.html.j2` — single-page HTML
  report with print-friendly CSS:
  - `@page` rule (A4, generous margins, page-number footer).
  - Header strip with target / scan type / status / generated timestamp.
  - Scan-details grid (target IP, hostname, scan type, status, started /
    completed, duration, scan ID).
  - Four summary cards (open ports, total ports recorded, vulnerabilities,
    web findings).
  - Severity rollup row (Critical/High/Medium/Low/Info/Unknown — always all
    six cells, colored per severity).
  - Three tables: **Open Ports**, **Vulnerabilities** (sorted by CVSS desc
    from the loader), **Web Findings**, each with a severity pill where
    relevant. Empty sections show a muted "No … recorded." line instead of
    an empty table.
  - All styling is inlined in a `<style>` block — WeasyPrint doesn't load
    external CSS, and an inlined sheet is the most portable across viewers.
- **modified** `backend/scanner/reporter.py`
  - `to_html() -> bytes`: builds a Jinja2 `Environment` with autoescape on
    for HTML/XML (defense in depth — a malicious banner or hostname can't
    inject markup), registers an `iso` filter so datetimes render as ISO
    8601 with a trailing `Z` instead of Python's default repr.
  - `to_pdf() -> bytes`: routes `to_html()` through
    `weasyprint.HTML(string=…).write_pdf()`. Imported lazily so the module
    still loads on systems without WeasyPrint's native libs.
  - Templates live next to the module at `scanner/templates/` — packaging
    (PyInstaller / Docker COPY) doesn't need a separate data-file step.
- **modified** `backend/api/routes.py`
  - `format=html` and `format=pdf` now route through the same `_EXPORT_FORMATS`
    table added in 7.1. PDF rendering goes through `asyncio.to_thread` so
    WeasyPrint's CPU work doesn't block the event loop.
  - HTML defaults to **inline** so a browser pointed at the URL just displays
    it. Add `?download=true` to force an attachment.
- **modified** `docker/backend.Dockerfile`
  - Added `libpango-1.0-0`, `libpangoft2-1.0-0`, `libharfbuzz0b`,
    `libfontconfig1` to the `apt-get install` step. WeasyPrint loads these
    via `ctypes` at runtime — they must be in the final image.

## Key concepts
- **Jinja2 templating** — `{{ var }}` expressions, `{% for %}` / `{% if %}`
  blocks, `|` filters (`| iso`, `| selectattr(...) | list`). Autoescape
  ensures any `&`/`<`/`>`/`"` in a banner or description is HTML-encoded
  before it lands in the document.
- **`select_autoescape(["html", "xml"])`**: turns autoescape on for templates
  whose name ends in `.html` / `.xml`. The template file uses `.html.j2`, so
  this catches it.
- **Print CSS** — `@page` for page margins and headers/footers,
  `page-break-inside: avoid` on table rows to keep a single row from
  splitting across pages.
- **`asyncio.to_thread`** — WeasyPrint is synchronous and CPU-heavy.
  Offloading it to the default executor lets uvicorn keep handling other
  requests while a PDF builds.
- **Lazy imports** — `from jinja2 import …` / `from weasyprint import …` live
  inside the methods that need them. A JSON-only request never imports
  WeasyPrint; a broken WeasyPrint install never breaks the JSON path.

## How to run / test
```bash
docker compose up -d --build       # rebuild needed: new apt packages in the image

# pick a finished scan
SID=$(curl -s http://localhost:8000/api/scans?limit=1 \
        | python3 -c "import sys,json;print(json.load(sys.stdin)['items'][0]['id'])")

# HTML — open in browser
open "http://localhost:8000/api/scans/$SID/export?format=html"

# PDF — download
curl -s -OJ "http://localhost:8000/api/scans/$SID/export?format=pdf"
file cyberscan-$SID.pdf            # → PDF document
```

## Testing status
- Template renders with fake data (two open ports, one critical CVE, one
  medium web finding) → 7.6 KB HTML, all six headings present, the iso filter
  produces `2026-01-01T12:00:00Z` from a naive UTC datetime.
- WeasyPrint smoke-test in-process couldn't run on this host: the
  `glib`/`pango` Homebrew formulae aren't installed, so WeasyPrint fails
  `libgobject-2.0-0` at import. The Docker image has them (apt-installed in
  this commit), which is the real deploy target.

This finishes Phase 7. Phase 8 (Next.js dashboard) is the natural next
direction — it consumes both the WebSocket from 6.3 and the export endpoints
from this phase.
