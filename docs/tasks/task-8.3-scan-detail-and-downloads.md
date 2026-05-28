# Task 8.3 — Scan Detail Page + Report Downloads

## What was built
The static, persistent view of a finished scan — ports, vulnerabilities,
web findings — plus the buttons that hand the user the JSON / CSV / HTML /
PDF reports built in Phase 7.

### Files created / modified
- **new** `frontend/components/export-buttons.tsx` — four anchors pointing
  at `GET /api/scans/{id}/export?format=…`.
  - HTML opens in a new tab (the backend serves it inline by default;
    that's what you usually want for a quick visual check).
  - JSON / CSV / PDF carry `Content-Disposition: attachment` from the
    backend, so the browser saves them with `cyberscan-<id>.<ext>`.
  - Uses `<Button asChild><a … /></Button>` so the anchor inherits the
    button styling but the browser handles the download natively — no
    `fetch` + `blob` shuffle, no JS download dance.
- **new** `frontend/app/scans/[id]/page.tsx` — client page (uses
  `useQuery`).
  - Header: target name, IP (mono), scan type, status badge, started /
    finished timestamps.
  - Sections: Open ports table, Vulnerabilities table (CVE / severity
    pill / CVSS / product / port / source), Web findings table (type /
    severity / URL / description). Empty sections show a muted
    "No … recorded." line rather than an empty table.
  - Delete: a destructive icon button with `confirm()`, calls
    `useMutation(api.deleteScan)`; on success invalidates the
    `["scans"]` query so the dashboard list refreshes, then routes home.
  - `ExportButtons` lives in the header so downloads are reachable
    without scrolling on long scans.

### Why this shape
- **No SSR data-fetch**: the detail page is a client component using
  TanStack Query. That keeps the auth model trivial (the browser already
  has whatever credentials it needs to talk to the backend) and lets us
  reuse the existing `api.getScan` client. SSR would force the Next.js
  server to also reach the backend (different host, different network
  path inside the container) — premature for this phase.
- **Severity pills** centralize via `SeverityBadge` (Phase 8.1) — same
  HSL values as the PDF report so the user sees a consistent color story
  between the dashboard and a saved PDF.

## Key concepts
- **`useMutation.onSuccess` + `queryClient.invalidateQueries`** — the
  canonical TanStack Query pattern for "I changed something on the server;
  re-fetch anything that depended on it." Here that's the dashboard scan
  list.
- **Cross-origin browser downloads** — because the backend lives on a
  different host (`:8000`) than the frontend (`:3000`), the download
  works as long as the backend doesn't reject the GET. FastAPI's default
  CORS is permissive for GET; we never opened the door for non-GET
  cross-origin requests. (POST `/api/scans` from the new-scan form works
  for the same reason FastAPI defaults allow it; if we ever lock CORS
  down, the create endpoint will need an explicit allowlist.)
- **`asChild` button + `<a>`** — `Button` is a `Slot`-aware wrapper. When
  `asChild` is set it merges its className/handlers onto its single
  child, so the child remains a real `<a>` element (download behavior,
  keyboard focus, middle-click "open in new tab" — all native).

## How to run / test
```bash
docker compose up -d --build

# create a scan, wait for it to finish
SID=$(curl -s -X POST http://localhost:8000/api/scans \
        -H 'Content-Type: application/json' \
        -d '{"target":"127.0.0.1","scan_type":"port","options":{"ports":"1-1024"}}' \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
sleep 3

# open the detail view + click the download buttons
open "http://localhost:3000/scans/$SID"
```

## Testing status
- `npx tsc --noEmit` clean; `npx next build` produces the dynamic
  `/scans/[id]` route.
- Dev-server GET on `/scans/abc` returns 200 (loading state — `<h1>` is
  hidden behind the loader; correct empty-state path).
- End-to-end download path needs Docker up and is the natural manual check
  the next time the stack is running. The endpoints themselves are
  covered by Phase 7's task docs.

This closes Phase 8. Phase 9 (C extension for the port-scanner hot path),
Phase 10 (production Docker + binary packaging), and Phase 11 (advanced
features / automation) are the remaining work in `TODO.md`.
