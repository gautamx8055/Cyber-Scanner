# Task 8.1 — Next.js Dashboard Scaffold + Home + Docker

## What was built
A Next.js 14 (App Router) + TypeScript + Tailwind frontend that talks to the
FastAPI backend over REST + WebSocket. The dashboard home shows a risk
summary, a paginated scan list, and a severity-mix donut chart. The whole
app is wired into Docker Compose as a third service.

### Page map
```
/                         dashboard home (scan list + summary + chart)
/scans/new                new-scan form (Task 8.2)
/scans/[id]/live          WebSocket-driven live progress (Task 8.2)
/scans/[id]               static scan detail + downloads (Task 8.3)
```

### Files created / modified
- **scaffold** — `npx create-next-app@14 frontend --typescript --tailwind --eslint --app --no-src-dir --import-alias "@/*"` (Next 14.2.35, React 18). The default
  `app/page.tsx` (Vercel splash) and `app/layout.tsx` (metadata) were
  rewritten.
- **new** `frontend/tailwind.config.ts` — shadcn-style CSS-variable theme
  (HSL tokens for `--background`, `--foreground`, `--primary`, `--muted`,
  `--card`, `--popover`, `--border`, `--input`, `--ring`). Added a custom
  `severity` palette (`critical/high/medium/low/info/unknown`) whose HSL
  values mirror the PDF template in
  `backend/scanner/templates/report.html.j2` — same colors in HTML/PDF and
  dashboard.
- **new** `frontend/app/globals.css` — `@layer base` CSS variables for the
  theme + `* { @apply border-border }` reset.
- **new** `frontend/lib/utils.ts` — `cn(...)` (clsx + tailwind-merge).
- **new** `frontend/lib/types.ts` — hand-written TypeScript mirror of
  `backend/api/schemas.py` (ScanSummary, ScanDetail, PortOut, …) plus a
  discriminated `WSEvent` union for the executor's hub events.
- **new** `frontend/lib/api.ts` — REST client using `fetch`. `API_URL` is
  read from `NEXT_PUBLIC_API_URL` (default `http://localhost:8000`).
  Exposes `api.listScans`, `api.getScan`, `api.createScan`,
  `api.deleteScan`, `scanEventsURL(id)`, and `exportURL(id, fmt, opts)`.
- **new** `frontend/lib/severity.ts` — central `SEVERITY_STYLES` map
  (`bg/text/hsl` per severity) so the badge, the chart, and any future
  consumer read from one place.
- **new** `frontend/components/ui/*` — six shadcn-style primitives written
  by hand (no `npx shadcn add` step): `button`, `card`, `input`, `label`,
  `select` (Radix), `table`, `badge`, `progress`. Total ~250 LOC.
- **new** `frontend/components/providers.tsx` — single `QueryClient` per
  tab, `staleTime: 5s`, `refetchOnWindowFocus: false`.
- **new** `frontend/components/severity-badge.tsx`, `scan-status-badge.tsx`.
- **new** `frontend/components/scan-list.tsx` — paginated table of recent
  scans; row links route to `/scans/[id]/live` while running, `/scans/[id]`
  once finished. Refetches every 5s (paused on background tabs).
- **new** `frontend/components/risk-summary.tsx` — four headline cards
  (Scans / Open ports / Vulnerabilities / Web findings). Hydrates by
  fetching detail for each scan in the latest list page (no `/api/stats`
  endpoint exists yet — bounded by page size).
- **new** `frontend/components/risk-chart.tsx` — Recharts donut keyed off
  `SEVERITY_STYLES.hsl`. Shows an empty-state when no findings exist
  instead of a full ring in one color.
- **modified** `frontend/app/layout.tsx` — global header with logo + nav,
  wraps children in `<Providers>`.
- **modified** `frontend/app/page.tsx` — the dashboard home that composes
  RiskSummary + ScanList + RiskChart.
- **new** `docker/frontend.Dockerfile` — `node:20-alpine`, `npm ci`, runs
  `next dev` against a host bind-mount for hot reload. Anonymous volumes
  for `/app/node_modules` and `/app/.next` so the host (which may have no
  `node_modules` in a clean checkout) doesn't shadow the image's.
- **modified** `docker-compose.yml` — added the `frontend` service:
  - publishes 3000:3000;
  - `NEXT_PUBLIC_API_URL` defaults to `http://localhost:8000` (the browser
    reaches the backend through the host port, not the in-network DNS name);
  - `depends_on: backend: { condition: service_healthy }`;
  - `wget --spider` healthcheck on `/`.

### Why each library
- **TanStack Query** — fetch caching + interval polling with one hook;
  serves the "list refreshes while a scan runs" UX in 4 lines.
- **Zustand** — was added to deps; not used yet (the live page got by with
  `useState`). Kept in `package.json` for Phase 8.2 onwards if cross-page
  state shows up.
- **Recharts** — declarative, composable, ships zero CSS. Good fit for the
  dashboard donut.
- **Radix Slot / Label / Select** — accessibility primitives behind the
  shadcn-style components. No global UI framework dep; we own the styling.

## Key concepts
- **App Router file conventions** — `app/<segment>/page.tsx` defines a
  route; `app/layout.tsx` is the shell rendered around every page.
  `app/<dyn>/[id]/page.tsx` injects `params: { id }` (sync in Next 14,
  async-Promise in Next 15 — important detail).
- **Server vs client components** — a `.tsx` is a Server Component by
  default. Adding `"use client"` at the top puts it on the client. Our
  data-fetching components, the providers, and any hooks-using component
  must opt in.
- **`NEXT_PUBLIC_` prefix** — only env vars with that prefix get inlined
  into the browser bundle at build time. `API_URL` needs it; a server-only
  secret would not.
- **Browser-vs-container networking** — the frontend code runs in the user's
  browser, so reaches the backend at `http://localhost:8000` (the host
  port). Code that runs **inside** the frontend container — Next.js SSR or
  server actions, neither used here — would call `http://backend:8000`.

## How to run / test
```bash
# bring up everything
docker compose up -d --build
open http://localhost:3000

# or run the frontend on the host against a dockerized backend
cd frontend && npm install && npm run dev
# → http://localhost:3000
```

## Testing status
- `npx tsc --noEmit` is clean.
- `npx next build` succeeds; 6 routes generated (`/`, `/_not-found`,
  `/scans/new`, `/scans/[id]`, `/scans/[id]/live`).
- Hot dev server on the host serves `/`, `/scans/new`, `/scans/abc`,
  `/scans/abc/live` with HTTP 200 and the right `<h1>` in each (verified
  via `curl`). The list and detail pages call the backend at runtime;
  without a running backend the cards stay at zero and the list shows
  "Loading scans…", which is the correct empty state.

Next: 8.2 wires the new-scan form + the WebSocket-driven live progress
page; 8.3 adds the static detail view + report downloads.
