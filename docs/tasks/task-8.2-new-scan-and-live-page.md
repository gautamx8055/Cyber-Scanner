# Task 8.2 — New-Scan Form + Live Progress Page

## What was built
Two interactive client pages glue the dashboard to the backend's POST
endpoint and the WebSocket stream from Task 6.3:

```
/scans/new                ──POST /api/scans──►   201 { id }
        │                                            │
        └──router.push(`/scans/${id}/live`)──────────┘
                                │
                  /scans/[id]/live  ──WS /ws/scan/{id}──► live events
                                │
                  on completed/failed: router.replace(`/scans/${id}`)
```

### Files created / modified
- **new** `frontend/lib/use-scan-events.ts` — `useScanEvents(scanId)` hook.
  - Opens one `WebSocket` per id, cleans up on unmount via the
    effect-return.
  - Folds the discriminated `WSEvent` union from `lib/types.ts` into a
    `LiveScanState` (status, phase, resolvedIp, progress, ports, vulns,
    findings, error, events).
  - **Bounded event log** — only the last 200 raw events are kept so a
    full-scan over thousands of ports doesn't OOM the tab.
  - Reconnect on unexpected close is deliberately **off**: the executor
    always emits a terminal event before closing in the happy path; a
    silent reconnect would mask a real backend problem from the user.
  - `ws.close()` is guarded on `readyState` to avoid the noisy
    "WebSocket is already in CLOSING or CLOSED state" warning.
- **new** `frontend/app/scans/new/page.tsx` — client form (TanStack Query
  `useMutation`).
  - Fields: target IP/host, scan type (Select), and — conditionally on
    scan type — port range / timeout / concurrency / NVD toggle.
  - On success, `router.push(\`/scans/\${id}/live\`)`. Network/validation
    errors are surfaced inline from `mutation.error`.
- **new** `frontend/app/scans/[id]/live/page.tsx` — client page.
  - `useScanEvents(id)` produces the live state.
  - Status pill (`ScanStatusBadge`), spinner while running, `Progress` bar
    derived from `progress.done / progress.total`.
  - Two live tables: **Open ports** (each `port` event appends a row),
    **Findings** (vulns + web findings merged).
  - On `completed` / `failed`, an 800 ms delay (so the final progress tick
    paints) then `router.replace` to the static detail view.
  - "View results" button appears next to the status pill when terminal,
    short-circuiting the redirect for users who want to jump immediately.

### Why this shape
- **One source of truth per kind of state**:
  - REST → TanStack Query (`scans`, `scan` keys);
  - Live updates → the `useScanEvents` hook (local component state);
  - Form drafts → plain `useState`.
  The hook intentionally doesn't write into the Query cache — when the
  scan terminates the user navigates to a Query-driven page that refetches.
- **Why `router.replace` and not `router.push`** on completion: the live
  URL becomes uninteresting once the scan is done. `replace` keeps it out
  of the back-stack so the browser back button skips it.

## Key concepts
- **Discriminated unions for messages**: `WSEvent` in `lib/types.ts` is a
  `type:` discriminated union. TypeScript narrows each `case` body in
  `applyEvent`, so adding a new event type forces the compiler to flag any
  case I forgot to handle (the unhandled-default branch only catches
  *runtime* surprises).
- **Effect cleanup for sockets**: returning a cleanup from `useEffect`
  closes the WS when the component unmounts or `scanId` changes. Without
  it, navigating between scans would leak sockets and double-deliver
  events.
- **Conditional inputs are part of state shape**: hiding port/timeout/NVD
  inputs based on scan type is UI sugar; the JSON body deliberately omits
  the keys when the inputs aren't shown, so the backend's defaults take
  effect.

## How to run / test
```bash
docker compose up -d --build
open http://localhost:3000/scans/new
# fill in target=127.0.0.1, type=Port scan, defaults, submit → redirects
# to /scans/<id>/live and streams open-port rows as they're discovered.
```

## Testing status
- `npx tsc --noEmit` clean; `npx next build` produces both routes
  (`/scans/new` static, `/scans/[id]/live` dynamic).
- Dev server returned 200 for both `/scans/new` and `/scans/abc/live`
  during a host smoke check; `<h1>` headings match expected.
- Live behavior end-to-end (real WebSocket frames, real scan completion)
  needs the backend running and is the natural next manual check the next
  time Docker is up. Backend side of this contract is already covered by
  Task 6.3's verification log.
