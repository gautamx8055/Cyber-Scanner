# Task 5.3 — OWASP Basic Probes

## What was built
Three active probes in `web_scanner.py`, run concurrently by `scan_probes`.
Each injects into the target URL's existing query params, or — if it has none —
a default set (`id`, `q`, `search`, `page`, …).

- **Open redirect** (`probe_open_redirect`): sets redirect-style params
  (`next`, `url`, `redirect`, `redirect_uri`, `dest`, …) to a canary URL and
  checks whether a 30x `Location` points off-site to it. Finding: High.
- **Reflected XSS** (`probe_xss`): injects a marked payload
  `cyb9z1xss<script>alert(1)</script>` and flags only a **verbatim** reflection
  (tags intact) — an HTML-encoded echo won't match, avoiding false positives.
  Finding: High.
- **Error-based SQLi** (`probe_sqli`): appends a single quote `'` and scans the
  response for DB error signatures (MySQL, PostgreSQL, Oracle `ORA-#####`, MSSQL,
  SQLite, generic "unclosed quotation mark"). Finding: High.

## Files modified
- **modified** `backend/scanner/web_scanner.py` — `scan_probes`,
  `probe_open_redirect`, `probe_xss`, `probe_sqli`, `_with_param`,
  `_params_to_test`, `SQL_ERROR_PATTERNS`, `REDIRECT_PARAMS`

## Key concepts
- **Canary host is `*.invalid`** (`canary.cyberscanner.invalid`): a reserved TLD
  that never resolves, so the open-redirect test proves off-site redirection
  without ever sending a real victim anywhere.
- **Marked, verbatim XSS detection**: a unique marker + exact-substring match for
  the unescaped `<script>` tag is what separates "reflected and would execute"
  from "reflected but safely encoded."
- **Error-based (not blind) SQLi**: the simplest, most reliable signal for a
  learning scanner — provoke a DB error with a stray quote and pattern-match the
  message. No timing/boolean inference.
- **These are active checks.** They send crafted params (plain GETs, not
  destructive), but the CLI prints an authorisation reminder, and they can be
  turned off with `--checks ssl,headers,dirs,subdomains`.

## How to run
```bash
docker-compose exec backend python -m cli web "https://example.com/search?q=test" --checks probes
```

## Testing status
Param injection (`_with_param`/`_params_to_test`) and the SQL signature set
(incl. a negative control) are unit-verified. Live probing needs a deliberately
vulnerable target (e.g. a local DVWA / juice-shop) + the rebuilt backend image.
