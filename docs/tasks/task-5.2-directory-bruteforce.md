# Task 5.2 — Directory Brute-Forcer

## What was built
An async directory/file brute-forcer in `web_scanner.py` (`scan_dirs`) plus a
curated wordlist.

- **Bundled wordlist** `backend/scanner/data/web_wordlist.txt` (~155 high-signal
  paths): source-control dirs (`.git/config`), env/secret files (`.env`,
  `wp-config.php`, `.aws/credentials`), backups (`backup.sql`, `db.sql`), admin
  surfaces (`admin`, `phpmyadmin`), diagnostics (`phpinfo.php`, `actuator/env`),
  API docs (`swagger.json`, `graphql`), and common dirs. `#` comments + blanks
  ignored.
- **Async probing**: all paths fire through `httpx` under an `asyncio.Semaphore`
  (default 50). Redirects are **not** followed (`follow_redirects=False`) so we
  see the real status.
- **Reported statuses**: 200/204 (accessible), 401 (auth required, exists),
  403 (forbidden, exists), 30x (redirect — Location recorded), 500.
- **Sensitive-path severity bump**: a hit on `.env`, `.git`, `backup`, etc. is
  rated High (200) / Medium (403) instead of Low.
- **Soft-404 calibration** (`_calibrate_soft404`): first requests a random path.
  If the server answers 200 (i.e. it lies about missing pages), the baseline
  body length is recorded and same-size 200s are filtered out — kills the false
  positives that plague naive brute-forcers.

## Files modified
- **modified** `backend/scanner/web_scanner.py` — `scan_dirs`, `_probe_path`,
  `_calibrate_soft404`, `load_dir_wordlist`, `_is_sensitive`, `SENSITIVE_HINTS`
- **new** `backend/scanner/data/web_wordlist.txt`

## Key concepts
- **Soft 404s**: many sites return `200 OK` with a "not found" page for any URL.
  Comparing each 200 against a known-bogus baseline distinguishes a real page
  from the server's catch-all. (A size delta ≤ 64 bytes is treated as the same.)
- **Why concurrency is capped**: hundreds of simultaneous requests can trip rate
  limits / WAFs and skew results; the semaphore keeps it polite and stable.
- **HEAD vs GET**: we use GET because many servers mishandle HEAD; the body is
  also what the soft-404 check needs.

## How to run
```bash
docker-compose exec backend python -m cli web https://example.com --checks dirs
docker-compose exec backend python -m cli web https://example.com --checks dirs --wordlist /app/scanner/data/web_wordlist.txt
```

## Testing status
Wordlist loading, sensitive-path detection, and status→severity mapping are
unit-verified. Live brute-forcing needs network + the rebuilt backend image.
