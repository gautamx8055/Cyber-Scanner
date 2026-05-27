# Task 5.1 — SSL/TLS Checker + HTTP Security Header Analysis

## What was built
The foundation of Phase 5's web scanner (`backend/scanner/web_scanner.py`): a
`WebFinding` dataclass, a `WebScanResult` container, target parsing, and the two
5.1 checks.

- **SSL/TLS inspection** (`check_ssl`): does two handshakes against the host.
  1. A **non-verifying** handshake (`CERT_NONE`) always completes — even for
     self-signed or expired certs — so we can read the certificate and the
     negotiated TLS version + cipher.
  2. A **verifying** handshake (`ssl.create_default_context()`) reports whether
     a normal browser would trust the cert (CA chain + hostname).
  Findings: expired / expiring-soon cert, self-signed cert, legacy TLS version
  (< 1.2), weak cipher (RC4/3DES/DES/EXPORT/… or < 128-bit), untrusted chain,
  plus a one-line "endpoint reachable" Info line so healthy hosts still report.
- **HTTP security headers** (`scan_headers`): one async GET, then flags missing
  `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and reports
  info-leak headers (`Server`, `X-Powered-By`, …).

## Files created / modified
- **new** `backend/scanner/web_scanner.py` — module skeleton + `check_ssl`,
  `scan_headers`, `normalize_target`, `render_web_table`, `save_web_scan`
- **modified** `backend/db/models.py` — `WebFinding` ORM model
- **new** `backend/alembic/versions/c3d4e5f6a7b8_add_web_findings_table.py`
- **modified** `backend/cli.py` — `web` subcommand (covers all of Phase 5)
- **modified** `backend/requirements.txt` — `cryptography` (cert field parsing)

## Key concepts
- **Why two handshakes:** Python's `ssl` only hands back a *parsed* cert dict
  when verification is on. A scanner must inspect *broken* certs, so we read the
  raw DER under `CERT_NONE` and parse it with `cryptography`, then separately ask
  "would a default client trust this?" The split lets us report expiry/issuer on
  an untrusted cert *and* say why it's untrusted.
- **`verify=False` on the HTTP client is deliberate** — the scanner still needs
  to reach hosts with bad TLS; cert problems are findings, not connection errors.
- **HSTS only matters over HTTPS**, so that header is only flagged on https URLs.

## How to run
```bash
docker-compose exec backend alembic upgrade head      # create web_findings
docker-compose exec backend python -m cli web https://example.com --checks ssl,headers
```

## Testing status
Dependency-light logic (target parsing, header set, severity ordering) is unit-
verified. The live TLS handshake + header fetch require network and the rebuilt
backend image (new `cryptography` dep) — run the command above after
`docker-compose build backend`.
