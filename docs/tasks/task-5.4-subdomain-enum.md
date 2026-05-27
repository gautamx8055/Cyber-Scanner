# Task 5.4 — Subdomain Enumeration

## What was built
Async DNS brute-force in `web_scanner.py` (`scan_subdomains`) over a bundled
label wordlist.

- **Wordlist** `backend/scanner/data/subdomains.txt` (~143 labels): `www`,
  `mail`, `api`, `dev`, `staging`, `admin`, `vpn`, `git`, `gitlab`, `jenkins`,
  `grafana`, `db`, `cdn`, … `#` comments + blanks ignored.
- For each label we resolve `label.target.com`'s A records concurrently under an
  `asyncio.Semaphore` (default 100); every one that resolves becomes an Info
  `subdomain` finding with its IP(s).
- IP-literal targets are skipped (nothing to brute-force).

## Resolver: aiodns with a fallback
The plan names **aiodns** (c-ares async DNS). The module prefers it, but if
`aiodns`/`pycares` isn't importable it transparently falls back to asyncio's
built-in async resolver (`loop.getaddrinfo`, with a per-query `wait_for`
timeout). So enumeration works everywhere — `aiodns` in the Docker image, the
stdlib fallback on a bare machine — without a hard C-extension dependency.

## Files modified
- **modified** `backend/scanner/web_scanner.py` — `scan_subdomains`,
  `_resolve_a`, `load_subdomain_wordlist`, optional `aiodns` import + `_HAVE_AIODNS`
- **new** `backend/scanner/data/subdomains.txt`
- **modified** `backend/requirements.txt` — `aiodns`

## Key concepts
- **Brute-force vs zone transfer / cert-transparency**: this is the active,
  guess-and-resolve approach — fast and simple, but only finds labels in the
  wordlist. (CT-log / passive recon is a later enhancement.)
- **Why async DNS**: like the port scanner, the work is I/O-bound waiting on
  resolver round-trips; firing all lookups concurrently turns minutes into a
  second or two. The semaphore stops us from swamping the local resolver.
- **Graceful degradation** keeps an optional native dependency from becoming a
  hard install requirement.

## How to run
```bash
docker-compose exec backend python -m cli web example.com --checks subdomains
```

## Testing status
Wordlist loading is unit-verified and the aiodns→getaddrinfo fallback path is
exercised (the test box has neither aiodns nor network, so `_HAVE_AIODNS=False`).
Live resolution needs network + the rebuilt backend image.
