# CyberScanner — Task Tracker

Mark tasks as done by changing `[ ]` to `[x]`.

---

## Phase 1 — Project Foundation + Docker Setup
- [x] 1.1 Write `docker-compose.yml` with PostgreSQL 16 container
- [x] 1.1 Create `.env` and `.env.example` with DB credentials
- [x] 1.1 Create `docker/backend.Dockerfile`
- [x] 1.1 Add `.gitignore`
- [x] 1.2 Create full folder structure (backend, frontend, tests, docker)
- [x] 1.2 Write `backend/requirements.txt` with all core dependencies
- [x] 1.2 Create `backend/main.py` entry point (FastAPI hello world)
- [x] 1.2 Install dependencies into venv
- [x] 1.3 Write `backend/db/session.py` — async SQLAlchemy engine + session factory
- [x] 1.3 Write `backend/db/models.py` — Scan ORM model with enums
- [x] 1.3 Initialize Alembic and configure `alembic/env.py`
- [x] 1.3 Write first migration — `scans` table with indexes
- [x] 1.3 Write `tests/test_db_connection.py` — connection verification script

---

## Phase 2 — Core Port Scanner (Synchronous)
- [x] 2.1 Write `backend/scanner/port_scanner.py` — `scan_port(ip, port)` using Python `socket`
- [x] 2.1 Handle open / closed / filtered port states
- [x] 2.1 Print results to terminal with Rich table
- [x] 2.2 Banner grabbing — read first bytes from open port
- [x] 2.2 Service map — common ports to service names (22=SSH, 80=HTTP, etc.)
- [x] 2.2 Parse banner for software/version info
- [x] 2.2 Save scan results to PostgreSQL via SQLAlchemy
- [x] 2.3 Time the synchronous scanner — record baseline speed
- [x] 2.3 Add `argparse` CLI — `cyberscan ports <ip> -p 1-1000 --timeout 1`
- [x] 2.3 Support port formats: single (`80`), range (`1-1000`), list (`80,443,8080`)

---

## Phase 3 — Async Port Scanner (Fast Version)
- [x] 3.1 Rewrite `scan_port()` as `async def` using `asyncio.open_connection()`
- [x] 3.1 Use `asyncio.gather()` to scan all ports simultaneously
- [x] 3.1 Benchmark: compare sync vs async on same target
- [x] 3.2 Add `asyncio.Semaphore` — limit max concurrent connections
- [x] 3.2 Add per-connection timeout with `asyncio.wait_for()`
- [x] 3.2 Write basic UDP scanner using `sendto`/`recvfrom`
- [x] 3.3 ICMP ping sweep using scapy — scan subnet for live hosts
- [x] 3.3 Add `--sweep` flag to CLI: `cyberscan sweep 192.168.1.0/24`
- [x] 3.4 DNS resolution — hostname → IP and reverse (IP → hostname)
- [x] 3.4 OS fingerprinting hints from TTL values (Linux=64, Windows=128)

---

## Phase 4 — Vulnerability Detection Engine
- [x] 4.1 Write regex patterns to extract versions from banners
- [x] 4.1 Build local CVE database JSON file (~50 known CVEs)
- [x] 4.1 Write `backend/scanner/vuln_scanner.py` — match versions against local CVE DB
- [x] 4.2 Connect to NIST NVD API — query live CVE data
- [x] 4.2 Implement CVSS risk scoring: Critical / High / Medium / Low
- [x] 4.2 Display colored risk levels with Rich
- [x] 4.3 Add `vulnerabilities` table to DB schema
- [x] 4.3 Run Alembic migration for vulnerabilities table
- [x] 4.3 Save CVEs with scores to DB, linked to parent scan

---

## Phase 5 — Web Security Scanner
- [ ] 5.1 SSL/TLS checker — expiry, issuer, self-signed, cipher suites
- [ ] 5.1 HTTP security header analysis — X-Frame-Options, CSP, HSTS, etc.
- [ ] 5.2 Directory brute-forcer with wordlist — async GET via httpx
- [ ] 5.2 Report 200 / 403 / 301 responses
- [ ] 5.3 Open redirect probe
- [ ] 5.3 Reflected XSS probe
- [ ] 5.3 SQL injection (error-based) probe
- [ ] 5.4 Subdomain enumeration via async DNS brute-force with aiodns

---

## Phase 6 — FastAPI Backend + Database Models
- [ ] 6.1 Define full SQLAlchemy models: Scan, Port, Vulnerability, WebFinding
- [ ] 6.1 Write Alembic migration for complete schema
- [ ] 6.1 Add indexes (scan_id, target_ip, created_at)
- [ ] 6.2 `POST /api/scans` — start a new scan
- [ ] 6.2 `GET /api/scans` — list scans with pagination
- [ ] 6.2 `GET /api/scans/{id}` — full scan details
- [ ] 6.2 `DELETE /api/scans/{id}` — delete a scan
- [ ] 6.3 Run scans as FastAPI background tasks
- [ ] 6.3 WebSocket `/ws/scan/{id}` — push live progress updates
- [ ] 6.4 Add backend container to docker-compose with health checks
- [ ] 6.4 Configure container networking (backend → db by service name)

---

## Phase 7 — Report Engine
- [ ] 7.1 Write `backend/scanner/reporter.py` with `ScanReport` dataclass
- [ ] 7.1 Export to JSON — full structured report
- [ ] 7.1 Export to CSV — flat table (one row per finding)
- [ ] 7.1 `GET /api/scans/{id}/export?format=json` endpoint
- [ ] 7.2 Design HTML report template with Jinja2
- [ ] 7.2 Convert HTML → PDF with WeasyPrint
- [ ] 7.2 `GET /api/scans/{id}/export?format=pdf` and `?format=html` endpoints

---

## Phase 8 — Next.js Dashboard
- [ ] 8.1 Set up Next.js project with shadcn/ui + TailwindCSS
- [ ] 8.1 Dashboard home — scan list, risk summary cards, Recharts charts
- [ ] 8.1 Add frontend container to docker-compose
- [ ] 8.2 New scan form — target input, scan type selector
- [ ] 8.2 Live scan page — WebSocket connection, real-time progress bar + port table
- [ ] 8.3 Per-scan detail page — ports, vulnerabilities, web findings
- [ ] 8.3 Severity badges (Critical/High/Medium/Low)
- [ ] 8.3 Report download buttons — JSON / PDF / HTML / CSV

---

## Phase 9 — C Extension for Speed
- [ ] 9.1 Write `backend/c_extensions/port_scan.c` — scan function using POSIX sockets
- [ ] 9.1 Compile to shared library (`.so`)
- [ ] 9.2 Load `.so` from Python with `ctypes.CDLL`
- [ ] 9.2 Benchmark: Python async scanner vs C scanner on 10,000 ports
- [ ] 9.3 SYN scanner in C using raw sockets (half-open scan)

---

## Phase 10 — Docker Production + Packaging
- [ ] 10.1 Multi-stage Dockerfile for backend (build + slim runtime)
- [ ] 10.1 Multi-stage Dockerfile for frontend (Next.js build → nginx)
- [ ] 10.2 Package CLI as single binary with PyInstaller
- [ ] 10.2 Write one-line install script
- [ ] 10.3 GitHub Actions workflow — tests, Docker Hub push, GitHub Release

---

## Phase 11 — Advanced Features + Automation
- [ ] 11.1 Scheduled scans with APScheduler — `cyberscan schedule add <ip> --every 24h`
- [ ] 11.1 Slack webhook notification on Critical vulnerability found
- [ ] 11.2 CIDR notation input — scan all hosts in a subnet
- [ ] 11.2 Aggregate results — network risk map
- [ ] 11.3 Plugin system — drop `.py` files into `/plugins/` folder
- [ ] 11.3 Write two example plugins
- [ ] 11.4 Add Redis container to docker-compose
- [ ] 11.4 Celery/ARQ job queue for background scans at scale
