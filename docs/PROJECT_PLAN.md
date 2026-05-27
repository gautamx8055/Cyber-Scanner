# CyberScanner — Full Project Plan

> A professional-grade, open-source cybersecurity scanner inspired by Nmap.
> Solo project. ~3 hours/day. Built to learn Python, Networking, Web Security, Docker, and Full-Stack Dev.

---

## Vision

Build a downloadable, cross-platform cybersecurity scanner that:
- Runs as a **CLI tool** (terminal-native, like Nmap)
- Runs as a **Web Dashboard** (Next.js frontend + FastAPI backend)
- Produces **exportable reports** — JSON, PDF, HTML, CSV (user picks)
- Ships as a **Docker container** and a **downloadable binary**
- Uses **PostgreSQL** as the database from day one

---

## Tech Stack

### Backend (Python)
| Layer | Technology | Why |
|---|---|---|
| Core engine | Python 3.12 + `asyncio` | Scan hundreds of ports at once without waiting |
| Port scanning | Raw sockets + `asyncio` | Full control, fast, educational |
| Web scanning | `httpx` (async HTTP) | Built for async, better than `requests` |
| Packet crafting | `scapy` | Low-level network packets, SYN scans |
| API server | `FastAPI` | Async-first, auto-generates API docs |
| Database | `PostgreSQL` + `SQLAlchemy` + `Alembic` | Production-grade from day one |
| Reports | `WeasyPrint` (PDF) + `Jinja2` (HTML) | Industry standard |
| CLI styling | `Rich` | Beautiful terminal output, tables, progress bars |
| Packaging | `PyInstaller` + `Docker` | Downloadable binary or container |

### Frontend (Next.js)
| Layer | Technology | Why |
|---|---|---|
| Framework | Next.js 14 (App Router) | React-based, SSR, perfect for dashboards |
| UI | `shadcn/ui` + `TailwindCSS` | Clean, fast to build, professional look |
| Charts | `Recharts` | Visualize ports, risk scores, scan history |
| State | `Zustand` | Simple state management, no Redux boilerplate |
| API calls | `TanStack Query` | Auto-caching + polling live scan status |

### Docker Stack
| Container | What it runs |
|---|---|
| `backend` | FastAPI Python app |
| `frontend` | Next.js app |
| `db` | PostgreSQL 16 |
| `redis` *(later)* | Job queue for background scans |

### C Extensions (Phase 9)
- Rewrite port scanner hot-path in C
- Expose to Python via `ctypes`
- Learn: why C is faster, how Python calls native code

---

## Time Budget

| Per day | 3 hours |
|---|---|
| Per task | ~1.5 hours |
| Per phase (2 tasks) | ~1 day |
| Per phase (4 tasks) | ~2 days |
| Full project (all phases) | ~5-6 weeks at 3hrs/day |

---

## What You Will Learn — Phase by Phase

| Phase | Python | Networking | Docker | Web/Security |
|---|---|---|---|---|
| 1 | project structure, venv | — | basics, compose, postgres | — |
| 2 | sockets, asyncio | TCP/IP, ports | volumes, networking | — |
| 3 | classes, dataclasses | ICMP, UDP, DNS | — | — |
| 4 | regex, API calls | banners, versions | — | CVEs, CVSS scores |
| 5 | httpx, async | HTTP protocol | — | OWASP Top 10, SSL/TLS |
| 6 | FastAPI, SQLAlchemy | — | multi-container | REST API design |
| 7 | Alembic, background tasks | WebSockets | — | live data streaming |
| 8 | Jinja2 templates | — | — | report design |
| 9 | ctypes, C interop | raw sockets | — | SYN scans |
| 10 | — | — | Dockerfile optimization, CI | — |
| 11 | Next.js (React) | — | — | security dashboard UX |
| 12 | scheduling, plugins | — | — | automation |

---

## Phases

---

### Phase 1 — Project Foundation + Docker Setup
**Goal**: Set up the full development environment. PostgreSQL running in Docker. Python project skeleton ready.
**Time estimate**: 1-2 days

**What you will learn:**
- Docker fundamentals: images, containers, volumes, ports
- Docker Compose: running multiple containers together
- Connecting Python to PostgreSQL
- Project structure best practices

**Tasks:**

#### Task 1.1 — Docker + PostgreSQL Setup
- Install Docker Desktop (if not done)
- Write `docker-compose.yml` with a PostgreSQL 16 container
- Configure environment variables (DB name, user, password) via `.env` file
- Verify PostgreSQL is running: connect with `psql` or a GUI tool like DBeaver
- **Docker lesson**: what is an image vs container? What does `docker-compose up` do?

#### Task 1.2 — Python Project Skeleton
- Create the full folder structure (backend, frontend, docs, tests)
- Set up Python virtual environment inside the project
- Install core dependencies: `fastapi`, `sqlalchemy`, `asyncpg`, `alembic`, `rich`, `httpx`, `scapy`
- Write `requirements.txt`
- Create `backend/main.py` as the entry point (just a hello world for now)
- **Python lesson**: what is a virtual environment and why do we use one?

#### Task 1.3 — Connect Python to PostgreSQL
- Configure SQLAlchemy to connect to the Docker PostgreSQL container
- Write a simple test: create a `scans` table, insert a row, read it back
- Set up Alembic for database migrations (learn: what is a migration and why it matters)
- **Python lesson**: what is an ORM (SQLAlchemy)? How is it different from raw SQL?

---

### Phase 2 — Core Port Scanner (Synchronous)
**Goal**: Build a working TCP port scanner the simple way first — then understand why it is slow.
**Time estimate**: 1-2 days

**What you will learn:**
- How TCP connections work (the 3-way handshake)
- Python sockets from scratch
- Why synchronous I/O is slow for network scanning
- Clean CLI with `argparse` and `Rich`

**Tasks:**

#### Task 2.1 — TCP Connect Scanner (Synchronous)
- Write `port_scanner.py` with a `scan_port(ip, port)` function using Python `socket`
- Scan a range of ports one by one (sequential)
- Handle: open, closed, filtered states
- Print results to terminal with `Rich` table
- **Networking lesson**: what is a port? What is a TCP handshake? What does "filtered" mean?

#### Task 2.2 — Banner Grabbing + Service Detection
- After a port is confirmed open, read the first bytes the service sends (the banner)
- Build a service map: common ports → service names (22=SSH, 80=HTTP, 443=HTTPS, etc.)
- Parse banner for software/version info: `SSH-2.0-OpenSSH_8.2` → `OpenSSH 8.2`
- Save results to PostgreSQL via SQLAlchemy
- **Networking lesson**: what is a service banner? Why do servers announce themselves?

#### Task 2.3 — Measure the Problem + Add argparse CLI
- Time the synchronous scanner on 1-1000 ports — record how slow it is
- Add a full CLI with `argparse`: `cyberscan ports 192.168.1.1 -p 1-1000 --timeout 1`
- Support port formats: single (`80`), range (`1-1000`), list (`80,443,8080`)
- **Python lesson**: `argparse` — how CLI tools parse user input

---

### Phase 3 — Async Port Scanner (The Fast Version)
**Goal**: Rewrite the scanner using `asyncio`. Understand WHY it is dramatically faster.
**Time estimate**: 1-2 days

**What you will learn:**
- `asyncio` fundamentals: event loop, coroutines, tasks, `await`
- Why async beats threading for I/O-bound work
- `asyncio.gather()` — launch hundreds of tasks at once
- Semaphores — controlling concurrency safely

**Tasks:**

#### Task 3.1 — Rewrite Scanner with asyncio
- Convert `scan_port()` to an `async def` coroutine
- Use `asyncio.open_connection()` instead of `socket.connect()`
- Use `asyncio.gather()` to scan all ports simultaneously
- Benchmark: compare sync vs async on same target
- **Python lesson**: what is `async def`? What does `await` mean? What is the event loop?

#### Task 3.2 — Concurrency Control + UDP Scanner
- Add `asyncio.Semaphore` to limit max concurrent connections (avoid crashing target)
- Add a timeout per connection with `asyncio.wait_for()`
- Write a basic UDP scanner (different from TCP — no handshake, uses `sendto`/`recvfrom`)
- **Networking lesson**: UDP vs TCP — connectionless vs connection-based

#### Task 3.3 — Host Discovery (Ping Sweep)
- Write an ICMP ping sweep: scan a subnet (e.g. `192.168.1.0/24`) for live hosts
- Use `scapy` to send ICMP echo requests
- Add `--sweep` flag to CLI: `cyberscan sweep 192.168.1.0/24`
- **Networking lesson**: what is ICMP? How does ping work? What is a subnet?

#### Task 3.4 — DNS Resolution + OS Fingerprinting Hints
- Resolve hostnames to IPs (and reverse: IP → hostname)
- Detect OS hints from TTL values in ping responses (Linux=64, Windows=128)
- Display resolved hostnames in scan results
- **Networking lesson**: what is DNS? What is TTL and why does it hint at OS type?

---

### Phase 4 — Vulnerability Detection Engine
**Goal**: Identify known vulnerabilities from the service banners you collected.
**Time estimate**: 2 days

**What you will learn:**
- What CVEs are and how they are structured
- Working with external REST APIs in Python
- Regex for version extraction
- Risk scoring (CVSS)

**Tasks:**

#### Task 4.1 — Version Extraction + Local CVE Database
- Write regex patterns to extract versions from banners: `Apache/2.4.49` → `{Apache, 2.4.49}`
- Build a local JSON file with ~50 known CVEs for common software
- Write `vuln_scanner.py` that matches extracted versions against the local CVE DB
- **Python lesson**: regex with `re` module — patterns, groups, match vs search

#### Task 4.2 — NVD API Integration + Risk Scoring
- Connect to the NIST NVD API (free, no auth required for basic use)
- Query live CVE data for a given software + version
- Implement CVSS-based risk scoring: Critical (9+) / High (7-9) / Medium (4-7) / Low (<4)
- Display colored risk levels in terminal with `Rich`
- **Security lesson**: what is CVSS? How is a vulnerability scored?

#### Task 4.3 — Save Vulnerabilities to PostgreSQL
- Add `vulnerabilities` table to the database schema
- Run an Alembic migration to add the new table
- Save all found CVEs with their scores to the DB, linked to the parent scan
- **Docker lesson**: running `alembic upgrade head` inside a Docker container

---

### Phase 5 — Web Security Scanner
**Goal**: Scan web applications for OWASP Top 10 issues and misconfigurations.
**Time estimate**: 2 days

**What you will learn:**
- HTTP protocol in depth (headers, methods, status codes)
- What OWASP Top 10 is and why each issue matters
- SSL/TLS certificates
- Async HTTP with `httpx`

**Tasks:**

#### Task 5.1 — SSL/TLS Checker + HTTP Header Analysis
- Check SSL certificate: valid, expiry date, issuer, self-signed flag
- Check weak cipher suites
- Analyze security headers: `X-Frame-Options`, `CSP`, `HSTS`, `X-Content-Type-Options`, `Server` header info leak
- Score each header: present/missing/misconfigured
- **Security lesson**: what does each header protect against? What is SSL/TLS?

#### Task 5.2 — Directory Brute-Forcer
- Load a wordlist of common paths (`/admin`, `/.env`, `/backup.zip`, `/phpmyadmin`, etc.)
- Async GET requests to all paths simultaneously with `httpx`
- Report: 200 (found), 403 (forbidden but exists), 301/302 (redirect)
- **Security lesson**: why do attackers brute-force directories? What is a `.env` file leak?

#### Task 5.3 — OWASP Basic Probes
- Open redirect: test `?url=https://evil.com` and check if it redirects
- Reflected XSS: inject `<script>alert(1)</script>` in params, check if reflected in response
- SQL injection (error-based): inject `'` and check for SQL error messages in response
- **Security lesson**: how do each of these attacks work? Why are they dangerous?

#### Task 5.4 — Subdomain Enumeration
- DNS brute-force: try `www`, `mail`, `api`, `admin`, `dev` + target domain
- Use `asyncio` + `aiodns` for fast async DNS lookups
- Report live subdomains with their IPs
- **Networking lesson**: what is subdomain enumeration? Why is it part of recon?

---

### Phase 6 — FastAPI Backend + Database Models
**Goal**: Expose all scanner functionality through a REST API with PostgreSQL persistence.
**Time estimate**: 2 days

**What you will learn:**
- REST API design
- FastAPI route handlers, request/response models
- SQLAlchemy ORM models
- Background tasks in FastAPI

**Tasks:**

#### Task 6.1 — Database Models + Alembic Migrations
- Define full SQLAlchemy models: `Scan`, `Port`, `Vulnerability`, `WebFinding`
- Write Alembic migration for the complete schema
- Add indexes for fast queries (scan_id, target_ip, created_at)
- **Python lesson**: SQLAlchemy models — how Python classes map to database tables

#### Task 6.2 — Core API Routes
- `POST /api/scans` — start a new scan (port, vuln, or web)
- `GET /api/scans` — list all past scans with pagination
- `GET /api/scans/{id}` — get full scan details
- `DELETE /api/scans/{id}` — delete a scan
- Auto-generated API docs at `/docs` (FastAPI Swagger UI — free with FastAPI)
- **Python lesson**: Pydantic models — how FastAPI validates request/response data

#### Task 6.3 — Background Tasks + WebSocket Live Updates
- Run scans as FastAPI background tasks (scan starts, API returns immediately)
- Open a WebSocket at `/ws/scan/{id}` — scanner pushes progress updates in real-time
- Client (CLI or dashboard) receives live updates: `{"port": 80, "state": "open"}`
- **Python lesson**: what is a WebSocket? How is it different from HTTP?

#### Task 6.4 — Docker Compose: Full Multi-Container Setup
- Add `backend` container to `docker-compose.yml`
- Configure container networking: frontend → backend → db (containers talk by name)
- Add health checks: backend waits for postgres to be ready before starting
- Use Docker volumes for PostgreSQL data persistence
- **Docker lesson**: container networking, health checks, depends_on, volumes

---

### Phase 7 — Report Engine
**Goal**: Generate professional scan reports in multiple formats.
**Time estimate**: 1-2 days

**What you will learn:**
- Jinja2 HTML templating
- PDF generation from HTML
- Structuring data for export

**Tasks:**

#### Task 7.1 — JSON + CSV Export
- Write `reporter.py` with a clean `ScanReport` data class
- Export to JSON: full structured report with all findings
- Export to CSV: flat table format (one row per finding)
- Add `GET /api/scans/{id}/export?format=json` API endpoint
- **Python lesson**: `dataclasses`, `json` module, `csv` module

#### Task 7.2 — HTML + PDF Report
- Design an HTML report template with Jinja2 (risk summary, port table, vuln table, charts)
- Convert HTML → PDF with `WeasyPrint`
- Add `GET /api/scans/{id}/export?format=pdf` endpoint
- Add `GET /api/scans/{id}/export?format=html` endpoint
- **Python lesson**: Jinja2 templates — variables, loops, conditionals in HTML

---

### Phase 8 — Next.js Dashboard
**Goal**: Build a professional web dashboard to view scan results and run new scans.
**Time estimate**: 2-3 days

**What you will learn:**
- Next.js App Router structure
- React components and hooks
- Fetching data from a backend API
- Real-time updates with WebSocket

**Tasks:**

#### Task 8.1 — Dashboard Layout + Scan History Page
- Set up Next.js project with shadcn/ui + TailwindCSS
- Dashboard home: list all scans, risk summary cards, recent findings
- Charts with Recharts: open ports by category, risk level distribution
- Add `frontend` container to Docker Compose
- **Next.js lesson**: App Router file structure, `page.tsx`, `layout.tsx`

#### Task 8.2 — New Scan Form + Live Progress Page
- Form to start a new scan: target input, scan type selector, options
- Live scan page: WebSocket connection to backend → real-time progress bar + live port table
- Show ports appearing as they are discovered
- **React lesson**: `useState`, `useEffect`, WebSocket in React

#### Task 8.3 — Scan Detail Page + Report Download
- Per-scan detail page: full port list, vulnerability findings, web security findings
- Severity badges (Critical/High/Medium/Low) with color coding
- Report download buttons: select JSON / PDF / HTML / CSV and download
- **React lesson**: dynamic routes in Next.js (`/scan/[id]`), TanStack Query for data fetching

---

### Phase 9 — C Extension for Speed
**Goal**: Rewrite the port scanner inner loop in C. Learn how Python and C interact.
**Time estimate**: 2 days

**What you will learn:**
- Basic C programming (enough for systems-level tasks)
- How Python calls C via `ctypes`
- Raw socket programming in C
- Performance benchmarking

**Tasks:**

#### Task 9.1 — Write Port Scanner in C
- Write `port_scan.c`: a function that takes an IP and port list, returns open ports
- Use POSIX sockets in C (`socket()`, `connect()`, `select()`)
- Compile to a shared library (`.so` on Linux, `.dll` on Windows)
- **C lesson**: what is a shared library? How does compilation work?

#### Task 9.2 — Expose C Library to Python with ctypes
- Load the `.so` from Python using `ctypes.CDLL`
- Call `scan_ports()` from Python, pass IP and port array, receive results
- Benchmark: Python async scanner vs C scanner on 10,000 ports
- **Python lesson**: `ctypes` — Python's built-in C foreign function interface

#### Task 9.3 — SYN Scan with Raw Sockets
- Write a SYN scanner in C using raw sockets (send SYN, check for SYN-ACK, never complete handshake)
- SYN scans are faster and stealthier than full TCP connect scans
- Requires root/admin privileges — document this
- **Networking lesson**: what is a half-open scan? Why is SYN scanning stealthier?

---

### Phase 10 — Docker Production + Packaging
**Goal**: Make CyberScanner installable and distributable. Learn production Docker.
**Time estimate**: 2 days

**What you will learn:**
- Multi-stage Docker builds (smaller images)
- Docker networking in production
- PyInstaller for binary packaging
- GitHub Actions basics

**Tasks:**

#### Task 10.1 — Production Dockerfiles (Multi-Stage Builds)
- Write multi-stage `Dockerfile` for backend: build stage + slim runtime stage
- Write `Dockerfile` for frontend: build Next.js → serve with nginx
- Reduce image sizes (learn: why image size matters in production)
- **Docker lesson**: multi-stage builds, layer caching, `.dockerignore`

#### Task 10.2 — PyInstaller Binary + Install Script
- Package the CLI tool as a single binary with PyInstaller (`cyberscan.exe` / `cyberscan`)
- Write a one-line install script: `curl https://... | bash`
- Test on Linux and Windows (via Docker for cross-compile)
- **Python lesson**: how PyInstaller bundles Python + dependencies into one file

#### Task 10.3 — GitHub Actions CI/CD
- Write a GitHub Actions workflow that:
  - Runs tests on every push
  - Builds Docker images and pushes to Docker Hub
  - Creates a GitHub Release with binary downloads
- **DevOps lesson**: what is CI/CD? What is a pipeline?

---

### Phase 11 — Advanced Features + Automation
**Goal**: Add enterprise-grade automation features.
**Time estimate**: 2-3 days

**What you will learn:**
- Scheduled jobs in Python
- External notifications (Slack/email)
- Plugin architecture design

**Tasks:**

#### Task 11.1 — Scheduled Scans + Alerting
- Add scheduled scan support: `cyberscan schedule add 192.168.1.1 --every 24h`
- Use `APScheduler` library for cron-style scheduling
- Send Slack webhook notification when scan finds new Critical vulnerability
- **Python lesson**: `APScheduler`, webhook HTTP calls

#### Task 11.2 — Multi-Target + Subnet Scanning
- Accept CIDR notation input: `192.168.1.0/24` → scan all 254 hosts
- Parallel host scanning with concurrency limits
- Aggregate results: overall network risk map
- **Networking lesson**: what is CIDR notation? What is a subnet mask?

#### Task 11.3 — Plugin System
- Design a plugin interface: users drop a `.py` file into `/plugins/` folder
- Scanner automatically loads and runs plugins
- Write two example plugins: custom port check, custom web probe
- **Python lesson**: dynamic module loading with `importlib`

#### Task 11.4 — Redis Job Queue (Background Scans at Scale)
- Add Redis container to Docker Compose
- Use `Celery` or `ARQ` for async job queue
- Large scans run as queued background jobs instead of blocking API
- **Docker lesson**: adding a third service, Redis basics

---

## Folder Structure

```
cyber-scanner/
├── docs/
│   ├── PROJECT_PLAN.md          ← This file
│   └── workflow/
│       └── WORKFLOW.md
│
├── backend/
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── port_scanner.py
│   │   ├── vuln_scanner.py
│   │   ├── web_scanner.py
│   │   ├── resolver.py
│   │   └── reporter.py
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py
│   ├── db/
│   │   ├── __init__.py
│   │   ├── models.py
│   │   └── session.py
│   ├── c_extensions/
│   │   └── port_scan.c
│   ├── alembic/
│   ├── main.py
│   └── requirements.txt
│
├── frontend/
│   ├── app/
│   │   ├── page.tsx
│   │   ├── layout.tsx
│   │   └── scan/[id]/
│   ├── components/
│   └── package.json
│
├── docker/
│   ├── backend.Dockerfile
│   └── frontend.Dockerfile
│
├── docker-compose.yml
├── docker-compose.prod.yml
├── .env.example
└── tests/
```

---

## Progress Tracker

- [x] Project planned
- [x] **Phase 1** — Foundation + Docker Setup
  - [x] 1.1 Docker + PostgreSQL setup
  - [x] 1.2 Python project skeleton
  - [x] 1.3 Connect Python to PostgreSQL
- [x] **Phase 2** — Synchronous Port Scanner
  - [x] 2.1 TCP connect scanner
  - [x] 2.2 Banner grabbing + service detection
  - [x] 2.3 argparse CLI
- [x] **Phase 3** — Async Port Scanner
  - [x] 3.1 Rewrite with asyncio
  - [x] 3.2 Concurrency control + UDP scanner
  - [x] 3.3 Host discovery (ping sweep)
  - [x] 3.4 DNS resolution + OS fingerprinting
- [x] **Phase 4** — Vulnerability Detection
  - [x] 4.1 Version extraction + local CVE DB
  - [x] 4.2 NVD API + risk scoring
  - [x] 4.3 Save vulnerabilities to PostgreSQL
- [x] **Phase 5** — Web Security Scanner
  - [x] 5.1 SSL/TLS + HTTP header analysis
  - [x] 5.2 Directory brute-forcer
  - [x] 5.3 OWASP basic probes
  - [x] 5.4 Subdomain enumeration
- [ ] **Phase 6** — FastAPI Backend
  - [x] 6.1 Database models + migrations
  - [x] 6.2 Core API routes
  - [x] 6.3 Background tasks + WebSocket
  - [ ] 6.4 Full Docker Compose setup
- [ ] **Phase 7** — Report Engine
  - [ ] 7.1 JSON + CSV export
  - [ ] 7.2 HTML + PDF report
- [ ] **Phase 8** — Next.js Dashboard
  - [ ] 8.1 Dashboard layout + scan history
  - [ ] 8.2 New scan form + live progress
  - [ ] 8.3 Scan detail + report download
- [ ] **Phase 9** — C Extensions
  - [ ] 9.1 Port scanner in C
  - [ ] 9.2 ctypes integration
  - [ ] 9.3 SYN scan with raw sockets
- [ ] **Phase 10** — Packaging + Distribution
  - [ ] 10.1 Production Dockerfiles
  - [ ] 10.2 PyInstaller binary
  - [ ] 10.3 GitHub Actions CI/CD
- [ ] **Phase 11** — Advanced Automation
  - [ ] 11.1 Scheduled scans + alerting
  - [ ] 11.2 Multi-target + subnet scanning
  - [ ] 11.3 Plugin system
  - [ ] 11.4 Redis job queue
