# CyberScanner — System Workflow

How all parts of CyberScanner connect and communicate.
This is the "map" of the entire project — refer back to this as you build each phase.

---

## Big Picture Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          USER                                        │
│                                                                      │
│    Terminal (CLI)                    Browser (localhost:3000)        │
│    cyberscan ports 10.0.0.1          Next.js Dashboard               │
└────────┬────────────────────────────────────┬────────────────────────┘
         │                                    │
         │                                    │ HTTP / WebSocket
         ▼                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      FastAPI Backend  :8000                          │
│                                                                      │
│   POST /api/scans          WebSocket /ws/scan/{id}                   │
│   GET  /api/scans          GET /api/scans/{id}/export                │
│   GET  /api/scans/{id}                                               │
└────────────────────────────┬────────────────────────────────────────┘
                             │
         ┌───────────────────┼───────────────────────┐
         │                   │                       │
         ▼                   ▼                       ▼
┌─────────────────┐ ┌─────────────────┐  ┌─────────────────────────┐
│  Port Scanner   │ │  Vuln Detector  │  │    Web Scanner          │
│  asyncio+socket │ │  CVE lookup     │  │    httpx + OWASP checks │
│  banner grab    │ │  CVSS scoring   │  │    SSL/TLS, headers     │
└────────┬────────┘ └────────┬────────┘  └──────────┬──────────────┘
         │                   │                       │
         └───────────────────┼───────────────────────┘
                             │
                             ▼
              ┌──────────────────────────┐
              │     PostgreSQL (Docker)  │
              │                          │
              │  scans table             │
              │  ports table             │
              │  vulnerabilities table   │
              │  web_findings table      │
              └──────────────┬───────────┘
                             │
                             ▼
              ┌──────────────────────────┐
              │      Report Engine       │
              │                          │
              │  JSON  │ CSV             │
              │  HTML  │ PDF             │
              └──────────────────────────┘
```

---

## Docker Container Map

```
docker-compose.yml
│
├── db  (postgres:16)
│     port: 5432
│     volume: postgres_data → /var/lib/postgresql/data
│     env: POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB
│
├── backend  (python:3.12)
│     port: 8000
│     depends_on: db (waits for healthy)
│     env: DATABASE_URL=postgresql://user:pass@db:5432/cyberscanner
│     volumes: ./backend → /app  (live reload in dev)
│
└── frontend  (node:20)
      port: 3000
      depends_on: backend
      env: NEXT_PUBLIC_API_URL=http://localhost:8000
      volumes: ./frontend → /app  (live reload in dev)

Key Docker concept:
  Containers talk to each other by SERVICE NAME, not localhost.
  Python connects to PostgreSQL at: postgresql://user:pass@db:5432/...
                                                              ^^
                                               this "db" is the service name
```

---

## Phase 1 Workflow — Foundation

```
Developer runs:  docker-compose up -d

    ├── Docker pulls postgres:16 image (if not cached)
    ├── Creates container "db", starts PostgreSQL on internal port 5432
    ├── Docker builds backend image from Dockerfile
    ├── Starts "backend" container — waits for db health check
    └── Starts "frontend" container — waits for backend

Health check:
    Docker runs:  pg_isready -U user  every 5 seconds
    Backend only starts after this returns healthy

Developer then runs:
    alembic upgrade head
    → connects to PostgreSQL
    → reads migration files in alembic/versions/
    → creates all tables
    → records which migrations were applied
```

---

## Phase 2–3 Workflow — Port Scanner

```
User runs:  cyberscan ports 192.168.1.1 -p 1-1000

              main.py
                 │  argparse: target=192.168.1.1, ports=1-1000
                 ▼
           PortScanner(target, port_range)
                 │
                 ├── resolver.resolve("192.168.1.1")   → validate IP / resolve hostname
                 │
                 ├── ping_host()   → ICMP check — is the host alive?
                 │       Uses scapy: send ICMP echo request, wait for reply
                 │       If no reply: host may be down or blocking ICMP
                 │
                 └── asyncio.run(scan_all_ports())
                             │
                             │  asyncio event loop starts
                             │  creates 1000 coroutine tasks
                             │  launches ALL of them at once
                             │
                             ├── scan_port(1)   ─┐
                             ├── scan_port(2)    │  All running
                             ├── scan_port(3)    │  simultaneously
                             │   ...             │  (not waiting one by one)
                             └── scan_port(1000)─┘
                                      │
                                      │  Each coroutine:
                                      ├── asyncio.open_connection(ip, port)
                                      │       ├── SUCCESS (SYN-ACK received) → OPEN
                                      │       ├── ConnectionRefused            → CLOSED
                                      │       └── asyncio.TimeoutError         → FILTERED
                                      │
                                      └── if OPEN: grab_banner()
                                              └── reader.read(1024)
                                                    "SSH-2.0-OpenSSH_8.2\r\n"
                                                    → parse: service=SSH, version=8.2

              Results collected → ScanResult objects
                 │
                 ├── Print Rich table to terminal
                 └── Save to PostgreSQL via SQLAlchemy


WHY asyncio IS FAST (key concept):
  Sequential: scan port 1 → wait 1s timeout → scan port 2 → wait → ...
              1000 ports × 1s = 16 minutes

  Async:      launch all 1000 connections at once
              wait for ALL simultaneously
              1000 ports → done in ~1-2 seconds (limited by network, not code)

  asyncio uses ONE thread with an event loop.
  While port 1 is "waiting for response", the event loop switches to port 2, 3, 4...
  When port 1 gets a response, the loop switches back to handle it.
  No threads. No wasted waiting time.
```

---

## Phase 4 Workflow — Vulnerability Detection

```
ScanResult: { port: 80, service: "http", banner: "Apache/2.4.49 (Unix)" }
                 │
                 ▼
           VulnScanner.analyze(scan_result)
                 │
                 ├── extract_version(banner)
                 │       regex: r"Apache/(\d+\.\d+\.\d+)"
                 │       → { software: "Apache", version: "2.4.49" }
                 │
                 ├── local_cve_lookup("Apache", "2.4.49")
                 │       → reads data/cve_db.json
                 │       → matches: CVE-2021-41773 (Path Traversal, CVSS 9.8)
                 │                  CVE-2021-42013 (RCE, CVSS 9.8)
                 │
                 ├── nvd_api_lookup("Apache", "2.4.49")   [async HTTP call]
                 │       → GET https://services.nvd.nist.gov/rest/json/cves/2.0?...
                 │       → returns live CVE data (more complete than local DB)
                 │
                 └── risk_scorer(cvss_score=9.8)
                         9.0-10.0 → CRITICAL  (red)
                         7.0-8.9  → HIGH      (orange)
                         4.0-6.9  → MEDIUM    (yellow)
                         0.1-3.9  → LOW       (green)

           VulnResult saved to PostgreSQL:
           { scan_id, port, software, version, cve_id, cvss, risk_level, description }
```

---

## Phase 5 Workflow — Web Scanner

```
User runs:  cyberscan web https://example.com

              WebScanner("https://example.com")
                 │
                 ├── ssl_checker()
                 │       Uses ssl module + OpenSSL:
                 │       → fetch certificate from server
                 │       → check expiry (days until expiry)
                 │       → check issuer (is it self-signed?)
                 │       → check cipher suite (TLS 1.2? 1.3? weak ciphers?)
                 │
                 ├── header_checker()
                 │       async GET to https://example.com
                 │       Check response headers:
                 │       ┌─────────────────────────────────────────┐
                 │       │ Header                  │ Protects from │
                 │       ├─────────────────────────┼───────────────┤
                 │       │ X-Frame-Options         │ Clickjacking  │
                 │       │ Content-Security-Policy │ XSS           │
                 │       │ Strict-Transport-Sec    │ MITM (HSTS)   │
                 │       │ X-Content-Type-Options  │ MIME sniff    │
                 │       │ Server: Apache/2.4.49   │ Info leakage  │
                 │       └─────────────────────────┴───────────────┘
                 │
                 ├── dir_bruteforcer()
                 │       Load wordlist (500+ common paths)
                 │       asyncio: launch all requests simultaneously
                 │       Record: 200 (exists), 403 (forbidden/exists), 404 (not found)
                 │       Flag: /.env, /admin, /.git, /backup, /wp-admin
                 │
                 └── owasp_probes()
                         open_redirect:  GET /?redirect=https://evil.com
                                         Check: does response redirect to evil.com?
                         xss_probe:      GET /?q=<script>alert(1)</script>
                                         Check: is payload reflected in HTML body?
                         sqli_probe:     GET /?id=1'
                                         Check: does response contain SQL error?
```

---

## Phase 6–7 Workflow — API + Real-Time Updates

```
POST /api/scans
Body: { "target": "192.168.1.1", "type": "full", "ports": "1-1000" }

    FastAPI receives request
         │
         ├── Validate with Pydantic model
         ├── Create Scan record in PostgreSQL (status: "queued")
         ├── Return immediately: { "scan_id": "abc123", "status": "queued" }
         └── Launch background task (non-blocking)


Background task runs:
         │
         ├── Update scan status → "running"
         ├── PortScanner.run()
         │       For each result → push to WebSocket: { "event": "port_found", "port": 80 }
         ├── VulnScanner.run()
         │       For each result → push to WebSocket: { "event": "vuln_found", "cve": "..." }
         ├── WebScanner.run()
         │       For each result → push to WebSocket: { "event": "web_finding", "type": "..." }
         ├── Save all results to PostgreSQL
         └── Update scan status → "completed"


WebSocket flow:
    Client connects to: ws://localhost:8000/ws/scan/abc123
    Server pushes events as scan progresses:

    → {"event": "started", "target": "192.168.1.1"}
    → {"event": "port_found", "port": 22, "service": "SSH", "state": "open"}
    → {"event": "port_found", "port": 80, "service": "HTTP", "state": "open"}
    → {"event": "vuln_found", "cve": "CVE-2021-41773", "risk": "CRITICAL"}
    → {"event": "completed", "duration_seconds": 12, "total_findings": 5}

    Next.js dashboard receives these events → updates UI in real time
```

---

## Phase 8 Workflow — Dashboard Data Flow

```
Browser loads localhost:3000/

    Next.js App Router
         │
         ├── /                     → Dashboard home
         │       TanStack Query:   GET /api/scans  (auto-refreshes every 30s)
         │       Renders:          scan history table, risk chart, recent findings
         │
         ├── /scan/[id]            → Live scan or completed scan
         │       On mount:         opens WebSocket ws://localhost:8000/ws/scan/{id}
         │       Receives events → updates port table in real-time
         │       After complete → shows full results
         │
         └── /reports              → Report download center
                 Buttons: JSON | PDF | HTML | CSV
                 Click PDF → GET /api/scans/{id}/export?format=pdf
                          → browser downloads file


State management (Zustand):
    - currentScan: which scan is being viewed
    - scanList: all scans (updated by TanStack Query)
    - liveEvents: WebSocket events for active scan
```

---

## Phase 9 Workflow — C Extension

```
Python (slow inner loop):
    for port in range(1, 10001):
        try:
            sock = socket.socket()
            sock.connect((ip, port))
            open_ports.append(port)
        except:
            pass


C (fast inner loop):  port_scan.c
    int* scan_ports(const char* ip, int* ports, int count) {
        // uses POSIX select() for I/O multiplexing
        // no Python overhead, no GIL, compiled machine code
        // returns array of open ports
    }

    Compiled to: libportscan.so


Python calling C:
    import ctypes
    lib = ctypes.CDLL("./libportscan.so")
    lib.scan_ports.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_int]
    lib.scan_ports.restype = ctypes.POINTER(ctypes.c_int)

    result = lib.scan_ports(b"192.168.1.1", port_array, len(ports))


Benchmark expected:
    Python async:    1000 ports in ~1.5 seconds
    C extension:     1000 ports in ~0.2 seconds
    Improvement:     ~7-8x faster
```

---

## Database Schema

```
scans
├── id (UUID, PK)
├── target_ip (VARCHAR)
├── target_hostname (VARCHAR, nullable)
├── scan_type (ENUM: port, vuln, web, full)
├── status (ENUM: queued, running, completed, failed)
├── started_at (TIMESTAMP)
├── completed_at (TIMESTAMP, nullable)
└── options (JSONB)  ← flexible: port range, scan flags, etc.

ports
├── id (UUID, PK)
├── scan_id (FK → scans.id)
├── port_number (INTEGER)
├── protocol (ENUM: tcp, udp)
├── state (ENUM: open, closed, filtered)
├── service (VARCHAR)
├── banner (TEXT)
└── version (VARCHAR)

vulnerabilities
├── id (UUID, PK)
├── scan_id (FK → scans.id)
├── port_id (FK → ports.id, nullable)
├── cve_id (VARCHAR)
├── software (VARCHAR)
├── version (VARCHAR)
├── cvss_score (FLOAT)
├── risk_level (ENUM: critical, high, medium, low)
└── description (TEXT)

web_findings
├── id (UUID, PK)
├── scan_id (FK → scans.id)
├── finding_type (VARCHAR)  ← "missing_header", "xss", "sqli", etc.
├── severity (ENUM: critical, high, medium, low, info)
├── url (VARCHAR)
├── description (TEXT)
└── evidence (TEXT)
```

---

## Full Scan-to-Report Flow

```
Input: target (IP / domain / URL)
         │
         1. Resolve hostname → IP
         │
         2. Ping sweep → host alive?
         │
         3. Port scan → list of open ports
         │
         4. Banner grab → service + version per port
         │
         5. Vuln scan → CVEs per service (local DB + NVD API)
         │
         6. Web scan (if port 80/443 open) → OWASP checks
         │
         7. Risk scoring → severity for each finding
         │
         8. Aggregate → unified ScanReport object
         │
         9. Save to PostgreSQL
         │
         10. Export (user choice):
             ├── JSON  → structured data dump
             ├── CSV   → flat table (one row per finding)
             ├── HTML  → styled webpage with Jinja2 template
             └── PDF   → HTML rendered to PDF via WeasyPrint
```
