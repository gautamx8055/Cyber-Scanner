# Task 2.1 — TCP Connect Scanner (Synchronous)

## What was built
A synchronous TCP port scanner using Python's stdlib `socket` module.
Scans a list of ports one at a time, classifies each result as
**open**, **closed**, or **filtered**, and prints the findings as a
Rich-formatted table in the terminal.

## Files created / modified
- **new** `backend/scanner/port_scanner.py` — scanner core
  - `PortResult` dataclass — single-port finding
  - `scan_port(ip, port, timeout)` — one-port TCP connect scan
  - `scan_ports(ip, ports, timeout)` — sequential loop over ports
  - `render_results_table(ip, results, elapsed)` — Rich table renderer

## Key concepts

### TCP three-way handshake
A TCP connection starts with three packets:

1. Client → server: **SYN** ("I want to talk")
2. Server → client: **SYN-ACK** ("OK, let's talk")
3. Client → server: **ACK** ("great, starting now")

`socket.connect()` performs all three. If the handshake completes, the
port is listening (**open**). If the server replies with **RST** instead
of SYN-ACK, nothing is bound to that port (**closed**). If no reply
arrives at all, a firewall is silently dropping our SYN (**filtered**).

### Mapping Python exceptions to port states
| Exception | Meaning | State |
|---|---|---|
| `connect()` returns cleanly | handshake OK | open |
| `ConnectionRefusedError` | server sent RST | closed |
| `socket.timeout` / `TimeoutError` | no reply within timeout | filtered |
| `OSError` (host unreachable, etc.) | no route | filtered |

### Why it's slow
Each `connect()` call blocks the whole thread until it resolves.
Scanning 1,000 filtered ports with a 1-second timeout means waiting
1,000 seconds — over 16 minutes — because every port is scanned
strictly after the previous one. Phase 3 fixes this with `asyncio`.

## How to run

Make sure Docker services are up:

```bash
docker-compose up -d
```

Then invoke the scanner from the `backend/` directory:

```bash
cd backend
python -m cli ports 127.0.0.1 -p 22,80,443,5432,8000 --timeout 1
```

Expected output (localhost with our stack running):

```
CyberScanner — 127.0.0.1    2 open / 5 scanned    2.04s
┏━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━┓
┃     Port ┃ State ┃ Service    ┃ Product ┃ Version ┃ Banner ┃
┡━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━┩
│ 5432/tcp │ open  │ PostgreSQL │ -       │ -       │ -      │
│ 8000/tcp │ open  │ HTTP-Alt   │ -       │ -       │ -      │
└──────────┴───────┴────────────┴─────────┴─────────┴────────┘
```
