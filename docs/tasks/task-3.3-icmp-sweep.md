# Task 3.3 — ICMP Ping Sweep

## What was built

A `sweep` subcommand that takes a CIDR and reports which hosts in the
network reply to ICMP echo. Built on scapy because `socket` can't open
raw sockets without going through `SOCK_DGRAM` ICMP (Linux-only and
limited). Scapy gives us proper raw ICMP send + receive in a couple of
lines, at the cost of needing root.

## Files created / modified

- **`backend/scanner/host_sweep.py`** (new):
  - `HostResult` dataclass — `ip`, `alive`, `rtt_ms`, `hostname`. The
    `hostname` field is reserved for Task 3.4 (DNS resolution).
  - `ping_sweep(cidr, timeout)` — expands the CIDR with `ipaddress`,
    fans out a single `IP(dst=hosts)/ICMP()` packet through scapy's
    `sr()`, and computes per-host RTT from `sent_time` / `time`.
  - `render_sweep_table()` — Rich table with IP / Status / RTT.
  - Permission-error translation: scapy raises plain `OSError` when
    raw sockets are denied; we re-raise as `PermissionError` with a
    one-line hint about `sudo -E`.
- **`backend/cli.py`**:
  - New `sweep` subparser. Args: `cidr`, `--timeout`, `--show-down`.
  - `cmd_sweep()` handler with friendly error messages for invalid
    CIDR (exit 2) and missing privileges (exit 1).
  - Top-of-file usage updated to mention the new subcommand.
- **`TODO.md`** — Phase 3.3 boxes ticked.

## Key concepts

### Why scapy and not the stdlib

The stdlib `socket` module can send ICMP only via `SOCK_RAW`, which
needs root anyway, and parsing replies means hand-rolling the IP +
ICMP headers. Scapy abstracts this:

```python
from scapy.all import IP, ICMP, sr

ans, unans = sr(IP(dst=hosts) / ICMP(), timeout=2, verbose=0)
```

`sr()` ("send + receive") sends every packet and listens for replies
on a single shared raw socket, so a /24 sweep finishes in ~one
timeout instead of N.

### CIDR expansion via `ipaddress`

```python
network = ipaddress.IPv4Network(cidr, strict=False)
hosts = [str(h) for h in network.hosts()] or [str(network.network_address)]
```

`hosts()` skips the network and broadcast addresses, which is usually
what you want — except for `/32` and `/31` where `hosts()` is empty,
so we fall back to the network address itself.

### Why not async

Scapy's `sr()` is synchronous and already does its own parallelism
(one raw socket, kernel-level fan-in for replies). Wrapping it in
`asyncio.run_in_executor` would just add overhead without changing
the throughput. So the sweep stays a plain blocking call.

### Why no DB persistence yet

The current `Scan` model has `target_ip: str` and a `scan_type` enum
of `port | vuln | web | full` — neither the CIDR nor a `sweep` enum
fits. Phase 6 expands the schema (Scan / Port / Vulnerability /
WebFinding); we'll add a sweep-friendly model there rather than
forcing it now.

## How to run / test it

From the project root:

```bash
# Tiny loopback sweep — handy for testing the code path without a LAN
sudo -E ./venv/bin/python -m backend.cli sweep 127.0.0.0/30

# Real LAN sweep
sudo -E ./venv/bin/python -m backend.cli sweep 192.168.1.0/24

# Single-host ping
sudo -E ./venv/bin/python -m backend.cli sweep 8.8.8.8/32

# Show non-responding hosts too (useful for verifying coverage)
sudo -E ./venv/bin/python -m backend.cli sweep 192.168.1.0/28 --show-down
```

Without root, the CLI prints:

```
error: ICMP sweep needs root or CAP_NET_RAW (scapy uses raw sockets).
       Try: sudo -E ./venv/bin/python -m cli sweep …
```

…and exits 1. No traceback, no scapy noise.

## Known caveats

- **Root required.** Raw sockets need it. CAP_NET_RAW on the python
  binary is an alternative if you don't want to `sudo`:
  `sudo setcap cap_net_raw+eip $(realpath venv/bin/python)`.
- **Hosts that filter ICMP look identical to hosts that are down.**
  ICMP echo is the cheapest discovery probe; for paranoid networks
  Phase 4+ scans (port scan + service detection) are more reliable.
- **Large networks (/16+) take a single timeout but generate a lot
  of packets.** No rate limiting yet — be neighbourly on shared LAN.

## Next up

Task 3.4 — DNS resolution (hostname ↔ IP) and TTL-based OS
fingerprinting hints. Will populate the `hostname` field on
`HostResult` and add a `ttl` / `os_hint` column to the sweep table.
