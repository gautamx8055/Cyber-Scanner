# Task 3.4 — DNS Resolution + TTL-Based OS Hints

## What was built

Two enrichments that make the scanner output far more useful without
adding new probes:

1. **Forward and reverse DNS** as a small reusable module. Forward DNS
   feeds the `ports` subcommand so you can scan by hostname; reverse
   DNS enriches sweep results so each alive IP carries its PTR name.
2. **OS family hint** for sweep results, derived from the TTL value of
   the ICMP echo reply (Linux ~64, Windows ~128, network gear ~255).

## Files created / modified

- **`backend/scanner/dns_utils.py`** (new):
  - `resolve_forward(host)` — `socket.gethostbyname` wrapper, returns
    `None` instead of raising.
  - `resolve_reverse(ip)` — `socket.gethostbyaddr` wrapper, same
    behaviour.
  - `resolve_reverse_many(ips, max_workers=32)` — parallel PTR lookups
    via `ThreadPoolExecutor`.
  - `is_ip_literal(host)` — quick IPv4/IPv6 detection so the CLI can
    skip DNS when the user already passed an IP.
- **`backend/scanner/host_sweep.py`**:
  - `HostResult` gained `ttl` and `os_hint` fields. `hostname` is now
    populated for real (no longer a Phase-3.4 placeholder).
  - `os_hint_from_ttl(ttl)` maps a received TTL to the smallest
    matching bucket of `[64, 128, 255]`.
  - `ping_sweep(..., resolve=True)` — captures `received.ttl`, runs
    `resolve_reverse_many` over the alive set, fills the new fields.
  - `render_sweep_table` — added `Hostname`, `TTL`, `OS hint` columns.
- **`backend/scanner/port_scanner.py`**:
  - `save_scan_results` now takes an optional `target_hostname` and
    persists it on the `Scan` row (the column already existed).
- **`backend/cli.py`**:
  - `cmd_ports`: if the target isn't an IP literal, run a single
    `resolve_forward` up front. Display "host (ip)" in the header and
    table title; pass the IP to the scanners (so per-port connects
    don't re-resolve) and the hostname to `save_scan_results`.
  - `cmd_sweep`: new `--no-resolve` flag wired into `ping_sweep`.
- **`TODO.md`** — Phase 3.4 boxes ticked.

## Key concepts

### Why both forward and reverse DNS

Forward (`A` lookup) lets you say `scan example.com` instead of looking
up the IP yourself. Reverse (`PTR` lookup) lets sweep output identify
hosts by name, which is invaluable on a LAN where every device shows
up by hostname (printer, NAS, router) but the IPs change.

Both go through the same stdlib resolver — no `aiodns` or `dnspython`
dependency for now. We can switch later when the DNS step becomes a
bottleneck.

### Why a thread pool for reverse DNS

`socket.gethostbyaddr` is a blocking call. For a /24 sweep, doing PTR
serially after the ICMP step would add 254 × resolver-RTT to the wall
clock. A pool of 32 threads is enough to overlap them — beyond that we
just pile pressure on the local resolver. We only PTR the *alive* set,
so dead hosts don't pay any DNS cost.

### TTL → OS hint

Each hop on the network path decrements the IP TTL by 1, so the value
we *receive* is `initial_ttl − hops`. The common initial TTLs are:

| Initial TTL | OS family            |
|-------------|----------------------|
| 64          | Linux, macOS, *BSD   |
| 128         | Windows              |
| 255         | Cisco, Solaris, gear |

The hint picks the smallest bucket `>=` the received TTL — so a TTL of
54 is "Linux/Unix" (started at 64, 10 hops), and 117 is "Windows"
(started at 128, 11 hops). This is intentionally coarse; real OS
fingerprinting (nmap `-O`) inspects window sizes, options ordering,
and a dozen other signals.

### Resolve once at the CLI boundary

`asyncio.open_connection(host, port)` does its own DNS lookup. If we
hand it a hostname for a 1000-port scan, that's 1000 redundant DNS
calls. Resolving once at the CLI and passing the IP down avoids that
and gives us a single deterministic IP to display and persist.

## How to run / test it

```bash
# Hostname target — header shows the resolved IP
python -m cli ports scanme.nmap.org -p 22,80,443 --async --timeout 3 --no-save

# Sweep with reverse DNS (default) and TTL/OS hints
sudo -E ./venv/bin/python -m backend.cli sweep 192.168.1.0/24

# Sweep without reverse DNS (faster, useful for large nets)
sudo -E ./venv/bin/python -m backend.cli sweep 10.0.0.0/22 --no-resolve
```

Observed run against scanme.nmap.org:

```
Scanning scanme.nmap.org (45.33.32.156) — 3 tcp port(s), timeout=3.0s (async, concurrency=500)
  CyberScanner — scanme.nmap.org (45.33.32.156)    2 open / 3 scanned    2.29s
  Port    State  Service  Product  Version    Banner
  22/tcp  open   SSH      OpenSSH  6.6.1p1    SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
  80/tcp  open   HTTP     -        -          -
  Summary: 2 open, 0 open|filtered, 0 filtered, 1 closed.
```

## Known caveats

- **PTR records are sparse.** Most public IPs don't have one; many LAN
  devices don't either. A blank Hostname column is normal, not a bug.
- **TTL hint is a guess.** A Linux box configured with TTL 128 will be
  reported as "Windows". Treat it as a lead, not a fact.
- **The local resolver is the bottleneck.** If DNS is slow on your
  network, `--no-resolve` is the escape hatch.

## Phase 3 — DONE

All four sub-phases complete. The discovery + scan layer now has:
sync + async TCP, sync + async UDP, ICMP sweep, forward + reverse DNS,
OS hints, and a Rich CLI with sensible defaults. Phase 4 starts the
vulnerability detection engine — banner version regex, a local CVE
database, and NVD API lookup.
