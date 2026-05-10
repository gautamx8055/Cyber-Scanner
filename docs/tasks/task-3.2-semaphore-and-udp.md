# Task 3.2 — Concurrency Cap, Per-Connection Timeout, UDP Scanner

## What was built

Three improvements that make the async scanner production-ish and add a
second protocol:

1. **Concurrency cap** on the TCP and UDP async scanners via
   `asyncio.Semaphore`. Without it, `asyncio.gather()` would launch one
   coroutine per port — 65k file descriptors blow past the Linux default
   limit (1024) and the OS starts refusing sockets.
2. **Per-connection timeout** is now used everywhere we await network I/O
   (`open_connection`, banner read, UDP probe response) by wrapping the
   awaitable in `asyncio.wait_for()`. The TCP path already had this from
   Task 3.1; UDP needed it added.
3. **Basic UDP scanner**, sync and async, with a small probe library so
   common services (DNS, NTP, SNMP) actually reply.

## Files modified

- **`backend/scanner/port_scanner.py`**
  - Added `proto` field to `PortResult` (`"tcp"` default, `"udp"` for the
    new functions). Existing TCP code is unchanged.
  - Added `COMMON_UDP_SERVICES` and `UDP_PROBES` (DNS query for
    example.com, NTPv3 client request, SNMPv1 GetRequest sysDescr.0).
  - Updated `scan_ports_async()` to take a `concurrency` parameter and
    fan out through an `asyncio.Semaphore`.
  - Added `scan_udp_port()` / `scan_udp_ports()` — sync,
    `socket.SOCK_DGRAM` with `sendto` / `recvfrom`.
  - Added `_UDPProbeProtocol` (subclass of `asyncio.DatagramProtocol`)
    that bridges the first reply or `error_received` ICMP to a Future.
  - Added `scan_udp_port_async()` / `scan_udp_ports_async()` — built on
    `loop.create_datagram_endpoint(remote_addr=...)`, capped by a
    Semaphore.
  - Updated `render_results_table()` to render `r.proto` in the port
    column and to colour the new `open|filtered` state magenta.
- **`backend/cli.py`**
  - New flags on the `ports` subcommand: `--udp`, `-c/--concurrency`.
  - `cmd_ports` dispatches to the TCP or UDP function pair based on
    `--udp`; concurrency is forwarded to the async path.
  - `_run_benchmark` now reports the concurrency cap and refuses
    `--udp` (UDP doesn't show a meaningful sync-vs-async speedup —
    the scan is timeout-bound either way).
- **`TODO.md`** — Phase 3.2 boxes ticked.

## Key concepts

### `asyncio.Semaphore` — bounded concurrency

```python
sem = asyncio.Semaphore(concurrency)

async def _bounded(p):
    async with sem:
        return await scan_port_async(ip, p, timeout)

await asyncio.gather(*(_bounded(p) for p in ports))
```

`async with sem` blocks until a permit is free, runs the body, then
releases. Order of completion isn't guaranteed but `gather` preserves
input order in the result list.

### `asyncio.wait_for(awaitable, timeout)`

The async equivalent of `socket.settimeout`. If the inner awaitable
hasn't completed in time, `wait_for` cancels it and raises
`asyncio.TimeoutError`. We use it three places now:

- around `asyncio.open_connection` (TCP connect)
- around `reader.read` (TCP banner grab)
- around the UDP response Future

### UDP states are not symmetric with TCP

| Outcome                        | State            |
|--------------------------------|------------------|
| service replied with data      | `open`           |
| ICMP port-unreachable received | `closed`         |
| no reply within timeout        | `open\|filtered` |
| local kernel rejected the send | `filtered`       |

`closed` only fires reliably when the socket is *connected*. That's why
the async path uses `create_datagram_endpoint(remote_addr=(ip, port))` —
without `remote_addr` the kernel won't deliver ICMP unreachable into
`error_received`.

### Why service-specific probes matter

A UDP service that doesn't reply to garbage looks identical to a
firewalled port — both produce timeouts. So we ship a probe table:

- **DNS (53)** — standard A query for `example.com`
- **NTP (123)** — 48-byte mode-3 client request
- **SNMP (161)** — GetRequest for `sysDescr.0`, community `public`

Anything not in `UDP_PROBES` gets an empty datagram and will almost
always come back as `open|filtered`.

## How to run / test it

From `backend/` with the venv active:

```bash
# TCP async with a tighter concurrency cap
python -m cli ports 127.0.0.1 -p 1-1000 --async -c 200 --no-save

# UDP scan against a known DNS server — port 53 should return "open"
python -m cli ports 8.8.8.8 -p 53,123,161 --udp --async --timeout 2 --no-save

# Sync UDP path (uses sendto/recvfrom directly)
python -m cli ports 8.8.8.8 -p 53 --udp --timeout 2 --no-save
```

Observed run against `8.8.8.8`:

```
 53/udp  open           DNS  -  -  <DNS reply payload>
123/udp  open|filtered  NTP  -  -  -
161/udp  open|filtered  SNMP -  -  -
Summary: 1 open, 2 open|filtered, 0 filtered, 0 closed.
```

DNS comes back `open` because Google's resolver answered our probe.
NTP and SNMP are reachable but Google's edge filters them, so we
correctly fall back to `open|filtered`.

## Known caveats

- **Binary banners render as garbage.** The DNS reply is binary; the
  current banner column tries to UTF-8 decode it and you get mojibake.
  Fixing this (hex preview for non-printable bytes) is a small follow-up
  but not part of 3.2.
- **`closed` detection on the sync UDP path is unreliable** because we
  don't `connect()` the socket — Linux occasionally surfaces a cached
  ICMP unreachable, but most closed ports will report `open|filtered`.
  The async path uses `remote_addr` and is reliable.

## Next up

Task 3.3 — ICMP ping sweep with scapy and a `--sweep` CLI flag for
discovering live hosts in a subnet.
