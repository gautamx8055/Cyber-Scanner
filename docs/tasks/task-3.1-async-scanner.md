# Task 3.1 — Async Port Scanner + Benchmark

## What was built

An async version of the TCP port scanner that reuses the Phase 2 data model
(`PortResult`, banner parsing, service map) but replaces the blocking socket
with `asyncio.open_connection()`. All ports in the requested set are awaited
concurrently through `asyncio.gather()`, turning the scan time from
*O(ports × timeout)* in the worst case (filtered ports) into roughly *one
timeout* regardless of how many ports are scanned.

A `--benchmark` flag on the `ports` subcommand runs the sync scanner and then
the async scanner against the same target and prints the speedup so you can
see the difference for yourself.

## Files created / modified

- **`backend/scanner/port_scanner.py`** — added:
  - `scan_port_async(ip, port, timeout)` — single-port coroutine using
    `asyncio.wait_for(asyncio.open_connection(...), timeout)`.
  - `_grab_banner_async(reader, ...)` — non-blocking banner read via
    `reader.read()` wrapped in `asyncio.wait_for`.
  - `scan_ports_async(ip, ports, timeout)` — fans out via `asyncio.gather`.
  - Module docstring updated; `import asyncio` added.
- **`backend/cli.py`** — added flags to the `ports` subcommand:
  - `--async` — run the async scanner instead of the sync one.
  - `--benchmark` — run both, report elapsed time and speedup.
- **`TODO.md`** — Phase 3.1 checkboxes marked done.

## Key concepts

- **`asyncio.open_connection(host, port)`** — the async analogue of
  `socket.connect`. Returns `(StreamReader, StreamWriter)`. It does not
  accept a timeout parameter, so we wrap it in `asyncio.wait_for(...)` to
  bound how long a single port can hold up the event loop.
- **State mapping is the same as the sync version.** Timeout ⇒ `filtered`,
  `ConnectionRefusedError` ⇒ `closed`, success ⇒ `open`. The only thing
  that changed is *how* we wait, not what the results mean.
- **`asyncio.gather(*coros)`** — waits for all coroutines concurrently and
  returns results in the original order. For the scanner this means 1,000
  open-connection attempts run in parallel rather than one-after-another.
- **Why no concurrency cap yet?** At 65k ports we'd try to open 65k sockets
  simultaneously and the OS would refuse most of them. That's the exact
  problem `asyncio.Semaphore` solves — deferred to Task 3.2.
- **Banner-grab reuse.** Parsing and the product/version regex are shared
  with the sync path; only the I/O primitive changed.

## How to run / test it

From `backend/` with the venv active:

```bash
# async scan of top-1000 ports
python -m cli ports 127.0.0.1 -p 1-1000 --timeout 1 --async --no-save

# sync vs async comparison — best seen on a target with filtered ports,
# because that's where sync has to wait out the full timeout for each port
python -m cli ports 10.255.255.1 -p 1-20 --timeout 1 --benchmark
```

Observed on a 20-port scan of an unroutable IP (every port → filtered):

```
Benchmark — 10.255.255.1, 20 port(s), timeout=1.0s
  sync :   20.03s  (0 open)
  async:    1.00s  (0 open)
  speedup: 19.9x
```

Note: against `127.0.0.1` the speedup disappears because closed ports
RST instantly on loopback — there's no latency to parallelize away. Pick a
target with real network distance or filtered ports to see the async win.

## Next up

Task 3.2 — add an `asyncio.Semaphore` to cap concurrent connections, add a
per-connection timeout path with `asyncio.wait_for`, and write a basic UDP
scanner.
