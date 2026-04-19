"""
CyberScanner CLI.

Run from the `backend/` directory:
    python -m cli ports 127.0.0.1 -p 1-1000 --timeout 1

Subcommands:
    ports   TCP connect port scan
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from datetime import datetime, timezone

from scanner.port_scanner import (
    render_results_table,
    save_scan_results,
    scan_ports,
    scan_ports_async,
)


def parse_ports(spec: str) -> list[int]:
    """Parse a user port spec into a sorted, de-duplicated list.

    Accepts:
        "80"                single port
        "1-1000"            inclusive range
        "80,443,8080"       explicit list
        "22,80,8000-8100"   mix of the above
    """
    out: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, _, hi_s = chunk.partition("-")
            lo, hi = int(lo_s), int(hi_s)
            if not (1 <= lo <= hi <= 65535):
                raise ValueError(f"invalid port range: {chunk!r}")
            out.update(range(lo, hi + 1))
        else:
            p = int(chunk)
            if not 1 <= p <= 65535:
                raise ValueError(f"invalid port: {p}")
            out.add(p)
    if not out:
        raise ValueError("no ports specified")
    return sorted(out)


def cmd_ports(args: argparse.Namespace) -> int:
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.benchmark:
        return _run_benchmark(args, ports)

    mode = "async" if args.use_async else "sync"
    print(
        f"Scanning {args.target} — {len(ports)} port(s), "
        f"timeout={args.timeout}s ({mode})"
    )
    started = datetime.now(timezone.utc).replace(tzinfo=None)
    t0 = time.perf_counter()
    if args.use_async:
        results = asyncio.run(
            scan_ports_async(args.target, ports, timeout=args.timeout)
        )
    else:
        results = scan_ports(args.target, ports, timeout=args.timeout)
    elapsed = time.perf_counter() - t0
    completed = datetime.now(timezone.utc).replace(tzinfo=None)

    render_results_table(
        args.target, results, elapsed, show_closed=args.show_closed
    )

    if args.no_save:
        return 0

    try:
        scan_id = asyncio.run(save_scan_results(
            target_ip=args.target,
            port_spec=args.ports,
            timeout=args.timeout,
            started_at=started,
            completed_at=completed,
            results=results,
        ))
        print(f"Saved scan: id={scan_id}")
    except Exception as e:
        # DB being down shouldn't fail the scan — the results are still on screen.
        print(f"warning: could not save scan to DB: {e}", file=sys.stderr)
    return 0


def _run_benchmark(args: argparse.Namespace, ports: list[int]) -> int:
    """Run sync then async against the same target and print the speedup."""
    print(
        f"Benchmark — {args.target}, {len(ports)} port(s), "
        f"timeout={args.timeout}s"
    )

    t0 = time.perf_counter()
    sync_results = scan_ports(args.target, ports, timeout=args.timeout)
    sync_elapsed = time.perf_counter() - t0
    sync_open = sum(1 for r in sync_results if r.state == "open")
    print(f"  sync : {sync_elapsed:7.2f}s  ({sync_open} open)")

    t0 = time.perf_counter()
    async_results = asyncio.run(
        scan_ports_async(args.target, ports, timeout=args.timeout)
    )
    async_elapsed = time.perf_counter() - t0
    async_open = sum(1 for r in async_results if r.state == "open")
    print(f"  async: {async_elapsed:7.2f}s  ({async_open} open)")

    if async_elapsed > 0:
        print(f"  speedup: {sync_elapsed / async_elapsed:.1f}x")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyberscan",
        description="CyberScanner — open-source cybersecurity scanner",
    )
    sub = p.add_subparsers(dest="command", required=True)

    ports = sub.add_parser("ports", help="TCP port scan (synchronous)")
    ports.add_argument("target", help="target IP or hostname")
    ports.add_argument(
        "-p", "--ports",
        default="1-1000",
        help="ports: '80', '1-1000', or '80,443,8080' (default: 1-1000)",
    )
    ports.add_argument(
        "--timeout", type=float, default=1.0,
        help="per-port connect timeout in seconds (default: 1.0)",
    )
    ports.add_argument(
        "--show-closed", action="store_true",
        help="show closed and filtered ports in the output table",
    )
    ports.add_argument(
        "--no-save", action="store_true",
        help="don't persist scan results to PostgreSQL",
    )
    ports.add_argument(
        "--async", dest="use_async", action="store_true",
        help="use the async scanner (concurrent via asyncio.gather)",
    )
    ports.add_argument(
        "--benchmark", action="store_true",
        help="run sync then async on the same target and print the speedup",
    )
    ports.set_defaults(func=cmd_ports)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
