"""
CyberScanner CLI.

Run from the `backend/` directory:
    python -m cli ports 127.0.0.1 -p 1-1000 --timeout 1
    sudo -E ./venv/bin/python -m cli sweep 192.168.1.0/24

Subcommands:
    ports   TCP/UDP port scan (sync or async)
    sweep   ICMP ping sweep across a CIDR (needs root for raw sockets)
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from datetime import datetime, timezone

from scanner.dns_utils import is_ip_literal, resolve_forward
from scanner.host_sweep import ping_sweep, render_sweep_table
from scanner.port_scanner import (
    DEFAULT_TCP_CONCURRENCY,
    DEFAULT_UDP_CONCURRENCY,
    render_results_table,
    save_scan_results,
    scan_ports,
    scan_ports_async,
    scan_udp_ports,
    scan_udp_ports_async,
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

    # Resolve hostname targets up-front so every per-port connect doesn't
    # repeat the DNS round trip — and so we can show "host (ip)" in the
    # output and persist both halves to the DB.
    target_hostname: str | None = None
    if is_ip_literal(args.target):
        target_ip = args.target
        target_label = args.target
    else:
        resolved = resolve_forward(args.target)
        if resolved is None:
            print(f"error: could not resolve {args.target!r}", file=sys.stderr)
            return 2
        target_hostname = args.target
        target_ip = resolved
        target_label = f"{args.target} ({resolved})"

    if args.benchmark:
        return _run_benchmark(args, ports, target_ip, target_label)

    proto = "udp" if args.udp else "tcp"
    mode = "async" if args.use_async else "sync"
    concurrency_note = f", concurrency={args.concurrency}" if args.use_async else ""
    print(
        f"Scanning {target_label} — {len(ports)} {proto} port(s), "
        f"timeout={args.timeout}s ({mode}{concurrency_note})"
    )
    started = datetime.now(timezone.utc).replace(tzinfo=None)
    t0 = time.perf_counter()
    if args.udp:
        if args.use_async:
            results = asyncio.run(scan_udp_ports_async(
                target_ip, ports,
                timeout=args.timeout, concurrency=args.concurrency,
            ))
        else:
            results = scan_udp_ports(target_ip, ports, timeout=args.timeout)
    else:
        if args.use_async:
            results = asyncio.run(scan_ports_async(
                target_ip, ports,
                timeout=args.timeout, concurrency=args.concurrency,
            ))
        else:
            results = scan_ports(target_ip, ports, timeout=args.timeout)
    elapsed = time.perf_counter() - t0
    completed = datetime.now(timezone.utc).replace(tzinfo=None)

    render_results_table(
        target_label, results, elapsed, show_closed=args.show_closed
    )

    if args.no_save:
        return 0

    try:
        scan_id = asyncio.run(save_scan_results(
            target_ip=target_ip,
            target_hostname=target_hostname,
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


def _run_benchmark(
    args: argparse.Namespace,
    ports: list[int],
    target_ip: str,
    target_label: str,
) -> int:
    """Run sync then async against the same target and print the speedup.

    TCP only — UDP doesn't benefit from concurrency the same way (most ports
    answer with silence, so the scan is timeout-bound either way).
    """
    if args.udp:
        print("error: --benchmark is TCP-only", file=sys.stderr)
        return 2
    print(
        f"Benchmark — {target_label}, {len(ports)} port(s), "
        f"timeout={args.timeout}s, concurrency={args.concurrency}"
    )

    t0 = time.perf_counter()
    sync_results = scan_ports(target_ip, ports, timeout=args.timeout)
    sync_elapsed = time.perf_counter() - t0
    sync_open = sum(1 for r in sync_results if r.state == "open")
    print(f"  sync : {sync_elapsed:7.2f}s  ({sync_open} open)")

    t0 = time.perf_counter()
    async_results = asyncio.run(scan_ports_async(
        target_ip, ports,
        timeout=args.timeout, concurrency=args.concurrency,
    ))
    async_elapsed = time.perf_counter() - t0
    async_open = sum(1 for r in async_results if r.state == "open")
    print(f"  async: {async_elapsed:7.2f}s  ({async_open} open)")

    if async_elapsed > 0:
        print(f"  speedup: {sync_elapsed / async_elapsed:.1f}x")
    return 0


def cmd_sweep(args: argparse.Namespace) -> int:
    resolve_note = "" if args.resolve else ", no reverse-DNS"
    print(f"Sweeping {args.cidr} (timeout={args.timeout}s{resolve_note}) …")
    t0 = time.perf_counter()
    try:
        results = ping_sweep(
            args.cidr, timeout=args.timeout, resolve=args.resolve,
        )
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except PermissionError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    elapsed = time.perf_counter() - t0
    render_sweep_table(args.cidr, results, elapsed, show_down=args.show_down)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyberscan",
        description="CyberScanner — open-source cybersecurity scanner",
    )
    sub = p.add_subparsers(dest="command", required=True)

    ports = sub.add_parser("ports", help="TCP/UDP port scan (sync or async)")
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
        "--udp", action="store_true",
        help="UDP scan instead of TCP (recommend bumping --timeout to 2+)",
    )
    ports.add_argument(
        "-c", "--concurrency", type=int, default=DEFAULT_TCP_CONCURRENCY,
        help=(
            "max concurrent probes for the async scanner "
            f"(default: {DEFAULT_TCP_CONCURRENCY} TCP / "
            f"{DEFAULT_UDP_CONCURRENCY} suggested for UDP)"
        ),
    )
    ports.add_argument(
        "--benchmark", action="store_true",
        help="run sync then async on the same target and print the speedup",
    )
    ports.set_defaults(func=cmd_ports)

    sweep = sub.add_parser(
        "sweep",
        help="ICMP ping sweep across a CIDR (needs root for raw sockets)",
    )
    sweep.add_argument(
        "cidr",
        help="target subnet, e.g. 192.168.1.0/24 or 10.0.0.5/32",
    )
    sweep.add_argument(
        "--timeout", type=float, default=2.0,
        help="seconds to wait for ICMP replies (default: 2.0)",
    )
    sweep.add_argument(
        "--show-down", action="store_true",
        help="show non-responding hosts in the output table",
    )
    sweep.add_argument(
        "--no-resolve", dest="resolve", action="store_false",
        help="skip reverse-DNS lookup for alive hosts (faster)",
    )
    sweep.set_defaults(func=cmd_sweep, resolve=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
