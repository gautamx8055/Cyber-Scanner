"""
ICMP ping sweep — Phase 3.3, extended in Phase 3.4 with reverse DNS and
TTL-based OS hints.

Public surface:
    ping_sweep(cidr, timeout, *, resolve=True) -> list[HostResult]
    os_hint_from_ttl(ttl)                       -> str | None
    render_sweep_table(cidr, results, elapsed, *, show_down=False)

Built on scapy. Sending and receiving ICMP needs raw sockets, so the
process needs root or CAP_NET_RAW. Permission errors from scapy are
re-raised as PermissionError so the CLI can print a clean message.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.table import Table

from .dns_utils import resolve_reverse_many


@dataclass
class HostResult:
    ip: str
    alive: bool
    rtt_ms: Optional[float] = None
    hostname: Optional[str] = None
    ttl: Optional[int] = None
    os_hint: Optional[str] = None


# Common initial TTL values per OS family. Each hop on the path decrements
# the TTL by 1, so the value we *receive* is (initial_ttl - hops). To pick
# the most likely initial value we take the smallest of these >= received.
# This is a coarse heuristic; real OS fingerprinting (nmap -O) inspects far
# more signals than just TTL.
_TTL_BUCKETS: list[tuple[int, str]] = [
    (64,  "Linux/Unix"),
    (128, "Windows"),
    (255, "Network device"),
]


def os_hint_from_ttl(ttl: int) -> Optional[str]:
    """Map a received ICMP TTL to a coarse OS family guess."""
    if ttl is None or ttl <= 0:
        return None
    for ceiling, label in _TTL_BUCKETS:
        if ttl <= ceiling:
            return label
    return None


def ping_sweep(
    cidr: str,
    timeout: float = 2.0,
    *,
    resolve: bool = True,
) -> list[HostResult]:
    """ICMP-echo every host in `cidr` and report which ones reply.

    For every responding host we also capture the reply TTL (used for the
    OS hint) and, if `resolve` is True, the reverse-DNS hostname.

    Returns one HostResult per host in the network, in iteration order.
    Hosts that don't reply within `timeout` come back as alive=False —
    indistinguishable from "down", "filtered", or "rate-limited".

    Raises:
        ValueError      — `cidr` isn't a valid IPv4 network
        PermissionError — process can't open a raw socket (needs root)
    """
    network = ipaddress.IPv4Network(cidr, strict=False)
    # /32 networks have no .hosts() output; treat the network address itself
    # as the single target so single-host sweeps still work.
    hosts = [str(h) for h in network.hosts()] or [str(network.network_address)]

    # Scapy chatter on import is noisy; mute it before pulling it in.
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    # Lazy import — scapy is slow to load (~1s) and only this command needs it.
    from scapy.all import IP, ICMP, sr  # type: ignore

    try:
        # sr() takes a single packet whose dst can be a list, then fans out
        # one ICMP echo per host and reads replies on a shared raw socket.
        # That's how a /24 sweep finishes in ~one timeout instead of N.
        ans, _unans = sr(
            IP(dst=hosts) / ICMP(),
            timeout=timeout,
            verbose=0,
        )
    except OSError as e:
        # scapy surfaces "Operation not permitted" as plain OSError on Linux
        # when raw sockets are denied. Translate it so the CLI can react.
        if "permitted" in str(e).lower():
            raise PermissionError(
                "ICMP sweep needs root or CAP_NET_RAW (scapy uses raw "
                "sockets). Try: sudo -E ./venv/bin/python -m cli sweep …"
            ) from e
        raise

    rtt_by_ip: dict[str, float] = {}
    ttl_by_ip: dict[str, int] = {}
    for sent, received in ans:
        ip = received.src
        if sent.sent_time and received.time:
            rtt_by_ip[ip] = (received.time - sent.sent_time) * 1000.0
        if received.ttl is not None:
            ttl_by_ip[ip] = int(received.ttl)

    # Reverse-DNS only the responders — it'd be wasteful (and slow) to PTR
    # every dead host in a /24. The thread pool keeps the wall clock low.
    hostnames: dict[str, str | None] = {}
    if resolve and ttl_by_ip:
        hostnames = resolve_reverse_many(list(ttl_by_ip.keys()))

    return [
        HostResult(
            ip=h,
            alive=h in ttl_by_ip,
            rtt_ms=rtt_by_ip.get(h),
            ttl=ttl_by_ip.get(h),
            os_hint=os_hint_from_ttl(ttl_by_ip[h]) if h in ttl_by_ip else None,
            hostname=hostnames.get(h),
        )
        for h in hosts
    ]


def render_sweep_table(cidr: str, results: list[HostResult], elapsed: float,
                       *, show_down: bool = False) -> None:
    console = Console()
    alive_hosts = [r for r in results if r.alive]

    title = (
        f"HostSweep — {cidr}    "
        f"{len(alive_hosts)} alive / {len(results)} scanned    "
        f"{elapsed:.2f}s"
    )
    table = Table(title=title)
    table.add_column("IP", style="cyan")
    table.add_column("Hostname")
    table.add_column("Status", style="bold")
    table.add_column("RTT", justify="right")
    table.add_column("TTL", justify="right")
    table.add_column("OS hint")

    rows = results if show_down else alive_hosts
    for r in rows:
        if r.alive:
            status = "[green]alive[/green]"
            rtt = f"{r.rtt_ms:.1f} ms" if r.rtt_ms is not None else "-"
            ttl = str(r.ttl) if r.ttl is not None else "-"
        else:
            status = "[red]down[/red]"
            rtt = "-"
            ttl = "-"
        table.add_row(
            r.ip,
            r.hostname or "-",
            status,
            rtt,
            ttl,
            r.os_hint or "-",
        )
    console.print(table)
    console.print(
        f"[dim]Summary: {len(alive_hosts)} alive, "
        f"{len(results) - len(alive_hosts)} no-reply.[/dim]"
    )
