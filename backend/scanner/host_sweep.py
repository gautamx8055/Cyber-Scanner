"""
ICMP ping sweep — Phase 3.3.

Public surface:
    ping_sweep(cidr, timeout)               -> list[HostResult]
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


@dataclass
class HostResult:
    ip: str
    alive: bool
    rtt_ms: Optional[float] = None
    hostname: Optional[str] = None  # populated in Task 3.4


def ping_sweep(cidr: str, timeout: float = 2.0) -> list[HostResult]:
    """ICMP-echo every host in `cidr` and report which ones reply.

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

    alive: set[str] = set()
    rtt_by_ip: dict[str, float] = {}
    for sent, received in ans:
        alive.add(received.src)
        # sent_time and time are Unix timestamps in seconds; subtract for RTT.
        if sent.sent_time and received.time:
            rtt_by_ip[received.src] = (received.time - sent.sent_time) * 1000.0

    return [
        HostResult(ip=h, alive=h in alive, rtt_ms=rtt_by_ip.get(h))
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
    table.add_column("Status", style="bold")
    table.add_column("RTT", justify="right")

    rows = results if show_down else alive_hosts
    for r in rows:
        if r.alive:
            status = "[green]alive[/green]"
            rtt = f"{r.rtt_ms:.1f} ms" if r.rtt_ms is not None else "-"
        else:
            status = "[red]down[/red]"
            rtt = "-"
        table.add_row(r.ip, status, rtt)
    console.print(table)
    console.print(
        f"[dim]Summary: {len(alive_hosts)} alive, "
        f"{len(results) - len(alive_hosts)} no-reply.[/dim]"
    )
