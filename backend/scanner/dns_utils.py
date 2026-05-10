"""
DNS helpers — Phase 3.4.

Public surface:
    resolve_forward(host)          -> str | None       # hostname -> IPv4
    resolve_reverse(ip)            -> str | None       # IP -> PTR hostname
    resolve_reverse_many(ips)      -> dict[str, str | None]

All lookups are stdlib-only (`socket.gethostbyname` / `gethostbyaddr`) and
return None on any failure — callers shouldn't have to distinguish
"NXDOMAIN" from "DNS server unreachable" for the basic display use case.

`resolve_reverse_many` parallelises PTR lookups over a thread pool. PTR
lookups serialise badly (one DNS roundtrip each), so a /24 sweep would
otherwise stall for many seconds.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable


def resolve_forward(host: str) -> str | None:
    """Hostname -> IPv4 address. Returns None if it doesn't resolve."""
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, socket.herror, OSError):
        return None


def resolve_reverse(ip: str) -> str | None:
    """IPv4 address -> PTR hostname. Returns None if no PTR record."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def resolve_reverse_many(
    ips: Iterable[str], max_workers: int = 32,
) -> dict[str, str | None]:
    """Reverse-resolve a batch of IPs in parallel. Returns {ip: hostname|None}.

    The thread pool is capped at 32 by default — beyond that we tend to
    swamp the local resolver more than we save wall-clock time. Each lookup
    has its own implicit timeout (the resolver's), so a slow PTR can't
    block the others.
    """
    ips = list(ips)
    if not ips:
        return {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        results = list(pool.map(resolve_reverse, ips))
    return dict(zip(ips, results))


def is_ip_literal(host: str) -> bool:
    """True if `host` parses as an IPv4/IPv6 literal — saves a DNS round trip."""
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        return False
