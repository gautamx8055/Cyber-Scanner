"""
Port scanner — synchronous (Phase 2) and async (Phase 3) for TCP and UDP.

The sync versions (`scan_port`, `scan_ports`) are kept as the baseline
the async versions are benchmarked against.

Public surface:
    # TCP
    scan_port(ip, port, timeout)                         -> PortResult
    scan_ports(ip, ports, timeout)                       -> list[PortResult]
    scan_port_async(ip, port, timeout)                   -> PortResult
    scan_ports_async(ip, ports, timeout, concurrency)    -> list[PortResult]

    # UDP
    scan_udp_port(ip, port, timeout)                     -> PortResult
    scan_udp_ports(ip, ports, timeout)                   -> list[PortResult]
    scan_udp_port_async(ip, port, timeout)               -> PortResult
    scan_udp_ports_async(ip, ports, timeout, concurrency)-> list[PortResult]

    render_results_table(ip, results, elapsed, show_closed=False)
    save_scan_results(...)                               -> scan id (UUID string)
"""
from __future__ import annotations

import asyncio
import re
import socket
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable

from rich.console import Console
from rich.table import Table

# Default concurrency caps for the async scanners. TCP gets 500 — comfortably
# under the typical Linux 1024 fd limit. UDP gets a smaller cap because each
# probe sits on the wire for the full timeout waiting for a reply.
DEFAULT_TCP_CONCURRENCY = 500
DEFAULT_UDP_CONCURRENCY = 100


# Common TCP port → service name. Covers the ports a new user is most likely
# to hit; the full IANA list is enormous and unnecessary for learning.
COMMON_SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPCbind",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP-Submission",
    631: "IPP", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    2375: "Docker", 2376: "Docker-TLS",
    3306: "MySQL", 3389: "RDP", 5000: "UPnP",
    5432: "PostgreSQL", 5672: "AMQP", 5900: "VNC",
    6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 9000: "HTTP-Alt", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB",
}

# Common UDP port → service name. UDP-only entries; the TCP map is reused
# for ports that also exist on TCP (e.g. 53 DNS).
COMMON_UDP_SERVICES: dict[int, str] = {
    53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client",
    69: "TFTP", 123: "NTP", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    161: "SNMP", 162: "SNMP-Trap", 500: "IKE", 514: "Syslog",
    520: "RIP", 1900: "SSDP", 4500: "IPSec-NAT-T", 5353: "mDNS",
}

# Service-specific UDP probes that elicit a reply from a real listener.
# The keys are well-known UDP ports; the values are payloads crafted to look
# like a valid request. For ports without a probe we send an empty datagram —
# most services won't reply to that, so the result will be "open|filtered".
UDP_PROBES: dict[int, bytes] = {
    # DNS: standard query A example.com (id=0x1234, RD=1)
    53: bytes.fromhex(
        "12340100000100000000000007"
        "6578616d706c6503636f6d0000010001"
    ),
    # NTPv3 client request: LI=0 VN=3 Mode=3, rest zero (48 bytes)
    123: b"\x1b" + b"\x00" * 47,
    # SNMPv1 GetRequest sysDescr.0 (OID 1.3.6.1.2.1.1.1.0), community "public"
    161: bytes.fromhex(
        "302902010004067075626c6963"
        "a01c020401020304020100020100"
        "3011300f06082b06010201010100"
        "0500"
    ),
}

# "<Name><sep><Version>" with sep in / _ whitespace.
# "-" is intentionally NOT a separator so we skip past the "SSH-2.0-"
# prefix of an SSH banner and land on "OpenSSH_8.2p1".
_VERSION_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9]{2,})[/_\s]+([0-9][0-9A-Za-z.\-_]*)"
)


@dataclass
class PortResult:
    port: int
    state: str
    proto: str = "tcp"
    service: str | None = None
    banner: str | None = None
    product: str | None = None
    version: str | None = None


def scan_port(ip: str, port: int, timeout: float = 1.0) -> PortResult:
    """Single-port TCP connect scan.

    connect() outcomes map to nmap-style states:
        success             -> open      (then passively grab a banner)
        ConnectionRefused   -> closed    (host is up, nothing listening)
        timeout / no route  -> filtered  (firewall or unreachable)
    """
    service = COMMON_SERVICES.get(port)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            banner = _grab_banner(sock)
    except (socket.timeout, TimeoutError):
        return PortResult(port=port, state="filtered", service=service)
    except ConnectionRefusedError:
        return PortResult(port=port, state="closed", service=service)
    except (OSError, socket.gaierror):
        return PortResult(port=port, state="filtered", service=service)

    product, version = _parse_banner(banner) if banner else (None, None)
    return PortResult(
        port=port,
        state="open",
        service=service,
        banner=banner,
        product=product,
        version=version,
    )


def _grab_banner(sock: socket.socket, max_bytes: int = 1024,
                 timeout: float = 2.0) -> str | None:
    # Most chatty services (SSH, FTP, SMTP, POP3) speak first on connect.
    # HTTP/HTTPS wait for a request, so they'll time out silently here —
    # that's fine, we still know the port is open.
    try:
        sock.settimeout(timeout)
        data = sock.recv(max_bytes)
    except (socket.timeout, OSError):
        return None
    if not data:
        return None
    return data.decode("utf-8", errors="replace").strip()


def _parse_banner(banner: str) -> tuple[str | None, str | None]:
    m = _VERSION_RE.search(banner)
    return (m.group(1), m.group(2)) if m else (None, None)


def scan_ports(ip: str, ports: Iterable[int],
               timeout: float = 1.0) -> list[PortResult]:
    """Sequential scan — one port, then the next. Deliberately slow."""
    return [scan_port(ip, p, timeout) for p in ports]


async def scan_port_async(ip: str, port: int,
                          timeout: float = 1.0) -> PortResult:
    """Async single-port scan using asyncio.open_connection().

    Same state mapping as scan_port(); the difference is that many of these
    coroutines can be awaited concurrently via asyncio.gather().
    """
    service = COMMON_SERVICES.get(port)
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout,
        )
    except (asyncio.TimeoutError, TimeoutError):
        return PortResult(port=port, state="filtered", service=service)
    except ConnectionRefusedError:
        return PortResult(port=port, state="closed", service=service)
    except (OSError, socket.gaierror):
        return PortResult(port=port, state="filtered", service=service)

    try:
        banner = await _grab_banner_async(reader)
    finally:
        writer.close()
        # wait_closed() can raise if the peer already dropped the connection;
        # we don't care — the port result is what matters.
        try:
            await writer.wait_closed()
        except OSError:
            pass

    product, version = _parse_banner(banner) if banner else (None, None)
    return PortResult(
        port=port,
        state="open",
        service=service,
        banner=banner,
        product=product,
        version=version,
    )


async def _grab_banner_async(reader: asyncio.StreamReader,
                             max_bytes: int = 1024,
                             timeout: float = 2.0) -> str | None:
    try:
        data = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    if not data:
        return None
    return data.decode("utf-8", errors="replace").strip()


async def scan_ports_async(
    ip: str,
    ports: Iterable[int],
    timeout: float = 1.0,
    concurrency: int = DEFAULT_TCP_CONCURRENCY,
) -> list[PortResult]:
    """Concurrent scan — fans out via asyncio.gather, capped by a Semaphore.

    The cap protects against running out of file descriptors on large port
    ranges (Linux defaults to 1024) and against tripping rate limits / IDS
    thresholds on the target. asyncio.gather() preserves input order, so
    results[i] still corresponds to ports[i].
    """
    sem = asyncio.Semaphore(concurrency)

    async def _bounded(p: int) -> PortResult:
        async with sem:
            return await scan_port_async(ip, p, timeout)

    return await asyncio.gather(*(_bounded(p) for p in ports))


# ----------------------------------------------------------------------------
# UDP scanners
# ----------------------------------------------------------------------------
#
# UDP is connectionless, so the four states are not symmetric with TCP:
#   - "open"           a service replied with data
#   - "closed"         the kernel surfaced an ICMP port-unreachable as
#                      ConnectionRefusedError (only reliable on connected
#                      sockets — see scan_udp_port_async)
#   - "open|filtered"  no reply within the timeout. We genuinely cannot tell
#                      whether the port is silently open or being firewalled
#   - "filtered"       the local kernel rejected the send (no route, etc.)
#
# Without raw sockets (root) we can't read raw ICMP, so most UDP scans land
# in "open|filtered". A service-specific probe in UDP_PROBES greatly improves
# the open-detection rate for ports we know how to talk to (DNS, NTP, SNMP).


def _udp_service(port: int) -> str | None:
    return COMMON_UDP_SERVICES.get(port) or COMMON_SERVICES.get(port)


def scan_udp_port(ip: str, port: int, timeout: float = 2.0) -> PortResult:
    """Single-port UDP scan via sendto/recvfrom.

    Sends a service-specific probe if one is registered in UDP_PROBES,
    otherwise an empty datagram. State mapping is documented above.
    """
    service = _udp_service(port)
    payload = UDP_PROBES.get(port, b"")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (ip, port))
        data, _ = sock.recvfrom(4096)
    except (socket.timeout, TimeoutError):
        return PortResult(port=port, state="open|filtered",
                          proto="udp", service=service)
    except ConnectionRefusedError:
        # Linux occasionally surfaces a cached ICMP unreachable here even on
        # an unconnected socket. Trust it when it happens.
        return PortResult(port=port, state="closed",
                          proto="udp", service=service)
    except (OSError, socket.gaierror):
        return PortResult(port=port, state="filtered",
                          proto="udp", service=service)
    finally:
        sock.close()

    banner = data.decode("utf-8", errors="replace").strip() if data else None
    product, version = _parse_banner(banner) if banner else (None, None)
    return PortResult(
        port=port, state="open", proto="udp", service=service,
        banner=banner, product=product, version=version,
    )


def scan_udp_ports(ip: str, ports: Iterable[int],
                   timeout: float = 2.0) -> list[PortResult]:
    """Sequential UDP scan — one port, then the next."""
    return [scan_udp_port(ip, p, timeout) for p in ports]


class _UDPProbeProtocol(asyncio.DatagramProtocol):
    """Bridges a one-shot UDP probe to a Future.

    The first datagram_received call resolves the future as ("open", data).
    error_received is invoked when the kernel translates an ICMP message
    into a socket error; ConnectionRefusedError means port-unreachable was
    received (port closed on Linux, when remote_addr was passed to
    create_datagram_endpoint).
    """

    def __init__(self, response: asyncio.Future) -> None:
        self._response = response

    def datagram_received(self, data: bytes, addr) -> None:
        if not self._response.done():
            self._response.set_result(("open", data))

    def error_received(self, exc: Exception) -> None:
        if self._response.done():
            return
        if isinstance(exc, ConnectionRefusedError):
            self._response.set_result(("closed", b""))
        else:
            self._response.set_result(("filtered", b""))

    def connection_lost(self, exc: Exception | None) -> None:  # noqa: D401
        # Nothing to do — the future is either already resolved or about to
        # be resolved by the wait_for() timeout in scan_udp_port_async.
        pass


async def scan_udp_port_async(ip: str, port: int,
                              timeout: float = 2.0) -> PortResult:
    """Async UDP scan using loop.create_datagram_endpoint().

    Passing remote_addr connects the underlying socket so the kernel will
    deliver ICMP port-unreachable replies into error_received() — that's
    what gives us reliable "closed" detection on Linux without raw sockets.
    """
    service = _udp_service(port)
    payload = UDP_PROBES.get(port, b"")

    loop = asyncio.get_running_loop()
    response: asyncio.Future = loop.create_future()

    try:
        transport, _proto = await loop.create_datagram_endpoint(
            lambda: _UDPProbeProtocol(response),
            remote_addr=(ip, port),
        )
    except (OSError, socket.gaierror):
        return PortResult(port=port, state="filtered",
                          proto="udp", service=service)

    try:
        transport.sendto(payload)
        try:
            state, data = await asyncio.wait_for(response, timeout=timeout)
        except asyncio.TimeoutError:
            return PortResult(port=port, state="open|filtered",
                              proto="udp", service=service)
    finally:
        transport.close()

    if state != "open":
        return PortResult(port=port, state=state,
                          proto="udp", service=service)

    banner = data.decode("utf-8", errors="replace").strip() if data else None
    product, version = _parse_banner(banner) if banner else (None, None)
    return PortResult(
        port=port, state="open", proto="udp", service=service,
        banner=banner, product=product, version=version,
    )


async def scan_udp_ports_async(
    ip: str,
    ports: Iterable[int],
    timeout: float = 2.0,
    concurrency: int = DEFAULT_UDP_CONCURRENCY,
) -> list[PortResult]:
    """Concurrent UDP scan, capped by a Semaphore.

    UDP probes spend most of their time waiting for a possible reply, so the
    default concurrency is lower than the TCP equivalent — saturating the
    socket buffer makes us drop replies and report false open|filtered.
    """
    sem = asyncio.Semaphore(concurrency)

    async def _bounded(p: int) -> PortResult:
        async with sem:
            return await scan_udp_port_async(ip, p, timeout)

    return await asyncio.gather(*(_bounded(p) for p in ports))


def render_results_table(ip: str, results: list[PortResult], elapsed: float,
                         *, show_closed: bool = False) -> None:
    console = Console()
    open_ports = [r for r in results if r.state == "open"]
    open_filtered = sum(1 for r in results if r.state == "open|filtered")
    filtered = sum(1 for r in results if r.state == "filtered")
    closed = sum(1 for r in results if r.state == "closed")

    title = (
        f"CyberScanner — {ip}    "
        f"{len(open_ports)} open / {len(results)} scanned    "
        f"{elapsed:.2f}s"
    )
    table = Table(title=title)
    table.add_column("Port",    justify="right", style="cyan")
    table.add_column("State",                     style="bold")
    table.add_column("Service")
    table.add_column("Product")
    table.add_column("Version")
    table.add_column("Banner", overflow="fold", max_width=48)

    # show_closed surfaces every non-open state too (closed, filtered, open|filtered)
    rows = results if show_closed else open_ports
    state_color = {
        "open": "green",
        "closed": "red",
        "filtered": "yellow",
        "open|filtered": "magenta",
    }
    for r in rows:
        color = state_color.get(r.state, "white")
        table.add_row(
            f"{r.port}/{r.proto}",
            f"[{color}]{r.state}[/{color}]",
            r.service or "-",
            r.product or "-",
            r.version or "-",
            r.banner or "-",
        )
    console.print(table)
    console.print(
        f"[dim]Summary: {len(open_ports)} open, "
        f"{open_filtered} open|filtered, "
        f"{filtered} filtered, {closed} closed.[/dim]"
    )


async def save_scan_results(
    *,
    target_ip: str,
    port_spec: str,
    timeout: float,
    started_at: datetime,
    completed_at: datetime,
    results: list[PortResult],
    target_hostname: str | None = None,
) -> str:
    """Persist a completed port scan to PostgreSQL. Returns the scan id."""
    # Imported lazily so the scanner module itself has no DB dependency —
    # lets `--no-save` runs work even when postgres is down.
    from db.models import Scan, ScanStatus, ScanType
    from db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        scan = Scan(
            target_ip=target_ip,
            target_hostname=target_hostname,
            scan_type=ScanType.port,
            status=ScanStatus.completed,
            started_at=started_at,
            completed_at=completed_at,
            options={"port_spec": port_spec, "timeout": timeout},
            results=[asdict(r) for r in results],
        )
        session.add(scan)
        await session.commit()
        return scan.id
