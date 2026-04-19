"""
TCP port scanner — synchronous (Phase 2) and async (Phase 3).

The sync versions (`scan_port`, `scan_ports`) are kept as the baseline
the async versions are benchmarked against.

Public surface:
    scan_port(ip, port, timeout) -> PortResult
    scan_ports(ip, ports, timeout) -> list[PortResult]
    scan_port_async(ip, port, timeout) -> PortResult
    scan_ports_async(ip, ports, timeout) -> list[PortResult]
    render_results_table(ip, results, elapsed, show_closed=False)
    save_scan_results(...) -> scan id (UUID string)
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


async def scan_ports_async(ip: str, ports: Iterable[int],
                           timeout: float = 1.0) -> list[PortResult]:
    """Concurrent scan — every port is awaited at once via asyncio.gather().

    No concurrency cap yet; Task 3.2 adds an asyncio.Semaphore.
    """
    coros = [scan_port_async(ip, p, timeout) for p in ports]
    return await asyncio.gather(*coros)


def render_results_table(ip: str, results: list[PortResult], elapsed: float,
                         *, show_closed: bool = False) -> None:
    console = Console()
    open_ports = [r for r in results if r.state == "open"]
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

    rows = results if show_closed else open_ports
    state_color = {"open": "green", "closed": "red", "filtered": "yellow"}
    for r in rows:
        color = state_color.get(r.state, "white")
        table.add_row(
            f"{r.port}/tcp",
            f"[{color}]{r.state}[/{color}]",
            r.service or "-",
            r.product or "-",
            r.version or "-",
            r.banner or "-",
        )
    console.print(table)
    console.print(
        f"[dim]Summary: {len(open_ports)} open, "
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
) -> str:
    """Persist a completed port scan to PostgreSQL. Returns the scan id."""
    # Imported lazily so the scanner module itself has no DB dependency —
    # lets `--no-save` runs work even when postgres is down.
    from db.models import Scan, ScanStatus, ScanType
    from db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        scan = Scan(
            target_ip=target_ip,
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
