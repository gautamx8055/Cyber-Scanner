"""
Background scan executor (Phase 6.3).

A queued scan (created by POST /api/scans) is run here as a FastAPI background
task: the executor flips the row to `running`, drives the right scanner, writes
normalized child rows (ports / vulnerabilities / web_findings), streams live
progress over the event hub, and finally marks the row `completed` or `failed`.

It opens its OWN database session via AsyncSessionLocal rather than reusing the
request's session — that one is already committed and closed by the time a
background task runs.
"""

import asyncio
import os
from datetime import datetime, timezone

from api.events import hub
from db.models import Port, Scan, ScanStatus, ScanType, Vulnerability, WebFinding
from db.session import AsyncSessionLocal
from scanner.dns_utils import is_ip_literal, resolve_forward
from scanner.port_scanner import DEFAULT_TCP_CONCURRENCY, scan_port_async
from scanner.vuln_scanner import scan_local, scan_nvd
from scanner.web_scanner import ALL_CHECKS, run_web_scan

# Emit a progress heartbeat every N completed ports during a port scan.
_PROGRESS_EVERY = 50


def _now() -> datetime:
    # Naive UTC to match the DateTime columns (which store naive timestamps).
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _parse_port_spec(spec: str | None) -> list[int]:
    """Parse '80' / '1-1000' / '80,443,8080' into a sorted port list.

    Defaults to 1-1024 when unset. Mirrors the CLI's parser but kept local so
    the API layer doesn't import the CLI entry point.
    """
    if not spec:
        spec = "1-1024"
    out: set[int] = set()
    for chunk in str(spec).split(","):
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


async def execute_scan(scan_id: str) -> None:
    """Run a queued scan to completion. Entry point for the background task."""
    # Flip to running and read the inputs we need, then release the session.
    async with AsyncSessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = ScanStatus.running
        scan.started_at = _now()
        scan.completed_at = None
        scan_type = ScanType(scan.scan_type)
        raw_target = scan.target_ip
        hostname = scan.target_hostname
        options = dict(scan.options or {})
        await session.commit()

    hub.publish(scan_id, {"type": "status", "status": "running",
                          "scan_type": scan_type.value})

    try:
        # port / vuln need a real IP; web takes the original host/URL as-is.
        ip = ""
        if scan_type in (ScanType.port, ScanType.vuln, ScanType.full):
            ip = await _resolve_ip(scan_id, raw_target, hostname)

        if scan_type == ScanType.port:
            summary = await _run_port(scan_id, ip, options)
        elif scan_type == ScanType.vuln:
            summary = await _run_vuln(scan_id, ip, options)
        elif scan_type == ScanType.web:
            summary = await _run_web(scan_id, hostname or raw_target, options)
        else:  # ScanType.full
            summary = await _run_full(scan_id, ip, hostname or raw_target, options)

        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            if scan is not None:
                scan.status = ScanStatus.completed
                scan.completed_at = _now()
                scan.results = summary
                await session.commit()
        hub.publish(scan_id, {"type": "completed", "status": "completed",
                              "summary": summary})

    except Exception as exc:  # any scanner failure marks the scan failed
        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            if scan is not None:
                scan.status = ScanStatus.failed
                scan.completed_at = _now()
                await session.commit()
        hub.publish(scan_id, {"type": "failed", "status": "failed",
                              "error": str(exc)})


async def _resolve_ip(scan_id: str, raw_target: str, hostname: str | None) -> str:
    """Return an IP for raw_target, resolving a hostname if needed and storing
    the resolved IP back on the scan. Raises if the name doesn't resolve."""
    if is_ip_literal(raw_target):
        return raw_target
    name = hostname or raw_target
    ip = await asyncio.to_thread(resolve_forward, name)
    if ip is None:
        raise RuntimeError(f"could not resolve {name!r}")
    async with AsyncSessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if scan is not None:
            scan.target_ip = ip
            if scan.target_hostname is None:
                scan.target_hostname = name
            await session.commit()
    hub.publish(scan_id, {"type": "resolved", "host": name, "ip": ip})
    return ip


async def _scan_ports_live(scan_id, ip, ports, timeout, concurrency):
    """Connect-scan `ports`, emitting a 'port' event per open port and periodic
    'progress' heartbeats. Returns the full list of PortResult."""
    hub.publish(scan_id, {"type": "started", "phase": "ports",
                          "target": ip, "total": len(ports)})
    sem = asyncio.Semaphore(concurrency)

    async def one(p):
        async with sem:
            return await scan_port_async(ip, p, timeout)

    tasks = [asyncio.create_task(one(p)) for p in ports]
    results = []
    done = 0
    for coro in asyncio.as_completed(tasks):
        r = await coro
        results.append(r)
        done += 1
        if r.state == "open":
            hub.publish(scan_id, {"type": "port", "port": r.port, "proto": r.proto,
                                  "state": r.state, "service": r.service,
                                  "product": r.product, "version": r.version})
        if done % _PROGRESS_EVERY == 0 or done == len(ports):
            hub.publish(scan_id, {"type": "progress", "done": done, "total": len(ports)})
    return results


async def _persist_ports(scan_id, results) -> int:
    """Persist the open ports as Port rows. Returns how many were stored."""
    open_ports = [r for r in results if r.state == "open"]
    if open_ports:
        async with AsyncSessionLocal() as session:
            for r in open_ports:
                session.add(Port(
                    scan_id=scan_id, port=r.port, proto=r.proto, state=r.state,
                    service=r.service, product=r.product, version=r.version,
                    banner=r.banner,
                ))
            await session.commit()
    return len(open_ports)


async def _run_port(scan_id, ip, options) -> dict:
    ports = _parse_port_spec(options.get("ports"))
    timeout = float(options.get("timeout", 1.0))
    concurrency = int(options.get("concurrency", DEFAULT_TCP_CONCURRENCY))
    results = await _scan_ports_live(scan_id, ip, ports, timeout, concurrency)
    open_count = await _persist_ports(scan_id, results)
    return {"scan_type": "port", "ports_scanned": len(ports), "open": open_count}


async def _run_vuln(scan_id, ip, options) -> dict:
    ports = _parse_port_spec(options.get("ports"))
    timeout = float(options.get("timeout", 1.0))
    concurrency = int(options.get("concurrency", DEFAULT_TCP_CONCURRENCY))
    use_nvd = bool(options.get("nvd", False))

    results = await _scan_ports_live(scan_id, ip, ports, timeout, concurrency)
    open_count = await _persist_ports(scan_id, results)

    findings = scan_local(results)
    if use_nvd:
        nvd_findings, _errors = await scan_nvd(results, api_key=os.getenv("NVD_API_KEY"))
        findings += nvd_findings

    if findings:
        async with AsyncSessionLocal() as session:
            for f in findings:
                session.add(Vulnerability(
                    scan_id=scan_id, cve_id=f.cve_id, product=f.product,
                    version=f.version, port=f.port, proto=f.proto,
                    cvss_score=f.cvss_score, severity=f.severity,
                    description=f.description, source=f.source,
                ))
            await session.commit()
    for f in findings:
        hub.publish(scan_id, {"type": "vuln", "cve_id": f.cve_id,
                              "severity": f.severity, "cvss_score": f.cvss_score,
                              "product": f.product, "version": f.version, "port": f.port})
    return {"scan_type": "vuln", "ports_scanned": len(ports), "open": open_count,
            "vulnerabilities": len(findings), "nvd": use_nvd}


async def _run_web(scan_id, target, options) -> dict:
    checks = tuple(options.get("checks") or ALL_CHECKS)
    timeout = float(options.get("timeout", 10.0))
    concurrency = int(options.get("concurrency", 50))
    wordlist = options.get("wordlist")

    hub.publish(scan_id, {"type": "started", "phase": "web",
                          "target": target, "checks": list(checks)})
    result = await run_web_scan(target, checks=checks, timeout=timeout,
                                concurrency=concurrency, dir_wordlist=wordlist)
    if result.findings:
        async with AsyncSessionLocal() as session:
            for f in result.findings:
                session.add(WebFinding(
                    scan_id=scan_id, finding_type=f.finding_type, severity=f.severity,
                    url=f.url, description=f.description, evidence=f.evidence or None,
                ))
            await session.commit()
    for f in result.findings:
        hub.publish(scan_id, {"type": "finding", "finding_type": f.finding_type,
                              "severity": f.severity, "url": f.url})
    return {"scan_type": "web", "checks_run": list(result.checks_run),
            "findings": len(result.findings)}


async def _run_full(scan_id, ip, web_target, options) -> dict:
    """Run port + vuln + web in sequence; one phase failing doesn't abort the
    others — each phase's outcome (or error) is recorded in the summary."""
    summary: dict = {"scan_type": "full", "phases": {}}
    phases = (
        ("port", _run_port(scan_id, ip, options)),
        ("vuln", _run_vuln(scan_id, ip, options)),
        ("web", _run_web(scan_id, web_target, options)),
    )
    for name, coro in phases:
        try:
            summary["phases"][name] = await coro
        except Exception as exc:
            summary["phases"][name] = {"error": str(exc)}
            hub.publish(scan_id, {"type": "phase_error", "phase": name, "error": str(exc)})
    return summary
