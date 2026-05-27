"""
Web security scanner (Phase 5).

Given a URL or hostname, runs a set of web-security checks and returns a flat
list of WebFinding objects. The checks map 1:1 to the Phase 5 tasks:

    ssl          5.1  TLS/certificate inspection (expiry, issuer, self-signed,
                      negotiated protocol + cipher strength)
    headers      5.1  HTTP security-header analysis (HSTS, CSP, X-Frame-Options,
                      …) plus Server/X-Powered-By info-leak detection
    dirs         5.2  async directory brute-force over a path wordlist, with a
                      soft-404 calibration step; reports 200 / 401 / 403 / 30x
    probes       5.3  active OWASP probes — open redirect, reflected XSS,
                      error-based SQL injection
    subdomains   5.4  async DNS brute-force over a subdomain-label wordlist

Public surface:
    normalize_target(target)                     -> (target_url, root_url, host, port, scheme)
    check_ssl(host, port, *, timeout)            -> list[WebFinding]       (blocking)
    scan_headers(client, url)                    -> list[WebFinding]
    scan_dirs(client, root_url, words, ...)      -> list[WebFinding]
    scan_probes(client, target_url, ...)         -> list[WebFinding]
    scan_subdomains(domain, labels, ...)         -> list[WebFinding]
    run_web_scan(target, *, checks, ...)         -> WebScanResult
    render_web_table(result)
    save_web_scan(...)                           -> scan id (UUID string)

Design notes:
    - Mirrors scanner/vuln_scanner.py: dataclass findings, a render_* table, a
      save_* persistence helper with a lazy DB import (so --no-save needs no DB).
    - The httpx client runs with verify=False on purpose: a scanner must still
      reach hosts with broken TLS. Certificate problems are reported by the ssl
      check, not by refusing to connect.
    - The active probes (5.3) send crafted request parameters. They are not
      destructive (plain GETs), but only run them against targets you are
      authorised to test.
"""
from __future__ import annotations

import asyncio
import random
import re
import socket
import ssl
import string
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlencode, urlsplit, urlunsplit

import httpx
from rich.console import Console
from rich.table import Table

from scanner.dns_utils import is_ip_literal

# Optional: cryptography gives us cert fields (expiry/issuer) even for untrusted
# certs. Without it the ssl check still reports protocol/cipher and trust state.
try:
    from cryptography import x509

    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - exercised only when the dep is absent
    x509 = None  # type: ignore[assignment]
    _HAVE_CRYPTO = False

# Optional: aiodns is the Phase 5.4 target library. If it (or its pycares C
# extension) isn't available, we fall back to asyncio's built-in async resolver,
# so subdomain enumeration works everywhere without a hard dependency.
try:
    import aiodns

    _HAVE_AIODNS = True
except ImportError:  # pragma: no cover
    aiodns = None  # type: ignore[assignment]
    _HAVE_AIODNS = False


_DIR_WORDLIST_PATH = Path(__file__).parent / "data" / "web_wordlist.txt"
_SUBDOMAIN_WORDLIST_PATH = Path(__file__).parent / "data" / "subdomains.txt"

DEFAULT_HTTP_TIMEOUT = 10.0
DEFAULT_HTTP_CONCURRENCY = 50
USER_AGENT = "CyberScanner/0.1 (+https://github.com/gautamx8055/Cyber-Scanner)"

ALL_CHECKS = ("ssl", "headers", "dirs", "probes", "subdomains")

SEVERITY_COLOR = {
    "Critical": "bold red",
    "High": "red",
    "Medium": "yellow",
    "Low": "cyan",
    "Info": "dim",
}
# Render order — worst first.
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


@dataclass
class WebFinding:
    finding_type: str       # ssl | missing_header | info_leak | dir | open_redirect | xss | sqli | subdomain
    severity: str           # Critical | High | Medium | Low | Info
    url: str
    description: str
    evidence: str = ""


@dataclass
class WebScanResult:
    target_url: str         # full URL the checks ran against (scheme + path)
    root_url: str           # scheme://host[:port]/ — base for dir brute-force
    host: str
    port: int
    scheme: str
    findings: list[WebFinding] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)


# ----------------------------------------------------------------------------
# Target parsing
# ----------------------------------------------------------------------------

def normalize_target(target: str) -> tuple[str, str, str, int, str]:
    """Turn a user target into (target_url, root_url, host, port, scheme).

    Accepts bare hosts ("example.com"), hosts with a path
    ("example.com/app?id=1"), or full URLs. A scheme-less target defaults to
    https. `target_url` keeps the path+query (used by header + probe checks);
    `root_url` is just scheme://netloc/ (the base for directory brute-forcing).
    """
    if "://" not in target:
        target = "https://" + target
    parts = urlsplit(target)
    scheme = parts.scheme or "https"
    host = parts.hostname or ""
    port = parts.port or (443 if scheme == "https" else 80)
    target_url = urlunsplit((scheme, parts.netloc, parts.path or "/", parts.query, ""))
    root_url = urlunsplit((scheme, parts.netloc, "/", "", ""))
    return target_url, root_url, host, port, scheme


# ----------------------------------------------------------------------------
# 5.1 — SSL / TLS inspection
# ----------------------------------------------------------------------------

# OpenSSL protocol strings we consider obsolete (TLS 1.2 is the modern floor).
WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
# Substrings that mark a cipher suite as weak/broken.
WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "EXP", "MD5", "ANON", "ADH")


def check_ssl(host: str, port: int = 443, *, timeout: float = DEFAULT_HTTP_TIMEOUT) -> list[WebFinding]:
    """Inspect the TLS endpoint at host:port. Synchronous (uses blocking
    sockets) — call via asyncio.to_thread from async code.

    Two handshakes:
      1. A non-verifying handshake always completes (even for self-signed /
         expired certs) so we can read the certificate and the negotiated
         protocol + cipher.
      2. A verifying handshake tells us whether a normal client would trust the
         cert (CA chain + hostname), surfacing issues the first one ignores.
    """
    url = f"https://{host}:{port}"
    findings: list[WebFinding] = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
                cipher = ssock.cipher()
    except (OSError, ssl.SSLError) as e:
        return [WebFinding("ssl", "Info", url,
                           "Could not establish a TLS connection", str(e))]

    self_signed = False
    if der and _HAVE_CRYPTO:
        cert_findings, self_signed = _inspect_certificate(der, url)
        findings += cert_findings
    elif not _HAVE_CRYPTO:
        findings.append(WebFinding(
            "ssl", "Info", url,
            "Certificate fields not parsed (install 'cryptography' for expiry/issuer)",
            "",
        ))

    # Negotiated protocol version.
    if tls_version in WEAK_TLS_VERSIONS:
        findings.append(WebFinding(
            "ssl", "Medium", url,
            f"Server negotiated a legacy TLS version ({tls_version})", tls_version))

    # Negotiated cipher strength.
    if cipher:
        name, _proto, bits = cipher
        weak = any(tok in name.upper() for tok in WEAK_CIPHER_TOKENS)
        if weak or (bits and bits < 128):
            findings.append(WebFinding(
                "ssl", "Medium", url,
                f"Weak cipher negotiated ({name}, {bits}-bit)", name))

    # Trust + hostname verification (a normal browser's view).
    verify_err = _verify_chain(host, port, timeout)
    if verify_err and not self_signed:
        findings.append(WebFinding(
            "ssl", "Medium", url,
            "Certificate not trusted by a default client", verify_err))

    # Always emit a one-line status so a healthy endpoint produces visible output.
    proto = tls_version or "?"
    cipher_name = cipher[0] if cipher else "?"
    trust = "untrusted" if (verify_err or self_signed) else "trusted"
    findings.append(WebFinding(
        "ssl", "Info", url,
        f"TLS endpoint reachable ({proto}, {cipher_name}, {trust})",
        f"version={proto} cipher={cipher_name}"))
    return findings


def _inspect_certificate(der: bytes, url: str) -> tuple[list[WebFinding], bool]:
    """Parse a DER cert and flag expiry / self-signed. Returns (findings,
    self_signed)."""
    findings: list[WebFinding] = []
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as e:  # malformed cert — don't let it sink the scan
        return [WebFinding("ssl", "Info", url, "Could not parse certificate", str(e))], False

    # cryptography >= 42 exposes tz-aware *_utc accessors; older returns naive UTC.
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    days_left = (not_after - now).days

    if days_left < 0:
        findings.append(WebFinding(
            "ssl", "High", url,
            f"Certificate expired {-days_left} day(s) ago",
            f"notAfter={not_after.date()}"))
    elif days_left <= 14:
        findings.append(WebFinding(
            "ssl", "Medium", url,
            f"Certificate expires in {days_left} day(s)",
            f"notAfter={not_after.date()}"))
    elif days_left <= 30:
        findings.append(WebFinding(
            "ssl", "Low", url,
            f"Certificate expires in {days_left} day(s)",
            f"notAfter={not_after.date()}"))

    self_signed = cert.issuer == cert.subject
    if self_signed:
        findings.append(WebFinding(
            "ssl", "Medium", url, "Self-signed certificate",
            _name_str(cert.subject)))
    return findings, self_signed


def _name_str(name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


def _verify_chain(host: str, port: int, timeout: float) -> str | None:
    """Return None if a default client would trust the cert + hostname, else a
    short reason string."""
    vctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with vctx.wrap_socket(sock, server_hostname=host):
                return None
    except ssl.SSLCertVerificationError as e:
        return getattr(e, "verify_message", None) or str(e)
    except (OSError, ssl.SSLError) as e:
        return str(e)


# ----------------------------------------------------------------------------
# 5.1 — HTTP security headers
# ----------------------------------------------------------------------------

# header (lowercase) -> (why it matters, severity if missing)
SECURITY_HEADERS: dict[str, tuple[str, str]] = {
    "strict-transport-security": (
        "HSTS missing — clients can be downgraded to plaintext HTTP (MITM)", "Medium"),
    "content-security-policy": (
        "Content-Security-Policy missing — weaker XSS / data-injection defense", "Medium"),
    "x-frame-options": (
        "X-Frame-Options missing — page can be framed (clickjacking)", "Medium"),
    "x-content-type-options": (
        "X-Content-Type-Options missing — browser MIME-sniffing possible", "Low"),
    "referrer-policy": (
        "Referrer-Policy missing — full URL may leak to third parties via Referer", "Low"),
    "permissions-policy": (
        "Permissions-Policy missing — browser features (camera, geolocation) unrestricted", "Low"),
}
# Headers that commonly leak software + version.
INFO_LEAK_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


async def scan_headers(client: httpx.AsyncClient, url: str) -> list[WebFinding]:
    """Fetch `url` and report missing security headers + info-leaking headers."""
    try:
        resp = await client.get(url, follow_redirects=True)
    except httpx.HTTPError as e:
        return [WebFinding("missing_header", "Info", url,
                           "Could not fetch URL for header analysis", str(e))]

    headers = {k.lower(): v for k, v in resp.headers.items()}
    final_url = str(resp.url)
    findings: list[WebFinding] = []

    for header, (desc, sev) in SECURITY_HEADERS.items():
        # HSTS is only meaningful over HTTPS.
        if header == "strict-transport-security" and not final_url.startswith("https"):
            continue
        if header not in headers:
            findings.append(WebFinding("missing_header", sev, final_url, desc, header))

    for header in INFO_LEAK_HEADERS:
        value = headers.get(header, "").strip()
        if value:
            findings.append(WebFinding(
                "info_leak", "Info", final_url,
                f"Response advertises software via '{header}'",
                f"{header}: {value}"))
    return findings


# ----------------------------------------------------------------------------
# 5.2 — Directory brute-force
# ----------------------------------------------------------------------------

# Path prefixes that warrant a higher severity when found (secrets / config /
# source control / admin surfaces).
SENSITIVE_HINTS = (
    ".env", ".git", ".svn", ".hg", ".ssh", ".aws", "config", "backup", "dump",
    "wp-config", "id_rsa", "credentials", "secret", ".htpasswd", "db.sql",
    "phpinfo", "adminer", "phpmyadmin", "admin", ".DS_Store", "web.config",
)
# Status codes worth reporting (everything else, incl. 404, is silent).
INTERESTING_STATUSES = {200, 204, 301, 302, 307, 308, 401, 403, 500}


@lru_cache(maxsize=4)
def load_dir_wordlist(path: str | None = None) -> tuple[str, ...]:
    """Load the directory wordlist (one path per line; '#' comments, blanks
    skipped)."""
    return _load_wordlist(Path(path) if path else _DIR_WORDLIST_PATH)


def _load_wordlist(p: Path) -> tuple[str, ...]:
    out: list[str] = []
    with p.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return tuple(out)


def _is_sensitive(path: str) -> bool:
    low = path.lower().lstrip("/")
    return any(hint.lower() in low for hint in SENSITIVE_HINTS)


async def _calibrate_soft404(client: httpx.AsyncClient, root_url: str) -> int | None:
    """Request a random path. If the server answers 200 (a soft-404), return the
    body length so real 200s of the same size can be filtered out. Otherwise
    return None (the server 404s normally and statuses can be trusted)."""
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=24))
    try:
        resp = await client.get(urljoin(root_url, rand), follow_redirects=False)
    except httpx.HTTPError:
        return None
    return len(resp.content) if resp.status_code == 200 else None


async def _probe_path(
    client: httpx.AsyncClient, root_url: str, path: str,
    sem: asyncio.Semaphore, soft404_len: int | None,
) -> WebFinding | None:
    url = urljoin(root_url, path.lstrip("/"))
    async with sem:
        try:
            resp = await client.get(url, follow_redirects=False)
        except httpx.HTTPError:
            return None

    status = resp.status_code
    if status not in INTERESTING_STATUSES:
        return None
    # Filter soft-404s: a 200 the same size as the random-path baseline isn't real.
    if status == 200 and soft404_len is not None and abs(len(resp.content) - soft404_len) <= 64:
        return None

    sensitive = _is_sensitive(path)
    if status in (200, 204):
        sev = "High" if sensitive else "Low"
        label = "accessible"
    elif status in (301, 302, 307, 308):
        sev = "Info"
        label = f"redirect -> {resp.headers.get('location', '?')}"
    elif status == 401:
        sev = "Low"
        label = "auth required (exists)"
    elif status == 403:
        sev = "Medium" if sensitive else "Low"
        label = "forbidden (exists)"
    else:  # 500
        sev = "Low"
        label = "server error (exists)"

    return WebFinding(
        "dir", sev, url,
        f"HTTP {status} — {label}",
        f"status={status} len={len(resp.content)}")


async def scan_dirs(
    client: httpx.AsyncClient, root_url: str, words: tuple[str, ...], *,
    concurrency: int = DEFAULT_HTTP_CONCURRENCY,
) -> list[WebFinding]:
    """Brute-force `words` against `root_url`, concurrency-limited. Reports
    every interesting status; flags sensitive paths at higher severity."""
    sem = asyncio.Semaphore(concurrency)
    soft404_len = await _calibrate_soft404(client, root_url)
    results = await asyncio.gather(
        *(_probe_path(client, root_url, w, sem, soft404_len) for w in words)
    )
    found = [r for r in results if r is not None]
    found.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.url))
    return found


# ----------------------------------------------------------------------------
# 5.3 — OWASP probes (open redirect, reflected XSS, error-based SQLi)
# ----------------------------------------------------------------------------

# A reserved .invalid host never resolves, so the redirect target is provably
# off-site without ever pointing a real victim anywhere.
CANARY_HOST = "canary.cyberscanner.invalid"
CANARY_URL = f"https://{CANARY_HOST}/"
REDIRECT_PARAMS = (
    "next", "url", "redirect", "redirect_uri", "redirect_url", "return",
    "returnUrl", "returnTo", "dest", "destination", "continue", "goto", "out",
)

XSS_MARKER = "cyb9z1xss"  # unlikely to occur naturally → low false-positive risk
XSS_PAYLOAD = f"{XSS_MARKER}<script>alert(1)</script>"

# Param names to fuzz when the target URL carries none of its own.
DEFAULT_PROBE_PARAMS = ("id", "q", "search", "query", "page", "s", "name", "item", "cat")

SQL_ERROR_PATTERNS = [re.compile(p, re.I) for p in (
    r"you have an error in your sql syntax",
    r"warning:\s*mysqli?_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)|pg_exec\(\)",
    r"postgresql query failed|org\.postgresql\.util\.psqlexception",
    r"sqlite3?::|sqlite_error|sqlitedatabase",
    r"ora-\d{5}",
    r"odbc sql server driver|microsoft ole db provider for sql server",
    r"unterminated quoted string|syntax error at or near",
    r"supplied argument is not a valid mysql",
)]


def _with_param(url: str, key: str, value: str) -> str:
    """Return `url` with query parameter `key` set to `value` (replacing any
    existing value)."""
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[key] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/",
                       urlencode(query), parts.fragment))


def _params_to_test(url: str) -> list[str]:
    parts = urlsplit(url)
    existing = [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)]
    return existing or list(DEFAULT_PROBE_PARAMS)


async def probe_open_redirect(client: httpx.AsyncClient, url: str, sem: asyncio.Semaphore) -> list[WebFinding]:
    for param in REDIRECT_PARAMS:
        test = _with_param(url, param, CANARY_URL)
        async with sem:
            try:
                resp = await client.get(test, follow_redirects=False)
            except httpx.HTTPError:
                continue
        location = resp.headers.get("location", "")
        if resp.status_code in (301, 302, 303, 307, 308) and CANARY_HOST in location:
            return [WebFinding(
                "open_redirect", "High", test,
                f"Parameter '{param}' redirects off-site to an attacker-controlled URL",
                f"Location: {location}")]
    return []


async def probe_xss(client: httpx.AsyncClient, url: str, sem: asyncio.Semaphore) -> list[WebFinding]:
    for param in _params_to_test(url):
        test = _with_param(url, param, XSS_PAYLOAD)
        async with sem:
            try:
                resp = await client.get(test, follow_redirects=True)
            except httpx.HTTPError:
                continue
        # Only a *verbatim* reflection (tags intact) indicates the payload would
        # execute; HTML-encoded reflections won't contain this exact substring.
        if XSS_PAYLOAD in resp.text:
            return [WebFinding(
                "xss", "High", test,
                f"Parameter '{param}' reflects an unescaped <script> payload",
                f"reflected verbatim: {XSS_PAYLOAD}")]
    return []


async def probe_sqli(client: httpx.AsyncClient, url: str, sem: asyncio.Semaphore) -> list[WebFinding]:
    for param in _params_to_test(url):
        test = _with_param(url, param, "'")
        async with sem:
            try:
                resp = await client.get(test, follow_redirects=True)
            except httpx.HTTPError:
                continue
        for pat in SQL_ERROR_PATTERNS:
            if pat.search(resp.text):
                return [WebFinding(
                    "sqli", "High", test,
                    f"Parameter '{param}' provokes a database error (possible SQL injection)",
                    f"matched signature: /{pat.pattern}/")]
    return []


async def scan_probes(
    client: httpx.AsyncClient, target_url: str, *,
    concurrency: int = DEFAULT_HTTP_CONCURRENCY,
) -> list[WebFinding]:
    """Run the three OWASP probes against `target_url` concurrently."""
    sem = asyncio.Semaphore(concurrency)
    groups = await asyncio.gather(
        probe_open_redirect(client, target_url, sem),
        probe_xss(client, target_url, sem),
        probe_sqli(client, target_url, sem),
    )
    return [f for group in groups for f in group]


# ----------------------------------------------------------------------------
# 5.4 — Subdomain enumeration (async DNS brute-force)
# ----------------------------------------------------------------------------

@lru_cache(maxsize=4)
def load_subdomain_wordlist(path: str | None = None) -> tuple[str, ...]:
    """Load the subdomain-label wordlist (one label per line)."""
    return _load_wordlist(Path(path) if path else _SUBDOMAIN_WORDLIST_PATH)


async def _resolve_a(name: str, resolver, *, timeout: float) -> list[str]:
    """Resolve `name` to its A records. Uses aiodns if available, else asyncio's
    built-in async resolver. Returns [] on any failure (NXDOMAIN, timeout, …)."""
    if resolver is not None:
        try:
            answers = await resolver.query(name, "A")
            return sorted({a.host for a in answers})
        except Exception:
            return []
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(name, None, family=socket.AF_INET, type=socket.SOCK_STREAM),
            timeout=timeout,
        )
        return sorted({info[4][0] for info in infos})
    except (asyncio.TimeoutError, socket.gaierror, OSError):
        return []


async def scan_subdomains(
    domain: str, labels: tuple[str, ...], *,
    concurrency: int = 100, timeout: float = 3.0,
) -> list[WebFinding]:
    """Brute-force `labels` under `domain`; report each that resolves."""
    if is_ip_literal(domain):
        return []  # subdomain enumeration only makes sense for a domain name
    resolver = aiodns.DNSResolver(timeout=timeout) if _HAVE_AIODNS else None
    sem = asyncio.Semaphore(concurrency)

    async def resolve_one(label: str) -> WebFinding | None:
        name = f"{label}.{domain}"
        async with sem:
            ips = await _resolve_a(name, resolver, timeout=timeout)
        if not ips:
            return None
        return WebFinding(
            "subdomain", "Info", f"https://{name}",
            f"Subdomain resolves: {name}", ", ".join(ips))

    results = await asyncio.gather(*(resolve_one(label) for label in labels))
    found = [r for r in results if r is not None]
    found.sort(key=lambda f: f.url)
    return found


# ----------------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------------

async def run_web_scan(
    target: str, *,
    checks: tuple[str, ...] = ALL_CHECKS,
    timeout: float = DEFAULT_HTTP_TIMEOUT,
    concurrency: int = DEFAULT_HTTP_CONCURRENCY,
    dir_wordlist: str | None = None,
    sub_wordlist: str | None = None,
) -> WebScanResult:
    """Run the selected checks against `target` and collect all findings."""
    target_url, root_url, host, port, scheme = normalize_target(target)
    result = WebScanResult(target_url, root_url, host, port, scheme)

    limits = httpx.Limits(max_connections=concurrency,
                          max_keepalive_connections=concurrency)
    async with httpx.AsyncClient(
        verify=False, timeout=timeout, follow_redirects=False,
        headers={"User-Agent": USER_AGENT}, limits=limits,
    ) as client:
        if "ssl" in checks and scheme == "https":
            result.checks_run.append("ssl")
            result.findings += await asyncio.to_thread(check_ssl, host, port, timeout=timeout)
        if "headers" in checks:
            result.checks_run.append("headers")
            result.findings += await scan_headers(client, target_url)
        if "dirs" in checks:
            result.checks_run.append("dirs")
            result.findings += await scan_dirs(
                client, root_url, load_dir_wordlist(dir_wordlist), concurrency=concurrency)
        if "probes" in checks:
            result.checks_run.append("probes")
            result.findings += await scan_probes(client, target_url, concurrency=concurrency)

    # DNS brute-force doesn't use the HTTP client.
    if "subdomains" in checks:
        result.checks_run.append("subdomains")
        result.findings += await scan_subdomains(
            host, load_subdomain_wordlist(sub_wordlist),
            concurrency=concurrency, timeout=min(timeout, 5.0))

    return result


# ----------------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------------

def render_web_table(result: WebScanResult, *, console: Console | None = None) -> None:
    console = console or Console()
    checks = ", ".join(result.checks_run) or "none"
    if not result.findings:
        console.print(
            f"[green]No web findings for {result.target_url} "
            f"(checks: {checks}).[/green]")
        return

    ordered = sorted(
        result.findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.finding_type, f.url),
    )

    table = Table(
        title=f"Web findings — {result.target_url}    "
              f"{len(ordered)} finding(s)   [checks: {checks}]")
    table.add_column("Severity", style="bold")
    table.add_column("Type")
    table.add_column("URL / Detail", overflow="fold", max_width=46)
    table.add_column("Description", overflow="fold", max_width=46)
    table.add_column("Evidence", overflow="fold", max_width=34, style="dim")

    counts: dict[str, int] = {}
    for f in ordered:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.finding_type,
            f.url,
            f.description,
            f.evidence or "-",
        )
    console.print(table)

    summary = "  ".join(
        f"[{SEVERITY_COLOR.get(sev, 'white')}]{counts[sev]} {sev}[/{SEVERITY_COLOR.get(sev, 'white')}]"
        for sev in sorted(counts, key=lambda s: SEVERITY_ORDER.get(s, 9))
    )
    console.print(f"[dim]Summary:[/dim] {summary}")


# ----------------------------------------------------------------------------
# Persistence
# ----------------------------------------------------------------------------

async def save_web_scan(
    *,
    target_ip: str,
    result: WebScanResult,
    started_at: datetime,
    completed_at: datetime,
    target_hostname: str | None = None,
    options: dict | None = None,
) -> str:
    """Persist a web scan: one `scans` row (type=web) plus one `web_findings`
    row per finding, linked by scan_id. Returns the scan id."""
    # Lazy import keeps this module DB-free for --no-save runs.
    from db.models import Scan, ScanStatus, ScanType
    from db.models import WebFinding as WebFindingRow
    from db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        scan = Scan(
            target_ip=target_ip,
            target_hostname=target_hostname,
            scan_type=ScanType.web,
            status=ScanStatus.completed,
            started_at=started_at,
            completed_at=completed_at,
            options=options or {},
            results=[asdict(f) for f in result.findings],
        )
        session.add(scan)
        await session.flush()  # populate scan.id before we reference it

        for f in result.findings:
            session.add(WebFindingRow(
                scan_id=scan.id,
                finding_type=f.finding_type,
                severity=f.severity,
                url=f.url,
                description=f.description,
                evidence=f.evidence or None,
            ))

        await session.commit()
        return scan.id
