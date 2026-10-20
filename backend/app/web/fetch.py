"""SSRF-safe HTTP fetcher for live-site scans: public addresses only, pinned to the vetted IP."""

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from app.errors import AppError

PORTS = {"http": 80, "https": 443}
MAX_REDIRECTS = 5
CHUNK = 64 * 1024
BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa")
USER_AGENT = "DepGuard-AI/1.0 (+dependency security scan; reads public HTML/JS only)"

Resolver = Callable[[str, int], Awaitable[list[str]]]


def url_error(code: str, message: str, hint: str = "", status: int = 422) -> AppError:
    return AppError(code, message, hint, status)


async def system_resolve(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({str(i[4][0]) for i in infos})


def blocked(ip: str) -> bool:
    """True for anything that is not a plain public unicast address."""
    try:
        a = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return True
    if isinstance(a, ipaddress.IPv6Address):
        embedded = a.ipv4_mapped or a.sixtofour or (a.teredo[1] if a.teredo else None)
        if embedded is not None:
            a = embedded
    return (not a.is_global or a.is_multicast or a.is_reserved or a.is_loopback
            or a.is_link_local or a.is_private or a.is_unspecified)


@dataclass(frozen=True)
class Target:
    url: str
    scheme: str
    host: str
    port: int
    path: str

    @property
    def host_header(self) -> str:
        return self.host if self.port == PORTS[self.scheme] else f"{self.host}:{self.port}"


def parse_target(raw: str, any_port: bool = False) -> Target:
    text = (raw or "").strip()
    if not text or len(text) > 2048 or any(c.isspace() for c in text):
        raise url_error("E_URL_INVALID", "That is not a valid web address.",
                        "Example: https://example.com")
    if "://" not in text:
        text = "https://" + text
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        raise url_error("E_URL_INVALID", "That is not a valid web address.",
                        "Example: https://example.com") from None
    scheme = parts.scheme.lower()
    if scheme not in PORTS:
        raise url_error("E_URL_SCHEME", "Only http:// and https:// sites can be scanned.")
    if parts.username or parts.password:
        raise url_error("E_URL_INVALID", "Addresses with credentials are not allowed.",
                        "Remove the user:password@ part.")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise url_error("E_URL_INVALID", "The address has no host name.")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise url_error("E_URL_INVALID", "The host name is not valid.") from None
    port = port or PORTS[scheme]
    if port not in PORTS.values() and not any_port:
        raise url_error("E_URL_PORT", "Only the standard web ports (80, 443) are allowed.")
    if host == "localhost" or host.endswith(BLOCKED_SUFFIXES):
        raise url_error("E_URL_BLOCKED", "Local and internal addresses cannot be scanned.",
                        "Use a public website URL.")
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    url = f"{scheme}://{host}{'' if port == PORTS[scheme] else f':{port}'}{path}"
    return Target(url, scheme, host, port, path)


@dataclass
class Fetched:
    url: str
    status: int
    content_type: str
    body: bytes
    truncated: bool = False
    redirects: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class Fetcher:
    """One scan's fetcher: shared byte budget, no cookies, no proxies, no JS."""

    def __init__(self, *, timeout_s: float = 10, total_bytes: int = 15 * 1024 * 1024,
                 resolver: Resolver = system_resolve,
                 transport: httpx.AsyncBaseTransport | None = None,
                 allow_private: bool = False):
        self.timeout = timeout_s
        self.budget = total_bytes
        self.resolver = resolver
        self.allow_private = allow_private
        self.client = httpx.AsyncClient(timeout=timeout_s, transport=transport,
                                        follow_redirects=False, trust_env=False,
                                        headers={"User-Agent": USER_AGENT,
                                                 "Accept-Encoding": "gzip, deflate"})

    async def __aenter__(self) -> "Fetcher":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.client.aclose()

    async def vet(self, t: Target) -> str:
        try:
            literal = ipaddress.ip_address(t.host.strip("[]"))
            ips = [str(literal)]
        except ValueError:
            try:
                ips = await asyncio.wait_for(self.resolver(t.host, t.port), self.timeout)
            except (OSError, TimeoutError):
                ips = []
        if not ips:
            raise url_error("E_URL_DNS", f"{t.host} could not be resolved.",
                            "Check the address and try again.")
        if not self.allow_private and any(blocked(ip) for ip in ips):
            raise url_error("E_URL_BLOCKED",
                            f"{t.host} points to a private or reserved address.",
                            "Only public websites can be scanned.")
        return ips[0]

    async def get(self, raw: str, max_bytes: int, accept: str = "*/*") -> Fetched:
        url, redirects = raw, []
        for _ in range(MAX_REDIRECTS + 1):
            t = parse_target(url, self.allow_private)
            ip = await self.vet(t)
            host = f"[{ip}]" if ":" in ip else ip
            self.client.cookies.clear()
            req = self.client.build_request(
                "GET", f"{t.scheme}://{host}:{t.port}{t.path}",
                headers={"Host": t.host_header, "Accept": accept},
                extensions={"sni_hostname": t.host} if t.scheme == "https" else {})
            try:
                resp = await self.client.send(req, stream=True)
            except httpx.HTTPError as exc:
                raise url_error("E_URL_UNREACHABLE", f"Could not reach {t.host} "
                                f"({exc.__class__.__name__}).", "Check the site is up.",
                                502) from None
            try:
                location = resp.headers.get("location")
                if resp.status_code in (301, 302, 303, 307, 308) and location:
                    url = urljoin(t.url, location)
                    redirects.append(url)
                    continue
                body, truncated = await self.read(resp, max_bytes)
            finally:
                await resp.aclose()
            return Fetched(t.url, resp.status_code,
                           resp.headers.get("content-type", "").split(";")[0].strip().lower(),
                           body, truncated, redirects)
        raise url_error("E_URL_REDIRECTS", f"More than {MAX_REDIRECTS} redirects.",
                        "Use the final address of the page.")

    async def read(self, resp: httpx.Response, max_bytes: int) -> tuple[bytes, bool]:
        chunks, size = [], 0
        cap = min(max_bytes, self.budget)
        try:
            async for chunk in resp.aiter_bytes(CHUNK):
                if size + len(chunk) > cap:
                    chunks.append(chunk[:max(cap - size, 0)])
                    size = cap
                    self.budget -= size
                    return b"".join(chunks), True
                chunks.append(chunk)
                size += len(chunk)
        except httpx.HTTPError as exc:
            raise url_error("E_URL_UNREACHABLE", f"Download failed ({exc.__class__.__name__}).",
                            "", 502) from None
        self.budget -= size
        return b"".join(chunks), False
