import re
import threading
import time
from collections import deque

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.errors import AppError

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)
HEADERS = {
    "content-security-policy": CSP,
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
}
RAW_HEADERS = [(k.encode(), v.encode()) for k, v in HEADERS.items()]


class SecurityHeaders:
    """Pure ASGI so streaming (SSE) responses are not buffered."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def wrapped(message: Message) -> None:
            if message["type"] == "http.response.start":
                names = {k.lower() for k, _ in message.get("headers", [])}
                message["headers"] = list(message.get("headers", [])) + [
                    h for h in RAW_HEADERS if h[0] not in names
                ]
            await send(message)

        await self.app(scope, receive, wrapped)


UNITS = {"s": 1, "sec": 1, "second": 1, "m": 60, "min": 60, "minute": 60,
         "h": 3600, "hour": 3600}


def parse_rate(rate: str) -> tuple[int, int]:
    m = re.fullmatch(r"\s*(\d+)\s*/\s*([a-z]+)\s*", rate.lower())
    if not m or m.group(2) not in UNITS:
        raise ValueError(f"invalid RATE_LIMIT {rate!r}; use e.g. 30/min")
    return int(m.group(1)), UNITS[m.group(2)]


class RateLimiter:
    """Sliding-window limiter keyed by client IP."""

    def __init__(self, rate: str, clock=time.monotonic):
        self.limit, self.window = parse_rate(rate)
        self.clock = clock
        self.hits: dict[str, deque[float]] = {}
        self.lock = threading.Lock()

    def check(self, key: str) -> None:
        now = self.clock()
        with self.lock:
            q = self.hits.setdefault(key, deque())
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                retry = max(1, int(q[0] + self.window - now) + 1)
                raise AppError("E_RATE_LIMIT", "Too many requests.",
                               f"Try again in {retry} s.", 429, {"Retry-After": str(retry)})
            q.append(now)
            if len(self.hits) > 10_000:
                self.hits = {k: v for k, v in self.hits.items() if v and v[-1] > now - self.window}


REDACTED = "[REDACTED]"
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)(_auth(?:Token)?\s*=\s*)\S+"),
    re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)\S+"),
    re.compile(r"(?i)\b((?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*)['\"]?[^\s'\",]{6,}"),
    re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"(?i)(https?://[^\s/:@]+:)[^\s/@]+(@)"),
]


def redact(value):
    """Mask credentials in strings, recursively through dicts and lists."""
    if isinstance(value, str):
        for pat in SECRET_PATTERNS:
            value = pat.sub(lambda m: (m.group(1) if m.re.groups else "") + REDACTED
                            + (m.group(2) if m.re.groups > 1 else ""), value)
        return value
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


IMMUTABLE = ("/assets/fonts/", "/vendor/")


class CacheHeaders:
    """Fonts and vendored libraries never change; app code and API responses revalidate."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if path.startswith(IMMUTABLE):
            value = b"public, max-age=31536000, immutable"
        elif path.startswith("/api/"):
            value = b"no-store"
        else:
            value = b"no-cache"

        async def wrapped(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                has = any(k.lower() == b"cache-control" for k, _ in headers)
                if not has:
                    headers.append((b"cache-control", value))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, wrapped)


JSON_BODY_LIMIT = 64 * 1024


class BodyLimit:
    """Cap request bodies while they stream, so chunked uploads cannot bypass Content-Length."""

    def __init__(self, app: ASGIApp, upload_limit: int):
        self.app = app
        self.upload_limit = upload_limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            return await self.app(scope, receive, send)
        if scope["path"] == "/api/jobs":
            return await self.app(scope, self.streaming(receive), send)
        body, more = b"", True
        while more:
            message = await receive()
            if message["type"] != "http.request":
                return await self.app(scope, receive, send)
            body += message.get("body", b"")
            more = message.get("more_body", False)
            if len(body) > JSON_BODY_LIMIT:
                return await too_large(send)
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    def streaming(self, receive: Receive) -> Receive:
        total = 0

        async def limited() -> Message:
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.upload_limit:
                    raise AppError("E_TOO_LARGE", "Request body is too large.",
                                   "Upload a smaller project or exclude node_modules.", 413)
            return message

        return limited


async def too_large(send: Send) -> None:
    body = (b'{"error":{"code":"E_TOO_LARGE","message":"Request body is too large.",'
            b'"hint":"Send a smaller request."}}')
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})
