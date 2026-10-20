import asyncio
import json
from pathlib import Path
from urllib.parse import quote

import httpx

from app.scanner.cache import DiskCache

ACCEPT = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8"
KEEP = ("dependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta",
        "deprecated")
NAME_OK = set("abcdefghijklmnopqrstuvwxyz0123456789-._~@/")


class RegistryError(Exception):
    pass


def trim(doc: dict) -> dict:
    """Keep only what remediation needs; abbreviated packuments are otherwise large."""
    versions = {}
    for ver, meta in (doc.get("versions") or {}).items():
        if isinstance(meta, dict):
            versions[ver] = {k: meta[k] for k in KEEP if meta.get(k)}
    return {"name": doc.get("name"), "dist-tags": doc.get("dist-tags") or {},
            "versions": versions}


def file_name(name: str) -> str:
    return name.replace("/", "__") + ".json"


def valid_name(name: str) -> bool:
    return 0 < len(name) <= 214 and set(name.lower()) <= NAME_OK and ".." not in name


class Registry:
    def __init__(self, base_url: str, cache: DiskCache, recorded: Path | None = None,
                 offline: bool = False, timeout_s: float = 15,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.base = base_url.rstrip("/")
        self.cache = cache
        self.recorded = recorded
        self.offline = offline
        self.timeout = timeout_s
        self.transport = transport
        self.memo: dict[str, dict] = {}
        self.down = False
        self.sources: dict[str, str] = {}

    async def packument(self, name: str) -> dict:
        if not valid_name(name):
            raise RegistryError(f"invalid package name {name!r}")
        if name in self.memo:
            return self.memo[name]
        doc, source = await self._load(name)
        self.memo[name], self.sources[name] = doc, source
        return doc

    async def _load(self, name: str) -> tuple[dict, str]:
        key = f"npm:{name}"
        reason = f"registry metadata for {name} is unavailable"
        if not self.offline:
            fresh = self.cache.get(key)
            if fresh is not None:
                return fresh, "cache"
            try:
                if self.down:
                    raise RegistryError(f"registry unreachable; skipped {name}")
                doc = trim(await self._fetch(name))
                self.cache.put(key, doc)
                return doc, "live"
            except RegistryError as exc:
                reason = str(exc)
                stale = self.cache.get(key, allow_stale=True)
                if stale is not None:
                    return stale, "cache"
        if self.recorded and (path := self.recorded / file_name(name)).is_file():
            return json.loads(path.read_text(encoding="utf-8")), "recorded"
        raise RegistryError(reason)

    async def _fetch(self, name: str) -> dict:
        url = f"{self.base}/{quote(name, safe='@')}"
        last = ""
        async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport,
                                     headers={"Accept": ACCEPT,
                                              "User-Agent": "DepGuard-AI"}) as client:
            for attempt in range(2):
                try:
                    resp = await client.get(url)
                    if resp.status_code == 404:
                        raise RegistryError(f"{name} is not on the registry")
                    if resp.status_code < 400:
                        return resp.json()
                    last = f"HTTP {resp.status_code}"
                except (httpx.TimeoutException, httpx.TransportError) as exc:
                    last = exc.__class__.__name__
                    self.down = True
                except ValueError:
                    last = "invalid JSON"
                if attempt == 0:
                    await asyncio.sleep(0.3)
        raise RegistryError(f"registry unavailable for {name} ({last})")
