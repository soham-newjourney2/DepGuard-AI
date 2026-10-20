import asyncio
from datetime import UTC, datetime
from pathlib import Path

import httpx

from app.jobs import iso, utcnow
from app.scanner.base import Package, ScanError, ScanResult, build_result
from app.scanner.cache import DiskCache

CHUNK = 1000
RETRIES = 2
CONCURRENCY = 8
RETRYABLE = {429, 500, 502, 503, 504}


class OsvApiScanner:
    name = "osv-api"

    def __init__(self, base_url: str, cache: DiskCache, timeout_s: float = 15,
                 backoff_s: float = 0.5, transport: httpx.AsyncBaseTransport | None = None):
        self.base = base_url.rstrip("/")
        self.cache = cache
        self.timeout = timeout_s
        self.backoff = backoff_s
        self.transport = transport
        self.meta = {"name": self.name, "version": "osv.dev API v1"}

    async def scan(self, packages: list[Package], lockfile: Path | None = None) -> ScanResult:
        started = iso(utcnow())
        try:
            async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport,
                                         headers={"User-Agent": "DepGuard-AI"}) as client:
                ids = await self._query(client, packages)
                records = await self._fetch(client, {i: m for v in ids.values() for i, m in v})
        except ScanError as exc:
            cached = self.from_cache(packages)
            if cached is None:
                raise
            cached.notes.append(f"Live scan failed: {exc}")
            return cached
        results = {p: [records[i] for i, _ in ids[p] if i in records] for p in packages}
        return build_result(results, self.meta, started)

    async def _request(self, client: httpx.AsyncClient, method: str, path: str,
                       body: dict | None = None) -> dict:
        last = ""
        for attempt in range(RETRIES + 1):
            try:
                resp = await client.request(method, f"{self.base}{path}", json=body)
                if resp.status_code in RETRYABLE:
                    last = f"HTTP {resp.status_code}"
                elif resp.status_code >= 400:
                    raise ScanError(f"OSV {path} returned HTTP {resp.status_code}")
                else:
                    return resp.json()
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last = exc.__class__.__name__
            except ValueError:
                last = "invalid JSON"
            if attempt < RETRIES:
                await asyncio.sleep(self.backoff * 2 ** attempt)
        raise ScanError(f"OSV unavailable ({last})")

    async def _query(self, client, packages: list[Package]) -> dict[Package, list[tuple]]:
        found: dict[Package, list[tuple]] = {p: [] for p in packages}
        todo = list(packages)
        tokens: dict[Package, str] = {}
        while todo:
            for start in range(0, len(todo), CHUNK):
                chunk = todo[start:start + CHUNK]
                queries = [{"package": {"name": p.name, "ecosystem": p.ecosystem},
                            "version": p.version,
                            **({"page_token": tokens[p]} if p in tokens else {})} for p in chunk]
                data = await self._request(client, "POST", "/v1/querybatch", {"queries": queries})
                results = data.get("results") or []
                if len(results) != len(chunk):
                    raise ScanError("OSV querybatch returned a mismatched result count")
                for p, r in zip(chunk, results, strict=True):
                    found[p] += [(v["id"], v.get("modified", "")) for v in r.get("vulns") or []]
                    if r.get("next_page_token"):
                        tokens[p] = r["next_page_token"]
                    else:
                        tokens.pop(p, None)
            todo = [p for p in todo if p in tokens]
        for p, ids in found.items():
            self.cache.put(f"osv:q:{p.key}", ids)
        return found

    async def _fetch(self, client, ids: dict[str, str]) -> dict[str, dict]:
        sem = asyncio.Semaphore(CONCURRENCY)
        out: dict[str, dict] = {}

        async def one(vid: str, modified: str) -> None:
            cached = self.cache.get(f"osv:v:{vid}", allow_stale=True)
            if cached and cached.get("modified") == modified and modified:
                out[vid] = cached
                return
            async with sem:
                record = await self._request(client, "GET", f"/v1/vulns/{vid}")
            self.cache.put(f"osv:v:{vid}", record)
            out[vid] = record

        await asyncio.gather(*(one(v, m) for v, m in sorted(ids.items())))
        return out

    def from_cache(self, packages: list[Package]) -> ScanResult | None:
        results, oldest = {}, None
        for p in packages:
            entry = self.cache.entry(f"osv:q:{p.key}", allow_stale=True)
            if entry is None:
                return None
            oldest = min(oldest or entry["ts"], entry["ts"])
            records = []
            for vid, _ in entry["value"]:
                rec = self.cache.get(f"osv:v:{vid}", allow_stale=True)
                if rec is None:
                    return None
                records.append(rec)
            results[p] = records
        ts = iso(datetime.fromtimestamp(oldest or 0, UTC))
        return build_result(results, self.meta, ts, source="cache")
