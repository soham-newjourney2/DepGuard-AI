"""Fill in dependency paths for flat lockfiles from PyPI and the Go proxy, never adding packages."""

import asyncio
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

import httpx
from packaging.requirements import InvalidRequirement, Requirement

from app.graph import Graph
from app.scanner.cache import DiskCache
from app.stacks.base import norm_name

PYPI = "https://pypi.org/pypi/{name}/{version}/json"
GOPROXY = "https://proxy.golang.org/{module}/@v/{version}.mod"
ECOSYSTEMS = {"pip": "PyPI", "pipenv": "PyPI", "go": "Go"}
CONCURRENCY = 8
TIMEOUT_S = 10
BUDGET_S = 40
GO_REQUIRE = re.compile(r"^\s*(?:require\s+)?([^\s()]+)\s+v\S+", re.M)


@dataclass
class Result:
    deps: dict[str, list[str]] = field(default_factory=dict)
    source: str = "live"
    failed: int = 0


def go_escape(module: str) -> str:
    """Module proxy case-encoding: upper-case letters become '!' + lower-case."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), module)


def pypi_deps(doc: dict) -> list[str]:
    out = []
    for raw in (doc.get("info") or {}).get("requires_dist") or []:
        try:
            req = Requirement(raw)
        except InvalidRequirement:
            continue
        if req.marker is not None and "extra" in str(req.marker):
            continue
        out.append(req.name)
    return out


def go_deps(text: str) -> list[str]:
    body = re.sub(r"//.*", "", text)
    blocks = re.findall(r"require\s*\((.*?)\)", body, re.S)
    lines = "\n".join(blocks) + "\n" + "\n".join(
        x for x in body.splitlines() if x.strip().startswith("require ") and "(" not in x)
    return sorted({m.group(1) for m in GO_REQUIRE.finditer(lines)})


class Metadata:
    """Live registry metadata with a 24 h disk cache."""

    def __init__(self, cache_root: Path, ttl_s: float, pypi: str = PYPI, goproxy: str = GOPROXY,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.cache = DiskCache(cache_root / "deps", ttl_s)
        self.pypi, self.goproxy, self.transport = pypi, goproxy, transport

    async def one(self, client: httpx.AsyncClient, eco: str, name: str,
                  version: str) -> list[str] | None:
        key = f"{eco}|{name}|{version}"
        if (hit := self.cache.get(key)) is not None:
            return hit
        try:
            if eco == "PyPI":
                r = await client.get(self.pypi.format(name=quote(name), version=quote(version)))
                deps = pypi_deps(r.json()) if r.status_code == 200 else None
            else:
                url = self.goproxy.format(module=go_escape(name), version=f"v{version}")
                r = await client.get(url)
                deps = go_deps(r.text) if r.status_code == 200 else None
        except (httpx.HTTPError, ValueError):
            return None
        if deps is not None:
            self.cache.put(key, deps)
        return deps

    async def fetch(self, eco: str, packages: list[tuple[str, str]]) -> Result:
        sem = asyncio.Semaphore(CONCURRENCY)
        out = Result()
        async with httpx.AsyncClient(timeout=TIMEOUT_S, transport=self.transport,
                                     follow_redirects=True,
                                     headers={"User-Agent": "DepGuard-AI"}) as client:
            async def go(name: str, version: str) -> None:
                async with sem:
                    deps = await self.one(client, eco, name, version)
                if deps is None:
                    out.failed += 1
                else:
                    out.deps[f"{name}@{version}"] = deps
            await asyncio.gather(*(go(n, v) for n, v in packages))
        return out


class RecordedMetadata:
    """Test fixture replay (fixture scanner only)."""

    def __init__(self, path: Path):
        self.path = path

    async def fetch(self, eco: str, packages: list[tuple[str, str]]) -> Result:
        try:
            doc = json.loads(self.path.read_text("utf-8"))
        except (OSError, ValueError):
            return Result(source="recorded", failed=len(packages))
        recorded = doc.get(eco) or {}
        found = {f"{n}@{v}": recorded[f"{n}@{v}"] for n, v in packages if f"{n}@{v}" in recorded}
        return Result(found, "recorded", len(packages) - len(found))


def edges_of(g: Graph) -> list[tuple[str, str, str]]:
    return [(e.src, e.dst, e.kind) for src in list(g.out) for e in g.out[src]]


def rebuild(g: Graph, eco: str, result: Result) -> tuple[Graph, int]:
    """Graph with inferred edges added; returns it and how many packages still have no path."""
    by_name = {norm_name(eco, n.name): k for k, n in g.nodes.items() if k}
    edges = edges_of(g)
    root_all = sum(1 for s, _, _ in edges if s == "") == len(by_name)
    inferred = []
    for key, deps in result.deps.items():
        if key not in g.nodes:
            continue
        kind = "dev" if g.nodes[key].dev else "prod"
        for dep in deps:
            target = by_name.get(norm_name(eco, dep))
            if target and target != key:
                inferred.append((key, target, kind))
    has_parent = {d for _, d, _ in inferred}
    if root_all:
        edges = [e for e in edges if not (e[0] == "" and e[1] in has_parent)]
    nodes = {k: n for k, n in g.nodes.items() if k}
    warnings = [w for w in g.lock.warnings if w["code"] != "W_FLAT_LOCK"]
    new = Graph.explicit(g.lock.root, nodes, edges + inferred, warnings, g.lock.version)
    new.lockfile_name = g.lockfile_name
    unreached = sum(1 for k in nodes if new.depth.get(k) is None)
    return new, unreached


async def infer(g: Graph, stack: str, provider) -> tuple[Graph | None, str]:
    """Return (new graph or None, log line); network trouble never raises."""
    eco = ECOSYSTEMS.get(stack)
    if eco is None or not any(w["code"] == "W_FLAT_LOCK" for w in g.lock.warnings):
        return None, ""
    packages = sorted({(n.name, n.version) for k, n in g.nodes.items() if k and n.installed})
    try:
        result = await asyncio.wait_for(provider.fetch(eco, packages), BUDGET_S)
    except TimeoutError:
        return None, "Dependency metadata timed out; paths stay unknown for this lockfile."
    if not result.deps:
        return None, ("Dependency metadata unavailable; paths stay unknown for this lockfile."
                      if packages else "")
    new, unreached = rebuild(g, eco, result)
    source = "PyPI" if eco == "PyPI" else "the Go module proxy"
    if unreached:
        new.lock.warnings.append({"code": "W_FLAT_LOCK", "message": (
            f"Paths were inferred from {source} metadata, but {unreached} package(s) could not "
            "be placed; their paths are unknown.")})
    new.lock.warnings.append({"code": "W_EDGES_INFERRED", "message": (
        f"{Path(g.lockfile_name).name} does not record who depends on whom; paths were inferred "
        f"from {source} metadata for the locked versions.")})
    return new, (f"Inferred dependency paths from {source} for {len(result.deps)} of "
                 f"{len(packages)} packages ({result.source})")


def make_provider(s):
    if s.local_only:
        return None
    if s.scanner == "fixture":
        return RecordedMetadata(s.recorded_dir.parent / "deps.json")
    return Metadata(s.data_dir / "cache", s.cache_ttl_h * 3600)
