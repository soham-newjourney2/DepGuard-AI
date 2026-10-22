"""Refresh the recorded test fixtures from live sources (needs internet)."""

import asyncio
import atexit
import json
import re
import shutil
import tempfile
from pathlib import Path

import httpx

from app.config import ROOT, Settings
from app.exploit import ExploitFeeds, cves_of
from app.jobs import iso, utcnow
from app.prioritize import enrich
from app.remediation.candidates import Planner
from app.remediation.registry import Registry, file_name
from app.samples import checkout, is_npm, load_graph, packages
from app.scanner.base import Package, build_result
from app.scanner.cache import DiskCache
from app.scanner.fixture import SAFE_ID, RecordedScanner, record
from app.scanner.normalize import normalize
from app.scanner.osv_api import OsvApiScanner
from app.stacks import found_in

SAMPLES = ("vuln-demo", "clean-demo", "messy-demo", "python-demo", "supplychain-demo")
_REAL = Path(tempfile.mkdtemp(prefix="depguard-record-"))
atexit.register(shutil.rmtree, _REAL, True)


def real(rel: str) -> Path:
    """A copy of a bundled folder (relative to the repo) with manifests under their real names."""
    dst = _REAL / rel
    return dst if dst.is_dir() else checkout(ROOT / rel, dst)


def orphans(db: Path) -> tuple[list[str], list[Path]]:
    """Recorded OSV keys whose package no sample, packument or proposal names; unused vuln files."""
    names = {p.name for name in SAMPLES for p in packages(load_graph(real(f"samples/{name}")))}
    names |= {f.stem.replace("__", "/") for f in (db.parent / "npm").glob("*.json")}
    proposals = " ".join(f.read_text("utf-8") for f in db.parent.glob("*.proposals.json"))
    index = json.loads((db / "index.json").read_text(encoding="utf-8"))

    def unused(key: str) -> bool:
        n = key.rsplit("@", 1)[0].split(":", 1)[-1]
        return n not in names and f"{n}@" not in proposals and f'"{n} ' not in proposals
    keys = [k for k in (*index["packages"], *index["clean"]) if unused(k)]
    used = {v.translate(SAFE_ID) for k, ids in index["packages"].items() if not unused(k)
            for v in ids}
    return keys, [f for f in sorted((db / "vulns").glob("*.json")) if f.stem not in used]


POPULAR = {
    "npm": ("https://unpkg.com/npm-high-impact@1.13.0/lib/top-download.js",
            "npm-high-impact 1.13.0 (MIT, wooorm) top-download list"),
    "pypi": ("https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json",
             "hugovk/top-pypi-packages (no licence stated; names only, attribution kept)"),
}
POPULAR_N = 5000


FLAT_FIXTURES = ("pip-flat", "pipenv", "go")


async def record_deps(out: Path) -> dict:
    """Live dependency metadata for the flat-lockfile test fixtures (replayed by tests)."""
    from app import flatedges
    doc: dict[str, dict] = {}
    with tempfile.TemporaryDirectory() as tmp:
        meta = flatedges.Metadata(Path(tmp), 0)
        for case in FLAT_FIXTURES:
            d = real(f"backend/tests/fixtures/stacks/{case}")
            stack = found_in(d)[0]
            g = stack.load(d)
            eco = flatedges.ECOSYSTEMS[stack.id]
            pkgs = sorted({(n.name, n.version) for k, n in g.nodes.items() if k and n.installed})
            result = await meta.fetch(eco, pkgs)
            doc.setdefault(eco, {}).update(result.deps)
            print(f"deps {case}: {len(result.deps)} of {len(pkgs)} packages")
    doc["recorded_at"] = iso(utcnow())
    out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return doc


def record_popular(out_dir: Path) -> None:
    """Typosquat reference lists: the most-downloaded package names per ecosystem."""
    out_dir.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=60, follow_redirects=True) as c:
        for eco, (url, label) in POPULAR.items():
            resp = c.get(url)
            resp.raise_for_status()
            if eco == "npm":
                names = re.findall(r"^\s*'([^']+)',?$", resp.text, re.M)
            else:
                names = [r["project"] for r in resp.json()["rows"]]
            names = list(dict.fromkeys(names))[:POPULAR_N]
            if len(names) < 1000:
                raise SystemExit(f"{eco}: only {len(names)} names parsed from {url}")
            head = [f"# {label}", f"# source: {url}", f"# fetched: {iso(utcnow())}",
                    f"# top {len(names)} names; regenerate with `python tasks.py record`"]
            (out_dir / f"{eco}.txt").write_text("\n".join([*head, *names]) + "\n",
                                                encoding="utf-8")
            print(f"popular {eco}: {len(names)} names")


def demo_cves(db: Path) -> list[str]:
    """CVE ids of every recorded advisory, the join key for exploit signals."""
    return sorted({c for f in (db / "vulns").glob("*.json")
                   for c in cves_of(json.loads(f.read_text(encoding="utf-8")))})


async def record_exploit(s: Settings, db: Path) -> dict:
    """Live KEV + EPSS for the recorded CVEs; KEV is trimmed to those CVEs."""
    cves = demo_cves(db)
    with tempfile.TemporaryDirectory() as tmp:
        sig = await ExploitFeeds(s.kev_url, s.epss_url, Path(tmp), 0).lookup(cves)
    if sig.kev is None or sig.epss is None:
        raise SystemExit(f"exploit feeds unavailable: {'; '.join(sig.notes)}; nothing recorded")
    doc = {"recorded_at": iso(utcnow()), "kev": {c: sig.kev[c] for c in cves if c in sig.kev},
           "epss": {c: v for c, v in sig.epss.items() if v.get("epss") is not None}}
    (db.parent / "exploit.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    top = sum(1 for v in doc["epss"].values() if v["percentile"] >= 0.8)
    print(f"exploit: {len(cves)} CVEs · {len(doc['kev'])} in CISA KEV · {len(doc['epss'])} with "
          f"EPSS · {top} at or above the 80th percentile")
    return doc


def expected(findings: list[dict]) -> list[dict]:
    return sorted(({"advisory": f["advisory"]["id"],
                    "package": f"{f['package']['name']}@{f['package']['version']}",
                    "severity": f["advisory"]["severity"]["label"],
                    "fixed_versions": f["fixed_versions"]} for f in findings),
                  key=lambda e: (e["package"], e["advisory"]))


def proposal_summary(finding: dict, proposals: list[dict]) -> dict:
    return {"finding": f"{finding['package']['name']}@{finding['package']['version']} "
                       f"{finding['advisory']['id']}",
            "proposals": [{"strategy": p["strategy"],
                           "changes": [f"{c['pkg']} {c['from']}->{c['to']}"
                                       for c in p["changes"]]} for p in proposals]}


async def run() -> None:
    s = Settings(_env_file=None)
    started = iso(utcnow())
    graphs = {name: load_graph(real(f"samples/{name}")) for name in SAMPLES}
    wanted = sorted({p for g in graphs.values() for p in packages(g)})
    osv = OsvApiScanner(s.osv_api_url, DiskCache(s.data_dir / "cache" / "osv", 0))
    result = await osv.scan(wanted)
    if result.source != "live":
        raise SystemExit("live OSV scan failed; nothing recorded")
    collected = {Package(r["package"]["name"], r["package"]["version"],
                         r["package"].get("ecosystem", "npm")): r["vulns"]
                 for r in result.raw["results"]}

    async def checker(pkgs: list[Package]) -> dict:
        res = await osv.scan(pkgs)
        if res.source != "live":
            raise SystemExit("live OSV re-check failed; nothing recorded")
        for p in pkgs:
            collected[p] = res.vulns_for(p)
        return {p.label: [v["id"] for v in res.vulns_for(p)] for p in pkgs}

    registry = Registry(s.registry_url, DiskCache(s.data_dir / "cache" / "npm", 0))
    summaries: dict[str, list] = {}
    for name, graph in graphs.items():
        if not is_npm(real(f"samples/{name}")):
            continue
        findings = enrich(normalize(result, graph))
        graph_json = graph.to_json()
        manifest = (real(f"samples/{name}") / "package.json").read_text(encoding="utf-8")
        summaries[name] = []
        for f in findings:
            props = await Planner(f, findings, graph_json, manifest, registry, checker).plan()
            summaries[name].append(proposal_summary(f, props))

    shutil.rmtree(s.recorded_dir, ignore_errors=True)
    record(build_result(collected, osv.meta, started), s.recorded_dir)
    npm_dir = s.recorded_dir.parent / "npm"
    npm_dir.mkdir(parents=True, exist_ok=True)
    for stale in npm_dir.glob("*.json"):
        stale.unlink()
    for name, doc in sorted(registry.memo.items()):
        (npm_dir / file_name(name)).write_text(json.dumps(doc, separators=(",", ":")) + "\n",
                                               encoding="utf-8")
    replay = await RecordedScanner(s.recorded_dir).scan(wanted)
    for name, graph in graphs.items():
        found = expected(normalize(replay, graph))
        out = s.recorded_dir.parent / f"{name}.expected.json"
        out.write_text(json.dumps(found, indent=1) + "\n", encoding="utf-8")
        print(f"{name}: {len(found)} findings")
    for name, items in summaries.items():
        if items:
            out = s.recorded_dir.parent / f"{name}.proposals.json"
            out.write_text(json.dumps(items, indent=1) + "\n", encoding="utf-8")
            print(f"{name}: {sum(len(x['proposals']) for x in items)} proposals across "
                  f"{len(items)} findings")
    print(f"npm metadata for {len(registry.memo)} packages")
    await record_exploit(s, s.recorded_dir)
    record_popular(ROOT / "backend" / "app" / "data" / "popular")
    await record_deps(s.recorded_dir.parent / "deps.json")


async def merge_samples(names: list[str]) -> None:
    """Add live OSV data for new samples to the recording without re-recording the others."""
    s = Settings(_env_file=None)
    db = s.recorded_dir
    graphs = {name: load_graph(real(f"samples/{name}")) for name in names}
    wanted = sorted({p for g in graphs.values() for p in packages(g)})
    result = await OsvApiScanner(s.osv_api_url, DiskCache(s.data_dir / "cache" / "osv", 0)).scan(
        wanted)
    if result.source != "live":
        raise SystemExit("live OSV scan failed; nothing merged")
    index = json.loads((db / "index.json").read_text(encoding="utf-8"))
    for r in result.raw["results"]:
        p = r["package"]
        label = Package(p["name"], p["version"], p.get("ecosystem", "npm")).key
        index["packages"].pop(label, None)
        if label in index["clean"]:
            index["clean"].remove(label)
        if r["vulns"]:
            index["packages"][label] = [v["id"] for v in r["vulns"]]
        else:
            index["clean"].append(label)
        for v in r["vulns"]:
            (db / "vulns" / f"{v['id'].translate(SAFE_ID)}.json").write_text(
                json.dumps(v, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    index["packages"] = dict(sorted(index["packages"].items()))
    index["clean"] = sorted(index["clean"])
    (db / "index.json").write_text(json.dumps(index, indent=1) + "\n", encoding="utf-8")
    replay = await RecordedScanner(db).scan(wanted)
    for name, graph in graphs.items():
        found = expected(normalize(replay, graph))
        (db.parent / f"{name}.expected.json").write_text(json.dumps(found, indent=1) + "\n",
                                                         encoding="utf-8")
        print(f"{name}: {len(found)} findings merged into the recording")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
