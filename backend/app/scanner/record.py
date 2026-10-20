"""Maintainer tool: python tasks.py record (needs network)."""

import asyncio
import json
import shutil
from pathlib import Path

from app.config import ROOT, Settings
from app.graph import Graph
from app.jobs import iso, utcnow
from app.lockfile import parse
from app.prioritize import enrich
from app.remediation.candidates import Planner
from app.remediation.registry import Registry, file_name
from app.scanner.base import Package, build_result
from app.scanner.cache import DiskCache
from app.scanner.fixture import RecordedScanner, record
from app.scanner.normalize import normalize
from app.scanner.osv_api import OsvApiScanner
from app.stacks import found_in
from app.web.site import build_graph, scan_files

SAMPLES = ("vuln-demo", "clean-demo", "messy-demo", "python-demo", "site-demo")


def is_npm(sample: Path) -> bool:
    return (sample / "package-lock.json").is_file()


def load_graph(sample: Path) -> Graph:
    if (sample / "index.html").is_file() and not found_in(sample):
        return build_graph(scan_files(sample))
    if not is_npm(sample):
        return found_in(sample)[0].load(sample)
    lock = json.loads((sample / "package-lock.json").read_text(encoding="utf-8"))
    manifest = json.loads((sample / "package.json").read_text(encoding="utf-8"))
    return Graph(parse(lock, manifest))


def packages(graph: Graph) -> list[Package]:
    return sorted({Package(graph.nodes[k[0]].name, graph.nodes[k[0]].version,
                            graph.nodes[k[0]].ecosystem)
                   for k in graph.packages().values()})


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
    graphs = {name: load_graph(ROOT / "samples" / name) for name in SAMPLES}
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
        if not is_npm(ROOT / "samples" / name):
            continue
        findings = enrich(normalize(result, graph))
        graph_json = graph.to_json()
        manifest = (ROOT / "samples" / name / "package.json").read_text(encoding="utf-8")
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


def main() -> None:
    asyncio.run(run())
