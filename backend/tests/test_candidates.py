import asyncio
import json

import pytest
from helpers import real

from app.config import RECORDED, ROOT
from app.prioritize import enrich
from app.remediation.candidates import (
    Planner,
    jump,
    max_satisfying,
    parse_spec,
    split_label,
)
from app.remediation.registry import Registry
from app.samples import load_graph, packages
from app.scanner.base import Package
from app.scanner.cache import DiskCache
from app.scanner.fixture import RecordedScanner
from app.scanner.normalize import normalize, parse_ver
from tools.record import proposal_summary

REC = RECORDED
DEMO = real(ROOT / "samples" / "vuln-demo")


@pytest.fixture(scope="module")
def demo():
    graph = load_graph(DEMO)
    scanner = RecordedScanner(REC / "osv")
    findings = enrich(normalize(asyncio.run(scanner.scan(packages(graph))), graph))
    return graph.to_json(), findings, (DEMO / "package.json").read_text(encoding="utf-8")


async def checker(pkgs):
    scanner = RecordedScanner(REC / "osv")
    result = await scanner.scan(pkgs)
    return {p.label: ([v["id"] for v in result.vulns_for(p)] if scanner.known(p) else None)
            for p in pkgs}


def plan(demo, tmp_path, name, version, advisory):
    graph, findings, manifest = demo
    f = next(x for x in findings if (x["package"]["name"], x["package"]["version"],
                                     x["advisory"]["id"]) == (name, version, advisory))
    registry = Registry("https://npm.invalid", DiskCache(tmp_path, 0), recorded=REC / "npm",
                        offline=True)
    return f, asyncio.run(Planner(f, findings, graph, manifest, registry, checker).plan())


def by_strategy(props):
    return {p["strategy"]: p for p in props}


def test_direct_bump_express(demo, tmp_path):
    _, props = plan(demo, tmp_path, "express", "4.17.1", "GHSA-rv95-896h-c2vc")
    p = props[0]
    assert p["strategy"] == "direct-bump" and p["confidence"] == "high"
    assert p["changes"] == [{"pkg": "express", "from": "4.17.1", "to": "4.20.0",
                             "jump": "minor"}]
    assert {"GHSA-rv95-896h-c2vc", "GHSA-qw6h-vgh9-j6wx"} <= set(p["resolves"])
    assert '-    "express": "4.17.1",' in p["diff"] and '+    "express": "4.20.0",' in p["diff"]
    assert p["pid"].startswith("p_") and len(p["pid"]) == 14


def test_parent_bump_express_for_qs(demo, tmp_path):
    _, props = plan(demo, tmp_path, "qs", "6.7.0", "GHSA-hrpp-h998-j3pp")
    s = by_strategy(props)
    assert list(s) == ["parent-bump", "override"]
    parent = s["parent-bump"]
    changes = {c["pkg"]: (c["from"], c["to"]) for c in parent["changes"]}
    assert changes["express"][0] == "4.17.1" and changes["qs"][0] == "6.7.0"
    assert parse_ver(changes["qs"][1]) >= parse_ver("6.7.3")
    assert "GHSA-hrpp-h998-j3pp" in parent["resolves"]
    assert any("predicted" in w for w in parent["warnings"])
    assert '"express": "4.22.3"' in parent["diff"]


def test_override_for_qs_warns_outside_parent_range(demo, tmp_path):
    _, props = plan(demo, tmp_path, "qs", "6.7.0", "GHSA-hrpp-h998-j3pp")
    o = by_strategy(props)["override"]
    assert o["changes"][0]["pkg"] == "qs"
    assert '"overrides": {' in o["diff"] and '"express": {' in o["diff"]
    assert o["confidence"] == "low"
    assert any("outside express@4.17.1's declared range" in w for w in o["warnings"])


def test_request_has_no_fix(demo, tmp_path):
    _, props = plan(demo, tmp_path, "request", "2.88.2", "GHSA-p8p7-x288-28g6")
    assert [p["strategy"] for p in props] == ["none"]
    none = props[0]
    assert none["changes"] == [] and none["diff"] == "" and none["resolves"] == []
    assert any("No published version of request" in w for w in none["warnings"])
    assert any("deprecated by its maintainers" in w for w in none["warnings"])


def test_least_change_first_and_major_warning(demo, tmp_path):
    _, props = plan(demo, tmp_path, "path-to-regexp", "0.1.7", "GHSA-37ch-88jc-xwx2")
    assert [p["strategy"] for p in props] == ["override", "parent-bump"]
    _, props = plan(demo, tmp_path, "uuid", "3.4.0", "GHSA-w5hq-g745-h8pq")
    assert any("Major version jump for uuid" in w for w in props[0]["warnings"])


def test_offline_plans_match_recorded_live_plans(demo, tmp_path):
    _graph, findings, _manifest = demo
    want = json.loads((REC / "vuln-demo.proposals.json").read_text(encoding="utf-8"))
    got = []
    for f in findings:
        _, props = plan(demo, tmp_path, f["package"]["name"], f["package"]["version"],
                        f["advisory"]["id"])
        got.append(proposal_summary(f, props))
    assert got == want


def test_unknown_candidate_versions_are_flagged(demo, tmp_path):
    graph, findings, manifest = demo
    f = next(x for x in findings if x["package"]["name"] == "express")

    async def blind(pkgs):
        return {p.label: None for p in pkgs}

    registry = Registry("https://npm.invalid", DiskCache(tmp_path, 0), recorded=REC / "npm",
                        offline=True)
    props = asyncio.run(Planner(f, findings, graph, manifest, registry, blind).plan())
    assert any("not re-checked against OSV" in w for w in props[0]["warnings"])


@pytest.mark.parametrize("old,new,kind", [
    ("4.17.1", "4.17.3", "patch"), ("4.17.1", "4.20.0", "minor"), ("4.17.1", "5.0.0", "major"),
    ("0.1.7", "0.1.12", "patch"), ("0.5.1", "0.6.0", "major"), ("1.0.0", "1.0.0", "none"),
])
def test_jump(old, new, kind):
    assert jump(old, new) == kind


def test_spec_helpers():
    doc = {"dist-tags": {"latest": "2.0.0"}, "versions": {v: {} for v in
           ["1.0.0", "1.2.0", "1.3.0-beta.1", "2.0.0"]}}
    assert max_satisfying(doc, "^1.0.0") == "1.2.0"
    assert max_satisfying(doc, ">= 1.0.0") == "2.0.0"
    assert max_satisfying(doc, "npm:other@^1.0.0") == "1.2.0"
    assert max_satisfying(doc, "git+https://example.com/x.git") is None
    assert parse_spec("latest") is None
    assert split_label("@scope/pkg@1.2.3") == ("@scope/pkg", "1.2.3")
    assert Package("a", "1").label == "a@1"
