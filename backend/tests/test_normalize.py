import json
from pathlib import Path

import pytest

from app.graph import Graph
from app.lockfile import parse
from app.scanner.base import Package, build_result
from app.scanner.normalize import normalize, severity

FIX = Path(__file__).parent / "fixtures"
REC = json.loads((FIX / "osv" / "synthetic.json").read_text(encoding="utf-8"))
OLD, NEW = Package("demo-lib", "1.0.0"), Package("demo-lib", "2.0.1")


@pytest.fixture(scope="module")
def graph():
    return Graph(parse(json.loads((FIX / "locks" / "demo_lib.json").read_text(encoding="utf-8"))))


def run(graph, mapping, source="live"):
    result = build_result({p: [REC[k] for k in keys] for p, keys in mapping.items()},
                          {"name": "fixture", "version": "t"}, "2099-01-01T00:00:00.000Z",
                          source=source)
    return normalize(result, graph)


def test_ghsa_preferred_and_duplicates_merged(graph):
    [f] = run(graph, {OLD: ["cve_with_ghsa_alias", "ghsa_same_advisory"]})
    adv = f["advisory"]
    assert adv["id"] == "GHSA-aaaa-bbbb-cccc"
    assert adv["aliases"] == ["CVE-2099-0001", "CVE-2099-0009"]
    assert f["id"].startswith("f_") and len(f["id"]) == 14


def test_cvss_v3_scored(graph):
    [f] = run(graph, {OLD: ["cve_with_ghsa_alias"]})
    assert f["advisory"]["severity"] == {
        "label": "critical", "score": 9.8, "source": "CVSS_V3",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}


def test_cvss_v4_db_and_unknown_severity():
    assert severity(REC["v4_only"])["score"] == 9.3
    assert severity(REC["v4_only"])["label"] == "critical"
    assert severity(REC["db_severity"]) == {"label": "medium", "score": None, "vector": None,
                                            "source": "database_specific"}
    assert severity(REC["no_severity"])["label"] == "unknown"
    assert severity({"severity": [{"type": "CVSS_V3", "score": "garbage"}]})["label"] == "unknown"


def test_ranges_only_for_this_package(graph):
    [f] = run(graph, {OLD: ["cve_with_ghsa_alias"]})
    assert f["affected_ranges"] == [
        {"introduced": "0", "fixed": "1.2.3", "text": ">=0 <1.2.3", "contains": True},
        {"introduced": "2.0.0", "fixed": "2.0.5", "text": ">=2.0.0 <2.0.5", "contains": False},
    ]
    assert f["fixed_versions"] == ["1.2.3", "2.0.5"]


def test_last_affected_and_open_ranges(graph):
    [f] = run(graph, {OLD: ["v4_only"]})
    assert f["affected_ranges"] == [{"introduced": "1.0.0", "last_affected": "1.9.0",
                                     "text": ">=1.0.0 <=1.9.0", "contains": True}]
    assert f["fixed_versions"] == []
    [g] = run(graph, {OLD: ["db_severity"]})
    rng = g["affected_ranges"][0]
    assert rng["text"] == ">=1.1.0" and rng["contains"] is False
    assert g["advisory"]["summary"] == "First line summary"


def test_withdrawn_skipped_and_refs_sanitised(graph):
    findings = run(graph, {OLD: ["withdrawn", "cve_with_ghsa_alias"]})
    assert [f["advisory"]["id"] for f in findings] == ["GHSA-aaaa-bbbb-cccc"]
    assert findings[0]["advisory"]["refs"] == [
        {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"}]


def test_graph_context_per_installed_copy(graph):
    findings = run(graph, {OLD: ["no_severity"], NEW: ["cve_with_ghsa_alias"]})
    by_ver = {f["package"]["version"]: f for f in findings}
    assert by_ver["1.0.0"]["direct"] is True and by_ver["1.0.0"]["depth"] == 1
    assert by_ver["2.0.1"]["paths"] == [["root", "wrapper@1.0.0", "demo-lib@2.0.1"]]
    assert by_ver["2.0.1"]["scope"] == "prod" and by_ver["2.0.1"]["direct"] is False
    assert [f["package"]["version"] for f in findings] == ["2.0.1", "1.0.0"], "critical first"


def test_finding_shape_and_scan_meta(graph):
    [f] = run(graph, {OLD: ["no_severity"]}, source="cache")
    assert set(f) == {"id", "advisory", "package", "affected_ranges", "fixed_versions", "scope",
                      "direct", "depth", "paths", "path_count", "lockfile", "reachability",
                      "priority", "evidence", "scan", "malicious"}
    assert f["malicious"] is False
    assert f["scan"] == {"scanner": "fixture", "version": "t", "ts": "2099-01-01T00:00:00.000Z",
                         "source": "cache"}
    assert f["reachability"]["label"] == "Unknown"
    assert f["package"] == {"name": "demo-lib", "version": "1.0.0", "ecosystem": "npm"}
