import json

import pytest
from helpers import real

from app.config import RECORDED, ROOT
from app.samples import load_graph, packages
from app.scanner.fixture import RecordedScanner
from app.scanner.normalize import normalize
from tools.record import expected, orphans

REC = RECORDED


async def findings_for(sample: str) -> list[dict]:
    graph = load_graph(real(ROOT / "samples" / sample))
    scan = await RecordedScanner(REC / "osv").scan(packages(graph))
    return normalize(scan, graph)


@pytest.mark.parametrize("sample", ["vuln-demo", "clean-demo", "messy-demo",
                                    "python-demo"])
async def test_sample_matches_expected_offline(sample):
    want = json.loads((REC / f"{sample}.expected.json").read_text(encoding="utf-8"))
    assert expected(await findings_for(sample)) == want


async def test_clean_demo_has_no_findings():
    assert await findings_for("clean-demo") == []


async def test_vuln_demo_demo_story():
    findings = await findings_for("vuln-demo")
    by = {(f["package"]["name"], f["package"]["version"], f["advisory"]["id"]): f for f in findings}
    qs = by[("qs", "6.7.0", "GHSA-hrpp-h998-j3pp")]
    assert qs["advisory"]["severity"]["label"] == "high"
    assert "6.7.3" in qs["fixed_versions"]
    assert ["root", "express@4.17.1", "qs@6.7.0"] in qs["paths"]
    assert ["root", "express@4.17.1", "body-parser@1.19.0", "qs@6.7.0"] in qs["paths"]
    assert qs["scope"] == "prod" and qs["direct"] is False
    request = [f for k, f in by.items() if k[0] == "request"]
    assert request and all(f["fixed_versions"] == [] for f in request), "no-fix case"
    minimist = [f for k, f in by.items() if k[0] == "minimist"]
    assert minimist and all(f["scope"] == "dev" for f in minimist)


async def test_messy_demo_covers_every_kind_of_problem():
    findings = await findings_for("messy-demo")
    labels = {f["advisory"]["severity"]["label"] for f in findings}
    assert {"critical", "high", "medium"} <= labels
    assert any(f["scope"] == "dev" for f in findings), "dev-only findings"
    assert any(not f["fixed_versions"] for f in findings
               if f["package"]["name"] == "node-serialize"), "no-fix critical"
    assert any(f["direct"] for f in findings) and any(not f["direct"] for f in findings)


async def test_python_demo_story():
    findings = await findings_for("python-demo")
    names = {f["package"]["name"] for f in findings}
    assert {"pyyaml", "requests", "werkzeug", "jinja2"} <= names
    assert all(f["package"]["ecosystem"] == "PyPI" for f in findings)
    yaml = [f for f in findings if f["package"]["name"] == "pyyaml"]
    assert all(f["direct"] and f["fixed_versions"] for f in yaml)
    werkzeug = next(f for f in findings if f["package"]["name"] == "werkzeug")
    assert ["root", "flask@2.2.2", "werkzeug@2.2.2"] in werkzeug["paths"]


def test_recorded_osv_has_no_orphans():
    keys, files = orphans(REC / "osv")
    assert keys == [] and files == []
