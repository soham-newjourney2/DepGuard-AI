import asyncio
import json
import shutil
import time

import pytest
from fastapi.testclient import TestClient
from helpers import real, wait_job

from app.config import RECORDED, ROOT, Settings
from app.main import create_app
from app.prioritize import enrich
from app.remediation.batch import plan_all
from app.remediation.registry import Registry
from app.samples import load_graph, packages
from app.scanner.cache import DiskCache
from app.scanner.fixture import RecordedScanner
from app.scanner.normalize import normalize

REC = RECORDED


@pytest.fixture(scope="module")
def plan(tmp_path_factory):
    graph = load_graph(real(ROOT / "samples" / "vuln-demo"))
    scanner = RecordedScanner(REC / "osv")
    findings = enrich(normalize(asyncio.run(scanner.scan(packages(graph))), graph))

    async def checker(pkgs):
        r = await scanner.scan(pkgs)
        return {p.label: ([v["id"] for v in r.vulns_for(p)] if scanner.known(p) else None)
                for p in pkgs}

    registry = Registry("https://npm.invalid", DiskCache(tmp_path_factory.mktemp("c"), 0),
                        recorded=REC / "npm", offline=True)
    manifest = (real(ROOT / "samples" / "vuln-demo") / "package.json").read_text(encoding="utf-8")
    return asyncio.run(plan_all(findings, graph.to_json(), manifest, registry, checker))


def by_status(plan):
    out = {}
    for i in plan["items"]:
        out.setdefault(i["status"], []).append(i)
    return out


def test_one_edit_per_target_and_highest_version_wins(plan):
    keys = [(e["op"], e.get("section"), e.get("name"), tuple(e.get("path", ())))
            for e in plan["edits"]]
    assert len(keys) == len(set(keys))
    express = [e for e in plan["edits"] if e.get("name") == "express"]
    assert express == [{"op": "set", "section": "dependencies", "name": "express",
                        "value": "4.22.3"}]
    merged = by_status(plan)["merged"]
    assert {i["package"] for i in merged} >= {"express@4.17.1", "body-parser@1.19.0"}
    assert all("superseded by 4.22.3" in i["note"] for i in merged
               if i["package"] == "express@4.17.1")


def test_override_under_bumped_parent_is_a_conflict(plan):
    conflicts = plan["conflicts"]
    assert {i["package"] for i in conflicts} == {"path-to-regexp@0.1.7"}
    assert not [e for e in plan["edits"] if e["op"] == "override" and e["path"][0] == "express"]
    assert any(w.startswith("Conflict: path-to-regexp@0.1.7") for w in plan["warnings"])
    assert {i["finding_id"] for i in conflicts}.isdisjoint(plan["finding_ids"])


def test_no_fix_and_counts(plan):
    st = by_status(plan)
    assert [i["package"] for i in st["no_fix"]] == ["request@2.88.2"]
    assert plan["title"] == f"Batch plan: {len(plan['finding_ids'])} of 22 findings"
    assert len(plan["items"]) == 22
    assert plan["diff"].startswith("--- a/package.json") and '"overrides"' in plan["diff"]
    assert plan["strategy"] == "batch" and plan["pid"].startswith("p_")


def test_batch_api_and_mock_verification(tmp_path):
    shutil.copytree(ROOT / "samples" / "vuln-demo", tmp_path / "samples" / "vuln-demo")
    s = Settings(_env_file=None, data_dir=tmp_path / "data", frontend_dir=tmp_path,
                 samples_dir=tmp_path / "samples", scanner="fixture", verify_mode="mock",
                 rate_limit="1000/min")
    with TestClient(create_app(s)) as c:
        job_id = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"])["id"]
        plan = c.post(f"/api/jobs/{job_id}/plan").json()
        assert plan["strategy"] == "batch" and "edits" not in plan
        assert c.post(f"/api/jobs/{job_id}/plan").json()["pid"] == plan["pid"]
        r = c.post(f"/api/jobs/{job_id}/proposals/{plan['pid']}/approve", json={"confirm": True})
        assert r.status_code == 202
        for _ in range(400):
            v = c.get(f"/api/jobs/{job_id}/proposals/{plan['pid']}/verification").json()
            if v["status"] in ("verified", "verify_failed", "unable_to_verify"):
                break
            time.sleep(0.05)
        assert v["status"] == "verified", v.get("reason")
        cmp = v["comparison"]
        assert cmp["target_resolved"] is True and cmp["after"] < cmp["before"]
        resolved = {x["advisory"] for x in cmp["resolved"]}
        assert {"GHSA-hrpp-h998-j3pp", "GHSA-xvch-5gv4-984h", "GHSA-rv95-896h-c2vc"} <= resolved
        report = c.get(f"/api/jobs/{job_id}/report").json()
        assert report["fix"]["strategy"] == "batch"
        assert json.dumps(report).count("GHSA-p8p7-x288-28g6") >= 1
