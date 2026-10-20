import json
import shutil

import pytest
from fastapi.testclient import TestClient
from helpers import wait_job

from app import policy
from app.config import ROOT, Settings
from app.main import create_app


def f(sev, scope="prod", fix=True, n=1):
    return {"id": f"f_{n}", "advisory": {"id": f"GHSA-{n}", "severity": {"label": sev}},
            "package": {"name": f"p{n}", "version": "1.0.0"}, "scope": scope,
            "fix_available": fix}


FINDINGS = [f("critical", n=1), f("high", "dev", n=2), f("medium", fix=False, n=3),
            f("unknown", n=4), f("low", n=5)]


@pytest.mark.parametrize("pol,ids", [
    ({"fail_on": "critical", "prod_only": False, "require_fix": False}, {"GHSA-1", "GHSA-4"}),
    ({"fail_on": "high", "prod_only": False, "require_fix": False},
     {"GHSA-1", "GHSA-2", "GHSA-4"}),
    ({"fail_on": "high", "prod_only": True, "require_fix": False}, {"GHSA-1", "GHSA-4"}),
    ({"fail_on": "low", "prod_only": False, "require_fix": True},
     {"GHSA-1", "GHSA-2", "GHSA-4", "GHSA-5"}),
    ({"fail_on": "none", "prod_only": False, "require_fix": False}, set()),
])
def test_evaluate(pol, ids):
    v = policy.evaluate(FINDINGS, pol, "test")
    assert {x["advisory"] for x in v["violations"]} == ids
    assert v["status"] == ("fail" if ids else "pass") and v["count"] == len(ids)


def test_load_default_valid_and_invalid(tmp_path):
    assert policy.load(tmp_path) == (policy.DEFAULT, "default", None)
    (tmp_path / policy.FILE).write_text(json.dumps({"fail_on": "high", "prod_only": True}))
    assert policy.load(tmp_path) == ({"fail_on": "high", "prod_only": True,
                                      "require_fix": False}, policy.FILE, None)
    (tmp_path / policy.FILE).write_text('{"fail_on": "severe", "prod_only": "yes", "x": 1}')
    pol, src, warn = policy.load(tmp_path)
    assert pol == policy.DEFAULT and src == policy.FILE
    assert "fail_on" in warn and "prod_only" in warn and "x" in warn
    (tmp_path / policy.FILE).write_text("{nope")
    assert policy.load(tmp_path)[2].endswith("using the default policy.")
    (tmp_path / policy.FILE).write_text("[1]")
    assert policy.load(tmp_path)[1] == "default"


def test_describe():
    assert policy.describe({"fail_on": "high", "prod_only": True, "require_fix": True}) == \
        "fails on high or worse, production scope only, only when a fix exists"


@pytest.mark.parametrize("file,status,count", [
    (None, "fail", 2),
    ({"fail_on": "critical", "prod_only": True}, "fail", 1),
    ({"fail_on": "none"}, "pass", 0),
])
def test_pipeline_and_report_policy(tmp_path, file, status, count):
    sample = tmp_path / "samples" / "vuln-demo"
    shutil.copytree(ROOT / "samples" / "vuln-demo", sample)
    if file:
        (sample / policy.FILE).write_text(json.dumps(file))
    s = Settings(_env_file=None, data_dir=tmp_path / "data", frontend_dir=tmp_path,
                 samples_dir=tmp_path / "samples", scanner="fixture", verify_mode="mock")
    with TestClient(create_app(s)) as c:
        job = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"])
        verdict = job["summary"]["policy"]
        assert (verdict["status"], verdict["count"]) == (status, count)
        assert verdict["source"] == (policy.FILE if file else "default")
        listed = c.get(f"/api/jobs/{job['id']}/findings").json()["summary"]["policy"]
        assert listed == verdict
        r = c.get(f"/api/jobs/{job['id']}/report").json()
        assert r["policy"]["before"] == {"status": status, "count": count}
        assert r["policy"]["after"] is None
