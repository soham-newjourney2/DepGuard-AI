import shutil

import pytest
from fastapi.testclient import TestClient
from helpers import wait_job

from app.config import ROOT, Settings
from app.main import create_app


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("proposals")
    shutil.copytree(ROOT / "samples" / "vuln-demo", tmp / "samples" / "vuln-demo")
    s = Settings(_env_file=None, data_dir=tmp / "data", frontend_dir=tmp / "none",
                 samples_dir=tmp / "samples", scanner="fixture", verify_mode="mock",
                 rate_limit="1000/min")
    with TestClient(create_app(s), raise_server_exceptions=False) as c:
        job_id = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"])["id"]
        yield c, job_id


def finding_id(c, job_id, q):
    return c.get(f"/api/jobs/{job_id}/findings", params={"q": q}).json()["items"][0]["id"]


def test_propose_qs(demo):
    c, job_id = demo
    fid = finding_id(c, job_id, "GHSA-hrpp-h998-j3pp")
    r = c.post(f"/api/jobs/{job_id}/findings/{fid}/proposal")
    assert r.status_code == 200
    items = r.json()["items"]
    assert [p["strategy"] for p in items] == ["parent-bump", "override"]
    assert all(p["status"] == "proposed" and p["finding_id"] == fid for p in items)
    assert "edits" not in items[0]
    again = c.post(f"/api/jobs/{job_id}/findings/{fid}/proposal").json()["items"]
    assert [p["pid"] for p in again] == [p["pid"] for p in items], "deterministic ids"


def test_get_proposal_and_patch(demo):
    c, job_id = demo
    fid = finding_id(c, job_id, "GHSA-rv95-896h-c2vc")
    pid = c.post(f"/api/jobs/{job_id}/findings/{fid}/proposal").json()["items"][0]["pid"]
    assert c.get(f"/api/jobs/{job_id}/proposals/{pid}").json()["strategy"] == "direct-bump"
    r = c.get(f"/api/jobs/{job_id}/patch", params={"pid": pid})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/x-diff")
    assert f'filename="depguard-{pid}.patch"' in r.headers["content-disposition"]
    assert r.text.startswith("--- a/package.json\n+++ b/package.json\n")


def test_no_fix_has_no_patch(demo):
    c, job_id = demo
    fid = finding_id(c, job_id, "request")
    [p] = c.post(f"/api/jobs/{job_id}/findings/{fid}/proposal").json()["items"]
    assert p["strategy"] == "none"
    assert c.get(f"/api/jobs/{job_id}/patch", params={"pid": p["pid"]}).status_code == 404


@pytest.mark.parametrize("pid", ["p_nope", "../../etc", "p_" + "a" * 12, "p_../../../x"])
def test_bad_pids(demo, pid):
    c, job_id = demo
    assert c.get(f"/api/jobs/{job_id}/proposals/{pid}").status_code == 404
    assert c.get(f"/api/jobs/{job_id}/patch", params={"pid": pid}).status_code == 404


def test_unknown_finding(demo):
    c, job_id = demo
    assert c.post(f"/api/jobs/{job_id}/findings/f_000000000000/proposal").status_code == 404
