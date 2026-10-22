import json
import shutil
import time

import pytest
from fastapi.testclient import TestClient
from helpers import wait_job

from app.config import ROOT, Settings
from app.main import create_app
from app.verify import modes, runner

QS = "GHSA-hrpp-h998-j3pp"
FINAL = {"verified", "verify_failed", "unable_to_verify"}


@pytest.fixture
def make_client(tmp_path):
    shutil.copytree(ROOT / "samples" / "vuln-demo", tmp_path / "samples" / "vuln-demo")

    def make(mode="mock"):
        s = Settings(_env_file=None, data_dir=tmp_path / f"data-{mode}", frontend_dir=tmp_path,
                     samples_dir=tmp_path / "samples", scanner="fixture", verify_mode=mode,
                     rate_limit="1000/min")
        return TestClient(create_app(s), raise_server_exceptions=False)
    return make


def setup(c, q=QS, index=0):
    job_id = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"])["id"]
    fid = c.get(f"/api/jobs/{job_id}/findings", params={"q": q}).json()["items"][0]["id"]
    items = c.post(f"/api/jobs/{job_id}/findings/{fid}/proposal").json()["items"]
    return job_id, items[index]


def wait_verification(c, job_id, pid, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = c.get(f"/api/jobs/{job_id}/proposals/{pid}/verification").json()
        if r["status"] in FINAL:
            return r
        time.sleep(0.05)
    raise AssertionError(f"verification stuck: {r}")


def events(c, job_id, pid):
    out = []
    with c.stream("GET", f"/api/jobs/{job_id}/proposals/{pid}/events") as r:
        for line in r.iter_lines():
            if line.startswith("data: "):
                out.append(json.loads(line[6:]))
    return out


def test_mock_verification_of_parent_bump(make_client):
    with make_client() as c:
        job_id, p = setup(c)
        assert p["strategy"] == "parent-bump"
        r = c.post(f"/api/jobs/{job_id}/proposals/{p['pid']}/approve", json={"confirm": True})
        assert r.status_code == 202 and r.json()["status"] == "approved"
        result = wait_verification(c, job_id, p["pid"])
        assert result["status"] == "verified" and result["mode"] == "mock"
        assert [s["name"] for s in result["stages"]] == ["resolve", "test"]
        assert all(s["status"] == "passed" and s["exit_code"] == 0 for s in result["stages"])
        cmp = result["comparison"]
        assert cmp["target_resolved"] is True
        assert QS in {x["advisory"] for x in cmp["resolved"]}
        assert cmp["after"] < cmp["before"]
        changed = {c["pkg"]: c for c in result["tree_delta"]["changed"]}
        assert changed["express"]["to"] == ["4.22.3"]
        assert result["lock_diff"].startswith("--- a/package-lock.json")
        assert result["tests"] == {"present": True, "exit_code": 0}
        assert any("Simulated verification" in x for x in result["labels"])
        assert any(x.startswith("Tests exited 0.") for x in result["labels"])
        assert "npm test --if-present" in result["stages"][1]["log"]
        assert c.get(f"/api/jobs/{job_id}/proposals/{p['pid']}").json()["status"] == "verified"
        evs = events(c, job_id, p["pid"])
        assert evs[-1]["type"] == "done" and evs[-1]["data"]["status"] == "verified"
        again = c.post(f"/api/jobs/{job_id}/proposals/{p['pid']}/approve",
                       json={"confirm": True})
        assert again.status_code == 409 and again.json()["error"]["code"] == "E_ALREADY_APPROVED"


def test_live_event_stream_during_run(make_client):
    with make_client() as c:
        job_id, p = setup(c)
        c.post(f"/api/jobs/{job_id}/proposals/{p['pid']}/approve", json={"confirm": True})
        evs = events(c, job_id, p["pid"])
        kinds = [e["type"] for e in evs]
        assert "log" in kinds and "stage" in kinds and kinds[-1] == "done"
        statuses = [e["data"]["status"] for e in evs if e["type"] == "status"]
        assert statuses[-3:] == ["testing", "rescanning", "verified"]
        assert all("\x1b[" not in json.dumps(e) or e["type"] == "log" for e in evs)


def test_confirm_required_and_no_patch(make_client):
    with make_client() as c:
        job_id, p = setup(c)
        r = c.post(f"/api/jobs/{job_id}/proposals/{p['pid']}/approve", json={"confirm": False})
        assert r.status_code == 422 and r.json()["error"]["code"] == "E_CONFIRM_REQUIRED"
        r = c.post(f"/api/jobs/{job_id}/proposals/{p['pid']}/approve", json={})
        assert r.status_code == 422
        _, none = setup(c, q="request")
        r = c.post(f"/api/jobs/{job_id}/proposals/{none['pid']}/approve", json={"confirm": True})
        assert r.status_code in (404, 409)


def test_failing_tests_mark_verify_failed(make_client, monkeypatch):
    class Failing(modes.MockExecutor):
        def __init__(self, changes):
            super().__init__(changes, test_exit=1)

    monkeypatch.setattr(runner, "MockExecutor", Failing)
    with make_client() as c:
        job_id, p = setup(c)
        c.post(f"/api/jobs/{job_id}/proposals/{p['pid']}/approve", json={"confirm": True})
        result = wait_verification(c, job_id, p["pid"])
        assert result["status"] == "verify_failed" and "Tests failed (exit 1)" in result["reason"]
        assert result["comparison"]["target_resolved"] is True


def test_off_mode_unable_to_verify(make_client):
    with make_client("off") as c:
        job_id, p = setup(c)
        c.post(f"/api/jobs/{job_id}/proposals/{p['pid']}/approve", json={"confirm": True})
        result = wait_verification(c, job_id, p["pid"])
        assert result["status"] == "unable_to_verify" and "turned off" in result["reason"]
        assert result["stages"] == []
        assert events(c, job_id, p["pid"])[-1]["type"] == "error"


def test_secrets_never_leave_logs(make_client, monkeypatch):
    class Leaky(modes.MockExecutor):
        async def run(self, stage, workspace, timeout, on_line):
            on_line("npm http fetch GET https://user:hunter2pass@registry.example.com/x")
            return await super().run(stage, workspace, timeout, on_line)

    monkeypatch.setattr(runner, "MockExecutor", Leaky)
    with make_client() as c:
        job_id, p = setup(c)
        c.post(f"/api/jobs/{job_id}/proposals/{p['pid']}/approve", json={"confirm": True})
        result = wait_verification(c, job_id, p["pid"])
        assert "hunter2pass" not in json.dumps(result)
        assert all("hunter2pass" not in json.dumps(e) for e in events(c, job_id, p["pid"]))
