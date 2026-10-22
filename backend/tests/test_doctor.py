import shutil
import time

import httpx
import respx
from fastapi.testclient import TestClient
from helpers import wait_job

from app.config import ROOT, Settings
from app.main import create_app
from app.verify import runner
from tools import doctor

QS = "GHSA-hrpp-h998-j3pp"


def test_node_version_rules(monkeypatch):
    monkeypatch.setattr(doctor, "version_of", lambda argv: "v20.11.0")
    assert doctor.check_node().ok
    monkeypatch.setattr(doctor, "version_of", lambda argv: "v16.20.0")
    r = doctor.check_node()
    assert not r.ok and r.required and "Node.js 18+" in r.detail
    monkeypatch.setattr(doctor, "version_of", lambda argv: None)
    assert "not found" in doctor.check_node().detail


def test_network_required_vs_optional(tmp_path):
    s = Settings(_env_file=None, data_dir=tmp_path, osv_api_url="https://osv.test",
                 registry_url="https://npm.test", kev_url="https://kev.test/k.json",
                 epss_url="https://epss.test/e", github_codeload_url="https://gh.test")
    with respx.mock(assert_all_called=False) as m:
        m.post("https://osv.test/v1/query").mock(return_value=httpx.Response(200, json={}))
        m.route(host="npm.test").mock(side_effect=httpx.ConnectError("down"))
        for host in ("kev.test", "epss.test", "gh.test", "pypi.org"):
            m.route(host=host).mock(return_value=httpx.Response(200))
        with httpx.Client() as client:
            results = {r.name: r for r in doctor.check_network(s, client)}
    assert results["OSV"].ok and results["CISA KEV"].ok
    npm = results["npm registry"]
    assert not npm.ok and npm.required and "need it" in npm.detail
    assert npm.mark(False) == "XX" and results["OSV"].mark() == "✓"


def test_main_exit_code(monkeypatch, capsys):
    good = doctor.Result("x", True, "fine")
    optional = doctor.Result("y", False, "missing", required=False)
    monkeypatch.setattr(doctor, "run_checks", lambda s, c: [good, optional])
    assert doctor.main() == 0 and "Ready for the demo." in capsys.readouterr().out
    bad = doctor.Result("z", False, "broken")
    monkeypatch.setattr(doctor, "run_checks", lambda s, c: [good, bad])
    assert doctor.main() == 1 and "1 required check(s) failed" in capsys.readouterr().out


def test_missing_npm_ends_with_a_clear_message(tmp_path, monkeypatch):
    shutil.copytree(ROOT / "samples" / "vuln-demo", tmp_path / "samples" / "vuln-demo")
    s = Settings(_env_file=None, data_dir=tmp_path / "data", frontend_dir=tmp_path,
                 samples_dir=tmp_path / "samples", scanner="fixture", verify_mode="auto",
                 rate_limit="1000/min")
    monkeypatch.setattr(runner.shutil, "which", lambda name: None)
    with TestClient(create_app(s)) as c:
        job_id = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"])["id"]
        fid = c.get(f"/api/jobs/{job_id}/findings", params={"q": QS}).json()["items"][0]["id"]
        pid = c.post(f"/api/jobs/{job_id}/findings/{fid}/proposal").json()["items"][0]["pid"]
        c.post(f"/api/jobs/{job_id}/proposals/{pid}/approve", json={"confirm": True})
        for _ in range(200):
            v = c.get(f"/api/jobs/{job_id}/proposals/{pid}/verification").json()
            if v["status"] == "unable_to_verify":
                break
            time.sleep(0.05)
    assert v["status"] == "unable_to_verify" and v["reason"] == runner.NO_NODE
