import shutil
import time

import respx
from fastapi.testclient import TestClient
from helpers import wait_job

from app.config import ROOT, Settings
from app.main import create_app
from app.remediation import make_registry


def settings(tmp_path, **kw):
    shutil.copytree(ROOT / "samples" / "vuln-demo", tmp_path / "samples" / "vuln-demo",
                    dirs_exist_ok=True)
    return Settings(_env_file=None, data_dir=tmp_path / "data", frontend_dir=tmp_path,
                    samples_dir=tmp_path / "samples", local_only=True, rate_limit="1000/min",
                    **kw)


def test_registry_stays_local(tmp_path):
    s = settings(tmp_path)
    assert make_registry(s).offline is True


def test_only_scanner_calls_leave_and_verification_is_refused(tmp_path):
    s = settings(tmp_path, scanner="fixture", verify_mode="auto")
    with respx.mock(assert_all_mocked=True) as m:
        with TestClient(create_app(s)) as c:
            health = c.get("/api/health").json()
            assert health["local_only"] is True and health["ai"] == "evidence-based"
            job_id = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"],
                              timeout=30)["id"]
            fid = c.get(f"/api/jobs/{job_id}/findings",
                        params={"q": "GHSA-hrpp-h998-j3pp"}).json()["items"][0]["id"]
            x = c.post(f"/api/jobs/{job_id}/findings/{fid}/explain").json()
            assert x["provider"] == "evidence-based"
            pid = c.post(f"/api/jobs/{job_id}/findings/{fid}/proposal").json()["items"][0]["pid"]
            c.post(f"/api/jobs/{job_id}/proposals/{pid}/approve", json={"confirm": True})
            for _ in range(200):
                v = c.get(f"/api/jobs/{job_id}/proposals/{pid}/verification").json()
                if v["status"] == "unable_to_verify":
                    break
                time.sleep(0.05)
            assert v["status"] == "unable_to_verify" and "Local-only" in v["reason"]
        hosts = {call.request.url.host for call in m.calls}
    assert hosts == set(), f"unexpected outbound hosts: {hosts}"
