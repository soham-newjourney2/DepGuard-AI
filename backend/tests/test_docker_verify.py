import asyncio
import shutil
import time

import pytest
from fastapi.testclient import TestClient
from helpers import wait_job

from app.config import ROOT, Settings
from app.main import create_app
from app.verify.modes import DockerExecutor

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not asyncio.run(DockerExecutor.available()),
                       reason="docker and the depguard-worker image are required"),
]


def test_docker_verifies_vuln_demo(tmp_path):
    shutil.copytree(ROOT / "samples" / "vuln-demo", tmp_path / "samples" / "vuln-demo")
    s = Settings(_env_file=None, data_dir=tmp_path / "data", frontend_dir=tmp_path,
                 samples_dir=tmp_path / "samples", scanner="osv-api", verify_mode="docker",
                 rate_limit="1000/min")
    with TestClient(create_app(s)) as c:
        job_id = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"], timeout=120)["id"]
        fid = c.get(f"/api/jobs/{job_id}/findings",
                    params={"q": "GHSA-hrpp-h998-j3pp"}).json()["items"][0]["id"]
        p = c.post(f"/api/jobs/{job_id}/findings/{fid}/proposal").json()["items"][0]
        c.post(f"/api/jobs/{job_id}/proposals/{p['pid']}/approve", json={"confirm": True})
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            r = c.get(f"/api/jobs/{job_id}/proposals/{p['pid']}/verification").json()
            if r["status"] in ("verified", "verify_failed", "unable_to_verify"):
                break
            time.sleep(2)
        assert r["mode"] == "docker" and r["status"] == "verified", r.get("reason")
        assert r["comparison"]["target_resolved"] is True
