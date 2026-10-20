import json
import shutil

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from helpers import upload, wait_job

from app.config import ROOT
from app.main import create_app


@pytest.fixture
def demo_settings(settings):
    shutil.copytree(ROOT / "samples" / "vuln-demo", settings.samples_dir / "vuln-demo")
    return settings


def test_demo_with_recorded_scanner_produces_findings(demo_settings):
    with TestClient(create_app(demo_settings)) as c:
        job = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"])
        assert job["status"] == "ready"
        assert job["summary"]["findings"] == 22
        assert job["summary"]["by_severity"]["critical"] == 2
        findings = json.loads((c.app.state.store.job_dir(job["id"]) / "findings.json").read_text())
        assert {f["advisory"]["id"] for f in findings} >= {"GHSA-hrpp-h998-j3pp"}
        scan = json.loads((c.app.state.store.job_dir(job["id"]) / "scan.json").read_text())
        assert scan["source"] == "live" and scan["scanner"]["name"] == "fixture"


def test_demo_falls_back_to_recorded_scan_when_osv_down(demo_settings):
    s = demo_settings.model_copy(update={"scanner": "osv-api", "osv_api_url": "https://osv.test"})
    with respx.mock(assert_all_called=False) as m:
        m.post("https://osv.test/v1/querybatch").mock(return_value=httpx.Response(503))
        with TestClient(create_app(s)) as c:
            job = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"], timeout=20)
    assert job["status"] == "ready" and job["summary"]["findings"] == 22
    assert job["summary"]["scan"]["source"] == "cache"
    [w] = [w for w in job["warnings"] if w["code"] == "W_CACHED_SCAN"]
    assert w["message"].startswith("Cached scan from ")
    assert "live scanner unavailable" in w["message"]


def test_upload_fails_honestly_when_osv_down(settings):
    s = settings.model_copy(update={"scanner": "osv-api", "osv_api_url": "https://osv.test"})
    with respx.mock(assert_all_called=False) as m:
        m.post("https://osv.test/v1/querybatch").mock(return_value=httpx.Response(503))
        with TestClient(create_app(s)) as c:
            job = wait_job(c, upload(c, "ok_root.zip").json()["job_id"], timeout=20)
    assert job["status"] == "failed" and job["step"] == "scanning"
    assert job["error"]["code"] == "E_SCAN_UNAVAILABLE"
