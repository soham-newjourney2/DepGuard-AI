import json
import shutil

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from helpers import upload, wait_job

from app import pipeline
from app.config import ROOT
from app.exploit import ExploitFeeds
from app.main import create_app
from app.scanner.base import build_result


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
        assert all(f["exploit"]["status"] in ("scored", "none", "unknown") for f in findings)
        assert not any(w["code"] == "W_EXPLOIT_UNAVAILABLE" for w in job["warnings"])


def test_exploit_feeds_down_never_fail_the_scan(demo_settings, monkeypatch, tmp_path):
    dead = ExploitFeeds("https://kev.test/x.json", "https://epss.test/x", tmp_path, 3600,
                        backoff_s=0)
    monkeypatch.setattr(pipeline, "make_feeds", lambda s: dead)
    with respx.mock(assert_all_called=False) as m:
        m.route(host__in=["kev.test", "epss.test"]).mock(side_effect=httpx.ConnectError("down"))
        with TestClient(create_app(demo_settings)) as c:
            job = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"], timeout=30)
            findings = json.loads((c.app.state.store.job_dir(job["id"]) / "findings.json")
                                  .read_text())
    assert job["status"] == "ready"
    assert {f["exploit"]["status"] for f in findings} <= {"unavailable", "unknown"}
    assert any(w["code"] == "W_EXPLOIT_UNAVAILABLE" for w in job["warnings"])
    e7 = next(e for e in findings[0]["evidence"] if e["kind"] == "exploit")
    assert e7["label"] == "Unknown"


def test_demo_fails_clearly_when_osv_down(demo_settings):
    s = demo_settings.model_copy(update={"scanner": "osv-api", "osv_api_url": "https://osv.test"})
    with respx.mock(assert_all_called=False) as m:
        m.post("https://osv.test/v1/querybatch").mock(return_value=httpx.Response(503))
        with TestClient(create_app(s)) as c:
            job = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"], timeout=20)
    assert job["status"] == "failed" and job["step"] == "scanning"
    assert job["error"]["code"] == "E_SCAN_UNAVAILABLE"
    assert job["error"]["message"].startswith("Could not connect to OSV (")
    assert job["error"]["message"].startswith("Could not connect to OSV (")
    assert job["error"]["hint"] == "Check your internet connection and retry."
    assert not any(w["code"] == "W_CACHED_SCAN" for w in job["warnings"])


def test_demo_refuses_stale_cache_when_osv_down(demo_settings, monkeypatch):
    class StaleScanner:
        name = "osv-api"

        async def scan(self, packages, lockfile=None):
            result = build_result({}, {"name": "osv-api"}, "2026-10-01T00:00:00Z", source="cache")
            result.notes.append("Live scan failed: OSV unavailable (ConnectError)")
            return result
    monkeypatch.setattr(pipeline, "make_scanner", lambda s: StaleScanner())
    with TestClient(create_app(demo_settings)) as c:
        job = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"])
    assert job["status"] == "failed" and job["error"]["code"] == "E_SCAN_UNAVAILABLE"
    assert job["error"]["message"] == "Could not connect to OSV (ConnectError)."
    assert not any(w["code"] == "W_CACHED_SCAN" for w in job["warnings"])


def test_upload_fails_honestly_when_osv_down(settings):
    s = settings.model_copy(update={"scanner": "osv-api", "osv_api_url": "https://osv.test"})
    with respx.mock(assert_all_called=False) as m:
        m.post("https://osv.test/v1/querybatch").mock(return_value=httpx.Response(503))
        with TestClient(create_app(s)) as c:
            job = wait_job(c, upload(c, "ok_root.zip").json()["job_id"], timeout=20)
    assert job["status"] == "failed" and job["step"] == "scanning"
    assert job["error"]["code"] == "E_SCAN_UNAVAILABLE"
    assert job["error"]["message"].startswith("Could not connect to OSV (")
