import json
import shutil

import pytest
from fastapi.testclient import TestClient
from helpers import upload, wait_job

from app import risks
from app.config import ROOT
from app.main import create_app


def planted(inputs):
    return [risks.risk("integrity", "high", "lodash resolved from a git URL", "Pin a registry "
                       "release.", confidence="high", evidence=["resolved: git+https://x"],
                       package="lodash@4.17.21", location={"file": "package-lock.json",
                                                           "line": 12}),
            risks.risk("secret", "medium", "AWS access key id", "Rotate it.", confidence="low",
                       evidence=["AKIA…MPLE"], location={"file": "test/a.js", "line": 3}),
            risks.risk("typosquat", "low", "lodahs looks like lodash", "Check the name.",
                       confidence="medium", evidence=["edit distance 1"], package="lodahs@1.0.0")]


def broken(inputs):
    raise RuntimeError("boom")


@pytest.fixture
def demo(settings, monkeypatch):
    shutil.copytree(ROOT / "samples" / "vuln-demo", settings.samples_dir / "vuln-demo")
    monkeypatch.setattr(risks, "CHECKS", [planted, broken])
    with TestClient(create_app(settings)) as c:
        job = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"])
        yield c, job


def test_risks_are_stored_counted_and_sorted(demo):
    c, job = demo
    assert job["status"] == "ready"
    body = c.get(f"/api/jobs/{job['id']}/risks").json()
    assert body["total"] == body["count"] == 3
    assert [r["kind"] for r in body["items"]] == ["integrity", "secret", "typosquat"]
    assert job["summary"]["risk_counts"] == body["counts"]
    assert body["counts"]["by_kind"] == {"malware": 0, "integrity": 1, "typosquat": 1,
                                         "secret": 1}
    r = body["items"][0]
    assert set(r) == {"id", "kind", "severity", "title", "package", "location", "evidence",
                      "recommendation", "confidence"}
    assert r["id"].startswith("r_") and r["location"] == {"file": "package-lock.json", "line": 12}
    stored = json.loads((c.app.state.store.job_dir(job["id"]) / "risks.json").read_text())
    assert stored == body["items"]


def test_filters_and_validation(demo):
    c, job = demo
    url = f"/api/jobs/{job['id']}/risks"
    assert c.get(url, params={"kind": "secret,typosquat"}).json()["count"] == 2
    assert c.get(url, params={"severity": "high"}).json()["items"][0]["kind"] == "integrity"
    bad = c.get(url, params={"kind": "virus"})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "E_INVALID"


def test_crashing_check_is_reported_not_fatal(demo):
    _, job = demo
    [w] = [w for w in job["warnings"] if w["code"] == "W_RISK_CHECK_FAILED"]
    assert "broken" in w["message"]


def test_ids_are_stable():
    a, b = planted(None)[0], planted(None)[0]
    assert a["id"] == b["id"]


def test_upload_with_no_checks_has_empty_risks(settings, monkeypatch):
    monkeypatch.setattr(risks, "CHECKS", [])
    with TestClient(create_app(settings)) as c:
        job = wait_job(c, upload(c, "ok_root.zip").json()["job_id"])
        body = c.get(f"/api/jobs/{job['id']}/risks").json()
    assert body["total"] == 0 and job["summary"]["risk_counts"]["total"] == 0


def test_not_ready_job_has_no_risks(client):
    job = client.app.state.store.create("upload", "x.zip")
    r = client.get(f"/api/jobs/{job['id']}/risks")
    assert r.status_code == 409
