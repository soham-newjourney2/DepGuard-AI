import shutil

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from helpers import upload, wait_job

from app.config import ROOT
from app.main import create_app
from app.report.answer_key import compare

KEY = {"generated_at": "2026-10-22T00:00:00Z", "tools": [{"name": "npm audit", "version": "11"}]}


def finding(fid, name, version, aliases=(), published="2024-01-01T00:00:00Z"):
    return {"advisory": {"id": fid, "aliases": list(aliases), "published": published,
                         "severity": {"label": "high"}},
            "package": {"name": name, "version": version}}


def entry(eid, name, version, aliases=()):
    return {"id": eid, "aliases": list(aliases), "package": name, "version": version,
            "reported_by": ["npm audit"]}


def test_all_classes_and_totals():
    key = {**KEY, "advisories": [entry("GHSA-a", "qs", "6.7.0"),
                                 entry("CVE-2", "Flask", "2.2.2"),
                                 entry("GHSA-c", "ms", "2.0.0")]}
    findings = [finding("GHSA-a", "qs", "6.7.0"),
                finding("PYSEC-9", "flask", "2.2.2", aliases=["CVE-2"]),
                finding("GHSA-new", "qs", "6.7.0", published="2026-10-23T08:00:00Z"),
                finding("GHSA-old", "qs", "6.7.0")]
    out = compare(key, findings)
    status = {r["advisory"]: (r["status"], r.get("note")) for r in out["rows"]}
    assert status == {"GHSA-a": ("matched", None),
                      "CVE-2": ("matched", "DepGuard lists it as PYSEC-9 (alias)"),
                      "GHSA-c": ("missed", "Reported by npm audit"),
                      "GHSA-new": ("extra", "New since answer key"),
                      "GHSA-old": ("extra", "Not reported by the reference tools")}
    assert out["totals"] == {"key": 3, "scan": 4, "matched": 2, "missed": 1, "extra": 2,
                             "extra_new": 1, "scan_matched": 2, "found_pct": 67}


def test_two_key_aliases_can_match_one_finding():
    key = {**KEY, "advisories": [entry("GHSA-a", "qs", "6.7.0"), entry("GHSA-b", "qs", "6.7.0")]}
    out = compare(key, [finding("GHSA-a", "qs", "6.7.0", aliases=["GHSA-b"])])
    assert [r["status"] for r in out["rows"]] == ["matched", "matched"]
    assert [r["scan_advisory"] for r in out["rows"]] == ["GHSA-a", "GHSA-a"]
    assert out["totals"]["scan_matched"] == 1 and out["totals"]["extra"] == 0


def test_version_mismatch_is_not_a_match():
    key = {**KEY, "advisories": [entry("GHSA-a", "qs", "6.7.0")]}
    out = compare(key, [finding("GHSA-a", "qs", "6.9.0")])
    assert [r["status"] for r in out["rows"]] == ["missed", "extra"]


def test_empty_key_has_no_found_percentage():
    out = compare({**KEY, "advisories": []}, [])
    assert out["rows"] == [] and out["totals"]["found_pct"] is None


@pytest.fixture
def demo_settings(settings):
    shutil.copytree(ROOT / "samples" / "vuln-demo", settings.samples_dir / "vuln-demo")
    shutil.copytree(ROOT / "samples" / "_answers", settings.samples_dir / "_answers")
    return settings


def run_demo(s):
    with TestClient(create_app(s)) as c:
        job = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"], timeout=20)
        return job, c.get(f"/api/jobs/{job['id']}/answer-key")


def test_demo_side_by_side_after_live_scan(demo_settings):
    job, res = run_demo(demo_settings)
    body = res.json()
    assert job["status"] == "ready" and res.status_code == 200 and body["available"] is True
    t = body["totals"]
    assert t["matched"] + t["missed"] == t["key"] and t["scan"] == job["summary"]["findings"]
    assert t["scan_matched"] + t["extra"] == t["scan"]
    assert len(body["rows"]) == t["key"] + t["extra"]
    assert body["key"]["tools"][0]["name"] == "npm audit"


def test_out_of_date_key_is_refused(demo_settings):
    lock = demo_settings.samples_dir / "vuln-demo" / "package-lock.json.sample"
    lock.write_bytes(lock.read_bytes() + b"\n")
    _, res = run_demo(demo_settings)
    assert res.json() == {"available": False, "key": res.json()["key"],
                          "reason": "The answer key is out of date for this lockfile."}


def test_failed_scan_has_no_comparison(demo_settings):
    s = demo_settings.model_copy(update={"scanner": "osv-api", "osv_api_url": "https://osv.test"})
    with respx.mock(assert_all_called=False) as m:
        m.post("https://osv.test/v1/querybatch").mock(return_value=httpx.Response(503))
        job, res = run_demo(s)
    assert job["status"] == "failed" and res.json()["available"] is False
    assert "did not finish" in res.json()["reason"]


def test_missing_key_says_so(settings):
    shutil.copytree(ROOT / "samples" / "vuln-demo", settings.samples_dir / "vuln-demo")
    _, res = run_demo(settings)
    assert res.json() == {"available": False, "reason": "No answer key is bundled for this demo."}


def test_upload_has_no_answer_key(settings):
    with TestClient(create_app(settings)) as c:
        job = wait_job(c, upload(c, "ok_root.zip").json()["job_id"])
        res = c.get(f"/api/jobs/{job['id']}/answer-key")
    assert res.status_code == 404 and res.json()["error"]["code"] == "E_NOT_FOUND"


def test_supplychain_demo_planted_risks_all_found(settings):
    for name in ("supplychain-demo", "_answers"):
        shutil.copytree(ROOT / "samples" / name, settings.samples_dir / name)
    with TestClient(create_app(settings)) as c:
        job = wait_job(c, c.post("/api/jobs/demo/supplychain-demo").json()["job_id"], timeout=30)
        body = c.get(f"/api/jobs/{job['id']}/answer-key").json()
        findings = c.get(f"/api/jobs/{job['id']}/findings").json()["items"]
    assert job["status"] == "ready" and body["available"] is True
    assert body["totals"]["missed"] == 0 and body["totals"]["matched"] == 1
    [extra] = [x for x in body["rows"] if x["status"] == "extra"]
    assert extra["advisory"] == "MAL-2025-25475", "OSV's MAL record is not in npm audit's data"
    r = body["risks"]
    assert r["totals"] == {"planted": 5, "matched": 5, "missed": 0, "extra": 0}, r["rows"]
    assert {f["package"]["name"] for f in findings if f["malicious"]} == {"loadyaml"}
    assert all(f["priority"]["band"] == "P1" for f in findings if f["malicious"])


def test_risk_comparison_classes():
    from app.report.answer_key import compare_risks
    planted = [{"kind": "secret", "file": "a.js", "note": "n"},
               {"kind": "typosquat", "package": "x@1", "note": "n"}]
    risks = [{"kind": "secret", "location": {"file": "a.js", "line": 1}, "package": None,
              "title": "t1", "severity": "high"},
             {"kind": "integrity", "package": "y@1", "location": None, "title": "t2",
              "severity": "medium"},
             {"kind": "integrity", "package": "w@1", "location": None, "title": "ws",
              "severity": "info"}]
    out = compare_risks(planted, risks)
    assert [x["status"] for x in out["rows"]] == ["matched", "missed", "extra"]
    assert out["totals"] == {"planted": 2, "matched": 1, "missed": 1, "extra": 1}
