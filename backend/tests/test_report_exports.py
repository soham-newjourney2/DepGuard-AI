import json
import re
import shutil
import time

import pytest
from fastapi.testclient import TestClient
from helpers import wait_job

from app.config import ROOT, Settings
from app.main import create_app
from app.report import export

HOSTILE = '<script>alert("x")</script><img src=x onerror=alert(1)> | `code` ```'


def finding(summary=HOSTILE):
    return {"advisory": {"id": "GHSA-<b>", "summary": summary,
                         "severity": {"label": "high"}},
            "package": {"name": "evil<pkg>", "version": "1.0.0\"><svg>"}, "scope": "prod",
            "priority": {"band": "P1"},
            "exploit": {"status": "listed", "cves": ["CVE-2024-0001"], "as_of": "2026-10-22",
                        "kev": {"cve": "CVE-2024-0001", "dateAdded": "2026-01-01"}, "epss": None,
                        "checked": {"kev": True, "epss": True}},
            "evidence": [{"eid": "E7", "kind": "exploit", "label": "Confirmed", "source": "kev",
                          "text": 'CVE-2024-0001 is in CISA KEV (known ransomware use: "><script>'
                                  "alert(3)</script>)."}]}


def report():
    job = {"id": "a" * 32, "filename": '<img src=x onerror=alert(2)>.zip',
           "summary": {"packages": 3, "lockfile_version": 3,
                       "scan": {"scanner": "fixture", "ts": "t", "source": "live"}}}
    proposal = {"pid": "p_1", "strategy": "direct-bump", "title": "Upgrade <x>",
                "changes": [], "resolves": [], "warnings": [], "confidence": "high",
                "status": "verified",
                "diff": "--- a/package.json\n+++ b/package.json\n@@ -1 +1 @@\n-<a>\n"
                        "+</pre><script>x</script>\n"}
    verification = {"status": "verified", "mode": "mock", "tests": {"present": True,
                                                                    "exit_code": 0},
                    "comparison": {"target_resolved": True}, "labels": ["<b>label</b>"],
                    "stages": [{"name": "test", "status": "passed", "exit_code": 0,
                                "duration_ms": 5}]}
    risks = [{"id": "r_1", "kind": "secret", "severity": "high", "confidence": "high",
              "title": "AWS key in <script>alert(4)</script>.js", "package": None,
              "location": {"file": "a|b.js", "line": 3}, "evidence": ["AKIA… (20 chars)"],
              "recommendation": "Rotate it."}]
    return export.build(job, [finding()], proposal, verification, [], {"provider": "evidence-based",
                                                                       "model": None},
                        risks=risks)


def test_html_escapes_everything():
    out = export.to_html(report())
    assert "<script>" not in out and "<svg>" not in out and "<img" not in out
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in out
    assert "onerror=alert(1)" in out.replace("&gt;", ">")
    assert len(re.findall(r"<script", out, re.I)) == 0
    assert "</pre><script>" not in out
    assert 'class="seal verified">VERIFIED<' in out
    assert "<th>Exploitation</th>" in out and ">CISA KEV listed</td>" in out
    assert "&quot;&gt;&lt;script&gt;alert(3)" in out
    assert "<h2>Supply-chain &amp; hygiene (1)</h2>" in out
    assert "&lt;script&gt;alert(4)" in out and "<code>a|b.js:3</code>" in out


def test_markdown_escapes_tables_and_html():
    out = export.to_markdown(report())
    row = next(line for line in out.splitlines() if line.startswith("| GHSA-"))
    assert row.count("|") - row.count("\\|") == 7, "pipes inside cells are escaped"
    assert "| CISA KEV listed |" in row
    assert "## Supply-chain & hygiene (1)" in out
    risk_row = next(line for line in out.splitlines() if line.startswith("| secret |"))
    assert r"a\|b.js:3" in risk_row and "&lt;script&gt;" in risk_row
    prose = re.sub(r"```diff\n.*?\n```", "", out, flags=re.S)
    assert "<script>" not in prose and "&lt;script&gt;" in prose
    assert out.count("```") == 2, "fence break-outs neutralised"
    assert "## Tests (reported separately from the scan)" in out


def test_json_roundtrip():
    r = report()
    assert json.loads(export.to_json(r)) == r
    assert r["counts"] == {"before": 1, "after": 0, "resolved": 1, "still_present": 0,
                           "newly_detected": 0, "unable_to_verify": 0}
    assert "Reachability not determined" in r["audit"]["limitations"][0]
    assert any("No language model is used" in x for x in r["audit"]["limitations"])
    assert any("Absence from KEV is not proof" in x for x in r["audit"]["limitations"])
    x = r["classes"]["resolved"][0]["exploit"]
    assert x["status"] == "listed" and x["label"] == "CISA KEV listed"
    assert "alert(3)" in x["evidence"]
    assert r["risks"]["counts"]["by_kind"]["secret"] == 1


@pytest.fixture(scope="module")
def verified_job(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("report")
    shutil.copytree(ROOT / "samples" / "vuln-demo", tmp / "samples" / "vuln-demo")
    s = Settings(_env_file=None, data_dir=tmp / "data", frontend_dir=tmp / "none",
                 samples_dir=tmp / "samples", scanner="fixture", verify_mode="mock",
                 rate_limit="1000/min")
    with TestClient(create_app(s), raise_server_exceptions=False) as c:
        job_id = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"])["id"]
        before = c.get(f"/api/jobs/{job_id}/report").json()
        fid = c.get(f"/api/jobs/{job_id}/findings",
                    params={"q": "GHSA-hrpp-h998-j3pp"}).json()["items"][0]["id"]
        pid = c.post(f"/api/jobs/{job_id}/findings/{fid}/proposal").json()["items"][0]["pid"]
        c.post(f"/api/jobs/{job_id}/proposals/{pid}/approve", json={"confirm": True})
        for _ in range(300):
            if c.get(f"/api/jobs/{job_id}/proposals/{pid}").json()["status"] == "verified":
                break
            time.sleep(0.05)
        yield c, job_id, pid, before


def test_report_api_before_and_after(verified_job):
    c, job_id, pid, before = verified_job
    assert before["seal"]["label"] == "Scan only" and before["fix"] is None
    assert before["counts"]["still_present"] == 22
    r = c.get(f"/api/jobs/{job_id}/report").json()
    assert r["fix"]["pid"] == pid and r["seal"]["label"] == "VERIFIED"
    assert r["counts"]["resolved"] >= 1 and r["counts"]["still_present"] >= 1
    assert "GHSA-hrpp-h998-j3pp" in {i["advisory"] for i in r["classes"]["resolved"]}
    assert r["tests"] == {"present": True, "exit_code": 0, "status": "passed"}
    assert [s["name"] for s in r["audit"]["stages"]] == ["resolve", "test"]
    assert r["audit"]["commands"][-1] == "npm test --if-present"


def test_report_downloads(verified_job):
    c, job_id, _, _ = verified_job
    md = c.get(f"/api/jobs/{job_id}/report", params={"format": "md"})
    assert md.headers["content-type"].startswith("text/markdown")
    assert "attachment" in md.headers["content-disposition"]
    html = c.get(f"/api/jobs/{job_id}/report", params={"format": "html"})
    assert html.headers["content-type"].startswith("text/html")
    assert "script-src" not in html.headers["content-security-policy"]
    assert html.headers["content-security-policy"].startswith("default-src 'none'")
    assert "VERIFIED" in html.text
    js = c.get(f"/api/jobs/{job_id}/report", params={"format": "json", "download": True})
    assert "attachment" in js.headers["content-disposition"]
    assert c.get(f"/api/jobs/{job_id}/report", params={"format": "pdf"}).status_code == 422
