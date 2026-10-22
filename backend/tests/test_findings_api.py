import shutil

import pytest
from fastapi.testclient import TestClient
from helpers import upload, wait_job

from app.config import ROOT, Settings
from app.main import create_app

QS = "GHSA-hrpp-h998-j3pp"


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("findings")
    shutil.copytree(ROOT / "samples" / "vuln-demo", tmp / "samples" / "vuln-demo")
    s = Settings(_env_file=None, data_dir=tmp / "data", frontend_dir=tmp / "none",
                 samples_dir=tmp / "samples", scanner="fixture", verify_mode="mock")
    with TestClient(create_app(s), raise_server_exceptions=False) as c:
        job = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"])
        assert job["status"] == "ready"
        yield c, job["id"]


def get(c, job_id, **params):
    r = c.get(f"/api/jobs/{job_id}/findings", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def test_list_sorted_by_priority(demo):
    c, job_id = demo
    data = get(c, job_id)
    assert data["total"] == data["count"] == 22
    scores = [i["priority"]["score"] for i in data["items"]]
    assert scores == sorted(scores, reverse=True)
    assert data["summary"]["by_severity"]["critical"] == 2
    assert sum(data["summary"]["by_band"].values()) == 22
    top = data["items"][0]
    assert set(top) >= {"id", "advisory", "package", "scope", "direct", "path", "priority",
                        "fix_available"}


def test_dev_critical_ranks_below_prod_high(demo):
    c, job_id = demo
    items = get(c, job_id)["items"]
    rank = {(i["package"]["name"], i["advisory"]["id"]): n for n, i in enumerate(items)}
    minimist = min(n for (name, _), n in rank.items() if name == "minimist")
    assert rank[("qs", QS)] < minimist


def test_filters_and_search(demo):
    c, job_id = demo
    crit = get(c, job_id, severity="critical")["items"]
    assert {i["advisory"]["severity"]["label"] for i in crit} == {"critical"} and len(crit) == 2
    dev = get(c, job_id, scope="dev")["items"]
    assert dev and {i["scope"] for i in dev} == {"dev"}
    direct = get(c, job_id, direct="direct")["items"]
    assert {i["package"]["name"] for i in direct} == {"express", "request"}
    nofix = get(c, job_id, fix="no")["items"]
    assert [i["package"]["name"] for i in nofix] == ["request"]
    assert {i["package"]["name"] for i in get(c, job_id, q="QS")["items"]} == {"qs"}
    assert get(c, job_id, q=QS.lower())["count"] == 1
    multi = get(c, job_id, severity="critical,high", scope="prod")["items"]
    assert multi and all(i["scope"] == "prod" for i in multi)


def test_sorts(demo):
    c, job_id = demo
    names = [i["package"]["name"] for i in get(c, job_id, sort="name")["items"]]
    assert names == sorted(names)
    sev = [i["advisory"]["severity"]["label"] for i in get(c, job_id, sort="severity")["items"]]
    assert sev[:2] == ["critical", "critical"]


@pytest.mark.parametrize("params", [{"sort": "bogus"}, {"direct": "maybe"}, {"fix": "perhaps"}])
def test_bad_params(demo, params):
    c, job_id = demo
    r = c.get(f"/api/jobs/{job_id}/findings", params=params)
    assert r.status_code == 422 and r.json()["error"]["code"] == "E_INVALID"


def test_detail(demo):
    c, job_id = demo
    item = next(i for i in get(c, job_id)["items"] if i["advisory"]["id"] == QS
                and i["package"]["version"] == "6.7.0")
    f = c.get(f"/api/jobs/{job_id}/findings/{item['id']}").json()
    assert ["root", "express@4.17.1", "qs@6.7.0"] in f["paths"]
    assert [e["eid"] for e in f["evidence"]] == ["E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8"]
    e8 = f["evidence"][7]
    assert f["advisory"]["cwes"] and e8["kind"] == "weakness"
    assert e8["source"].startswith("https://cwe.mitre.org/data/definitions/")
    x = f["exploit"]
    assert x["status"] == "scored" and x["cves"] == ["CVE-2022-24999"] and x["kev"] is None
    assert x["checked"] == {"kev": True, "epss": True} and 0 <= x["epss"]["percentile"] <= 1
    e7 = f["evidence"][6]
    assert (e7["kind"], e7["label"], e7["source"]) == ("exploit", "Possible", "first.org EPSS")
    assert "Not in CISA KEV as of" in e7["text"] and "not an observation" in e7["text"]
    assert item["exploit"]["status"] == "scored"
    assert f["priority"]["signals"][0] == {"key": "severity", "label": "Severity",
                                           "value": "high", "points": 30, "eid": "E1"}
    assert "6.7.3" in f["evidence"][3]["text"]
    r = c.get(f"/api/jobs/{job_id}/findings/f_nope")
    assert r.status_code == 404


def test_not_ready_and_unknown_job(demo, tmp_path):
    c, _ = demo
    assert c.get("/api/jobs/" + "a" * 32 + "/findings").status_code == 404
    job_id = wait_job(c, upload(c, "traversal.zip").json()["job_id"])["id"]
    r = c.get(f"/api/jobs/{job_id}/findings")
    assert r.status_code == 409 and r.json()["error"]["code"] == "E_NOT_READY"
