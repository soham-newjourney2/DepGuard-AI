import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import wait_job

from app.config import ROOT, Settings
from app.graph import Graph
from app.lockfile import parse
from app.main import create_app
from app.routes import graph as graph_route

LOCKS = Path(__file__).parent / "fixtures" / "locks"


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("graph")
    shutil.copytree(ROOT / "samples" / "vuln-demo", tmp / "samples" / "vuln-demo")
    s = Settings(_env_file=None, data_dir=tmp / "data", frontend_dir=tmp / "none",
                 samples_dir=tmp / "samples", scanner="fixture", verify_mode="mock")
    with TestClient(create_app(s), raise_server_exceptions=False) as c:
        job_id = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"])["id"]
        yield c, job_id


def by_label(data):
    return {n["label"]: n for n in data["nodes"]}


def test_focus_graph_contains_vulnerable_paths(demo):
    c, job_id = demo
    data = c.get(f"/api/jobs/{job_id}/graph").json()
    nodes = by_label(data)
    assert data["mode"] == "focus" and data["total_nodes"] == 96 and not data["truncated"]
    assert nodes["root"]["root"] is True and nodes["root"]["id"] == "#root"
    qs = nodes["qs@6.7.0"]
    assert qs["severity"] == "high" and qs["target"] and len(qs["findings"]) == 4
    assert {"express@4.17.1", "body-parser@1.19.0", "request@2.88.2", "mkdirp@0.5.1"} <= set(nodes)
    ids = {n["id"] for n in data["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in data["edges"])
    assert {"source": "node_modules/express", "target": "node_modules/qs", "kind": "prod"} \
        in data["edges"]
    assert nodes["minimist@0.0.8"]["scope"] == "dev"
    assert len(data["nodes"]) < data["total_nodes"]


def test_focus_on_single_finding(demo):
    c, job_id = demo
    items = c.get(f"/api/jobs/{job_id}/findings", params={"q": "minimist"}).json()["items"]
    data = c.get(f"/api/jobs/{job_id}/graph", params={"focus": items[0]["id"]}).json()
    core = {n["label"] for n in data["nodes"] if not n["target"]}
    assert {n["label"] for n in data["nodes"] if n["target"]} == {"minimist@0.0.8"}
    assert {"root", "mkdirp@0.5.1"} <= core and "qs@6.7.0" not in core


def test_full_graph(demo):
    c, job_id = demo
    data = c.get(f"/api/jobs/{job_id}/graph", params={"mode": "full"}).json()
    assert len(data["nodes"]) == data["total_nodes"] == 96
    clean = [n for n in data["nodes"] if n["severity"] is None and not n["root"]]
    assert clean and all(n["findings"] == [] for n in clean)


def test_bad_params(demo):
    c, job_id = demo
    assert c.get(f"/api/jobs/{job_id}/graph", params={"mode": "x"}).status_code == 422
    assert c.get(f"/api/jobs/{job_id}/graph", params={"focus": "f_nope"}).status_code == 404
    assert c.get("/api/jobs/" + "b" * 32 + "/graph").status_code == 404


def test_caps_truncate_with_warning(monkeypatch):
    g = Graph(parse(json.loads((LOCKS / "ladder.json").read_text(encoding="utf-8"))))
    findings = [{"id": "f_z", "package": {"name": "z", "version": "9.9.9"},
                 "advisory": {"severity": {"label": "low"}}, "priority": {"score": 1}}]
    monkeypatch.setattr(graph_route, "FOCUS_CAP", 5)
    monkeypatch.setattr(graph_route, "FULL_CAP", 4)
    focus = graph_route.build(g.to_json(), findings, "focus", None)
    assert len(focus["nodes"]) == 5 and focus["truncated"]
    labels = [n["label"] for n in focus["nodes"]]
    assert labels[:2] == ["root", "z@9.9.9"], "root and targets survive truncation"
    full = graph_route.build(g.to_json(), findings, "full", None)
    assert len(full["nodes"]) == 4 and "truncated to the 4 shallowest" in full["warnings"][0]
    kept = {n["id"] for n in full["nodes"]}
    assert all(e["source"] in kept and e["target"] in kept for e in full["edges"])
