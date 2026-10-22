import asyncio
import copy
import re
import shutil

import pytest
from fastapi.testclient import TestClient
from helpers import real, wait_job

from app import ai
from app.ai import context as ctxmod
from app.ai import grounding
from app.ai.template_provider import render
from app.config import RECORDED, ROOT, Settings
from app.exploit import RecordedFeeds, Signals, classify
from app.main import create_app
from app.prioritize import enrich
from app.samples import load_graph, packages
from app.scanner.fixture import RecordedScanner
from app.scanner.normalize import normalize

QS = "GHSA-hrpp-h998-j3pp"
APP = ROOT / "backend" / "app"


@pytest.fixture(scope="module")
def qs_finding():
    graph = load_graph(real(ROOT / "samples" / "vuln-demo"))
    scanner = RecordedScanner(RECORDED / "osv")
    scan = asyncio.run(scanner.scan(packages(graph)))
    findings = enrich(normalize(scan, graph))
    return next(f for f in findings if f["advisory"]["id"] == QS
                and f["package"]["version"] == "6.7.0")


async def test_explanations_are_deterministic_and_cached(qs_finding, tmp_path):
    a = await ai.explain(qs_finding, tmp_path / "a")
    b = await ai.explain(qs_finding, tmp_path / "b")
    assert {k: v for k, v in a.items() if k != "cached"} == {k: v for k, v in b.items()
                                                            if k != "cached"}
    assert a["grounding"] == "evidence" and a["provider"] == "evidence-based"
    assert a["model"] is None and a["stripped"] == [] and a["note"] is None
    assert "6.7.3" in a["recommended_action"]
    assert a["citations"] and all(c.startswith("E") for c in a["citations"])
    assert a["weakness"]["id"] == "CWE-1321" and a["quote"]["text"]
    again = await ai.explain(qs_finding, tmp_path / "a")
    assert again["cached"] is True and again["summary"] == a["summary"]


def test_no_language_model_client_anywhere():
    pattern = re.compile(r"\b(anthropic|openai|ollama|transformers|llama_cpp)\b", re.I)
    offenders = []
    for path in APP.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.lstrip().startswith(("import ", "from ")) and pattern.search(line):
                offenders.append(f"{path.relative_to(APP)}: {line.strip()}")
    assert offenders == []
    reqs = (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
    assert not pattern.search(reqs)


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("explain")
    shutil.copytree(ROOT / "samples" / "vuln-demo", tmp / "samples" / "vuln-demo")
    s = Settings(_env_file=None, data_dir=tmp / "data", frontend_dir=tmp / "none",
                 samples_dir=tmp / "samples", scanner="fixture", verify_mode="mock")
    with TestClient(create_app(s), raise_server_exceptions=False) as c:
        job_id = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"])["id"]
        yield c, job_id


def test_explain_endpoint(demo):
    c, job_id = demo
    item = c.get(f"/api/jobs/{job_id}/findings", params={"q": QS}).json()["items"][0]
    r = c.post(f"/api/jobs/{job_id}/findings/{item['id']}/explain")
    assert r.status_code == 200
    body = r.json()
    assert body["grounding"] == "evidence" and body["provider"] == "evidence-based"
    assert set(body) >= {"summary", "why_it_matters", "recommended_action", "tradeoffs",
                         "uncertainties", "citations", "grounding", "provider", "model",
                         "weakness", "quote"}
    assert c.post(f"/api/jobs/{job_id}/findings/{item['id']}/explain").json()["cached"] is True
    assert c.post(f"/api/jobs/{job_id}/findings/f_nope/explain").status_code == 404
    assert c.get("/api/health").json()["ai"] == "evidence-based"


def test_template_cites_exploit_evidence_and_stays_grounded(qs_finding):
    f = copy.deepcopy(qs_finding)
    sig = asyncio.run(RecordedFeeds(RECORDED / "exploit.json").lookup(["CVE-2022-24999"]))
    f["exploit"] = classify(["CVE-2022-24999"], sig)
    f = enrich([f])[0]
    ctx = ctxmod.build(f)
    out = render(ctx)
    assert "EPSS, a model estimate, puts it at the 96th percentile" in out["why_it_matters"]
    assert "[E7]" in out["why_it_matters"] and "E7" in out["citations"]
    _, status, stripped = grounding.validate(out, ctx, out)
    assert stripped == [] and status == "full"


def test_unknown_exploit_is_an_uncertainty(qs_finding):
    f = copy.deepcopy(qs_finding)
    f["exploit"] = classify([], Signals({}, {}, {"kev": "live", "epss": "live"}))
    out = render(ctxmod.build(enrich([f])[0]))
    assert any(u.startswith("The advisory has no CVE id") for u in out["uncertainties"])
