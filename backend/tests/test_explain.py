import asyncio
import json
import shutil
from types import SimpleNamespace

import anthropic
import httpx
import pytest
from fastapi.testclient import TestClient
from helpers import wait_job

from app import ai
from app.ai import context as ctxmod
from app.ai.anthropic_provider import AnthropicProvider
from app.ai.template_provider import TemplateProvider
from app.config import ROOT, Settings
from app.main import create_app
from app.prioritize import enrich
from app.scanner.fixture import RecordedScanner
from app.scanner.normalize import normalize
from app.scanner.record import load_graph, packages

QS = "GHSA-hrpp-h998-j3pp"


@pytest.fixture(scope="module")
def qs_finding():
    graph = load_graph(ROOT / "samples" / "vuln-demo")
    scanner = RecordedScanner(ROOT / "samples" / "_recorded" / "osv")
    scan = asyncio.run(scanner.scan(packages(graph)))
    findings = enrich(normalize(scan, graph))
    return next(f for f in findings if f["advisory"]["id"] == QS
                and f["package"]["version"] == "6.7.0")


def reply(payload, stop="end_turn"):
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return SimpleNamespace(stop_reason=stop, content=[SimpleNamespace(type="text", text=text)])


class FakeMessages:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    async def create(self, **params):
        self.calls.append(params)
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def provider(*replies, model="claude-haiku-5-5"):
    fake = FakeMessages(replies)
    return AnthropicProvider("k", model, client=SimpleNamespace(messages=fake)), fake


GOOD = {
    "summary": "qs@6.7.0 matches GHSA-hrpp-h998-j3pp [E1].",
    "why_it_matters": "It ships through express@4.17.1 in production [E2] [E3].",
    "recommended_action": "Move qs to 6.7.3 or later, then run the tests [E4].",
    "tradeoffs": ["An override is a smaller change than upgrading express."],
    "uncertainties": ["Whether the app parses attacker-controlled query strings is unknown [E5]."],
    "citations": ["E1", "E2", "E3", "E4", "E5"],
}


async def test_mocked_provider_grounded(qs_finding, tmp_path):
    p, fake = provider(reply(GOOD))
    out = await ai.explain(qs_finding, p, tmp_path)
    assert out["grounding"] == "full" and out["provider"] == "anthropic"
    assert out["model"] == "claude-haiku-5-5" and out["cached"] is False
    params = fake.calls[0]
    assert params["max_tokens"] == 700 and "temperature" not in params
    assert params["thinking"] == {"type": "disabled"}
    assert params["output_config"]["format"]["type"] == "json_schema"
    assert params["system"] == ctxmod.SYSTEM
    assert params["messages"][0]["content"].startswith("<evidence>")
    again = await ai.explain(qs_finding, p, tmp_path)
    assert again["cached"] is True and len(fake.calls) == 1


async def test_non_haiku_models_keep_default_thinking(qs_finding, tmp_path):
    p, fake = provider(reply(GOOD), model="claude-opus-5-5")
    await ai.explain(qs_finding, p, tmp_path)
    assert "thinking" not in fake.calls[0]


async def test_fabricated_version_from_model_is_partial(qs_finding, tmp_path):
    p, _ = provider(reply({**GOOD, "recommended_action": "Upgrade to qs 6.99.0 today."}))
    out = await ai.explain(qs_finding, p, tmp_path)
    assert out["grounding"] == "partial" and "6.99.0" in out["stripped"]
    shown = {k: out[k] for k in ("summary", "why_it_matters", "recommended_action",
                                  "tradeoffs", "uncertainties")}
    assert "6.99.0" not in json.dumps(shown)


async def test_invalid_json_retries_once_then_succeeds(qs_finding, tmp_path):
    p, fake = provider(reply("not json"), reply(GOOD))
    out = await ai.explain(qs_finding, p, tmp_path)
    assert out["grounding"] == "full" and len(fake.calls) == 2


async def test_invalid_twice_falls_back_to_template(qs_finding, tmp_path):
    p, fake = provider(reply("nope"), reply({"summary": "missing fields"}))
    out = await ai.explain(qs_finding, p, tmp_path)
    assert out["grounding"] == "template" and out["provider"] == "template"
    assert "AI unavailable" in out["note"] and len(fake.calls) == 2
    assert not list(tmp_path.glob("*.json")), "fallbacks are not cached"


@pytest.mark.parametrize("failure", [
    reply("", stop="refusal"),
    reply('{"summary": "trunc', stop="max_tokens"),
    anthropic.APIConnectionError(request=httpx.Request("POST", "https://api.anthropic.com")),
    anthropic.RateLimitError("slow down", response=httpx.Response(
        429, request=httpx.Request("POST", "https://api.anthropic.com")), body=None),
])
async def test_api_failures_fall_back_without_retry(qs_finding, tmp_path, failure):
    p, fake = provider(failure, reply(GOOD))
    out = await ai.explain(qs_finding, p, tmp_path)
    assert out["grounding"] == "template" and len(fake.calls) == 1


async def test_template_provider_deterministic(qs_finding, tmp_path):
    a = await ai.explain(qs_finding, TemplateProvider(), tmp_path / "a")
    b = await ai.explain(qs_finding, TemplateProvider(), tmp_path / "b")
    assert {k: v for k, v in a.items() if k != "cached"} == {k: v for k, v in b.items()
                                                            if k != "cached"}
    assert a["grounding"] == "template" and "6.7.3" in a["recommended_action"]
    assert a["citations"] and all(c.startswith("E") for c in a["citations"])


def test_make_provider_selection():
    base = Settings(_env_file=None)
    assert isinstance(ai.make_provider(base.model_copy(update={"anthropic_api_key": ""})),
                      TemplateProvider)
    off = base.model_copy(update={"ai_provider": "off", "anthropic_api_key": "sk"})
    assert isinstance(ai.make_provider(off), TemplateProvider)
    keyed = base.model_copy(update={"ai_provider": "auto", "anthropic_api_key": "sk-test"})
    assert isinstance(ai.make_provider(keyed), AnthropicProvider)
    forced = base.model_copy(update={"ai_provider": "anthropic", "anthropic_api_key": ""})
    assert isinstance(ai.make_provider(forced), TemplateProvider)


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("explain")
    shutil.copytree(ROOT / "samples" / "vuln-demo", tmp / "samples" / "vuln-demo")
    s = Settings(_env_file=None, data_dir=tmp / "data", frontend_dir=tmp / "none",
                 samples_dir=tmp / "samples", scanner="fixture", verify_mode="mock",
                 ai_provider="auto", anthropic_api_key="")
    with TestClient(create_app(s), raise_server_exceptions=False) as c:
        job_id = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"])["id"]
        yield c, job_id


def test_explain_endpoint_falls_back_without_key(demo):
    c, job_id = demo
    item = c.get(f"/api/jobs/{job_id}/findings", params={"q": QS}).json()["items"][0]
    r = c.post(f"/api/jobs/{job_id}/findings/{item['id']}/explain")
    assert r.status_code == 200
    body = r.json()
    assert body["grounding"] == "template" and body["provider"] == "template"
    assert set(body) >= {"summary", "why_it_matters", "recommended_action", "tradeoffs",
                         "uncertainties", "citations", "grounding", "provider", "model"}
    assert c.post(f"/api/jobs/{job_id}/findings/{item['id']}/explain").json()["cached"] is True
    assert c.post(f"/api/jobs/{job_id}/findings/f_nope/explain").status_code == 404
