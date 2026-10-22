import asyncio
import copy
import re

import pytest
from helpers import real

from app.ai import context as ctxmod
from app.ai import grounding
from app.ai.template_provider import render
from app.config import RECORDED, ROOT
from app.exploit import RecordedFeeds, classify, cves_of
from app.prioritize import enrich
from app.samples import load_graph, packages
from app.scanner.fixture import RecordedScanner
from app.scanner.normalize import normalize
from tools.record import SAMPLES

QS = "GHSA-hrpp-h998-j3pp"


def findings_for(sample: str) -> list[dict]:
    graph = load_graph(real(ROOT / "samples" / sample))
    scan = asyncio.run(RecordedScanner(RECORDED / "osv").scan(packages(graph)))
    found = normalize(scan, graph)
    feeds = RecordedFeeds(RECORDED / "exploit.json")
    sig = asyncio.run(feeds.lookup(sorted({c for f in found for c in cves_of(f["advisory"])})))
    for f in found:
        f["exploit"] = classify(cves_of(f["advisory"]), sig)
    return enrich(found)


@pytest.fixture(scope="module")
def vuln():
    return findings_for("vuln-demo")


def variant_of(base, **changes):
    f = copy.deepcopy(base)
    for k, v in changes.items():
        f[k] = v
    return enrich([f])[0]


def text_of(out):
    return " ".join([out["summary"], out["why_it_matters"], out["recommended_action"],
                     *out["tradeoffs"], *out["uncertainties"]])


def qs(vuln):
    return next(f for f in vuln if f["advisory"]["id"] == QS and f["package"]["version"] == "6.7.0")


def test_transitive_with_fix(vuln):
    out = render(ctxmod.build(qs(vuln)))
    assert "6.7.3" in out["recommended_action"]
    assert "parent" in out["recommended_action"]
    assert "transitive" in out["why_it_matters"] or "path is" in out["why_it_matters"]
    assert any("override" in t for t in out["tradeoffs"])


def test_direct_with_fix(vuln):
    f = qs(vuln)
    out = render(ctxmod.build(variant_of(f, direct=True, depth=1,
                                         paths=[["root", "qs@6.7.0"]])))
    assert "direct" in out["why_it_matters"]
    assert out["recommended_action"].startswith(("Upgrade qs to 6.7.3", "Raise qs to 6.7.3"))


def test_no_fix_offers_weakness_guidance(vuln):
    f = variant_of(qs(vuln), fixed_versions=[], affected_ranges=[
        {**r, "fixed": None} for r in qs(vuln)["affected_ranges"]])
    out = render(ctxmod.build(f))
    assert "fixed" in out["recommended_action"].lower()
    assert "General guidance for CWE-" in out["recommended_action"]
    assert not out["tradeoffs"] or "upgrade" not in " ".join(out["tradeoffs"]).lower()


def test_dev_scope_and_many_paths(vuln):
    out = render(ctxmod.build(variant_of(qs(vuln), scope="dev", path_count=4)))
    assert any("dev-only" in t for t in out["tradeoffs"])
    assert "4 dependency paths" in out["why_it_matters"]


def test_unknown_severity_and_no_cve(vuln):
    f = copy.deepcopy(qs(vuln))
    f["advisory"]["severity"] = {"label": "unknown", "score": None, "vector": None, "source": None}
    f["advisory"]["aliases"] = []
    f["exploit"] = {**f["exploit"], "status": "unknown", "cves": [], "epss": None}
    out = render(ctxmod.build(enrich([f])[0]))
    u = " ".join(out["uncertainties"])
    assert "no severity score" in u and "no CVE id" in u


def test_kev_and_epss_lines(vuln):
    f = qs(vuln)
    assert "EPSS, a model estimate" in render(ctxmod.build(f))["why_it_matters"]
    listed = copy.deepcopy(f)
    listed["exploit"] = {**f["exploit"], "status": "listed",
                         "kev": {"cve": "CVE-2022-24999", "dateAdded": "2026-01-02"}}
    out = render(ctxmod.build(enrich([listed])[0]))
    assert "CISA Known Exploited Vulnerabilities catalog since 2026-01-02" in out[
        "why_it_matters"]


def test_weakness_sentence_uses_the_kb(vuln):
    out = render(ctxmod.build(qs(vuln)))
    assert "Prototype Pollution" in out["why_it_matters"]
    assert any(u.startswith("This matters most when") for u in out["uncertainties"])


def test_variant_is_stable_per_id_and_varies_across_ids(vuln):
    ctx = ctxmod.build(qs(vuln))
    assert render(ctx) == render(copy.deepcopy(ctx))
    starts = {render(ctxmod.build(f))["summary"].split(" ")[0] for f in vuln}
    assert len(starts) >= 2


def test_citations_exist_and_cover_inline_refs(vuln):
    for f in vuln:
        ctx = ctxmod.build(f)
        out = render(ctx)
        eids = {e["eid"] for e in ctx["evidence"]}
        inline = set(re.findall(r"\[(E\d+)\]", text_of(out)))
        assert inline <= eids and set(out["citations"]) == inline


@pytest.mark.parametrize("sample", SAMPLES)
def test_every_recorded_finding_is_grounded(sample):
    for f in findings_for(sample):
        ctx = ctxmod.build(f)
        out = render(ctx)
        _, level, stripped = grounding.validate(out, ctx, out)
        assert stripped == [] and level == "full", (f["id"], stripped)


def test_context_carries_weakness_and_quote(vuln):
    ctx = ctxmod.build(qs(vuln))
    assert ctx["weakness"]["id"] == "CWE-1321" and ctx["weakness"]["short"] == "Prototype Pollution"
    assert ctx["quote"]["text"].startswith("qs before 6.10.3 allows attackers")
    assert ctx["finding_id"] == qs(vuln)["id"]
