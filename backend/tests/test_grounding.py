import pytest

from app.ai import grounding
from app.ai.template_provider import render

CTX = {
    "package": {"name": "qs", "version": "6.7.0", "ecosystem": "npm"},
    "advisory": {"id": "GHSA-hrpp-h998-j3pp", "aliases": ["CVE-2022-24999"], "summary": "s",
                 "severity": {"label": "high", "score": 7.5, "source": "CVSS_V3"},
                 "published": None, "details": ""},
    "affected_ranges": [">=6.7.0 <6.7.3"], "installed_in_range": [">=6.7.0 <6.7.3"],
    "fix_versions": ["6.7.3"], "scope": "prod", "direct": False, "depth": 2,
    "paths": ["root > express@4.17.1 > qs@6.7.0"], "path_count": 2, "reachability": "Unknown",
    "priority": {"score": 65, "band": "P2", "band_label": "Fix soon", "flags": []},
    "evidence": [{"eid": f"E{i}", "kind": k, "label": "Confirmed", "text": "t"}
                 for i, k in enumerate(["advisory", "path", "scope", "fix", "reachability",
                                        "scan"], 1)],
    "candidates": [],
}
FALLBACK = render(CTX)


def good(**over):
    base = {
        "summary": "qs@6.7.0 matches GHSA-hrpp-h998-j3pp (CVE-2022-24999) [E1].",
        "why_it_matters": "It ships to production via express@4.17.1 [E2] [E3].",
        "recommended_action": "Move qs to 6.7.3 or later and re-run tests [E4].",
        "tradeoffs": ["An override is smaller than upgrading express."],
        "uncertainties": ["Reachability is unknown [E5]."],
        "citations": ["E1", "E2", "E3", "E4", "E5"],
    }
    return {**base, **over}


def test_fully_grounded_passes_unchanged():
    out, level, stripped = grounding.validate(good(), CTX, FALLBACK)
    assert level == "full" and stripped == []
    assert out == good()


def test_fabricated_version_stripped_to_partial():
    exp = good(recommended_action="Upgrade qs to 6.11.9 immediately. Re-run your tests [E4].")
    out, level, stripped = grounding.validate(exp, CTX, FALLBACK)
    assert level == "partial" and stripped == ["6.11.9"]
    assert out["recommended_action"] == "Re-run your tests [E4]."
    assert "6.11.9" not in str(out)


def test_fabricated_cve_and_ghsa_stripped():
    exp = good(summary="This is CVE-2023-99999. It is also GHSA-mmmm-qqqq-wwww. "
                       "It affects qs [E1].")
    out, level, stripped = grounding.validate(exp, CTX, FALLBACK)
    assert level == "partial"
    assert stripped == ["CVE-2023-99999", "GHSA-mmmm-qqqq-wwww"]
    assert out["summary"] == "It affects qs [E1]."


def test_known_ids_case_insensitive_and_v_prefix():
    exp = good(summary="cve-2022-24999 is fixed in v6.7.3 [E4].")
    _, level, _ = grounding.validate(exp, CTX, FALLBACK)
    assert level == "full"


def test_invalid_citations_dropped_and_inline_added():
    exp = good(citations=["E1", "E9"], uncertainties=["Unknown reach [E5]. Also see [E12]."])
    out, level, stripped = grounding.validate(exp, CTX, FALLBACK)
    assert level == "partial" and set(stripped) == {"E9", "E12"}
    assert out["uncertainties"] == ["Unknown reach [E5]."]
    assert out["citations"] == ["E1", "E2", "E3", "E4", "E5"]


def test_emptied_field_falls_back_to_template():
    exp = good(recommended_action="Pin qs@9.9.9.")
    out, level, _ = grounding.validate(exp, CTX, FALLBACK)
    assert level == "partial" and out["recommended_action"] == FALLBACK["recommended_action"]
    assert "6.7.3" in out["recommended_action"]


def test_list_items_fully_unverified_are_removed():
    exp = good(tradeoffs=["Version 7.0.0 breaks things.", "Overrides are smaller."])
    out, level, _ = grounding.validate(exp, CTX, FALLBACK)
    assert out["tradeoffs"] == ["Overrides are smaller."] and level == "partial"


@pytest.mark.parametrize("text", ["Use Node 18 LTS.", "Takes about 2.5 hours.", "See RFC 7231."])
def test_non_semver_numbers_not_flagged(text):
    _, level, _ = grounding.validate(good(summary=text + " [E1]"), CTX, FALLBACK)
    assert level == "full"


def test_template_is_self_grounded():
    _, level, stripped = grounding.validate(FALLBACK, CTX, FALLBACK)
    assert level == "full" and stripped == []
    assert "6.7.3" in FALLBACK["recommended_action"]
    assert FALLBACK["uncertainties"][0].startswith("Reachability not determined")
