import pytest

from app import evidence
from app.prioritize import enrich, prioritize


def mk(sev="high", scope="prod", fix=True, direct=False, depth=2, path_count=1,
       reach="Unknown", name="pkg", score=None, version="1.0.0"):
    rng = {"introduced": "0", "text": ">=0 <2.0.0", "contains": True}
    if fix:
        rng["fixed"] = "2.0.0"
    f = {
        "id": f"f_{name}", "package": {"name": name, "version": version, "ecosystem": "npm"},
        "advisory": {"id": f"GHSA-{name}", "aliases": [], "summary": "s",
                     "severity": {"label": sev, "score": score, "vector": None, "source": None},
                     "modified": None},
        "affected_ranges": [rng], "fixed_versions": ["2.0.0"] if fix else [],
        "scope": scope, "direct": direct, "depth": 1 if direct else depth,
        "paths": [["root", f"{name}@{version}"]], "path_count": path_count,
        "reachability": {"label": reach, "evidence": []},
        "scan": {"scanner": "fixture", "version": "t", "ts": "2099-01-01T00:00:00Z",
                 "source": "live"},
    }
    f["evidence"] = evidence.build(f)
    return f


CASES = [
    # severity, scope, fix, direct, depth, paths, reach -> score, band
    (dict(sev="critical", scope="prod", fix=True, direct=True), 78, "P1"),
    (dict(sev="high", scope="prod", fix=True, depth=2), 65, "P2"),
    (dict(sev="critical", scope="dev", fix=True, depth=2), 55, "P2"),
    (dict(sev="medium", scope="prod", fix=False, depth=4), 40, "P3"),
    (dict(sev="low", scope="dev", fix=False, depth=3), 10, "P4"),
    (dict(sev="unknown", scope="prod", fix=True, depth=2), 50, "P2"),
    (dict(sev="high", scope="optional", fix=True, depth=2, path_count=3), 56, "P2"),
    (dict(sev="critical", scope="prod", fix=True, direct=True, path_count=5,
          reach="Strong evidence"), 93, "P1"),
    (dict(sev="medium", scope="peer", fix=True, depth=2, reach="Possible"), 47, "P3"),
    (dict(sev="high", scope="prod", fix=False, direct=True), 58, "P2"),
    (dict(sev="low", scope="prod", fix=True, depth=1, direct=True), 46, "P3"),
]


@pytest.mark.parametrize("kwargs,score,band", CASES)
def test_priority_table(kwargs, score, band):
    p = prioritize(mk(**kwargs))
    assert (p["score"], p["band"]) == (score, band)
    assert p["score"] == sum(s["points"] for s in p["signals"])


def test_high_prod_fix_outranks_critical_dev():
    a = mk(sev="high", scope="prod", fix=True, name="a")
    b = mk(sev="critical", scope="dev", fix=True, name="b")
    assert [f["package"]["name"] for f in enrich([b, a])] == ["a", "b"]


def test_signals_cite_evidence_and_flags():
    p = prioritize(mk(sev="unknown", fix=False))
    eids = {s["key"]: s["eid"] for s in p["signals"]}
    assert eids == {"severity": "E1", "scope": "E3", "fix": "E4", "depth": "E2",
                    "reachability": "E5", "exposure": "E2"}
    assert p["flags"] == ["severity unknown", "no fix"]
    assert [s["key"] for s in p["signals"]] == ["severity", "scope", "fix", "depth",
                                               "reachability", "exposure"]


def test_unknown_data_never_scored_as_safe():
    unknown = prioritize(mk(sev="unknown"))
    low = prioritize(mk(sev="low"))
    assert unknown["score"] > low["score"]
    f = mk(depth=None)
    f["depth"] = None
    assert prioritize(f)["flags"] == ["depth unknown"]
    assert next(s for s in prioritize(f)["signals"] if s["key"] == "depth")["points"] == 5


def test_ties_break_on_severity_score_then_name():
    a = mk(sev="high", score=7.5, name="zeta")
    b = mk(sev="high", score=8.1, name="alpha")
    c = mk(sev="high", score=8.1, name="beta")
    assert [f["package"]["name"] for f in enrich([a, c, b])] == ["alpha", "beta", "zeta"]


def test_fix_detection_uses_matching_range():
    f = mk(fix=False)
    f["fixed_versions"] = ["0.9.0", "3.0.0"]
    assert evidence.fix_versions(f) == ["3.0.0"]
    f["affected_ranges"] = [{"introduced": "0", "fixed": "1.2.0", "contains": True, "text": ""}]
    assert evidence.fix_versions(f) == ["1.2.0"]


def test_evidence_items():
    ev = mk(fix=False)["evidence"]
    assert [e["kind"] for e in ev] == ["advisory", "path", "scope", "fix", "reachability",
                                       "scan", "weakness"]
    assert ev[6]["text"] == "The advisory does not publish a weakness type (CWE)."
    assert ev[6]["label"] == "Unknown"
    assert ev[3]["text"] == "No fixed version is published for the affected range."
    assert ev[4]["text"].startswith("Reachability not determined")
    assert ev[4]["label"] == "Unknown" and ev[0]["label"] == "Confirmed"


def with_exploit(f, status, percentile=None, kev=None):
    f["exploit"] = {"status": status, "kev": kev, "cves": ["CVE-2024-0001"], "as_of": "2026-10-22",
                    "epss": None if percentile is None else {
                        "cve": "CVE-2024-0001", "epss": 0.4, "percentile": percentile,
                        "date": "2026-10-21"},
                    "checked": {"kev": status != "unavailable", "epss": status != "unavailable"}}
    f["evidence"] = evidence.build(f)
    return f


def test_kev_lifts_high_prod_from_p2_to_p1():
    base = prioritize(mk(sev="high", scope="prod", fix=True, depth=2))
    kev = {"cve": "CVE-2024-0001", "dateAdded": "2026-01-02", "knownRansomwareCampaignUse": "Known"}
    listed = prioritize(with_exploit(mk(sev="high", scope="prod", fix=True, depth=2), "listed",
                                     kev=kev))
    assert (base["score"], base["band"]) == (65, "P2")
    assert (listed["score"], listed["band"]) == (80, "P1")
    sig = listed["signals"][-1]
    assert sig == {"key": "exploitation", "label": "Exploitation", "value": "CISA KEV listed",
                   "points": 15, "eid": "E7"}


@pytest.mark.parametrize("pct,points,label", [(0.96, 8, "EPSS 96th pct"),
                                              (0.95, 8, "EPSS 95th pct"),
                                              (0.83, 4, "EPSS 83rd pct"),
                                              (0.42, 0, "EPSS 42nd pct")])
def test_epss_tiers(pct, points, label):
    p = prioritize(with_exploit(mk(), "scored", percentile=pct))
    assert (p["signals"][-1]["points"], p["signals"][-1]["value"]) == (points, label)
    assert "exploit unknown" not in p["flags"]


@pytest.mark.parametrize("status", ["unknown", "unavailable", "off"])
def test_missing_exploit_data_scores_zero_but_is_flagged(status):
    p = prioritize(with_exploit(mk(), status))
    assert p["signals"][-1]["points"] == 0 and "exploit unknown" in p["flags"]


def test_checked_and_absent_is_not_flagged():
    p = prioritize(with_exploit(mk(), "none"))
    assert p["signals"][-1]["value"] == "not in KEV, no EPSS"
    assert "exploit unknown" not in p["flags"]
