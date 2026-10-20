from app.report.compare import classify
from app.report.export import seal


def f(adv, name, version, sev="high"):
    return {"advisory": {"id": adv, "summary": f"{adv} summary", "severity": {"label": sev}},
            "package": {"name": name, "version": version}, "scope": "prod",
            "priority": {"band": "P2"}}


BEFORE = [f("GHSA-1", "qs", "6.7.0"), f("GHSA-2", "qs", "6.7.0", "low"),
          f("GHSA-3", "express", "4.17.1"), f("GHSA-4", "request", "2.88.2", "medium")]


def test_all_four_classes():
    after = [f("GHSA-2", "qs", "6.9.7", "low"), f("GHSA-4", "request", "2.88.2", "medium"),
             f("GHSA-9", "express", "4.22.3", "critical")]
    out = classify(BEFORE, after, "verified")
    assert [i["advisory"] for i in out["resolved"]] == ["GHSA-1", "GHSA-3"]
    assert [i["advisory"] for i in out["still_present"]] == ["GHSA-2", "GHSA-4"]
    assert out["still_present"][0]["versions_after"] == ["6.9.7"]
    assert [i["advisory"] for i in out["newly_detected"]] == ["GHSA-9"]
    assert out["unable_to_verify"] == []
    unable = classify(BEFORE, None, "unable_to_verify", targeted={"GHSA-1", "GHSA-2"})
    assert [i["advisory"] for i in unable["unable_to_verify"]] == ["GHSA-1", "GHSA-2"]
    assert [i["advisory"] for i in unable["still_present"]] == ["GHSA-3", "GHSA-4"]
    assert unable["resolved"] == [] and unable["newly_detected"] == []


def test_matching_is_by_advisory_and_package_name_not_version():
    after = [f("GHSA-1", "qs", "6.7.2")]
    out = classify([f("GHSA-1", "qs", "6.7.0")], after, "verify_failed")
    assert out["still_present"] and not out["resolved"]


def test_no_verification_means_still_present():
    out = classify(BEFORE, None, None)
    assert len(out["still_present"]) == 4 and not out["unable_to_verify"]


def test_seal_rules():
    ok = {"status": "verified", "tests": {"present": True, "exit_code": 0},
          "comparison": {"target_resolved": True}}
    assert seal(ok)[1] == "VERIFIED"
    assert seal({**ok, "tests": {"present": False, "exit_code": 0}})[1] == "Partially verified"
    assert seal({**ok, "comparison": {"target_resolved": False}})[1] == "Partially verified"
    assert seal({**ok, "status": "verify_failed"})[1] == "Verification failed"
    assert seal({"status": "unable_to_verify"})[1] == "Partially verified"
    assert seal(None)[1] == "Scan only"


def test_other_copy_still_matching_is_reported_by_version():
    from app.report.export import moved
    before = [f("GHSA-1", "qs", "6.7.0"), f("GHSA-1", "qs", "6.5.5")]
    after = [f("GHSA-1", "qs", "6.5.5")]
    out = classify(before, after, "verified")
    upgraded, untouched = out["still_present"]
    assert moved(upgraded) == " (still matched at 6.5.5)" and moved(untouched) == ""
