import json
from collections import Counter

import pytest

from app import cwe, evidence
from app.config import RECORDED
from app.scanner.normalize import cwes_of

FIELDS = ("id", "name", "plain", "impact", "matters_when", "mitigation")


def recorded_cwes() -> Counter:
    c = Counter()
    for f in (RECORDED / "osv" / "vulns").glob("*.json"):
        c.update(cwes_of(json.loads(f.read_text(encoding="utf-8"))))
    return c


def test_every_frequent_recorded_cwe_has_an_entry():
    frequent = [c for c, n in recorded_cwes().items() if n >= 2]
    assert len(frequent) >= 20
    missing = [c for c in frequent if not cwe.lookup(c)["known"]]
    assert missing == []


def test_entries_are_complete_and_link_mitre():
    ids = [e["id"] for e in json.loads(cwe.KB.read_text("utf-8"))["entries"]]
    assert len(ids) == len(set(ids)) >= 25
    for e in cwe.entries().values():
        assert all(isinstance(e[k], str) and e[k].strip() for k in FIELDS), e["id"]
        n = e["id"].split("-")[1]
        assert cwe.lookup(e["id"])["source"] == f"https://cwe.mitre.org/data/definitions/{n}.html"


def test_unknown_and_missing_fallbacks():
    u = cwe.lookup("CWE-99999")
    assert u["known"] is False and u["name"] is None
    assert u["source"] == "https://cwe.mitre.org/data/definitions/99999.html"
    assert cwe.weakness([]) is None and cwe.weakness(["NVD-CWE-Other"]) is None
    assert cwe.weakness(["CWE-99999", "CWE-79"])["id"] == "CWE-79", "known entries first"


def test_normaliser_reads_both_cwe_locations():
    rec = {"database_specific": {"cwe_ids": ["CWE-79", "junk"]},
           "affected": [{"database_specific": {"cwe_ids": ["CWE-20"]}}]}
    assert cwes_of(rec) == ["CWE-20", "CWE-79"]


@pytest.mark.parametrize("cwes,label,start", [
    (["CWE-1321"], "Confirmed", "The advisory classifies it as CWE-1321 (Improperly Controlled"),
    (["CWE-99999"], "Confirmed", "The advisory classifies it as CWE-99999."),
    ([], "Unknown", "The advisory does not publish a weakness type"),
])
def test_weakness_evidence(cwes, label, start):
    text, source, lab = evidence.weakness_text(cwes)
    assert lab == label and text.startswith(start)
    assert source == ("advisory" if not cwes else cwe.source(cwes[0]))
