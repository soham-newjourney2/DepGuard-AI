import hashlib
import importlib.util
import json

import pytest

from app.config import ROOT
from app.samples import STORED

KEYS = ROOT / "samples" / "_answers"
DEMOS = {"vuln-demo": "package-lock.json", "clean-demo": "package-lock.json",
         "messy-demo": "package-lock.json", "python-demo": "requirements.txt",
         "supplychain-demo": "package-lock.json"}
TOOLS = {"npm audit", "osv-scanner", "pip-audit"}


def load_tool():
    spec = importlib.util.spec_from_file_location("answers", ROOT / "tools" / "answers.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("demo,lockfile", DEMOS.items())
def test_answer_key_schema_and_lockfile_hash(demo, lockfile):
    key = json.loads((KEYS / f"{demo}.json").read_text(encoding="utf-8"))
    assert set(key) - {"expected_risks"} == {"demo", "generated_at", "lockfile_sha256", "tools",
                                             "advisories"}
    for r in key.get("expected_risks", []):
        assert r["source"] == "planted-by-design" and r["kind"] in {
            "malware", "integrity", "typosquat", "secret"} and (r.get("package") or r.get("file"))
    assert key["demo"] == demo and key["generated_at"].endswith("Z")
    lock = (ROOT / "samples" / demo / (lockfile + STORED)).read_bytes()
    assert key["lockfile_sha256"] == hashlib.sha256(lock).hexdigest()
    names = {t["name"] for t in key["tools"]}
    assert names and names <= TOOLS and all(t["version"] for t in key["tools"])
    for a in key["advisories"]:
        assert {"id", "aliases", "package", "version", "reported_by"} <= set(a)
        assert a["reported_by"] and set(a["reported_by"]) <= names


def test_clean_demo_key_is_empty():
    key = json.loads((KEYS / "clean-demo.json").read_text(encoding="utf-8"))
    assert key["advisories"] == []


def test_merge_pools_aliases_across_tools():
    tool = load_tool()
    npm = ({"name": "npm audit", "version": "11"},
           [{"id": "GHSA-a", "aliases": [], "package": "qs", "version": "6.7.0",
             "severity": "high"}])
    osv = ({"name": "osv-scanner", "version": "2"},
           [{"id": "GHSA-a", "aliases": ["CVE-1"], "package": "qs", "version": "6.7.0"},
            {"id": "GHSA-b", "aliases": [], "package": "qs", "version": "6.7.0"}])
    a, b = tool.merge([npm, osv])
    assert a == {"id": "GHSA-a", "aliases": ["CVE-1"], "package": "qs", "version": "6.7.0",
                 "reported_by": ["npm audit", "osv-scanner"], "severity": "high"}
    assert b["id"] == "GHSA-b" and b["reported_by"] == ["osv-scanner"]


def test_npm_range_filter():
    tool = load_tool()
    assert tool.affected("<6.7.3", "6.7.0") and not tool.affected("<6.7.3", "6.9.0")
    assert tool.affected("not a range", "1.0.0")
