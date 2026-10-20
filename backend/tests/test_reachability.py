import shutil
from pathlib import Path

import pytest

from app import evidence
from app.reachability import annotate, assess, index_sources, module_root

APP = Path(__file__).parent / "fixtures" / "reach_app"


def finding(name, paths):
    return {"package": {"name": name, "version": "1.0.0"}, "paths": paths,
            "reachability": {"label": "Unknown", "evidence": []}}


@pytest.fixture(scope="module")
def idx():
    return index_sources(APP)


def test_index_collects_literal_imports_and_skips_node_modules(idx):
    want = {"express", "qs", "lodash", "@scope/pkg", "chalk", "minimist", "supertest"}
    assert want <= set(idx.modules)
    assert "should-not-count" not in idx.modules
    assert "node:fs" not in idx.modules and "./local" not in idx.modules
    hit = idx.modules["qs"][0]
    assert (hit.file, hit.line, hit.test) == ("src/server.js", 2, False)
    assert idx.modules["minimist"][0].test is True
    assert [h.file for h in idx.dynamic] == ["lib/plugins.mjs"]


@pytest.mark.parametrize("spec,root", [("qs/lib/parse", "qs"), ("@scope/pkg/deep", "@scope/pkg"),
                                       ("./x", None), ("node:fs", None), ("/abs", None)])
def test_module_root(spec, root):
    assert module_root(spec) == root


def test_direct_import_is_strong_evidence(idx):
    r = assess(finding("qs", [["root", "express@4.17.1", "qs@6.7.0"]]), idx)
    assert r["label"] == "Strong evidence"
    assert r["evidence"][0] == {"file": "src/server.js", "line": 2,
                                "text": 'const { parse } = require("qs/lib/parse");',
                                "module": "qs", "kind": "direct", "test": False}


def test_parent_import_is_possible(idx):
    r = assess(finding("body-parser", [["root", "express@4.17.1", "body-parser@1.19.0"]]), idx)
    assert r["label"] == "Possible" and r["evidence"][0]["module"] == "express"


def test_test_only_usage_is_unknown_when_dynamic_requires_exist(idx):
    r = assess(finding("minimist", [["root", "mkdirp@0.5.1", "minimist@0.0.8"]]), idx)
    assert r["label"] == "Unknown"
    kinds = {e["kind"] for e in r["evidence"]}
    assert kinds == {"dynamic", "test"}


def test_not_observed_without_dynamic_requires(tmp_path):
    shutil.copytree(APP, tmp_path / "app")
    (tmp_path / "app" / "lib" / "plugins.mjs").unlink()
    r = assess(finding("minimist", [["root", "mkdirp@0.5.1", "minimist@0.0.8"]]),
               index_sources(tmp_path / "app"))
    assert r["label"] == "Not observed"
    assert r["evidence"][0]["test"] is True


def test_no_sources_is_unknown(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    r = assess(finding("qs", [["root", "qs@6.7.0"]]), index_sources(tmp_path))
    assert r == {"label": "Unknown", "evidence": []}


def test_evidence_text_and_priority_points(idx):
    f = finding("qs", [["root", "express@4.17.1", "qs@6.7.0"]])
    annotate([f], APP)
    text, source, label = evidence.reach_text(f)
    assert label == "Strong evidence" and "src/server.js:2" in text
    assert "not determined" in text and source == "import scan of project source"


def test_vuln_demo_labels():
    from app.config import ROOT
    idx = index_sources(ROOT / "samples" / "vuln-demo")
    qs = assess(finding("qs", [["root", "express@4.17.1", "qs@6.7.0"]]), idx)
    assert qs["label"] == "Possible" and qs["evidence"][0]["file"] == "index.js"
    mini = assess(finding("minimist", [["root", "mkdirp@0.5.1", "minimist@0.0.8"]]), idx)
    assert mini["label"] == "Not observed"
