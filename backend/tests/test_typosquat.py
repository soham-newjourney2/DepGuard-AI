from pathlib import Path

import pytest
from helpers import real

from app.graph import Graph
from app.lockfile import parse
from app.risks import Inputs, typosquat
from app.samples import load_graph

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("eco,name,target,rule", [
    ("npm", "expresss", "express", "edit distance 1"),
    ("npm", "lodahs", "lodash", "edit distance 1"),
    ("npm", "raect", "react", "edit distance 1"),
    ("npm", "crossenv", "cross-env", "only by - _ . separators"),
    ("npm", "c0lors", "colors", "look-alike characters"),
    ("npm", "babelcore", "@babel/core", "drops the scope"),
    ("PyPI", "reqeusts", "requests", "edit distance 1"),
    ("PyPI", "djang0", "django", "look-alike characters"),
    ("PyPI", "urllib4", "urllib3", "edit distance 1"),
    ("PyPI", "python-requests", "requests", "prefix 'python-'"),
])
def test_true_positives(eco, name, target, rule):
    assert name not in typosquat.popular(eco)
    hit = typosquat.near(eco, typosquat.norm(eco, name))
    assert hit is not None and hit[0] == target and rule in hit[1]


@pytest.mark.parametrize("eco,name", [
    ("npm", "preact"), ("npm", "react"), ("npm", "color"), ("npm", "colors"),
    ("npm", "chalk"), ("PyPI", "numpy"), ("PyPI", "requests"), ("PyPI", "urllib3"),
])
def test_popular_names_are_never_flagged(eco, name):
    assert name in typosquat.popular(eco) and typosquat.near(eco, name) is None


@pytest.mark.parametrize("name", ["@aws-sdk/client-sns", "@types/acorn", "abc", "babel-traverse"])
def test_known_safe_look_alikes(name):
    assert typosquat.near("npm", name) is None


def test_pypi_names_compare_normalised():
    assert typosquat.norm("PyPI", "Typing_Extensions") == "typing-extensions"
    assert typosquat.near("PyPI", typosquat.norm("PyPI", "Typing_Extensions")) is None


def test_distance_handles_transpositions():
    assert typosquat.distance("lodash", "lodahs") == 1
    assert typosquat.distance("express", "expresss") == 1
    assert typosquat.distance("abcdef", "badcfe") == 3


def test_lists_are_sourced_and_sized():
    for f in ("npm.txt", "pypi.txt"):
        lines = (typosquat.DATA / f).read_text("utf-8").splitlines()
        assert lines[0].startswith("# ") and lines[1].startswith("# source: https://")
        assert len([x for x in lines if not x.startswith("#")]) == 5000


def test_risk_severity_by_depth():
    lock = {"lockfileVersion": 3, "packages": {
        "": {"name": "app", "version": "1.0.0", "dependencies": {"expresss": "1.0.0"}},
        "node_modules/expresss": {"version": "1.0.0", "dependencies": {"lodahs": "1.0.0"}},
        "node_modules/lodahs": {"version": "1.0.0"}}}
    g = Graph(parse(lock))
    got = {r["package"]: r for r in typosquat.check(Inputs(Path("."), "npm", g, [], "upload"))}
    assert got["expresss@1.0.0"]["severity"] == "medium"
    assert got["lodahs@1.0.0"]["severity"] == "low"
    r = got["expresss@1.0.0"]
    assert r["kind"] == "typosquat" and r["confidence"] == "medium"
    assert r["title"] == "expresss@1.0.0 looks like a typosquat of express"
    assert r["evidence"][1].startswith("express is #") and "direct dependency" in r["evidence"]


@pytest.mark.parametrize("sample", ["vuln-demo", "messy-demo", "python-demo"])
def test_bundled_demos_have_no_typosquats(sample):
    root = real(ROOT / "samples" / sample)
    assert typosquat.check(Inputs(root, "x", load_graph(root), [], "demo")) == []
