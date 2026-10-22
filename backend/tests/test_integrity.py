from pathlib import Path

import pytest
from helpers import real

from app.risks import Inputs, integrity

FIX = real(Path(__file__).parent / "fixtures" / "integrity")


def run(case):
    return {r["title"]: r for r in integrity.check(Inputs(FIX / case, "x", None, [], "upload"))}


def summary(case):
    return sorted((r["severity"], t) for t, r in run(case).items())


def test_npm_rules_each_fire_once():
    got = run("npm-rules")
    assert summary("npm-rules") == [
        ("high", "plain@1.0.0 is fetched over plain HTTP"),
        ("low", "localfile@1.0.0 is installed from a local file"),
        ("low", "oldhash@1.0.0 is pinned only by a SHA-1 hash"),
        ("medium", "gitdep@1.0.0 is resolved from a git URL"),
        ("medium", "nohash@1.0.0 has no integrity hash in the lockfile"),
        ("medium", "tarball@1.0.0 is resolved from a non-registry URL (evil.example.com)")]
    r = got["plain@1.0.0 is fetched over plain HTTP"]
    assert r["kind"] == "integrity" and r["confidence"] == "high"
    assert r["location"] == {"file": "package-lock.json", "line": 25}
    assert r["package"] == "plain@1.0.0" and r["evidence"][0].startswith("resolved: http://")
    assert not any("ok@" in t for t in got)


def test_workspace_and_bundled_are_not_tampering():
    assert summary("npm-workspace") == [("info", "app-a@0.1.0 is a workspace package")]


def test_declared_registry_mirror_is_trusted():
    assert run("npm-mirror") == {}


@pytest.mark.parametrize("case,expected", [
    ("uv", [("medium", "gitpkg@0.2.0 is resolved from a git URL"),
            ("medium", "nohash@1.0.0 has no hashes in uv.lock"),
            ("medium", "urlpkg@0.3.0 is resolved from a non-PyPI URL")]),
    ("poetry", [("info", "localpkg@0.1.0 is a local package"),
                ("medium", "gitpkg@0.2.0 is resolved from a git URL"),
                ("medium", "nohash@1.0.0 has no hashes in poetry.lock")]),
    ("cargo", [("medium", "gitcrate@0.2.0 is resolved from a git URL")]),
    ("bundler", [("info", "localgem@0.1.0 is a local path gem"),
                 ("medium", "gitgem@0.2.0 is resolved from a git URL")]),
    ("composer", [("high", "plain/pkg@1.0.0 is fetched over plain HTTP"),
                  ("info", "local/pkg@dev-main is a local path package"),
                  ("medium", "nodist/pkg@dev-main has no dist archive")]),
    ("go", [("low", "github.com/old/lib is replaced with another module"),
            ("medium", "github.com/local/lib is replaced with a local path")]),
])
def test_other_ecosystems(case, expected):
    assert summary(case) == expected


def test_lines_point_at_the_entry():
    gem = run("bundler")["gitgem@0.2.0 is resolved from a git URL"]
    lines = (FIX / "bundler" / "Gemfile.lock").read_text().splitlines()
    assert lines[gem["location"]["line"] - 1].strip() == "gitgem (0.2.0)"


@pytest.mark.parametrize("sample", ["vuln-demo", "clean-demo", "messy-demo", "python-demo"])
def test_bundled_demos_have_no_tampering(sample):
    root = real(Path(__file__).resolve().parents[2] / "samples" / sample)
    assert integrity.check(Inputs(root, "x", None, [], "demo")) == []
