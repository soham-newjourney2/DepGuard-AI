import json
from pathlib import Path

import pytest

from app.graph import Graph
from app.lockfile import parse

LOCKS = Path(__file__).parent / "fixtures" / "locks"


def graph(name: str) -> Graph:
    return Graph(parse(json.loads((LOCKS / f"{name}.json").read_text(encoding="utf-8"))))


@pytest.fixture(scope="module")
def flat():
    return graph("flat")


def test_parse_nodes_and_flags(flat):
    labels = {k: n.label for k, n in flat.nodes.items()}
    assert labels == {"": "root", "node_modules/a": "a@1.0.0", "node_modules/b": "b@1.2.0",
                      "node_modules/c": "c@1.1.0", "node_modules/t": "t@1.0.0",
                      "node_modules/d": "d@2.0.0"}
    assert flat.nodes["node_modules/t"].dev and not flat.nodes["node_modules/a"].dev
    assert flat.nodes[""].deps["t"] == ("^1.0.0", "dev")
    assert flat.lock.version == 3 and flat.lock.warnings == []


def test_flat_paths_scope_depth(flat):
    c = flat.info("node_modules/c")
    assert c["paths"] == [["root", "a@1.0.0", "c@1.1.0"], ["root", "b@1.2.0", "c@1.1.0"],
                          ["root", "t@1.0.0", "c@1.1.0"]]
    assert (c["scope"], c["direct"], c["depth"], c["path_count"]) == ("prod", False, 2, 3)
    assert flat.info("node_modules/a")["direct"] is True
    assert flat.scope["node_modules/t"] == "dev" and flat.scope["node_modules/d"] == "dev"
    assert flat.info("node_modules/d")["paths"] == [["root", "t@1.0.0", "d@2.0.0"]]
    assert flat.disagreements == [] and flat.unresolved == []
    assert flat.stats() == {"packages": 5, "direct": 3, "max_depth": 2, "unresolved": 0}


def test_nested_duplicate_versions_use_node_lookup():
    g = graph("nested_dupes")
    assert g.lock.version == 2
    old = g.info("node_modules/a/node_modules/c")
    assert old["paths"] == [["root", "a@1.0.0", "c@1.0.5"]]
    assert (old["direct"], old["depth"]) == (False, 2)
    new = g.info("node_modules/c")
    assert new["paths"] == [["root", "c@2.0.0"], ["root", "a@1.0.0", "b@1.0.0", "c@2.0.0"]]
    assert (new["direct"], new["depth"], new["path_count"]) == (True, 1, 2)
    assert g.info("node_modules/e")["paths"] == [["root", "a@1.0.0", "c@1.0.5", "e@1.0.0"]]
    assert g.packages()["c@2.0.0"] == ["node_modules/c"]


def test_dev_only_scope_and_lockfile_disagreement():
    g = graph("dev_only")
    assert g.scope["node_modules/a"] == "prod"
    assert g.scope["node_modules/x"] == "dev" and g.scope["node_modules/y"] == "dev"
    assert g.disagreements == [{"package": "x@1.0.0", "computed": "dev", "lockfile": ["prod"]}]


def test_optional_and_peer_scopes_without_false_warnings():
    g = graph("optional")
    assert g.scope["node_modules/fsevents"] == "optional"
    assert g.scope["node_modules/react"] == "peer"
    assert g.scope["node_modules/a"] == "prod"
    assert g.unresolved == [] and g.disagreements == []
    assert g.info("node_modules/react")["paths"] == [["root", "a@1.0.0", "react@18.2.0"]]


def test_cycle_terminates_with_simple_paths():
    g = graph("cycle")
    assert g.info("node_modules/c")["paths"] == [["root", "a@1.0.0", "b@1.0.0", "c@1.0.0"]]
    assert g.info("node_modules/a")["paths"] == [["root", "a@1.0.0"]]
    assert g.info("node_modules/c")["path_count"] == 1
    assert g.depth == {"": 0, "node_modules/a": 1, "node_modules/b": 2, "node_modules/c": 3}


def test_missing_dependencies_become_warnings():
    g = graph("missing")
    assert g.unresolved == [
        {"from": "root", "dep": "ghost", "spec": "^1.0.0", "kind": "prod"},
        {"from": "a@1.0.0", "dep": "phantom", "spec": "^2.0.0", "kind": "prod"},
    ]
    assert g.stats()["unresolved"] == 2


def test_workspaces_links_followed():
    g = graph("workspaces")
    assert [w["code"] for w in g.lock.warnings] == ["W_WORKSPACES"]
    assert g.info("node_modules/left")["paths"] == [["root", "lib@0.1.0", "left@1.0.0"]]
    assert list(g.packages()) == ["left@1.0.0"]
    local = {n["label"]: n["local"] for n in g.to_json()["nodes"]}
    assert local == {"root": True, "lib@0.1.0": True, "left@1.0.0": False}


def test_scoped_and_aliased_names():
    g = graph("scoped_alias")
    assert g.nodes["node_modules/my-alias"].label == "real-pkg@2.0.0"
    assert g.nodes["node_modules/my-alias"].install_name == "my-alias"
    assert g.info("node_modules/my-alias")["paths"] == [
        ["root", "real-pkg@2.0.0"], ["root", "@scope/pkg@1.0.0", "real-pkg@2.0.0"]]


def test_path_cap_and_total_count():
    g = graph("ladder")
    info = g.info("node_modules/z")
    assert len(info["paths"]) == 20 and info["path_count"] == 32
    assert info["paths"][0] == ["root", "a1@1.0.0", "a2@1.0.0", "a3@1.0.0", "a4@1.0.0",
                                "a5@1.0.0", "z@9.9.9"]
    assert all(len(p) == 7 for p in info["paths"])
    assert len({tuple(p) for p in info["paths"]}) == 20


def test_empty_and_malformed_packages():
    g = Graph(parse({"lockfileVersion": 3, "packages": {"node_modules/x": "bad", 5: {}}}))
    assert list(g.nodes) == [""] and g.stats()["packages"] == 0
    assert g.paths_to("node_modules/missing") == []


def test_graph_json_shape(flat):
    data = flat.to_json()
    assert {e["kind"] for e in data["edges"]} == {"prod", "dev"}
    c = next(n for n in data["nodes"] if n["label"] == "c@1.1.0")
    assert c == {"id": "node_modules/c", "name": "c", "version": "1.1.0", "label": "c@1.1.0",
                 "scope": "prod", "depth": 2, "direct": False, "local": False, "ecosystem": "npm",
                 "dependents": 3, "dependencies": 0, "path_count": 3}
