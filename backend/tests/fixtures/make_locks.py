"""Regenerate lockfile fixtures: python backend/tests/fixtures/make_locks.py"""

import json
from pathlib import Path

OUT = Path(__file__).parent / "locks"


def lock(root: dict, packages: dict, version: int = 3) -> dict:
    return {"name": root.get("name", "app"), "version": "1.0.0", "lockfileVersion": version,
            "requires": True, "packages": {"": {"version": "1.0.0", **root}, **packages}}


FIXTURES = {
    "flat": lock(
        {"name": "flat-app", "dependencies": {"a": "^1.0.0", "b": "^1.0.0"},
         "devDependencies": {"t": "^1.0.0"}},
        {"node_modules/a": {"version": "1.0.0", "dependencies": {"c": "^1.0.0"}},
         "node_modules/b": {"version": "1.2.0", "dependencies": {"c": "^1.0.0"}},
         "node_modules/c": {"version": "1.1.0"},
         "node_modules/t": {"version": "1.0.0", "dev": True,
                            "dependencies": {"c": "^1.0.0", "d": "^2.0.0"}},
         "node_modules/d": {"version": "2.0.0", "dev": True}}),
    "nested_dupes": lock(
        {"name": "nested-app", "dependencies": {"a": "^1.0.0", "c": "^2.0.0"}},
        {"node_modules/a": {"version": "1.0.0", "dependencies": {"c": "^1.0.0", "b": "^1.0.0"}},
         "node_modules/a/node_modules/c": {"version": "1.0.5", "dependencies": {"e": "^1.0.0"}},
         "node_modules/b": {"version": "1.0.0", "dependencies": {"c": "^2.0.0"}},
         "node_modules/c": {"version": "2.0.0"},
         "node_modules/e": {"version": "1.0.0"}},
        version=2),
    "dev_only": lock(
        {"name": "dev-app", "dependencies": {"a": "^1.0.0"}, "devDependencies": {"lint": "^1.0.0"}},
        {"node_modules/a": {"version": "1.0.0"},
         "node_modules/lint": {"version": "1.0.0", "dev": True, "dependencies": {"x": "^1.0.0"}},
         "node_modules/x": {"version": "1.0.0", "dependencies": {"y": "^1.0.0"}},
         "node_modules/y": {"version": "1.0.0", "dev": True}}),
    "optional": lock(
        {"name": "opt-app", "dependencies": {"a": "^1.0.0"},
         "optionalDependencies": {"fsevents": "^2.0.0"}},
        {"node_modules/a": {"version": "1.0.0", "optionalDependencies": {"gone": "^1.0.0"},
                            "peerDependencies": {"react": "^18.0.0", "vue": "^3.0.0"},
                            "peerDependenciesMeta": {"vue": {"optional": True}}},
         "node_modules/fsevents": {"version": "2.3.3", "optional": True},
         "node_modules/react": {"version": "18.2.0", "peer": True}}),
    "cycle": lock(
        {"name": "cycle-app", "dependencies": {"a": "^1.0.0"}},
        {"node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^1.0.0"}},
         "node_modules/b": {"version": "1.0.0", "dependencies": {"a": "^1.0.0", "c": "^1.0.0"}},
         "node_modules/c": {"version": "1.0.0", "dependencies": {"b": "^1.0.0"}}}),
    "missing": lock(
        {"name": "missing-app", "dependencies": {"a": "^1.0.0", "ghost": "^1.0.0"}},
        {"node_modules/a": {"version": "1.0.0", "dependencies": {"phantom": "^2.0.0"}}}),
    "workspaces": lock(
        {"name": "mono", "workspaces": ["packages/*"]},
        {"packages/lib": {"name": "lib", "version": "0.1.0", "dependencies": {"left": "^1.0.0"}},
         "node_modules/lib": {"resolved": "packages/lib", "link": True},
         "node_modules/left": {"version": "1.0.0"}}),
    "scoped_alias": lock(
        {"name": "alias-app",
         "dependencies": {"@scope/pkg": "^1.0.0", "my-alias": "npm:real-pkg@^2.0.0"}},
        {"node_modules/@scope/pkg": {"version": "1.0.0", "dependencies": {"my-alias": "^2.0.0"}},
         "node_modules/my-alias": {"name": "real-pkg", "version": "2.0.0"}}),
    "demo_lib": lock(
        {"name": "norm-app", "dependencies": {"demo-lib": "^1.0.0", "wrapper": "^1.0.0"}},
        {"node_modules/demo-lib": {"version": "1.0.0"},
         "node_modules/wrapper": {"version": "1.0.0", "dependencies": {"demo-lib": "^2.0.0"}},
         "node_modules/wrapper/node_modules/demo-lib": {"version": "2.0.1"}}),
}


def ladder(layers: int = 5) -> dict:
    pkgs = {}
    for i in range(1, layers + 1):
        nxt = {f"a{i + 1}": "1", f"b{i + 1}": "1"} if i < layers else {"z": "1"}
        for side in "ab":
            pkgs[f"node_modules/{side}{i}"] = {"version": "1.0.0", "dependencies": nxt}
    pkgs["node_modules/z"] = {"version": "9.9.9"}
    return lock({"name": "ladder", "dependencies": {"a1": "1", "b1": "1"}}, pkgs)


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, data in {**FIXTURES, "ladder": ladder()}.items():
        (OUT / f"{name}.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
