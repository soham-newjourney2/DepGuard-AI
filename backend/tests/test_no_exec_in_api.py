"""§5.1: the API process never spawns npm/node — only code under app/verify/ may."""

import re
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"
SPAWN = re.compile(r"\b(subprocess|os\.system|os\.popen|os\.exec\w*|create_subprocess_\w+)\b")
NODE = re.compile(r"""["'](npm|npx|node|yarn|pnpm)["'\s]""")


def test_no_npm_or_node_spawn_outside_verify():
    offenders = []
    for path in APP.rglob("*.py"):
        if "verify" in path.relative_to(APP).parts:
            continue
        text = path.read_text(encoding="utf-8")
        if SPAWN.search(text) and NODE.search(text):
            offenders.append(str(path.relative_to(APP)))
    assert not offenders, f"npm/node spawned outside verify/: {offenders}"
