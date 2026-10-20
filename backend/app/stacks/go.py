import re
from pathlib import Path

from app.stacks.base import Builder, read_text

ECOSYSTEM = "Go"
LINE = re.compile(r"^(\S+)\s+(v\S+)(\s*//\s*indirect)?")
REPLACE = re.compile(r"^(\S+)(?:\s+(v\S+))?\s*=>\s*(\S+)(?:\s+(v\S+))?")


def go_version(v: str) -> str:
    """OSV records Go module versions without the leading v."""
    return v[1:] if v.startswith("v") else v


def directives(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    block = None
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip() if "// indirect" not in raw else raw.strip()
        if not line:
            continue
        if block:
            if line == ")":
                block = None
            else:
                out.setdefault(block, []).append(line)
            continue
        verb, _, rest = line.partition(" ")
        rest = rest.strip()
        if rest == "(":
            block = verb
        elif rest:
            out.setdefault(verb, []).append(rest)
    return out


def load_gomod(root: Path) -> Builder:
    d = directives(read_text(root / "go.mod"))
    module = (d.get("module") or [root.name])[0].strip('"')
    b = Builder(ECOSYSTEM, module)
    replaced: dict[tuple[str, str | None], tuple[str, str | None]] = {}
    for r in d.get("replace", []):
        if m := REPLACE.match(r):
            replaced[(m.group(1), m.group(2))] = (m.group(3), m.group(4))
    for req in d.get("require", []):
        m = LINE.match(req)
        if not m:
            continue
        name, version, indirect = m.group(1), m.group(2), bool(m.group(3))
        target = replaced.get((name, version)) or replaced.get((name, None))
        local = False
        if target:
            if target[1]:
                name, version = target
            else:
                local = True
        key = b.add(name, go_version(version), local=local)
        if not indirect:
            b.edges.append(("", key, "prod"))
    if len(b.edges) < len(b.nodes):
        b.flat("go.mod")
    return b
