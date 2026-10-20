import difflib
import json
import re

SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def detect_indent(text: str) -> str:
    m = re.search(r"^([ \t]+)\"", text, re.M)
    return m.group(1) if m else "  "


def apply(text: str, edits: list[dict]) -> str:
    """Apply manifest edits and re-serialise with the file's own indent and line endings."""
    data = json.loads(text.lstrip("﻿"))
    for e in edits:
        if e["op"] == "set":
            data.setdefault(e["section"], {})[e["name"]] = e["value"]
        elif e["op"] == "override":
            node = data.setdefault("overrides", {})
            *parents, leaf = e["path"]
            for p in parents:
                current = node.get(p)
                if isinstance(current, str):
                    node[p] = {".": current}
                node = node.setdefault(p, {})
            node[leaf] = e["value"]
        else:
            raise ValueError(f"unknown edit {e['op']!r}")
    out = json.dumps(data, indent=detect_indent(text), ensure_ascii=False)
    if text.endswith(("\n", "\r\n")):
        out += "\n"
    if "\r\n" in text:
        out = out.replace("\n", "\r\n")
    return ("﻿" if text.startswith("﻿") else "") + out


def unified(before: str, after: str, name: str = "package.json") -> str:
    lines = difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                 fromfile=f"a/{name}", tofile=f"b/{name}", n=3)
    return "".join(line if line.endswith("\n") else line + "\n" for line in lines)


def section_of(manifest: dict, name: str) -> str | None:
    return next((s for s in SECTIONS if name in (manifest.get(s) or {})), None)


def bump_spec(old: str, target: str) -> str:
    """Keep the author's range style: ^ and ~ stay, exact pins stay exact, other ranges get ^."""
    old = (old or "").strip()
    if old.startswith(("^", "~")):
        return old[0] + target
    if re.fullmatch(r"v?\d+\.\d+\.\d+(?:-[\w.]+)?", old):
        return target
    return "^" + target
