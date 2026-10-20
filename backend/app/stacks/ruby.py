import re
from pathlib import Path

from app.stacks.base import Builder, read_text

ECOSYSTEM = "RubyGems"
SPEC = re.compile(r"^    ([^\s(]+) \(([^)]+)\)$")
DEP = re.compile(r"^      ([^\s(]+)")
DIRECT = re.compile(r"^  ([^\s(!]+)")
GEM = re.compile(r"""^\s*gem\s+["']([^"']+)["'](.*)$""")
GROUP = re.compile(r"^\s*group\s+(.+?)\s+do\b")
BLOCK = re.compile(r"\bdo(\s*\|[^|]*\|)?$")
OPENER = re.compile(r"^(if|unless|case|begin)\b")
DEV_GROUPS = ("development", "test")


def gem_version(v: str) -> str:
    """Drop the platform suffix: 1.13.10-x86_64-linux → 1.13.10."""
    return v.split("-", 1)[0]


def dev_gems(root: Path) -> set[str]:
    path = root / "Gemfile"
    if not path.is_file():
        return set()
    dev: set[str] = set()
    blocks: list[bool] = []
    for line in read_text(path).splitlines():
        s = line.split("#", 1)[0].strip()
        if m := GROUP.match(s):
            blocks.append(is_dev_group(m.group(1)))
        elif BLOCK.search(s) or OPENER.match(s):
            blocks.append(False)
        elif s == "end":
            if blocks:
                blocks.pop()
        elif m := GEM.match(s):
            opts = m.group(2)
            if any(blocks) or (re.search(r"\bgroups?:", opts) and is_dev_group(opts)):
                dev.add(m.group(1))
    return dev


def is_dev_group(text: str) -> bool:
    return any(g in text for g in DEV_GROUPS) and "production" not in text


def load_gemfile(root: Path) -> Builder:
    b = Builder(ECOSYSTEM, root.name)
    section, current = "", None
    deps: dict[str, list[str]] = {}
    direct: list[str] = []
    for line in read_text(root / "Gemfile.lock").splitlines():
        if line and not line.startswith(" "):
            section, current = line.strip(), None
            continue
        if section in ("GEM", "GIT", "PATH"):
            if m := SPEC.match(line):
                current = b.add(m.group(1), gem_version(m.group(2)), local=section != "GEM")
                deps.setdefault(current, [])
            elif current and (m := DEP.match(line)):
                deps[current].append(m.group(1))
        elif section == "DEPENDENCIES" and (m := DIRECT.match(line)):
            direct.append(m.group(1))
    dev = dev_gems(root)
    for key, names in deps.items():
        for name in names:
            if b.find(name):
                b.edge(key, name)
    for name in direct:
        b.edge("", name, "dev" if name in dev else "prod")
    return b
