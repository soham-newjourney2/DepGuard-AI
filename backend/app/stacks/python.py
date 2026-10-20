import re
from pathlib import Path

from app.stacks.base import Builder, norm_name, opt_toml, read_json, read_text, read_toml

ECOSYSTEM = "PyPI"
REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(===|==|~=|!=|<=|>=|<|>)?"
                 r"\s*([^;\s#,]*)")
INCLUDE = re.compile(r"^(?:-r|--requirement)(?:\s+|=)?(\S+)$")
DEV_HINT = re.compile(r"(dev|test|lint|doc|ci)", re.I)
MAX_INCLUDE_DEPTH = 3


def dep_name(spec: str) -> str:
    m = REQ.match(spec.strip())
    return m.group(1) if m else ""


def project_meta(root: Path) -> tuple[str, dict[str, str]]:
    """Name and declared direct dependencies (name → kind) from pyproject.toml / Pipfile."""
    py = opt_toml(root / "pyproject.toml")
    proj, poetry = py.get("project") or {}, (py.get("tool") or {}).get("poetry") or {}
    direct: dict[str, str] = {}

    def put(names, kind):
        for n in names:
            if n and n.lower() != "python":
                direct.setdefault(n, kind)
    put((dep_name(s) for s in proj.get("dependencies") or []), "prod")
    put(poetry.get("dependencies") or {}, "prod")
    for specs in (proj.get("optional-dependencies") or {}).values():
        put((dep_name(s) for s in specs), "optional")
    put(poetry.get("dev-dependencies") or {}, "dev")
    for group in (poetry.get("group") or {}).values():
        put((group or {}).get("dependencies") or {}, "dev")
    for specs in (py.get("dependency-groups") or {}).values():
        put((dep_name(s) for s in specs if isinstance(s, str)), "dev")
    pip = opt_toml(root / "Pipfile")
    put(pip.get("packages") or {}, "prod")
    put(pip.get("dev-packages") or {}, "dev")
    return str(proj.get("name") or poetry.get("name") or root.name), direct


def link_direct(b: Builder, direct: dict[str, str]) -> None:
    if not direct:
        b.roots_without_parents()
        return
    for name, kind in direct.items():
        if b.find(name):
            b.edge("", name, kind)
        else:
            b.edges.append(("", name, kind))


def load_poetry(root: Path) -> Builder:
    name, direct = project_meta(root)
    b = Builder(ECOSYSTEM, name)
    lock = read_toml(root / "poetry.lock")
    pkgs = [p for p in lock.get("package") or [] if isinstance(p, dict)]
    keys = []
    for p in pkgs:
        local = (p.get("source") or {}).get("type") in ("directory", "file", "git", "url")
        keys.append(b.add(str(p.get("name")), str(p.get("version")),
                          dev=p.get("category") == "dev", optional=bool(p.get("optional")),
                          local=local))
    for key, p in zip(keys, pkgs, strict=True):
        for dep, spec in (p.get("dependencies") or {}).items():
            optional = isinstance(spec, dict) and spec.get("optional")
            if b.find(dep):
                b.edge(key, dep, "optional" if optional else "prod")
    link_direct(b, direct)
    return b


def load_uv(root: Path) -> Builder:
    lock = read_toml(root / "uv.lock")
    pkgs = [p for p in lock.get("package") or [] if isinstance(p, dict)]
    main = next((p for p in pkgs if (p.get("source") or {}).get("virtual") == "."
                 or (p.get("source") or {}).get("editable") == "."), None)
    b = Builder(ECOSYSTEM, str((main or {}).get("name") or root.name))
    keys = {}
    for p in pkgs:
        if p is main:
            keys[id(p)] = ""
            continue
        src = p.get("source") or {}
        local = any(k in src for k in ("virtual", "editable", "path", "directory", "git"))
        keys[id(p)] = b.add(str(p.get("name")), str(p.get("version") or "0.0.0"), local=local)
    for p in pkgs:
        src_key = keys[id(p)]
        groups = [("prod", p.get("dependencies") or [])]
        groups += [("optional", v) for v in (p.get("optional-dependencies") or {}).values()]
        groups += [("dev", v) for v in (p.get("dev-dependencies") or {}).values()]
        for kind, deps in groups:
            for d in deps:
                if isinstance(d, dict) and d.get("name"):
                    b.edge(src_key, str(d["name"]), kind, d.get("version"))
    if main is None:
        b.roots_without_parents()
    return b


def load_pipfile(root: Path) -> Builder:
    name, direct = project_meta(root)
    b = Builder(ECOSYSTEM, name)
    lock = read_json(root / "Pipfile.lock")
    for section, dev in (("default", False), ("develop", True)):
        for pkg, meta in (lock.get(section) or {}).items():
            version = str((meta or {}).get("version") or "")
            if version.startswith("=="):
                b.add(pkg, version[2:], dev=dev)
            else:
                b.warn("W_UNPINNED", f"{pkg} has no pinned version in Pipfile.lock; not scanned.")
    link_direct(b, direct)
    b.flat("Pipfile.lock")
    return b


def requirement_files(root: Path) -> list[Path]:
    files = sorted(root.glob("requirements*.txt")) + sorted(root.glob("requirements/*.txt"))
    files += sorted(p for p in root.glob("*requirements.txt") if p not in files)
    return files


def logical_lines(text: str) -> list[str]:
    lines, buf = [], ""
    for raw in text.splitlines():
        if raw.rstrip().endswith("\\") and not raw.lstrip().startswith("#"):
            buf += raw.rstrip()[:-1] + " "
            continue
        lines.append(buf + raw)
        buf = ""
    if buf:
        lines.append(buf)
    return lines


def is_dev_file(path: Path) -> bool:
    return bool(DEV_HINT.search(path.name.replace("requirements", "")))


def read_requirements(path: Path, root: Path, b: Builder, seen: set[Path],
                      depth: int = 0) -> tuple[list[tuple[str, list[str], bool]], list[str]]:
    """Pinned (key, via-parents, dev) entries plus unpinned names; follows -r in the project."""
    seen.add(path.resolve())
    dev = is_dev_file(path)
    entries: list[tuple[str, list[str], bool]] = []
    unpinned: list[str] = []
    via_list = False
    for line in logical_lines(read_text(path)):
        s = line.strip()
        if s.startswith("#"):
            body = s.lstrip("#").strip()
            if entries and body.startswith("via"):
                rest = body[3:].strip()
                via_list = not rest
                if rest:
                    entries[-1][1].append(rest)
            elif entries and via_list and body:
                entries[-1][1].append(body)
            continue
        via_list = False
        s = s.split(" #", 1)[0].strip()
        if not s:
            continue
        if inc_m := INCLUDE.match(s):
            inc = (path.parent / inc_m.group(1)).resolve()
            if (depth < MAX_INCLUDE_DEPTH and inc.is_relative_to(root.resolve())
                    and inc.is_file() and inc not in seen):
                sub, loose = read_requirements(inc, root, b, seen, depth + 1)
                entries += sub
                unpinned += loose
            continue
        if s.startswith("-") or "://" in s or " @ " in s:
            continue
        m = REQ.match(s)
        if not m:
            continue
        name, op, version = m.groups()
        if op in ("==", "===") and version and "*" not in version:
            entries.append((b.add(name, version, dev=dev), [], dev))
        else:
            unpinned.append(name)
    return entries, unpinned


def load_requirements(root: Path) -> Builder:
    name, direct = project_meta(root)
    b = Builder(ECOSYSTEM, name)
    declared = {norm_name(ECOSYSTEM, n) for n in direct}
    entries: list[tuple[str, list[str], bool]] = []
    unpinned: list[str] = []
    seen: set[Path] = set()
    for path in sorted(requirement_files(root), key=is_dev_file):
        if path.resolve() not in seen:
            found, loose = read_requirements(path, root, b, seen)
            entries += found
            unpinned += loose
    annotated, unattached = any(parents for _, parents, _ in entries), 0
    for key, parents, dev in entries:
        kind = "dev" if dev else "prod"
        to_root = not parents and (not declared
                                   or norm_name(ECOSYSTEM, b.nodes[key].name) in declared)
        for parent in parents:
            pname = parent.split(" (", 1)[0].strip()
            if not pname.startswith("-") and b.find(pname):
                b.edge(b.find(pname), b.nodes[key].name, "prod")
            else:
                to_root = True
        if to_root:
            b.edges.append(("", key, kind))
        elif not parents:
            unattached += 1
    if unpinned:
        sample = ", ".join(sorted(set(unpinned))[:5])
        b.warn("W_UNPINNED", f"{len(set(unpinned))} requirements are not pinned to an exact "
                             f"version and were not scanned ({sample}). Pin them with "
                             "`pip freeze > requirements.txt` or pip-compile.")
    if not b.nodes:
        b.warn("W_NOTHING_PINNED", "No requirement is pinned with ==; nothing can be scanned.")
    elif unattached:
        b.flat("requirements.txt")
    elif not annotated and not declared and len(b.nodes) > 1:
        b.warn("W_FLAT_LOCK", "requirements.txt does not say which packages are transitive; "
                              "every pinned package is treated as a direct dependency.")
    return b
