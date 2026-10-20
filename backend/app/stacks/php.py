from pathlib import Path

from app.stacks.base import Builder, read_json

ECOSYSTEM = "Packagist"


def php_version(v: str) -> str:
    return v[1:] if v[:1] in ("v", "V") and v[1:2].isdigit() else v


def platform(name: str) -> bool:
    return "/" not in name


def load_composer(root: Path) -> Builder:
    manifest = read_json(root / "composer.json") if (root / "composer.json").is_file() else {}
    b = Builder(ECOSYSTEM, str(manifest.get("name") or root.name))
    lock = read_json(root / "composer.lock")
    sections = [(lock.get("packages") or [], False), (lock.get("packages-dev") or [], True)]
    entries = []
    for pkgs, dev in sections:
        for p in pkgs:
            if isinstance(p, dict) and p.get("name"):
                dist = (p.get("dist") or {}).get("type")
                key = b.add(str(p["name"]), php_version(str(p.get("version") or "")), dev=dev,
                            local=dist == "path")
                entries.append((key, p))
    for key, p in entries:
        for dep in p.get("require") or {}:
            if not platform(dep):
                b.edge(key, dep, "prod")
    declared = [(d, "prod") for d in manifest.get("require") or {}]
    declared += [(d, "dev") for d in manifest.get("require-dev") or {}]
    declared = [(d, k) for d, k in declared if not platform(d)]
    if not declared:
        b.roots_without_parents()
    for dep, kind in declared:
        b.edge("", dep, kind)
    return b
