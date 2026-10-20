from pathlib import Path

from app.stacks.base import Builder, opt_toml, read_toml

ECOSYSTEM = "crates.io"


def load_cargo(root: Path) -> Builder:
    manifest = opt_toml(root / "Cargo.toml")
    pkg_name = str((manifest.get("package") or {}).get("name") or "")
    b = Builder(ECOSYSTEM, pkg_name or root.name)
    lock = read_toml(root / "Cargo.lock")
    pkgs = [p for p in lock.get("package") or [] if isinstance(p, dict)]
    keys = {}
    for p in pkgs:
        name, version = str(p.get("name")), str(p.get("version"))
        source = str(p.get("source") or "")
        if pkg_name and name == pkg_name and not source:
            keys[id(p)] = ""
            continue
        keys[id(p)] = b.add(name, version, local=not source.startswith("registry+"))
    dev_names = set(manifest.get("dev-dependencies") or {})
    for p in pkgs:
        src = keys[id(p)]
        for dep in p.get("dependencies") or []:
            parts = str(dep).split()
            kind = "dev" if src == "" and parts[0] in dev_names else "prod"
            b.edge(src, parts[0], kind, parts[1] if len(parts) > 1 else None)
    if not pkg_name:
        for p in pkgs:
            if not p.get("source"):
                b.edges.append(("", keys[id(p)], "prod"))
    return b
