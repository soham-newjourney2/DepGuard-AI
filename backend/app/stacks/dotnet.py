from pathlib import Path

from app.stacks.base import Builder, read_json

ECOSYSTEM = "NuGet"


def load_nuget(root: Path) -> Builder:
    proj = next(iter(sorted(root.glob("*.csproj")) + sorted(root.glob("*.fsproj"))), None)
    b = Builder(ECOSYSTEM, proj.stem if proj else root.name)
    lock = read_json(root / "packages.lock.json")
    entries = []
    for deps in (lock.get("dependencies") or {}).values():
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict):
                continue
            kind = meta.get("type")
            version = str(meta.get("resolved") or "")
            if kind == "Project" or not version:
                continue
            key = b.add(name, version)
            entries.append((key, meta))
            if kind == "Direct":
                b.edges.append(("", key, "prod"))
    for key, meta in entries:
        for dep in meta.get("dependencies") or {}:
            if b.find(dep):
                b.edge(key, dep)
    return b
