"""pnpm-lock.yaml reader (lockfile v5.x, v6 and v9, single project or workspace)."""

import re
from pathlib import Path

from app.stacks.base import Builder, bad_lock, read_text, read_yaml

ECOSYSTEM = "npm"
KINDS = {"dependencies": "prod", "optionalDependencies": "optional",
         "devDependencies": "dev"}
PEER = re.compile(r"[(_].*$")


def clean_version(v: object) -> str | None:
    """'4.17.1(react@18.2.0)' → '4.17.1'; links and file: refs → None."""
    s = str(v or "")
    if not s or s.startswith(("link:", "file:", "workspace:")):
        return None
    return PEER.sub("", s) or None


def split_key(key: str) -> tuple[str, str] | None:
    """'/express@4.17.1', 'express@4.17.1', '/express/4.17.1' or '/@a/b@1.0.0(x)' → name, ver."""
    k = PEER.sub("", key.lstrip("/"))
    at = k.rfind("@")
    if at > 0:
        return k[:at], k[at + 1:]
    if "/" in k:
        name, _, ver = k.rpartition("/")
        return name, ver
    return None


def importer_deps(block: dict) -> list[tuple[str, str, str]]:
    out = []
    for section, kind in KINDS.items():
        for name, spec in (block.get(section) or {}).items():
            version = spec.get("version") if isinstance(spec, dict) else spec
            v = clean_version(version)
            if v is not None:
                out.append((name, v, kind))
    return out


def load_pnpm(root: Path) -> Builder:
    path = root / "pnpm-lock.yaml"
    text = read_text(path)
    try:
        doc = read_yaml(path, text)
    except ValueError as exc:
        raise bad_lock(path, str(exc)[:80]) from None
    b = Builder(ECOSYSTEM, root.name)
    packages = doc.get("packages") or {}
    snapshots = doc.get("snapshots") or {}
    for key, entry in {**packages, **snapshots}.items():
        nv = split_key(str(key))
        if nv is None:
            continue
        meta = entry or {}
        b.add(nv[0], nv[1], dev=bool(meta.get("dev")), optional=bool(meta.get("optional")))
    graph_source = snapshots or packages
    for key, body in graph_source.items():
        nv = split_key(str(key))
        if nv is None:
            continue
        src = b.find(*nv)
        for section in ("dependencies", "optionalDependencies"):
            for dep, ver in ((body or {}).get(section) or {}).items():
                v = clean_version(ver)
                if v is not None:
                    b.edge(src, dep, "optional" if section.startswith("optional") else "prod",
                           version=v)
    importers = doc.get("importers") or {".": doc}
    for where, block in importers.items():
        src = ""
        if where != ".":
            src = b.add(str(where), "0.0.0-workspace", local=True)
            b.edges.append(("", src, "prod"))
        for name, version, kind in importer_deps(block or {}):
            b.edge(src, name, kind, version=version)
    return b
