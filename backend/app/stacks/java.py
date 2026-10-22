from pathlib import Path

from app.stacks.base import Builder, read_text

ECOSYSTEM = "Maven"


def load_gradle(root: Path) -> Builder:
    b = Builder(ECOSYSTEM, root.name)
    for raw in read_text(root / "gradle.lockfile").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coords, _, configs = line.partition("=")
        parts = coords.split(":")
        if len(parts) != 3:
            continue
        group, artifact, version = parts
        dev = bool(configs) and all(c.startswith("test") for c in configs.split(","))
        b.add(f"{group}:{artifact}", version, dev=dev)
    b.flat("gradle.lockfile")
    return b
