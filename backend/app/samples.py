"""Load a project's dependency graph and its package list."""

import json
import shutil
from pathlib import Path

from app.graph import Graph
from app.lockfile import parse
from app.scanner.base import Package
from app.stacks import found_in

# Demos and fixtures store manifests as <name>.sample so GitHub's dependency graph skips them.
STORED = ".sample"


def real_name(rel: Path) -> Path:
    return rel.with_name(rel.name.removesuffix(STORED)) if rel.name.endswith(STORED) else rel


def checkout(src: Path, dst: Path) -> Path:
    """Copy a bundled folder to dst with every manifest under its real name."""
    for path in sorted(src.rglob("*")):
        if path.is_file():
            out = dst / real_name(path.relative_to(src))
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, out)
    return dst


def is_npm(project: Path) -> bool:
    return (project / "package-lock.json").is_file()


def load_graph(project: Path) -> Graph:
    if not is_npm(project):
        return found_in(project)[0].load(project)
    lock = json.loads((project / "package-lock.json").read_text(encoding="utf-8"))
    manifest = json.loads((project / "package.json").read_text(encoding="utf-8"))
    return Graph(parse(lock, manifest))


def packages(graph: Graph) -> list[Package]:
    return sorted({Package(graph.nodes[k[0]].name, graph.nodes[k[0]].version,
                            graph.nodes[k[0]].ecosystem)
                   for k in graph.packages().values()})
