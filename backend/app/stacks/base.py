import json
import tomllib
from pathlib import Path

from packaging.utils import canonicalize_name

from app.errors import AppError
from app.graph import Graph
from app.lockfile import Node


def norm_name(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return canonicalize_name(name)
    if ecosystem in ("Packagist", "NuGet"):
        return name.lower()
    return name


def bad_lock(path: Path, why: str) -> AppError:
    return AppError("E_BAD_LOCKFILE", f"{path.name} could not be parsed ({why}).",
                    f"Regenerate {path.name} with its package manager and re-upload.")


def read_text(path: Path) -> str:
    try:
        return path.read_bytes().decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise bad_lock(path, exc.__class__.__name__) from None


def read_toml(path: Path) -> dict:
    try:
        return tomllib.loads(read_text(path))
    except tomllib.TOMLDecodeError as exc:
        raise bad_lock(path, str(exc)[:80]) from None


def read_json(path: Path) -> dict:
    try:
        data = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise bad_lock(path, exc.__class__.__name__) from None
    if not isinstance(data, dict):
        raise bad_lock(path, "expected a JSON object")
    return data


def opt_toml(path: Path) -> dict:
    return read_toml(path) if path.is_file() else {}


class Builder:
    """Collects nodes and edges for lockfiles that list packages (and maybe edges) directly."""

    def __init__(self, ecosystem: str, root_name: str = "root"):
        self.ecosystem = ecosystem
        self.root = Node("", root_name or "root", "0.0.0", ecosystem=ecosystem, installed=False)
        self.nodes: dict[str, Node] = {}
        self.by_name: dict[str, str] = {}
        self.edges: list[tuple[str, str, str]] = []
        self.warnings: list[dict] = []

    def add(self, name: str, version: str, *, dev: bool = False, optional: bool = False,
            local: bool = False) -> str:
        key = f"{name}@{version}"
        node = self.nodes.get(key)
        if node is None:
            node = self.nodes[key] = Node(key, name, version, install_name=name, dev=dev,
                                          optional=optional, ecosystem=self.ecosystem,
                                          installed=not local)
        else:
            node.dev, node.optional = node.dev and dev, node.optional and optional
        self.by_name.setdefault(norm_name(self.ecosystem, name), key)
        return key

    def find(self, name: str, version: str | None = None) -> str | None:
        if version:
            key = f"{name}@{version}"
            if key in self.nodes:
                return key
            for k, n in self.nodes.items():
                if n.version == version and norm_name(self.ecosystem, n.name) == \
                        norm_name(self.ecosystem, name):
                    return k
        return self.by_name.get(norm_name(self.ecosystem, name))

    def edge(self, src: str, dep: str, kind: str = "prod", version: str | None = None) -> None:
        self.edges.append((src, self.find(dep, version) or dep, kind))

    def roots_without_parents(self, kind_of=lambda n: "dev" if n.dev else "prod") -> None:
        """Fallback when no manifest says what is direct: anything nobody depends on."""
        has_parent = {dst for _, dst, _ in self.edges}
        for key, node in self.nodes.items():
            if key not in has_parent and node.installed:
                self.edges.append(("", key, kind_of(node)))

    def warn(self, code: str, message: str) -> None:
        if all(w["code"] != code for w in self.warnings):
            self.warnings.append({"code": code, "message": message})

    def flat(self, lockname: str) -> None:
        self.warn("W_FLAT_LOCK", f"{lockname} does not record which package depends on which; "
                                 "transitive packages are scanned but their paths are unknown.")

    def graph(self) -> Graph:
        return Graph.explicit(self.root, self.nodes, self.edges, self.warnings)
