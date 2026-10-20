from collections import defaultdict, deque
from dataclasses import dataclass

from app.lockfile import Lock, Node, is_installed

RANK = {"prod": 0, "optional": 1, "peer": 2, "dev": 3}
SCOPES = list(RANK)
PATH_CAP = 20
PATH_BUDGET = 50_000


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    kind: str
    spec: str = ""
    name: str = ""


def flag_scopes(n: Node) -> set[str]:
    if n.dev:
        return {"dev"}
    if n.dev_optional:
        return {"dev", "optional"}
    flags = {s for s, on in (("optional", n.optional), ("peer", n.peer)) if on}
    return flags or {"prod"}


class Graph:
    lockfile_name = "package-lock.json"

    def __init__(self, lock: Lock):
        self.lock = lock
        self.nodes = lock.nodes
        self.out: dict[str, list[Edge]] = defaultdict(list)
        self.inn: dict[str, list[Edge]] = defaultdict(list)
        self.unresolved: list[dict] = []
        self.disagreements: list[dict] = []
        self._resolve()
        self.depth = self._depths()
        self.scope = self._scopes()
        self.path_count = self._count_paths()

    @classmethod
    def explicit(cls, root: Node, nodes: dict[str, Node], edges: list[tuple[str, str, str]],
                 warnings: list[dict] | None = None, version: int = 0) -> "Graph":
        """Graph for ecosystems whose lockfiles list dependency edges directly."""
        g = cls.__new__(cls)
        g.lock = Lock(version, root, {"": root, **nodes}, warnings or [])
        g.nodes = g.lock.nodes
        g.out, g.inn = defaultdict(list), defaultdict(list)
        g.unresolved, g.disagreements = [], []
        best: dict[tuple[str, str], tuple[str, str, str]] = {}
        for src, dst, kind in edges:
            if src in g.nodes and dst in g.nodes:
                g._add(src, dst, kind, best, "", g.nodes[dst].name)
            elif src in g.nodes:
                g.unresolved.append({"from": g.nodes[src].label, "dep": dst, "spec": "",
                                     "kind": kind})
        g._build(best)
        g.depth = g._depths()
        g.scope = g._scopes()
        g.path_count = g._count_paths()
        return g

    def lookup(self, from_key: str, name: str) -> str | None:
        d = from_key
        while True:
            cand = f"{d}/node_modules/{name}" if d else f"node_modules/{name}"
            if cand in self.nodes:
                return self.follow(cand)
            if d == "":
                return None
            i = d.rfind("/node_modules/")
            d = d[:i] if i >= 0 else ""

    def follow(self, key: str) -> str:
        seen = set()
        while self.nodes[key].link and key not in seen:
            seen.add(key)
            target = self.nodes[key].resolved
            if target not in self.nodes:
                break
            key = target
        return key

    def _add(self, src: str, dst: str, kind: str, best: dict, spec: str = "",
             name: str = "") -> None:
        if src == dst:
            return
        prev = best.get((src, dst))
        if prev is None or RANK[kind] < RANK[prev[0]]:
            best[(src, dst)] = (kind, spec, name)

    def _resolve(self) -> None:
        best: dict[tuple[str, str], tuple[str, str, str]] = {}
        for key, node in self.nodes.items():
            if node.link:
                if not is_installed(self.follow(key)):
                    self._add("", self.follow(key), "prod", best, "*", node.install_name)
                continue
            for dep, (spec, kind) in node.deps.items():
                target = self.lookup(key, dep)
                if target is not None:
                    self._add(key, target, kind, best, spec, dep)
                elif kind == "optional" or (kind == "peer" and dep in node.peer_optional):
                    continue
                else:
                    self.unresolved.append({"from": node.label, "dep": dep, "spec": spec,
                                            "kind": kind})
        self._build(best)

    def _build(self, best: dict) -> None:
        for (src, dst), (kind, spec, name) in sorted(best.items()):
            edge = Edge(src, dst, kind, spec, name)
            self.out[src].append(edge)
            self.inn[dst].append(edge)
        for edges in (*self.out.values(), *self.inn.values()):
            edges.sort(key=lambda e: (self.nodes[e.src].label, self.nodes[e.dst].label))

    def _depths(self) -> dict[str, int]:
        depth = {"": 0}
        q = deque([""])
        while q:
            u = q.popleft()
            for e in self.out[u]:
                if e.dst not in depth:
                    depth[e.dst] = depth[u] + 1
                    q.append(e.dst)
        return depth

    def _scopes(self) -> dict[str, str]:
        scope: dict[str, str] = {"": "prod"}
        for limit, name in enumerate(SCOPES):
            q = deque(k for k in scope)
            seen = set(scope)
            while q:
                u = q.popleft()
                for e in self.out[u]:
                    if RANK[e.kind] <= limit and e.dst not in seen:
                        seen.add(e.dst)
                        scope.setdefault(e.dst, name)
                        q.append(e.dst)
        for key, node in self.nodes.items():
            if key == "" or node.link:
                continue
            flags = flag_scopes(node)
            if key not in scope:
                scope[key] = min(flags, key=RANK.get)
            elif node.installed and scope[key] not in flags:
                self.disagreements.append({"package": node.label, "computed": scope[key],
                                           "lockfile": sorted(flags, key=RANK.get)})
        return scope

    def _count_paths(self) -> dict[str, int]:
        order, on_stack, done = [], set(), set()
        stack = [("", iter(self.out[""]))]
        on_stack.add("")
        back: set[Edge] = set()
        while stack:
            u, it = stack[-1]
            e = next(it, None)
            if e is None:
                stack.pop()
                on_stack.discard(u)
                done.add(u)
                order.append(u)
            elif e.dst in on_stack:
                back.add(e)
            elif e.dst not in done:
                on_stack.add(e.dst)
                stack.append((e.dst, iter(self.out[e.dst])))
        count = {"": 1}
        for u in reversed(order):
            for e in self.out[u]:
                if e not in back:
                    count[e.dst] = count.get(e.dst, 0) + count.get(u, 0)
        return count

    def direct(self, key: str) -> bool:
        return any(e.src == "" for e in self.inn[key])

    def paths_to(self, key: str, cap: int = PATH_CAP) -> list[list[str]]:
        """Simple paths root→key as labels, shortest first, deduplicated, at most `cap`."""
        if key not in self.depth:
            return []
        found: list[list[str]] = []
        seen_labels: set[tuple[str, ...]] = set()
        q = deque([(key,)])
        budget = PATH_BUDGET
        while q and len(found) < cap and budget > 0:
            path = q.popleft()
            head = path[-1]
            if head == "":
                labels = tuple(self.nodes[k].label for k in reversed(path))
                if labels not in seen_labels:
                    seen_labels.add(labels)
                    found.append(list(labels))
                continue
            for e in self.inn[head]:
                if e.src not in path and e.src in self.depth:
                    q.append((*path, e.src))
                    budget -= 1
        return found

    def info(self, key: str) -> dict:
        paths = self.paths_to(key)
        return {"scope": self.scope.get(key, "prod"), "direct": self.direct(key),
                "depth": self.depth.get(key), "paths": paths,
                "path_count": max(self.path_count.get(key, 0), len(paths))}

    def packages(self) -> dict[str, list[str]]:
        """Installed packages keyed by name@version → lockfile keys."""
        out: dict[str, list[str]] = defaultdict(list)
        for key, node in self.nodes.items():
            if key and not node.link and node.installed:
                out[node.label].append(key)
        return dict(out)

    def to_json(self) -> dict:
        nodes = []
        for key, node in self.nodes.items():
            if node.link:
                continue
            nodes.append({
                "id": key, "name": node.name, "version": node.version, "label": node.label,
                "scope": self.scope.get(key, "prod"), "depth": self.depth.get(key),
                "direct": self.direct(key), "local": key == "" or not node.installed,
                "ecosystem": node.ecosystem,
                "dependents": len(self.inn[key]), "dependencies": len(self.out[key]),
                "path_count": self.path_count.get(key, 0),
            })
        edges = [{"from": e.src, "to": e.dst, "kind": e.kind, "spec": e.spec, "name": e.name}
                 for src in sorted(self.out) for e in self.out[src]]
        return {"root": "", "nodes": nodes, "edges": edges, "unresolved": self.unresolved,
                "scope_disagreements": self.disagreements}

    def stats(self) -> dict:
        pkgs = self.packages()
        depths = [d for k, d in self.depth.items() if k]
        return {"packages": len(pkgs), "direct": sum(1 for e in self.out[""]),
                "max_depth": max(depths, default=0), "unresolved": len(self.unresolved)}
