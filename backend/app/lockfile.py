from dataclasses import dataclass, field

DEP_FIELDS = (("dependencies", "prod"), ("optionalDependencies", "optional"),
              ("peerDependencies", "peer"))


@dataclass
class Node:
    key: str
    name: str
    version: str
    install_name: str = ""
    dev: bool = False
    optional: bool = False
    dev_optional: bool = False
    peer: bool = False
    link: bool = False
    resolved: str = ""
    deps: dict[str, tuple[str, str]] = field(default_factory=dict)
    ecosystem: str = "npm"
    installed: bool = True
    peer_optional: set[str] = field(default_factory=set)

    @property
    def label(self) -> str:
        return "root" if self.key == "" else f"{self.name}@{self.version}"


@dataclass
class Lock:
    version: int
    root: Node
    nodes: dict[str, Node]
    warnings: list[dict] = field(default_factory=list)


def install_name(key: str) -> str:
    return key.rsplit("node_modules/", 1)[-1] if "node_modules/" in key else key.rsplit("/", 1)[-1]


def is_installed(key: str) -> bool:
    return key == "" or key.startswith("node_modules/") or "/node_modules/" in key


def make_node(key: str, entry: dict, root: bool = False) -> Node:
    inst = install_name(key)
    node = Node(
        key=key,
        name=str(entry.get("name") or inst or "root"),
        version=str(entry.get("version") or "0.0.0"),
        install_name=inst,
        dev=bool(entry.get("dev")),
        optional=bool(entry.get("optional")),
        dev_optional=bool(entry.get("devOptional")),
        peer=bool(entry.get("peer")),
        link=bool(entry.get("link")),
        resolved=str(entry.get("resolved") or ""),
        installed=key != "" and is_installed(key),
    )
    fields = DEP_FIELDS + ((("devDependencies", "dev"),) if root else ())
    for fname, kind in fields:
        specs = entry.get(fname) or {}
        if isinstance(specs, dict):
            for dep, spec in specs.items():
                node.deps.setdefault(str(dep), (str(spec), kind))
    meta = entry.get("peerDependenciesMeta") or {}
    if isinstance(meta, dict):
        node.peer_optional = {k for k, v in meta.items()
                              if isinstance(v, dict) and v.get("optional")}
    return node


def parse(lockfile: dict, manifest: dict | None = None) -> Lock:
    packages = lockfile.get("packages")
    if not isinstance(packages, dict):
        packages = {}
    root_entry = packages.get("") if isinstance(packages.get(""), dict) else {}
    if not root_entry and manifest:
        root_entry = manifest
    root = make_node("", {**root_entry, "name": root_entry.get("name") or "root"}, root=True)
    nodes: dict[str, Node] = {"": root}
    warnings: list[dict] = []
    workspace = bool(root_entry.get("workspaces"))
    for key, entry in packages.items():
        if key == "" or not isinstance(entry, dict) or not isinstance(key, str):
            continue
        node = make_node(key, entry)
        nodes[key] = node
        if node.link or not is_installed(key):
            workspace = True
    if workspace:
        warnings.append({"code": "W_WORKSPACES", "message":
                         "Workspaces or linked packages detected; links are followed, "
                         "workspace packages are analysed as part of the root graph."})
    return Lock(int(lockfile.get("lockfileVersion") or 0), root, nodes, warnings)
