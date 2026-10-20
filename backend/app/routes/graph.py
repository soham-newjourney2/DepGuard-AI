import json
from collections import defaultdict, deque

from fastapi import APIRouter, Request

from app.errors import AppError
from app.routes.findings import load_findings
from app.scanner.normalize import SEV_ORDER

router = APIRouter(prefix="/api/jobs", tags=["graph"])
FOCUS_CAP = 300
FULL_CAP = 1500
ROOT_ID = "#root"


def nid(key: str) -> str:
    return ROOT_ID if key == "" else key


def ancestors(targets: set[str], parents: dict[str, set[str]]) -> set[str]:
    seen, q = set(targets), deque(targets)
    while q:
        for p in parents[q.popleft()]:
            if p not in seen:
                seen.add(p)
                q.append(p)
    return seen


def build(graph: dict, findings: list[dict], mode: str, focus: str | None) -> dict:
    nodes = {n["id"]: n for n in graph["nodes"]}
    parents: dict[str, set[str]] = defaultdict(set)
    children: dict[str, set[str]] = defaultdict(set)
    for e in graph["edges"]:
        parents[e["to"]].add(e["from"])
        children[e["from"]].add(e["to"])
    by_label: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_label[f"{f['package']['name']}@{f['package']['version']}"].append(f)

    warnings: list[str] = []
    if focus:
        f = next((f for f in findings if f["id"] == focus), None)
        if f is None:
            raise AppError("E_NOT_FOUND", "Finding not found.", "", 404)
        label = f"{f['package']['name']}@{f['package']['version']}"
        targets = {k for k, n in nodes.items() if n["label"] == label}
    else:
        targets = {k for k, n in nodes.items() if n["label"] in by_label}

    if mode == "full":
        order = sorted(nodes, key=lambda k: (nodes[k]["depth"] is None, nodes[k]["depth"] or 0, k))
        keep = order[:FULL_CAP]
        if len(order) > FULL_CAP:
            warnings.append(f"Graph truncated to the {FULL_CAP} shallowest of {len(order)} "
                            "packages.")
    else:
        core = ancestors(targets, parents) | {""}
        hop = {c for t in targets for c in children[t]} - core
        ranked = sorted(core, key=lambda k: (k != "", k not in targets,
                                             nodes.get(k, {}).get("depth") or 0, k))
        keep = (ranked + sorted(hop))[:FOCUS_CAP]
        if len(core) + len(hop) > FOCUS_CAP:
            warnings.append(f"Focus view truncated to {FOCUS_CAP} of {len(core) + len(hop)} "
                            "packages.")
    kept = set(keep) & set(nodes)

    out_nodes = []
    for k in keep:
        if k not in nodes:
            continue
        n = nodes[k]
        fs = sorted(by_label.get(n["label"], []), key=lambda f: -f["priority"]["score"])
        worst = max((f["advisory"]["severity"]["label"] for f in fs), key=SEV_ORDER.get,
                    default=None)
        out_nodes.append({
            "id": nid(k), "label": n["label"], "name": n["name"], "version": n["version"],
            "scope": n["scope"], "depth": n["depth"], "direct": n["direct"],
            "dependents": n["dependents"], "root": k == "", "local": n["local"],
            "severity": worst, "findings": [f["id"] for f in fs], "target": k in targets,
        })
    edges = [{"source": nid(e["from"]), "target": nid(e["to"]), "kind": e["kind"]}
             for e in graph["edges"] if e["from"] in kept and e["to"] in kept]
    return {"mode": mode, "focus": focus, "nodes": out_nodes, "edges": edges,
            "total_nodes": len(nodes), "truncated": bool(warnings), "warnings": warnings}


@router.get("/{job_id}/graph")
def get_graph(job_id: str, request: Request, mode: str = "focus", focus: str | None = None):
    if mode not in ("focus", "full"):
        raise AppError("E_INVALID", f"Unknown mode {mode!r}.", "Use focus or full.", 422)
    _, findings = load_findings(request, job_id)
    path = request.app.state.store.job_dir(job_id) / "graph.json"
    try:
        graph = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        raise AppError("E_NOT_FOUND", "Graph is missing for this job.", "Run the scan again.",
                       404) from None
    return build(graph, findings, mode, focus)
