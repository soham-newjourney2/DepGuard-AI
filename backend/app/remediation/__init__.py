import json
from pathlib import Path

from app.config import Settings
from app.errors import AppError
from app.jobs import iso, utcnow, write_atomic
from app.remediation import generic
from app.remediation.batch import plan_all
from app.remediation.candidates import Planner
from app.remediation.registry import Registry
from app.scanner import Package, ScanError, make_scanner
from app.scanner.cache import DiskCache
from app.scanner.fixture import RecordedScanner


def make_registry(s: Settings) -> Registry:
    return Registry(s.registry_url, DiskCache(s.data_dir / "cache" / "npm", s.cache_ttl_h * 3600),
                    recorded=s.recorded_dir.parent / "npm",
                    offline=s.scanner == "fixture" or s.local_only)


def make_checker(s: Settings, demo: bool = False):
    """OSV re-check; after one failure it stops calling out (bundled demos use the recording)."""
    state = {"down": False}
    recorded = RecordedScanner(s.recorded_dir) if demo else None

    def from_recording(packages: list[Package], result) -> dict[str, list[str] | None]:
        return {p.label: ([v["id"] for v in result.vulns_for(p)] if recorded.known(p) else None)
                for p in packages}

    async def check(packages: list[Package]) -> dict[str, list[str] | None]:
        scanner = make_scanner(s)
        if not state["down"]:
            try:
                result = await scanner.scan(packages)
            except ScanError:
                state["down"] = True
            else:
                if isinstance(scanner, RecordedScanner):
                    return {p.label: ([v["id"] for v in result.vulns_for(p)]
                                      if scanner.known(p) else None) for p in packages}
                if result.source == "cache":
                    state["down"] = True
                return {p.label: [v["id"] for v in result.vulns_for(p)] for p in packages}
        if recorded is not None:
            try:
                return from_recording(packages, await recorded.scan(packages))
            except ScanError:
                pass
        return {p.label: None for p in packages}
    return check


def project_stack(job_dir: Path) -> str:
    try:
        return str(json.loads((job_dir / "meta.json").read_text("utf-8")).get("stack") or "npm")
    except (OSError, ValueError):
        return "npm"


def project_root(job_dir: Path) -> Path:
    try:
        rel = json.loads((job_dir / "meta.json").read_text("utf-8"))["root"]
    except (OSError, ValueError, KeyError):
        raise AppError("E_NOT_FOUND", "Project files are missing for this job.",
                       "Run the scan again.", 404) from None
    root = (job_dir / rel).resolve()
    if not root.is_relative_to(job_dir.resolve()):
        raise AppError("E_NOT_FOUND", "Project files are missing for this job.", "", 404)
    return root


async def propose(job_dir: Path, finding: dict, findings: list[dict], s: Settings,
                  registry: Registry | None = None, checker=None,
                  demo: bool = False) -> list[dict]:
    root = project_root(job_dir)
    stack = project_stack(job_dir)
    if stack != "npm":
        proposals = await generic.plan(finding, findings, root, stack,
                                       checker or make_checker(s, demo))
    else:
        graph = json.loads((job_dir / "graph.json").read_text("utf-8"))
        text = (root / "package.json").read_text("utf-8")
        planner = Planner(finding, findings, graph, text, registry or make_registry(s),
                          checker or make_checker(s, demo))
        proposals = await planner.plan()
    folder = job_dir / "proposals"
    folder.mkdir(exist_ok=True)
    now = iso(utcnow())
    for p in proposals:
        path = folder / f"{p['pid']}.json"
        if path.exists():
            p.update({k: v for k, v in json.loads(path.read_text("utf-8")).items()
                      if k in ("status", "created_at")})
        else:
            p.update(status="proposed", created_at=now)
        write_atomic(path, json.dumps(p))
    return proposals


def load_proposal(job_dir: Path, pid: str) -> dict:
    if not pid.startswith("p_") or not pid[2:].isalnum() or len(pid) != 14:
        raise AppError("E_NOT_FOUND", "Proposal not found.", "", 404)
    try:
        return json.loads((job_dir / "proposals" / f"{pid}.json").read_text("utf-8"))
    except (OSError, ValueError):
        raise AppError("E_NOT_FOUND", "Proposal not found.", "", 404) from None


async def propose_batch(job_dir: Path, findings: list[dict], s: Settings, registry=None,
                        checker=None, demo: bool = False) -> dict:
    root = project_root(job_dir)
    stack = project_stack(job_dir)
    if stack != "npm":
        plan = await generic.plan_batch(findings, root, stack, checker or make_checker(s, demo))
    else:
        graph = json.loads((job_dir / "graph.json").read_text("utf-8"))
        text = (root / "package.json").read_text("utf-8")
        plan = await plan_all(findings, graph, text, registry or make_registry(s),
                              checker or make_checker(s, demo))
    if not plan["edits"] and not plan.get("changes"):
        raise AppError("E_NO_PATCH", "No finding has an applicable fix.",
                       "Every finding lacks a safe upgrade.", 409)
    folder = job_dir / "proposals"
    folder.mkdir(exist_ok=True)
    path = folder / f"{plan['pid']}.json"
    if path.exists():
        prev = json.loads(path.read_text("utf-8"))
        plan.update(status=prev.get("status", "proposed"), created_at=prev.get("created_at"))
    else:
        plan.update(status="proposed", created_at=iso(utcnow()))
    write_atomic(path, json.dumps(plan))
    return plan
