import asyncio
import json
import logging
import shutil
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from app.config import Settings
from app.graph import Graph
from app.jobs import PROPOSAL_TRANSITIONS, check_transition, iso, utcnow, write_atomic
from app.lockfile import parse as parse_lock
from app.prioritize import enrich
from app.remediation import patch
from app.remediation.candidates import split_label
from app.scanner import Package, ScanError, make_scanner
from app.scanner.fixture import RecordedScanner
from app.scanner.normalize import normalize
from app.security import redact
from app.verify.modes import (
    SKIP,
    DockerExecutor,
    LocalExecutor,
    MockExecutor,
    StageResult,
    sample_matches,
)

log = logging.getLogger("depguard.verify")
LOG_CAP = 200 * 1024
LINE_CAP = 4000
TAIL_LINES = 80
LOCK_DIFF_LINES = 600
NO_TEST = "no test specified"
DEMO_LOCAL_LABEL = "Verification ran without container isolation (bundled sample only)."
TESTS_LABEL = "Tests exited 0. Passing tests are evidence, not a guarantee of no regressions."


class StageLog:
    """Redacted, size-capped log for one stage; keeps the tail when it overflows."""

    def __init__(self, stage: str, emit: Callable[[dict], None]):
        self.stage = stage
        self.emit = emit
        self.lines: deque[str] = deque()
        self.size = 0
        self.truncated = False

    def add(self, line: str) -> None:
        line = redact(line)[:LINE_CAP]
        self.lines.append(line)
        self.size += len(line) + 1
        while self.size > LOG_CAP and self.lines:
            self.size -= len(self.lines.popleft()) + 1
            self.truncated = True
        self.emit({"type": "log", "data": {"stage": self.stage, "text": line}})

    def text(self) -> str:
        return ("[earlier output truncated]\n" if self.truncated else "") + "\n".join(self.lines)


@dataclass
class Verification:
    job_id: str
    pid: str
    job: dict
    job_dir: Path
    project: Path
    proposal: dict
    findings: list[dict]
    settings: Settings
    publish: Callable[[dict], None]
    result: dict = field(default_factory=dict)

    @property
    def dir(self) -> Path:
        return self.job_dir / "verify" / self.pid

    def emit(self, type_: str, data: dict) -> None:
        self.publish({"type": type_, "data": data, "ts": iso(utcnow())})

    def set_status(self, status: str, **extra) -> None:
        check_transition(PROPOSAL_TRANSITIONS, self.proposal["status"], status)
        self.proposal["status"] = status
        save_proposal(self.job_dir, self.proposal)
        self.result.update(status=status, **extra)
        self.save()
        self.emit("status", {"status": status, **extra})

    def save(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        write_atomic(self.dir / "result.json", json.dumps(self.result))


def save_proposal(job_dir: Path, proposal: dict) -> None:
    path = job_dir / "proposals" / f"{proposal['pid']}.json"
    write_atomic(path, json.dumps(proposal))


async def pick_executor(v: Verification):
    mode = v.settings.verify_mode
    if mode == "off":
        return None, "off", "Verification is turned off on this server."
    if mode == "mock":
        return MockExecutor(v.proposal["changes"]), "mock", None
    if v.settings.local_only:
        return None, mode, ("Local-only mode: verification needs the npm registry, so it is "
                            "disabled; only scanner calls may leave this machine.")
    if mode in ("auto", "docker") and await DockerExecutor.available():
        return DockerExecutor(), "docker", None
    if mode == "docker":
        return None, "docker", "Docker with the depguard-worker image is not available."
    is_sample = v.job["source"] == "demo" and await asyncio.to_thread(
        sample_matches, v.project, v.settings.samples_dir, v.job["filename"])
    if is_sample:
        return LocalExecutor(v.settings.data_dir / "cache" / "npm-local"), "demo-local", None
    return None, mode, ("No isolated runner is available: Docker is missing and only the "
                        "bundled samples may run without a container.")


def prepare(v: Verification) -> Path:
    work = v.dir / "work"
    shutil.rmtree(work, ignore_errors=True)
    shutil.copytree(v.project, work, ignore=lambda d, names: [n for n in names if n in SKIP])
    manifest = work / "package.json"
    text = manifest.read_text("utf-8")
    manifest.write_text(patch.apply(text, v.proposal.get("edits") or []), encoding="utf-8")
    return work


def has_tests(work: Path) -> bool:
    try:
        script = (json.loads((work / "package.json").read_text("utf-8")).get("scripts") or {})
    except ValueError:
        return False
    test = script.get("test") or ""
    return bool(test.strip()) and NO_TEST not in test


def tree_versions(graph: Graph) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for label in graph.packages():
        name, version = split_label(label)
        out.setdefault(name, set()).add(version)
    return out


def tree_delta(before: Graph, after: Graph) -> dict:
    a, b = tree_versions(before), tree_versions(after)
    changed = [{"pkg": n, "from": sorted(a[n]), "to": sorted(b[n])}
               for n in sorted(a.keys() & b.keys()) if a[n] != b[n]]
    return {"changed": changed, "added": sorted(f"{n}@{v}" for n in b.keys() - a.keys()
                                                for v in b[n]),
            "removed": sorted(f"{n}@{v}" for n in a.keys() - b.keys() for v in a[n])}


def key(f: dict) -> tuple[str, str]:
    return f["advisory"]["id"], f["package"]["name"]


def label(f: dict) -> dict:
    return {"advisory": f["advisory"]["id"], "severity": f["advisory"]["severity"]["label"],
            "package": f"{f['package']['name']}@{f['package']['version']}"}


def compare(before: list[dict], after: list[dict], targets: list[dict]) -> dict:
    b_keys, a_keys = {key(f) for f in before}, {key(f) for f in after}
    return {
        "before": len(before), "after": len(after),
        "target_resolved": bool(targets) and all(key(t) not in a_keys for t in targets),
        "resolved": [label(f) for f in before if key(f) not in a_keys],
        "introduced": [label(f) for f in after if key(f) not in b_keys],
        "residual": [label(f) for f in after if key(f) in b_keys],
    }


async def run_stage(v: Verification, executor, stage: str, work: Path, timeout: float) -> dict:
    slog = StageLog(stage, lambda e: v.emit(e["type"], e["data"]))
    started, t0 = iso(utcnow()), time.perf_counter()
    v.emit("stage", {"stage": stage, "state": "start"})
    try:
        res: StageResult = await executor.run(stage, work, timeout, slog.add, v.pid[2:10])
    except Exception as exc:
        log.exception("stage %s crashed", stage)
        res = StageResult(None, infra_error=str(exc))
    ms = round((time.perf_counter() - t0) * 1000)
    status = ("error" if res.infra_error else "timed_out" if res.timed_out
              else "passed" if res.exit_code == 0 else "failed")
    record = {"name": stage, "status": status, "exit_code": res.exit_code, "started": started,
              "finished": iso(utcnow()), "duration_ms": ms, "error": res.infra_error,
              "log": slog.text(), "log_truncated": slog.truncated}
    (v.dir / f"{stage}.log").write_text(slog.text(), encoding="utf-8")
    v.emit("stage", {"stage": stage, "state": "done", "status": status,
                     "exit_code": res.exit_code, "duration_ms": ms})
    return record


async def rescan(v: Verification, work: Path) -> dict:
    old_lock = json.loads((v.project / "package-lock.json").read_text("utf-8"))
    new_text = (work / "package-lock.json").read_text("utf-8")
    new_lock = json.loads(new_text)
    manifest = json.loads((work / "package.json").read_text("utf-8"))
    before_graph = Graph(parse_lock(old_lock))
    after_graph = Graph(parse_lock(new_lock, manifest))
    pkgs = sorted({Package(after_graph.nodes[k[0]].name, after_graph.nodes[k[0]].version,
                            after_graph.nodes[k[0]].ecosystem)
                   for k in after_graph.packages().values()})
    notes: list[str] = []
    try:
        scan = await asyncio.wait_for(
            make_scanner(v.settings).scan(pkgs, work / "package-lock.json"),
            v.settings.scan_timeout_s)
    except (ScanError, TimeoutError):
        if v.job["source"] != "demo":
            raise
        scan = await recorded_rescan(v, pkgs, after_graph, notes)
    after = enrich(normalize(scan, after_graph))
    ids = set(v.proposal.get("finding_ids") or [v.proposal["finding_id"]])
    targets = [f for f in v.findings if f["id"] in ids]
    old_text = (v.project / "package-lock.json").read_text("utf-8")
    lock_diff = patch.unified(old_text, new_text, "package-lock.json").splitlines()
    (v.dir / "findings.after.json").write_text(json.dumps(after), encoding="utf-8")
    if scan.source == "cache" and not notes:
        notes.append(f"Rescan used cached scan data from {scan.started} — live scanner "
                     "unavailable.")
    return {
        "notes": notes,
        "scan": {"scanner": scan.scanner.get("name"), "source": scan.source,
                 "ts": scan.finished},
        "comparison": compare(v.findings, after, targets),
        "tree_delta": tree_delta(before_graph, after_graph),
        "lock_diff": "\n".join(lock_diff[:LOCK_DIFF_LINES]),
        "lock_diff_truncated": len(lock_diff) > LOCK_DIFF_LINES,
    }


async def recorded_rescan(v: Verification, pkgs: list[Package], graph: Graph,
                         notes: list[str]):
    """Bundled demos only: rescan from the recording, refusing if the target is not covered."""
    recorded = RecordedScanner(v.settings.recorded_dir, source="cache")
    scan = await recorded.scan(pkgs)
    unknown = [p for p in pkgs if not recorded.known(p)]
    ids = set(v.proposal.get("finding_ids") or [v.proposal["finding_id"]])
    targets = {f["package"]["name"] for f in v.findings if f["id"] in ids}
    missing = [p.label for p in unknown if p.name in targets]
    if missing:
        raise ScanError(f"{', '.join(missing)} is not in the recorded scan, so it could not be "
                        "re-checked offline")
    notes.append(f"Rescan used the recorded scan from {scan.started} — live scanner unavailable.")
    if unknown:
        notes.append(f"{len(unknown)} package versions in the new tree are not in the recording "
                     "and are shown without advisories.")
    return scan


def finish(v: Verification, status: str, reason: str | None) -> None:
    v.result["finished"] = iso(utcnow())
    v.set_status(status, reason=reason)
    v.emit("done" if status == "verified" else "error", {"status": status, "reason": reason})


async def verify(v: Verification) -> dict:
    deadline = time.monotonic() + v.settings.verify_timeout_s
    v.result = {"pid": v.pid, "finding_id": v.proposal["finding_id"], "status": "approved",
                "started": iso(utcnow()), "finished": None, "stages": [], "labels": [],
                "mode": None, "tests": {"present": None, "exit_code": None}}
    executor, mode, reason = await pick_executor(v)
    v.result["mode"] = mode
    if mode == "demo-local":
        v.result["labels"].append(DEMO_LOCAL_LABEL)
    if mode == "mock":
        v.result["labels"].append("Simulated verification (test mode): nothing was installed.")
    if executor is None:
        finish(v, "unable_to_verify", reason)
        return v.result
    work = await asyncio.to_thread(prepare, v)
    try:
        v.set_status("resolving")
        stage = await run_stage(v, executor, "resolve", work, deadline - time.monotonic())
        v.result["stages"].append(stage)
        if stage["status"] in ("error", "timed_out"):
            finish(v, "unable_to_verify", stage["error"] or "Dependency resolution timed out.")
            return v.result
        if stage["status"] == "failed":
            finish(v, "verify_failed",
                   f"npm could not resolve the new dependency tree (exit {stage['exit_code']}).")
            return v.result
        v.set_status("testing")
        present = has_tests(work)
        stage = await run_stage(v, executor, "test", work, max(5, deadline - time.monotonic()))
        v.result["stages"].append(stage)
        v.result["tests"] = {"present": present, "exit_code": stage["exit_code"]}
        if stage["status"] in ("error", "timed_out"):
            finish(v, "unable_to_verify", stage["error"] or "The test stage timed out.")
            return v.result
        v.set_status("rescanning")
        try:
            v.result.update(await rescan(v, work))
            v.result["labels"] += v.result.pop("notes", [])
        except (ScanError, TimeoutError, OSError, ValueError) as exc:
            finish(v, "unable_to_verify", f"Rescan failed: {exc or 'timed out'}")
            return v.result
        comparison = v.result["comparison"]
        if stage["exit_code"] == 0 and present:
            v.result["labels"].append(TESTS_LABEL)
        if not present:
            v.result["labels"].append("No test script: nothing beyond dependency resolution "
                                      "was exercised.")
        if not comparison["target_resolved"]:
            finish(v, "verify_failed", "The advisory still matches after the change.")
        elif stage["exit_code"] != 0:
            finish(v, "verify_failed", f"Tests failed (exit {stage['exit_code']}).")
        else:
            finish(v, "verified", None)
        return v.result
    finally:
        await asyncio.to_thread(shutil.rmtree, work / "node_modules", True)
        await asyncio.to_thread(shutil.rmtree, work / ".npm-cache", True)
