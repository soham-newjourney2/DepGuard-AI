import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from app import flatedges
from app import policy as policy_mod
from app import risks as risks_mod
from app.config import Settings
from app.errors import AppError
from app.exploit import Signals, classify, cves_of, make_feeds
from app.graph import Graph
from app.intake import Intake, extract_project
from app.jobs import IllegalTransition, JobStore
from app.lockfile import parse as parse_lock
from app.prioritize import enrich
from app.reachability import LABELS, annotate
from app.samples import packages as sample_packages
from app.scanner import ScanError, ScanResult, make_scanner
from app.scanner.normalize import SEV_ORDER, normalize
from app.stacks import BY_ID

log = logging.getLogger("depguard.pipeline")
PENDING = "pending.zip"


@dataclass
class Context:
    job_id: str
    archive: Path
    settings: Settings
    store: JobStore
    project: str | None = None
    intake: Intake | None = None
    graph: Graph | None = None
    scan: ScanResult | None = None

    @property
    def dir(self) -> Path:
        return self.store.job_dir(self.job_id)

    def log(self, message: str, level: str = "info") -> None:
        self.store.emit_log(self.job_id, {"message": message, "level": level})


async def extracting(ctx: Context) -> None:
    try:
        ctx.intake = await asyncio.to_thread(extract_project, ctx.archive, ctx.dir / "src",
                                             ctx.settings, ctx.project)
    finally:
        if (ctx.intake and ctx.archive.is_file()
                and any(w["code"] == "W_MULTIPLE_PROJECTS" for w in ctx.intake.warnings)):
            ctx.archive.replace(ctx.dir / PENDING)
        ctx.archive.unlink(missing_ok=True)
    i = ctx.intake
    for w in i.warnings:
        ctx.store.update(ctx.job_id, warning=w)
    stack = BY_ID[i.stack]
    ctx.store.update(ctx.job_id, summary={"files": i.files, "lockfile_version": i.lockfile_version,
                                          "stack": stack.id, "ecosystem": stack.ecosystem,
                                          "language": stack.language})
    await asyncio.to_thread(write_json, ctx.dir / "meta.json",
                            {"root": i.root.relative_to(ctx.dir).as_posix(), "stack": stack.id})
    if stack.id == "npm":
        ctx.log(f"Extracted {i.files} files; package.json + package-lock.json "
                f"v{i.lockfile_version}")
    else:
        ctx.log(f"Extracted {i.files} files; {stack.language} project ({stack.lockfile})")


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")


def add_warning(ctx: Context, code: str, message: str) -> None:
    if all(w.get("code") != code for w in ctx.store.get(ctx.job_id)["warnings"]):
        ctx.store.update(ctx.job_id, warning={"code": code, "message": message})


async def parsing(ctx: Context) -> None:
    if ctx.intake.stack == "npm":
        lock = parse_lock(ctx.intake.lockfile, ctx.intake.manifest)
        g = ctx.graph = await asyncio.to_thread(Graph, lock)
    else:
        g = ctx.graph = await asyncio.to_thread(BY_ID[ctx.intake.stack].load, ctx.intake.root)
        provider = flatedges.make_provider(ctx.settings)
        if provider is not None:
            inferred, note = await flatedges.infer(g, ctx.intake.stack, provider)
            if inferred is not None:
                g = ctx.graph = inferred
            if note:
                ctx.log(note, "info" if inferred is not None else "warn")
        lock = g.lock
    await asyncio.to_thread(write_json, ctx.dir / "graph.json", g.to_json())
    stats = g.stats()
    ctx.store.update(ctx.job_id, summary=stats)
    for w in lock.warnings:
        add_warning(ctx, w["code"], w["message"])
    if g.unresolved:
        u = g.unresolved[0]
        add_warning(ctx, "W_UNRESOLVED",
                    f"{len(g.unresolved)} declared dependencies are missing from the lockfile "
                    f"(e.g. {u['from']} → {u['dep']}@{u['spec']}).")
    if g.disagreements:
        d = g.disagreements[0]
        ctx.log(f"Scope differs from lockfile flags for {len(g.disagreements)} packages "
                f"(e.g. {d['package']}: computed {d['computed']}, lockfile "
                f"{'/'.join(d['lockfile'])})", "warn")
    ctx.log(f"Resolved {stats['packages']} packages · {stats['direct']} direct · "
            f"max depth {stats['max_depth']}")


def osv_unavailable(reason: str) -> AppError:
    if reason.startswith("OSV unavailable (") and reason.endswith(")"):
        reason = reason[len("OSV unavailable ("):-1]
    return AppError("E_SCAN_UNAVAILABLE", f"Could not connect to OSV ({reason}).",
                    "Check your internet connection and retry.", 503)


async def scanning(ctx: Context) -> None:
    s = ctx.settings
    packages = sample_packages(ctx.graph)
    scanner = make_scanner(s)
    ctx.log(f"Querying {scanner.name} for {len(packages)} packages")
    lockfile = ctx.intake.root / BY_ID[ctx.intake.stack].lockfile
    try:
        result = await asyncio.wait_for(scanner.scan(packages, lockfile), s.scan_timeout_s)
    except (ScanError, TimeoutError) as exc:
        raise osv_unavailable(str(exc) or "timed out") from None
    if result.source == "cache" and ctx.store.get(ctx.job_id)["source"] == "demo":
        raise osv_unavailable(result.notes[0].removeprefix("Live scan failed: ")
                              if result.notes else "live scan failed")
    for note in result.notes:
        ctx.log(note, "warn")
    if result.source == "cache":
        add_warning(ctx, "W_CACHED_SCAN",
                    f"Cached scan from {result.started} — live scanner unavailable.")
    ctx.scan = result
    await asyncio.to_thread(write_json, ctx.dir / "scan.json", result.to_json())
    hits = sum(1 for r in result.raw["results"] if r["vulns"])
    ctx.store.update(ctx.job_id, summary={"scan": {
        "scanner": result.scanner.get("name"), "version": result.scanner.get("version"),
        "source": result.source, "ts": result.finished if result.source == "live"
        else result.started}})
    ctx.log(f"{hits} of {len(packages)} packages have known advisories ({result.source})")


async def exploit_signals(ctx: Context, findings: list[dict]) -> None:
    """KEV + EPSS per finding; the feeds can degrade the labels but never fail the scan."""
    if not findings:
        return
    cves = sorted({c for f in findings for c in cves_of(f["advisory"])})
    try:
        sig = await asyncio.wait_for(make_feeds(ctx.settings).lookup(cves), 60)
    except Exception as exc:
        log.warning("exploit feeds failed: %s", exc.__class__.__name__)
        sig = Signals(None, None, {"kev": "unavailable", "epss": "unavailable"},
                      [f"exploit feeds failed ({exc.__class__.__name__})"])
    for f in findings:
        f["exploit"] = classify(cves_of(f["advisory"]), sig)
    for note in sig.notes:
        ctx.log(note, "warn")
    if sig.off:
        ctx.log("Exploit signals are off (CISA KEV / EPSS not checked)")
        return
    if sig.degraded:
        add_warning(ctx, "W_EXPLOIT_UNAVAILABLE",
                    "CISA KEV or EPSS could not be reached; exploitation status is shown as "
                    "unavailable where it could not be checked.")
    status = [f["exploit"]["status"] for f in findings]
    high = sum(1 for f in findings if (f["exploit"]["epss"] or {}).get("percentile", 0) >= 0.8)
    ctx.log(f"Exploit signals: {status.count('listed')} in CISA KEV · {high} EPSS ≥80th "
            f"percentile · {status.count('unknown')} without a CVE")


async def supply_chain(ctx: Context, findings: list[dict]) -> list[dict]:
    inputs = risks_mod.Inputs(ctx.intake.root, ctx.intake.stack, ctx.graph, findings,
                              ctx.store.get(ctx.job_id)["source"])
    items, failed = await asyncio.to_thread(risks_mod.collect, inputs)
    await asyncio.to_thread(write_json, ctx.dir / "risks.json", items)
    counts = risks_mod.counts(items)
    ctx.store.update(ctx.job_id, summary={"risk_counts": counts})
    for name in failed:
        add_warning(ctx, "W_RISK_CHECK_FAILED", f"The {name} supply-chain check failed and was "
                                                "skipped; its risks are not shown.")
    ctx.log("Supply-chain checks: " + (", ".join(f"{n} {k}" for k, n in counts["by_kind"].items()
                                                 if n) or "no risk signals"))
    return items


async def analyzing(ctx: Context) -> None:
    findings = await asyncio.to_thread(normalize, ctx.scan, ctx.graph)
    idx = await asyncio.to_thread(annotate, findings, ctx.intake.root,
                                  BY_ID[ctx.intake.stack].ecosystem)
    await exploit_signals(ctx, findings)
    findings = enrich(findings)
    labels = [f["reachability"]["label"] for f in findings]
    ctx.log(f"Import scan: {idx.files} source files; " + ", ".join(
        f"{labels.count(lab)} {lab.lower()}" for lab in LABELS if labels.count(lab)))
    await asyncio.to_thread(write_json, ctx.dir / "findings.json", findings)
    risks = await supply_chain(ctx, findings)
    by_sev = dict.fromkeys(sorted(SEV_ORDER, key=SEV_ORDER.get, reverse=True), 0)
    by_band = dict.fromkeys(("P1", "P2", "P3", "P4"), 0)
    for f in findings:
        by_sev[f["advisory"]["severity"]["label"]] += 1
        by_band[f["priority"]["band"]] += 1
    policy, source, warning = policy_mod.load(ctx.intake.root)
    if warning:
        add_warning(ctx, "W_POLICY", warning)
    verdict = policy_mod.evaluate(findings, policy, source, risks)
    await asyncio.to_thread(write_json, ctx.dir / "policy.json",
                            {"policy": policy, "source": source})
    ctx.store.update(ctx.job_id, summary={
        "findings": len(findings), "by_severity": by_sev, "by_band": by_band,
        "policy": {k: verdict[k] for k in ("status", "count", "policy", "source")}})
    ctx.log(f"Policy ({source}): {verdict['status'].upper()} — {verdict['count']} violation"
            f"{'' if verdict['count'] == 1 else 's'}, {policy_mod.describe(policy)}",
            "warn" if verdict["status"] == "fail" else "info")
    ctx.log(f"{len(findings)} findings · " + " · ".join(f"{v} {k}" for k, v in by_sev.items() if v)
            if findings else "No known advisories for these packages")


Step = Callable[[Context], Awaitable[None]]
STEPS: list[tuple[str, Step]] = [
    ("extracting", extracting),
    ("parsing", parsing),
    ("scanning", scanning),
    ("analyzing", analyzing),
]

async def run(ctx: Context, steps: list[tuple[str, Step]] | None = None) -> None:
    store, job_id = ctx.store, ctx.job_id
    try:
        for name, step in steps or STEPS:
            store.transition(job_id, name)
            started = time.perf_counter()
            await step(ctx)
            ms = round((time.perf_counter() - started) * 1000)
            store.emit_log(job_id, {"step": name, "state": "done", "ms": ms}, kind="step")
        store.transition(job_id, "ready")
    except IllegalTransition:
        log.info("job %s left the pipeline (expired or deleted)", job_id)
    except AppError as exc:
        if exc.code != "E_NOT_FOUND":
            safe_fail(store, job_id, exc.code, exc.message, exc.hint, exc.options)
    except Exception:
        log.exception("pipeline crashed for job %s", job_id)
        safe_fail(store, job_id, "E_INTERNAL", "Analysis failed unexpectedly.",
                  "Retry; if it persists, report it with the job id.")
    finally:
        ctx.archive.unlink(missing_ok=True)


def safe_fail(store: JobStore, job_id: str, code: str, message: str, hint: str,
              options: list[str] | None = None) -> None:
    try:
        store.fail(job_id, code, message, hint, options)
    except (AppError, IllegalTransition):
        log.info("job %s vanished before it could be marked failed", job_id)
