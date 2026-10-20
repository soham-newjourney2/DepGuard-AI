import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path

from app import policy as policy_mod
from app.config import Settings
from app.errors import AppError
from app.graph import Graph
from app.intake import Intake, extract_project
from app.jobs import IllegalTransition, JobStore
from app.lockfile import parse as parse_lock
from app.prioritize import enrich
from app.reachability import LABELS, annotate
from app.scanner import Package, ScanError, ScanResult, make_scanner, recorded_scanner
from app.scanner.normalize import SEV_ORDER, normalize
from app.stacks import BY_ID
from app.web import site as web

log = logging.getLogger("depguard.pipeline")
PENDING = "pending.zip"


@dataclass
class Context:
    job_id: str
    archive: Path
    settings: Settings
    store: JobStore
    project: str | None = None
    url: str | None = None
    intake: Intake | None = None
    graph: Graph | None = None
    scan: ScanResult | None = None
    data: dict = field(default_factory=dict)

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


async def fetching(ctx: Context) -> None:
    s = ctx.settings
    ctx.log(f"Fetching {ctx.url} (HTML and scripts are read as text; nothing is executed)")
    site = ctx.data["site"] = await asyncio.wait_for(web.scan_site(ctx.url, s),
                                                     s.web_timeout_s * 6)
    root = ctx.dir / "site"
    root.mkdir(exist_ok=True)
    await asyncio.to_thread((root / "index.html").write_text, site.html, "utf-8")
    await asyncio.to_thread(write_json, ctx.dir / "site.json", site.to_json())
    await asyncio.to_thread(write_json, ctx.dir / "meta.json",
                            {"root": "site", "stack": "site", "url": site.final_url})
    ctx.intake = Intake(root, {}, {}, 0, 1 + site.fetched, [], "site")
    ctx.store.update(ctx.job_id, summary={
        "files": 1 + site.fetched, "stack": "site", "ecosystem": "npm", "language": "Website",
        "site": {"url": site.final_url, "title": site.title, "scripts": site.scripts,
                 "fetched": site.fetched}})
    for r in site.redirects:
        ctx.log(f"Redirected to {r}")
    for note in site.notes[:10]:
        ctx.log(note, "warn")
    if site.truncated:
        add_warning(ctx, "W_PAGE_TRUNCATED", "The page was larger than the download cap; only "
                                             "its first part was analysed.")
    ctx.log(f"Read the page and {site.fetched} of {site.scripts} scripts "
            f"({'title: ' + site.title if site.title else 'no title'})")


async def detecting(ctx: Context) -> None:
    site: web.SiteScan = ctx.data["site"]
    g = ctx.graph = web.build_graph(site)
    await asyncio.to_thread(write_json, ctx.dir / "graph.json", g.to_json())
    stats = g.stats()
    ctx.store.update(ctx.job_id, summary=stats)
    other = [d for d in site.detections if d.ecosystem is None]
    if other:
        names = ", ".join(f"{d.name} {d.version}" for d in other[:3])
        add_warning(ctx, "W_NOT_SCANNABLE", f"Detected {names}; there is no advisory feed for "
                                            "it in OSV, so it was not checked.")
    if not stats["packages"]:
        add_warning(ctx, "W_NO_LIBRARIES", "No versioned client-side library was recognised. "
                                           "Bundled apps usually strip version banners.")
    for d in site.detections:
        if d.ecosystem == "npm":
            ctx.log(f"Detected {d.name}@{d.version} ({d.confidence}, "
                    f"{d.evidence[0]['kind']})")


async def parsing(ctx: Context) -> None:
    if ctx.intake.stack == "npm":
        lock = parse_lock(ctx.intake.lockfile, ctx.intake.manifest)
        g = ctx.graph = await asyncio.to_thread(Graph, lock)
    else:
        g = ctx.graph = await asyncio.to_thread(BY_ID[ctx.intake.stack].load, ctx.intake.root)
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


def scan_packages(graph: Graph) -> list[Package]:
    return sorted({Package(graph.nodes[keys[0]].name, graph.nodes[keys[0]].version,
                            graph.nodes[keys[0]].ecosystem)
                   for keys in graph.packages().values()})


async def scanning(ctx: Context) -> None:
    s = ctx.settings
    packages = scan_packages(ctx.graph)
    scanner = make_scanner(s)
    if ctx.intake.stack == "site" and scanner.name == "osv-cli":
        scanner = make_scanner(s.model_copy(update={"scanner": "osv-api"}))
    ctx.log(f"Querying {scanner.name} for {len(packages)} packages")
    lockfile = ctx.intake.root / BY_ID[ctx.intake.stack].lockfile
    try:
        result = await asyncio.wait_for(scanner.scan(packages, lockfile), s.scan_timeout_s)
    except (ScanError, TimeoutError) as exc:
        reason = str(exc) or "timed out"
        if ctx.store.get(ctx.job_id)["source"] != "demo":
            raise AppError("E_SCAN_UNAVAILABLE", f"Vulnerability scan failed: {reason}",
                           "OSV may be unreachable; retry in a minute.", 503) from None
        ctx.log(f"Live scan failed ({reason}); using the recorded scan for this bundled sample",
                "warn")
        result = await recorded_scanner(s).scan(packages, lockfile)
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


async def analyzing(ctx: Context) -> None:
    findings = await asyncio.to_thread(normalize, ctx.scan, ctx.graph)
    if ctx.intake.stack == "site":
        web.annotate_site(findings, ctx.data["site"])
        findings = enrich(findings)
        ctx.log(f"{len(findings)} findings come from libraries the page loads")
    else:
        idx = await asyncio.to_thread(annotate, findings, ctx.intake.root,
                                      BY_ID[ctx.intake.stack].ecosystem)
        findings = enrich(findings)
        labels = [f["reachability"]["label"] for f in findings]
        ctx.log(f"Import scan: {idx.files} source files; " + ", ".join(
            f"{labels.count(lab)} {lab.lower()}" for lab in LABELS if labels.count(lab)))
    await asyncio.to_thread(write_json, ctx.dir / "findings.json", findings)
    by_sev = {k: 0 for k in sorted(SEV_ORDER, key=SEV_ORDER.get, reverse=True)}
    by_band = {b: 0 for b in ("P1", "P2", "P3", "P4")}
    for f in findings:
        by_sev[f["advisory"]["severity"]["label"]] += 1
        by_band[f["priority"]["band"]] += 1
    policy, source, warning = policy_mod.load(ctx.intake.root)
    if warning:
        add_warning(ctx, "W_POLICY", warning)
    verdict = policy_mod.evaluate(findings, policy, source)
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
SITE_STEPS: list[tuple[str, Step]] = [
    ("extracting", fetching),
    ("parsing", detecting),
    ("scanning", scanning),
    ("analyzing", analyzing),
]


async def run(ctx: Context, steps: list[tuple[str, Step]] | None = None) -> None:
    store, job_id = ctx.store, ctx.job_id
    try:
        for name, step in steps or (SITE_STEPS if ctx.url else STEPS):
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
