import json
from pathlib import Path

from fastapi import APIRouter, Request, Response

from app import remediation
from app.errors import AppError
from app.report import export
from app.report import sbom as sbom_mod
from app.routes.findings import load_findings
from app.routes.verify import read_result

router = APIRouter(prefix="/api/jobs", tags=["report"])
HTML_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'")


def latest_pid(job_dir: Path) -> str | None:
    best = None
    for path in (job_dir / "verify").glob("p_*/result.json"):
        try:
            finished = json.loads(path.read_text("utf-8")).get("finished")
        except (OSError, ValueError):
            continue
        if finished and (best is None or finished > best[0]):
            best = (finished, path.parent.name)
    return best[1] if best else None


def assemble(request: Request, job_id: str, pid: str | None) -> dict:
    state = request.app.state
    job, findings = load_findings(request, job_id)
    job_dir = state.store.job_dir(job_id)
    pid = pid or latest_pid(job_dir)
    proposal = verification = after = None
    if pid:
        proposal = {k: v for k, v in remediation.load_proposal(job_dir, pid).items()
                    if k != "edits"}
        if proposal.get("status", "proposed") != "proposed":
            verification = read_result(request, job_id, pid)
            try:
                after = json.loads((job_dir / "verify" / pid / "findings.after.json")
                                   .read_text("utf-8"))
            except (OSError, ValueError):
                after = None
    ai = {"provider": state.ai_provider.name, "model": state.ai_provider.model}
    try:
        policy = json.loads((job_dir / "policy.json").read_text("utf-8"))
    except (OSError, ValueError):
        policy = None
    return export.build(job, findings, proposal, verification, after, ai, policy)


@router.get("/{job_id}/report")
def report(job_id: str, request: Request, format: str = "json", pid: str | None = None,
           download: bool = False):
    if format not in ("json", "md", "html"):
        raise AppError("E_INVALID", f"Unknown format {format!r}.", "Use json, md or html.", 422)
    r = assemble(request, job_id, pid)
    name = f"depguard-report-{job_id[:8]}"
    if format == "json":
        if not download:
            return r
        return Response(export.to_json(r), media_type="application/json", headers={
            "Content-Disposition": f'attachment; filename="{name}.json"'})
    if format == "md":
        return Response(export.to_markdown(r), media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{name}.md"'})
    headers = {"Content-Security-Policy": HTML_CSP}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{name}.html"'
    return Response(export.to_html(r), media_type="text/html; charset=utf-8", headers=headers)


@router.get("/{job_id}/sbom")
def sbom(job_id: str, request: Request, download: bool = False):
    job, findings = load_findings(request, job_id)
    path = request.app.state.store.job_dir(job_id) / "graph.json"
    try:
        graph = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        raise AppError("E_NOT_FOUND", "Graph is missing for this job.", "", 404) from None
    doc = sbom_mod.build(job, graph, findings)
    if not download:
        return doc
    return Response(json.dumps(doc, indent=2), media_type="application/vnd.cyclonedx+json",
                    headers={"Content-Disposition":
                             f'attachment; filename="depguard-sbom-{job_id[:8]}.cdx.json"'})
