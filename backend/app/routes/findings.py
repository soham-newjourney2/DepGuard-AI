import json

from fastapi import APIRouter, Depends, Request, Response

from app import ai, remediation
from app.errors import AppError
from app.prioritize import sort_key
from app.routes.jobs import limited
from app.scanner.normalize import SEV_ORDER
from app.verify.modes import verify_candidate

router = APIRouter(prefix="/api/jobs", tags=["findings"])
SORTS = {
    "priority": sort_key,
    "severity": lambda f: (-SEV_ORDER[f["advisory"]["severity"]["label"]],
                           -(f["advisory"]["severity"]["score"] or 0), f["package"]["name"]),
    "name": lambda f: (f["package"]["name"], f["package"]["version"], f["advisory"]["id"]),
}


def load_findings(request: Request, job_id: str) -> tuple[dict, list[dict]]:
    store = request.app.state.store
    job = store.get(job_id)
    if job["status"] != "ready":
        raise AppError("E_NOT_READY", f"Job is {job['status']}; findings are not available.",
                       "Wait for the scan to reach ready.", 409)
    try:
        findings = json.loads((store.job_dir(job_id) / "findings.json").read_text("utf-8"))
    except (OSError, ValueError):
        raise AppError("E_NOT_FOUND", "Findings are missing for this job.",
                       "Run the scan again.", 404) from None
    return job, findings


def csv(value: str | None) -> set[str]:
    return {v.strip().lower() for v in (value or "").split(",") if v.strip()}


def flag(value: str | None, yes: str, no: str) -> bool | None:
    v = (value or "").lower()
    if v in ("true", "1", yes):
        return True
    if v in ("false", "0", no):
        return False
    if v:
        raise AppError("E_INVALID", f"Unsupported filter value {value!r}.",
                       f"Use {yes} or {no}.", 422)
    return None


def row(f: dict) -> dict:
    adv = f["advisory"]
    return {
        "id": f["id"],
        "advisory": {"id": adv["id"], "summary": adv["summary"], "severity": adv["severity"],
                     "aliases": adv["aliases"]},
        "package": f["package"], "scope": f["scope"], "direct": f["direct"],
        "depth": f["depth"], "path_count": f["path_count"],
        "path": f["paths"][0] if f["paths"] else [],
        "fix_available": f["fix_available"], "fixed_versions": f["fixed_versions"],
        "priority": {k: f["priority"][k] for k in ("score", "band", "band_label", "flags")},
        "exploit": f.get("exploit"),
        "malicious": bool(f.get("malicious")),
    }


@router.get("/{job_id}/findings")
def list_findings(job_id: str, request: Request, sort: str = "priority",
                  severity: str | None = None, scope: str | None = None,
                  direct: str | None = None, fix: str | None = None, q: str = "") -> dict:
    job, findings = load_findings(request, job_id)
    if sort not in SORTS:
        raise AppError("E_INVALID", f"Unknown sort {sort!r}.", "Use priority, severity or name.",
                       422)
    sevs, scopes = csv(severity), csv(scope)
    want_direct = flag(direct, "direct", "transitive")
    want_fix = flag(fix, "yes", "no")
    needle = q.strip().lower()[:100]
    items = [
        f for f in findings
        if (not sevs or f["advisory"]["severity"]["label"] in sevs)
        and (not scopes or f["scope"] in scopes)
        and (want_direct is None or f["direct"] == want_direct)
        and (want_fix is None or f["fix_available"] == want_fix)
        and (not needle or needle in " ".join([f["package"]["name"], f["advisory"]["id"],
                                               *f["advisory"]["aliases"],
                                               f["advisory"]["summary"]]).lower())
    ]
    items.sort(key=SORTS[sort])
    return {"total": len(findings), "count": len(items), "items": [row(f) for f in items],
            "summary": {k: job["summary"].get(k) for k in ("findings", "by_severity", "by_band",
                                                           "packages", "scan", "policy")}}


@router.get("/{job_id}/findings/{finding_id}")
def get_finding(job_id: str, finding_id: str, request: Request) -> dict:
    _, findings = load_findings(request, job_id)
    for f in findings:
        if f["id"] == finding_id:
            return f
    raise AppError("E_NOT_FOUND", "Finding not found.", "", 404)


@router.post("/{job_id}/findings/{finding_id}/explain", dependencies=[Depends(limited)])
async def explain_finding(job_id: str, finding_id: str, request: Request) -> dict:
    finding = get_finding(job_id, finding_id, request)
    state = request.app.state
    cache = state.store.job_dir(job_id) / "explanations"
    return await ai.explain(finding, cache)


@router.post("/{job_id}/findings/{finding_id}/proposal", dependencies=[Depends(limited)])
async def propose_fix(job_id: str, finding_id: str, request: Request) -> dict:
    job, findings = load_findings(request, job_id)
    finding = next((f for f in findings if f["id"] == finding_id), None)
    if finding is None:
        raise AppError("E_NOT_FOUND", "Finding not found.", "", 404)
    state = request.app.state
    items = await remediation.propose(state.store.job_dir(job_id), finding, findings,
                                      state.settings, verifiable=verify_candidate(job))
    return {"finding_id": finding_id, "items": [public_proposal(p) for p in items]}


def public_proposal(p: dict) -> dict:
    return {k: v for k, v in p.items() if k != "edits"}


@router.get("/{job_id}/proposals/{pid}")
def get_proposal(job_id: str, pid: str, request: Request) -> dict:
    request.app.state.store.get(job_id)
    return public_proposal(remediation.load_proposal(request.app.state.store.job_dir(job_id), pid))


@router.get("/{job_id}/patch")
def get_patch(job_id: str, pid: str, request: Request) -> Response:
    request.app.state.store.get(job_id)
    p = remediation.load_proposal(request.app.state.store.job_dir(job_id), pid)
    if not p["diff"]:
        raise AppError("E_NOT_FOUND", "This proposal has no patch.", "", 404)
    return Response(p["diff"], media_type="text/x-diff; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="depguard-{pid}.patch"'})


@router.post("/{job_id}/plan", dependencies=[Depends(limited)])
async def batch_plan(job_id: str, request: Request) -> dict:
    job, findings = load_findings(request, job_id)
    state = request.app.state
    plan = await remediation.propose_batch(state.store.job_dir(job_id), findings, state.settings,
                                           verifiable=verify_candidate(job))
    return public_proposal(plan)
