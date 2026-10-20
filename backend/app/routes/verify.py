import asyncio
import json
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app import remediation
from app.errors import AppError
from app.jobs import iso, utcnow
from app.routes.findings import load_findings
from app.routes.jobs import HEARTBEAT_S, limited, sse
from app.verify import runner

router = APIRouter(prefix="/api/jobs", tags=["verify"])
log = logging.getLogger("depguard.verify")
FINAL = {"verified", "verify_failed", "unable_to_verify"}


class Approval(BaseModel):
    confirm: bool = False


def hub_key(job_id: str, pid: str) -> str:
    return f"{job_id}:{pid}"


@router.post("/{job_id}/proposals/{pid}/approve", status_code=202,
             dependencies=[Depends(limited)])
async def approve(job_id: str, pid: str, body: Approval, request: Request) -> dict:
    state = request.app.state
    job, findings = load_findings(request, job_id)
    job_dir = state.store.job_dir(job_id)
    proposal = remediation.load_proposal(job_dir, pid)
    if not body.confirm:
        raise AppError("E_CONFIRM_REQUIRED", "Approval needs explicit confirmation.",
                       "Send {\"confirm\": true} after reviewing what will run.", 422)
    if proposal.get("verifiable") is False and proposal["strategy"] != "none":
        raise AppError("E_VERIFY_UNSUPPORTED",
                       "Isolated verification runs npm projects only.",
                       "Apply the command or patch shown and run your own test suite.", 409)
    if proposal["strategy"] == "none" or not proposal.get("edits"):
        raise AppError("E_NO_PATCH", "This proposal has nothing to apply.", "", 409)
    if proposal.get("status", "proposed") != "proposed":
        raise AppError("E_ALREADY_APPROVED", f"Proposal is already {proposal['status']}.",
                       "Open its verification instead.", 409)
    proposal["status"] = "approved"
    proposal["approved_at"] = iso(utcnow())
    runner.save_proposal(job_dir, proposal)
    key = hub_key(job_id, pid)
    v = runner.Verification(job_id, pid, job, job_dir, remediation.project_root(job_dir),
                            proposal, findings, state.settings,
                            lambda e: state.hub.publish(key, e))
    v.result = {"pid": pid, "status": "approved", "stages": []}
    v.save()
    state.hub.publish(key, {"type": "status", "data": {"status": "approved"},
                            "ts": iso(utcnow())})

    async def go():
        async with state.verify_sem:
            try:
                await runner.verify(v)
            except Exception:
                log.exception("verification crashed for %s", pid)
                if v.proposal["status"] not in FINAL:
                    try:
                        runner.finish(v, "unable_to_verify",
                                      "Verification crashed unexpectedly.")
                    except (OSError, RuntimeError):
                        log.info("verification %s could not record its failure", pid)

    task = asyncio.create_task(go())
    state.tasks[key] = task
    task.add_done_callback(lambda _: state.tasks.pop(key, None))
    return {"pid": pid, "status": "approved"}


def read_result(request: Request, job_id: str, pid: str) -> dict:
    job_dir = request.app.state.store.job_dir(job_id)
    proposal = remediation.load_proposal(job_dir, pid)
    try:
        result = json.loads((job_dir / "verify" / pid / "result.json").read_text("utf-8"))
    except (OSError, ValueError):
        result = {"pid": pid, "stages": []}
    result["status"] = proposal.get("status", "proposed")
    result["proposal"] = {k: v for k, v in proposal.items() if k != "edits"}
    return result


@router.get("/{job_id}/proposals/{pid}/verification")
def verification(job_id: str, pid: str, request: Request) -> dict:
    request.app.state.store.get(job_id)
    return read_result(request, job_id, pid)


@router.get("/{job_id}/proposals/{pid}/events")
async def verification_events(job_id: str, pid: str, request: Request) -> StreamingResponse:
    request.app.state.store.get(job_id)
    read_result(request, job_id, pid)
    hub = request.app.state.hub
    key = hub_key(job_id, pid)
    history, queue = hub.subscribe(key)

    async def stream():
        n = 0
        try:
            yield "retry: 3000\n\n"
            for event in history:
                n += 1
                yield sse(event, n)
                if event["type"] in ("done", "error"):
                    return
            current = read_result(request, job_id, pid)
            if current["status"] in FINAL or current["status"] == "proposed":
                kind = "done" if current["status"] == "verified" else "error"
                yield sse({"type": kind, "data": {"status": current["status"],
                                                  "reason": current.get("reason")},
                           "ts": iso(utcnow())}, n + 1)
                return
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), HEARTBEAT_S)
                except TimeoutError:
                    yield ": ping\n\n"
                    continue
                n += 1
                yield sse(event, n)
                if event["type"] in ("done", "error"):
                    return
        finally:
            hub.unsubscribe(key, queue)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
