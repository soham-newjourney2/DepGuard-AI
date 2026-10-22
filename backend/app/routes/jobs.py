import asyncio
import json
import re
import shutil
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from starlette.datastructures import UploadFile

from app import github, pipeline
from app.errors import AppError
from app.intake import MB, SKIP_DIRS
from app.jobs import iso, release_job, utcnow
from app.samples import STORED, real_name
from app.stacks import found_in

router = APIRouter(prefix="/api/jobs", tags=["jobs"])
SAMPLES = {"vuln-demo", "clean-demo", "messy-demo", "python-demo", "supplychain-demo"}
PUBLIC = ("id", "status", "step", "source", "filename", "created_at", "updated_at", "expires_at",
          "summary", "warnings", "error")
HEARTBEAT_S = 15


def limited(request: Request) -> None:
    request.app.state.limiter.check(request.client.host if request.client else "unknown")


def public(job: dict) -> dict:
    return {k: job[k] for k in PUBLIC}


def too_large(mb: int) -> AppError:
    return AppError("E_TOO_LARGE", f"Upload is larger than {mb} MB.",
                    "Exclude node_modules and build output.", 413)


def clean_filename(name: str | None) -> str:
    base = re.split(r"[\\/]", name or "")[-1]
    return re.sub(r"[\x00-\x1f\x7f]", "", base)[:200] or "upload.zip"


def copy_limited(src, dest: Path, limit: int, mb: int) -> None:
    written = 0
    with open(dest, "wb") as out:
        while chunk := src.read(MB):
            written += len(chunk)
            if written > limit:
                raise too_large(mb)
            out.write(chunk)


def zip_dir(src: Path, dest: Path) -> None:
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(src.rglob("*")):
            rel = path.relative_to(src)
            if path.is_file() and not path.is_symlink() and not SKIP_DIRS & set(rel.parts):
                zf.write(path, real_name(rel).as_posix())


def project_choice(value) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or len(value) > 200:
        raise AppError("E_INVALID", "Invalid project path.", "", 422)
    return value.strip().strip("/") or None


def launch(request: Request, job_id: str, archive: Path, project: str | None = None) -> None:
    state = request.app.state
    ctx = pipeline.Context(job_id, archive, state.settings, state.store, project=project)
    task = asyncio.create_task(pipeline.run(ctx))
    state.tasks[job_id] = task
    task.add_done_callback(lambda _: state.tasks.pop(job_id, None))


@router.post("", status_code=202, dependencies=[Depends(limited)])
async def upload(request: Request) -> dict:
    s, store = request.app.state.settings, request.app.state.store
    limit = s.max_upload_mb * MB
    length = request.headers.get("content-length", "")
    if length.isdigit() and int(length) > limit + 64 * 1024:
        raise too_large(s.max_upload_mb)
    form = await request.form(max_files=1, max_fields=2)
    file = form.get("file")
    project = project_choice(form.get("project"))
    if not isinstance(file, UploadFile):
        raise AppError("E_INVALID", "Missing multipart field `file`.",
                       "Send the zip as multipart/form-data field `file`.", 422)
    job = store.create("upload", clean_filename(file.filename))
    archive = store.job_dir(job["id"]) / "upload.zip"
    try:
        await asyncio.to_thread(copy_limited, file.file, archive, limit, s.max_upload_mb)
    except AppError:
        store.delete(job["id"])
        raise
    finally:
        await file.close()
    launch(request, job["id"], archive, project)
    return {"job_id": job["id"]}


@router.post("/demo/{sample}", status_code=202, dependencies=[Depends(limited)])
async def demo(sample: str, request: Request) -> dict:
    s, store = request.app.state.settings, request.app.state.store
    src = s.samples_dir / sample
    if sample not in SAMPLES:
        raise AppError("E_NOT_FOUND", "Unknown sample.", "Use one of: "
                       + ", ".join(sorted(SAMPLES)) + ".", 404)
    if not src.is_dir() or not (found_in(src) or any(src.glob("*" + STORED))):
        raise AppError("E_NOT_FOUND", "This sample is not bundled in this build.",
                       "Upload your own project zip instead.", 404)
    job = store.create("demo", f"{sample}.zip")
    archive = store.job_dir(job["id"]) / "upload.zip"
    await asyncio.to_thread(zip_dir, src, archive)
    launch(request, job["id"], archive)
    return {"job_id": job["id"]}


class GithubImport(BaseModel):
    repo: str
    project: str | None = None


@router.post("/github", status_code=202, dependencies=[Depends(limited)])
async def import_github(body: GithubImport, request: Request) -> dict:
    s, store = request.app.state.settings, request.app.state.store
    if s.local_only:
        raise AppError("E_LOCAL_ONLY", "GitHub import is disabled in local-only mode.",
                       "Upload a zip instead.", 403)
    link = github.parse_link(body.repo)
    owner, repo = link.owner, link.repo
    job = store.create("github", f"{owner}/{repo}")
    archive = store.job_dir(job["id"]) / "upload.zip"
    candidates = link.candidates()
    for i, candidate in enumerate(candidates):
        try:
            await github.download(owner, repo, candidate[0], archive, s.max_upload_mb * MB,
                                  s.github_codeload_url)
            ref, path = candidate
            break
        except AppError as exc:
            if exc.code == "E_GITHUB_NOT_FOUND" and i + 1 < len(candidates):
                continue
            store.delete(job["id"])
            raise
    project = project_choice(body.project) or path
    store.update(job["id"], filename=f"{owner}/{repo}@{ref}" + (f" ({path}/)" if path else ""))
    launch(request, job["id"], archive, project)
    return {"job_id": job["id"]}


class ProjectChoice(BaseModel):
    project: str


@router.post("/{job_id}/project", status_code=202, dependencies=[Depends(limited)])
async def choose_project(job_id: str, body: ProjectChoice, request: Request) -> dict:
    """Scan another project from the same multi-project archive, without uploading it again."""
    store = request.app.state.store
    job = store.get(job_id)
    multi = next((w for w in job["warnings"] if w.get("code") == "W_MULTIPLE_PROJECTS"), None)
    if multi is None:
        raise AppError("E_CONFLICT", "This scan has only one project.", "", 409)
    if body.project not in (multi.get("options") or []):
        raise AppError("E_INVALID", "Pick one of the projects found in the archive.", "", 422)
    pending = store.job_dir(job_id) / pipeline.PENDING
    if not pending.is_file():
        raise AppError("E_NOT_FOUND", "The uploaded archive is no longer available.",
                       "Upload the zip again.", 404)
    new = store.create(job["source"], job["filename"])
    archive = store.job_dir(new["id"]) / "upload.zip"
    await asyncio.to_thread(shutil.copyfile, pending, archive)
    launch(request, new["id"], archive, body.project)
    return {"job_id": new["id"]}


@router.get("/{job_id}")
def get_job(job_id: str, request: Request) -> dict:
    return public(request.app.state.store.get(job_id))


@router.delete("/{job_id}", status_code=204)
async def delete_job(job_id: str, request: Request) -> Response:
    state = request.app.state
    state.store.get(job_id)
    release_job(state, job_id)
    await asyncio.to_thread(state.store.delete, job_id)
    return Response(status_code=204)


def sse(event: dict, n: int) -> str:
    return f"id: {n}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n"


def is_terminal(event: dict) -> bool:
    return event["type"] in ("done", "error") or (
        event["type"] == "status" and event["data"].get("status") == "expired")


def closing_event(job: dict) -> dict | None:
    ts = iso(utcnow())
    if job["status"] == "ready":
        return {"type": "done", "data": {"status": "ready"}, "ts": ts}
    if job["status"] == "failed":
        return {"type": "error", "data": {"status": "failed", "error": job["error"]}, "ts": ts}
    if job["status"] == "expired":
        return {"type": "status", "data": {"status": "expired"}, "ts": ts}
    return None


@router.get("/{job_id}/events")
async def events(job_id: str, request: Request) -> StreamingResponse:
    store, hub = request.app.state.store, request.app.state.hub
    store.get(job_id)
    history, queue = hub.subscribe(job_id)

    async def stream():
        n = 0
        try:
            yield "retry: 3000\n\n"
            job = store.get(job_id)
            snapshot = {"type": "status", "ts": iso(utcnow()), "data": {
                "status": job["status"], "step": job["step"], "snapshot": True}}
            for event in [snapshot, *history]:
                n += 1
                yield sse(event, n)
                if is_terminal(event):
                    return
            if closing := closing_event(store.get(job_id)):
                yield sse(closing, n + 1)
                return
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), HEARTBEAT_S)
                except TimeoutError:
                    yield ": ping\n\n"
                    continue
                n += 1
                yield sse(event, n)
                if is_terminal(event):
                    return
        except AppError:
            return
        finally:
            hub.unsubscribe(job_id, queue)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
