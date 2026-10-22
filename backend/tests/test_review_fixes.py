import asyncio
import shutil
import time

from fastapi.testclient import TestClient
from helpers import ZIPS, wait_job

from app.config import ROOT
from app.jobs import EventHub
from app.main import create_app
from app.verify import modes


def chunks(total: int, size: int = 256 * 1024):
    sent = 0
    while sent < total:
        yield b"x" * min(size, total - sent)
        sent += size


def test_chunked_upload_without_length_is_capped(settings):
    s = settings.model_copy(update={"max_upload_mb": 1})
    with TestClient(create_app(s), raise_server_exceptions=False) as c:
        r = c.post("/api/jobs", content=chunks(3 * 1024 * 1024),
                   headers={"content-type": "multipart/form-data; boundary=zz"})
        assert r.status_code == 413 and r.json()["error"]["code"] == "E_TOO_LARGE"
        assert list(c.app.state.store.root.iterdir()) == []
        ok = c.post("/api/jobs", files={"file": ("a.zip", (ZIPS / "ok_root.zip").read_bytes(),
                                                  "application/zip")})
        assert ok.status_code == 202


def test_json_endpoints_reject_large_bodies(client):
    r = client.post("/api/jobs/github", content=b'{"repo": "' + b"a" * 70_000 + b'"}',
                    headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_event_hub_forgets_job_and_its_verifications():
    hub = EventHub()
    hub.history = {"job1": [1], "job1:p_1": [2], "job10": [3], "job2:p_9": [4]}
    hub.forget("job1")
    assert set(hub.history) == {"job10", "job2:p_9"}


def test_delete_cancels_running_verification(settings, monkeypatch):
    shutil.copytree(ROOT / "samples" / "vuln-demo", settings.samples_dir / "vuln-demo")

    async def slow(self, stage, workspace, timeout, on_line):
        await asyncio.sleep(30)
        return modes.StageResult(0)

    monkeypatch.setattr(modes.MockExecutor, "run", slow)
    s = settings.model_copy(update={"rate_limit": "1000/min"})
    with TestClient(create_app(s), raise_server_exceptions=False) as c:
        job_id = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"])["id"]
        fid = c.get(f"/api/jobs/{job_id}/findings",
                    params={"q": "GHSA-hrpp-h998-j3pp"}).json()["items"][0]["id"]
        pid = c.post(f"/api/jobs/{job_id}/findings/{fid}/proposal").json()["items"][0]["pid"]
        c.post(f"/api/jobs/{job_id}/proposals/{pid}/approve", json={"confirm": True})
        key = f"{job_id}:{pid}"
        for _ in range(100):
            if key in c.app.state.tasks:
                break
            time.sleep(0.02)
        task = c.app.state.tasks[key]
        assert c.delete(f"/api/jobs/{job_id}").status_code == 204
        for _ in range(100):
            if task.done():
                break
            time.sleep(0.02)
        assert task.cancelled() or task.done()
        assert key not in c.app.state.tasks
        assert not [k for k in c.app.state.hub.history if k.startswith(job_id)]
