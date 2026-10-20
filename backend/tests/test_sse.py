import asyncio

from helpers import read_sse, upload, wait_job

from app import pipeline


def statuses(events):
    return [e["data"]["status"] for e in events if e["type"] == "status"]


def test_sse_replays_completed_job(client):
    job = wait_job(client, upload(client, "ok_root.zip").json()["job_id"])
    events = read_sse(client, job["id"])
    assert events[0]["data"]["snapshot"] is True
    assert statuses(events[1:]) == ["queued", "extracting", "parsing", "scanning", "analyzing",
                                    "ready"]
    assert events[-1]["type"] == "done"
    assert all(set(e) == {"type", "data", "ts"} for e in events)
    steps = [e["data"]["step"] for e in events if e["type"] == "step"]
    assert steps == ["extracting", "parsing", "scanning", "analyzing"]
    assert any(e["type"] == "log" and "Extracted 3 files" in e["data"]["message"] for e in events)


def test_sse_failed_job_ends_with_error(client):
    job = wait_job(client, upload(client, "symlink.zip").json()["job_id"])
    events = read_sse(client, job["id"])
    assert events[-1]["type"] == "error"
    assert events[-1]["data"]["error"]["code"] == "E_SYMLINK"


def test_sse_streams_live_events(client, monkeypatch):
    async def slow(ctx):
        await asyncio.sleep(0.15)
        ctx.log("tick")

    monkeypatch.setattr(pipeline, "STEPS", [("extracting", pipeline.extracting),
                                            ("parsing", slow), ("scanning", slow),
                                            ("analyzing", slow)])
    job_id = upload(client, "ok_root.zip").json()["job_id"]
    events = read_sse(client, job_id)
    assert events[-1]["type"] == "done"
    assert sum(1 for e in events if e["type"] == "log" and e["data"]["message"] == "tick") == 3


def test_sse_without_history_synthesises_close(client):
    job = wait_job(client, upload(client, "ok_root.zip").json()["job_id"])
    client.app.state.hub.forget(job["id"])
    events = read_sse(client, job["id"])
    assert [e["type"] for e in events] == ["status", "done"]


def test_sse_unknown_job_404(client):
    r = client.get("/api/jobs/" + "f" * 32 + "/events")
    assert r.status_code == 404 and r.json()["error"]["code"] == "E_NOT_FOUND"
