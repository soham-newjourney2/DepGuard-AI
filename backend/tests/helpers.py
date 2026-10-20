import json
import time
from pathlib import Path

ZIPS = Path(__file__).parent / "fixtures" / "zips"
DONE = {"ready", "failed", "expired"}


def upload(client, name: str):
    data = (ZIPS / name).read_bytes()
    return client.post("/api/jobs", files={"file": (name, data, "application/zip")})


def wait_job(client, job_id: str, statuses=DONE, timeout: float = 30) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job.get("status") in statuses:
            return job
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} stuck at {job}")


def read_sse(client, job_id: str) -> list[dict]:
    events = []
    with client.stream("GET", f"/api/jobs/{job_id}/events") as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        for line in r.iter_lines():
            if line.startswith("data: "):
                events.append(json.loads(line[6:]))
    return events
