import atexit
import json
import shutil
import tempfile
import time
from pathlib import Path

from app.config import ROOT
from app.samples import checkout

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


_REAL = Path(tempfile.mkdtemp(prefix="depguard-real-"))
atexit.register(shutil.rmtree, _REAL, True)


def real(src: Path) -> Path:
    """A shared read-only copy of a bundled folder with manifests under their real names."""
    dst = _REAL / src.relative_to(ROOT)
    return dst if dst.is_dir() else checkout(src, dst)
