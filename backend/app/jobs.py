import asyncio
import json
import os
import re
import shutil
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from app import db
from app.errors import AppError

JOB_FLOW = ["queued", "extracting", "parsing", "scanning", "analyzing", "ready"]
PROPOSAL_END = {"verified", "verify_failed", "unable_to_verify"}

JOB_TRANSITIONS: dict[str, set[str]] = {
    s: ({JOB_FLOW[i + 1]} if i + 1 < len(JOB_FLOW) else set()) | {"failed", "expired"}
    for i, s in enumerate(JOB_FLOW)
}
JOB_TRANSITIONS["failed"] = {"expired"}
JOB_TRANSITIONS["expired"] = set()

PROPOSAL_TRANSITIONS: dict[str, set[str]] = {
    "proposed": {"approved"},
    "approved": {"resolving", "unable_to_verify"},
    "resolving": {"testing", "verify_failed", "unable_to_verify"},
    "testing": {"rescanning", "verify_failed", "unable_to_verify"},
    "rescanning": PROPOSAL_END,
    **{s: set() for s in PROPOSAL_END},
}

ID_RE = re.compile(r"^[0-9a-f]{32}$")


class IllegalTransition(RuntimeError):
    pass


def check_transition(table: dict[str, set[str]], old: str, new: str) -> None:
    if new not in table.get(old, set()):
        raise IllegalTransition(f"{old} -> {new}")


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class JobStore:
    def __init__(self, data_dir: Path, ttl_min: int, clock: Callable[[], datetime] = utcnow):
        self.root = data_dir / "jobs"
        self.root.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(minutes=ttl_min)
        self.clock = clock
        self.conn = db.connect(data_dir / "depguard.db")
        self.lock = threading.RLock()
        self.listeners: list[Callable[[str, dict], None]] = []

    def job_dir(self, job_id: str) -> Path:
        if not ID_RE.fullmatch(job_id or ""):
            raise AppError("E_NOT_FOUND", "Job not found.", status=404)
        return self.root / job_id

    def create(self, source: str, filename: str | None = None) -> dict:
        job_id = uuid.uuid4().hex
        now = self.clock()
        with self.lock:
            self.job_dir(job_id).mkdir()
            self.conn.execute(
                "INSERT INTO jobs (id, status, source, filename, created_at, updated_at,"
                " expires_at) VALUES (?, 'queued', ?, ?, ?, ?, ?)",
                (job_id, source, filename, iso(now), iso(now), iso(now + self.ttl)),
            )
        job = self.get(job_id)
        self._emit(job_id, {"type": "status", "data": {"status": "queued"}})
        return job

    def get(self, job_id: str) -> dict:
        self.job_dir(job_id)
        with self.lock:
            row = self.conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            raise AppError("E_NOT_FOUND", "Job not found.", "It may have expired.", 404)
        job = dict(row)
        job["summary"] = json.loads(job["summary"])
        job["warnings"] = json.loads(job["warnings"])
        job["error"] = json.loads(job["error"]) if job["error"] else None
        return job

    def transition(self, job_id: str, new: str, error: dict | None = None) -> dict:
        with self.lock:
            old = self.get(job_id)["status"]
            check_transition(JOB_TRANSITIONS, old, new)
            self.conn.execute(
                "UPDATE jobs SET status = ?, step = COALESCE(?, step), updated_at = ?, error = ?"
                " WHERE id = ?",
                (new, new if new in JOB_FLOW else None, iso(self.clock()),
                 json.dumps(error) if error else None, job_id),
            )
        event = {"status": new, **({"error": error} if error else {})}
        self._emit(job_id, {"type": "error" if new == "failed" else "status", "data": event})
        if new == "ready":
            self._emit(job_id, {"type": "done", "data": {"status": new}})
        return self.get(job_id)

    def fail(self, job_id: str, code: str, message: str, hint: str = "",
             options: list[str] | None = None) -> dict:
        error = {"code": code, "message": message, "hint": hint}
        if options:
            error["options"] = options
        return self.transition(job_id, "failed", error)

    def update(self, job_id: str, *, summary: dict | None = None,
               warning: dict | None = None, filename: str | None = None) -> dict:
        with self.lock:
            job = self.get(job_id)
            if filename is not None:
                self.conn.execute("UPDATE jobs SET filename = ? WHERE id = ?",
                                  (filename[:200], job_id))
            if summary is not None:
                job["summary"] = {**job["summary"], **summary}
            if warning is not None and warning not in job["warnings"]:
                job["warnings"].append(warning)
            self.conn.execute(
                "UPDATE jobs SET summary = ?, warnings = ?, updated_at = ? WHERE id = ?",
                (json.dumps(job["summary"]), json.dumps(job["warnings"]), iso(self.clock()),
                 job_id),
            )
        return self.get(job_id)

    def delete(self, job_id: str) -> None:
        path = self.job_dir(job_id)
        self.get(job_id)
        with self.lock:
            self.conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
        shutil.rmtree(path, ignore_errors=True)

    def purge_expired(self) -> list[str]:
        """Expire jobs past TTL (files removed, row kept one more TTL so clients see `expired`)."""
        now = self.clock()
        with self.lock:
            rows = self.conn.execute(
                "SELECT id FROM jobs WHERE expires_at <= ? AND status != 'expired'", (iso(now),)
            ).fetchall()
        ids = [r["id"] for r in rows]
        for job_id in ids:
            shutil.rmtree(self.root / job_id, ignore_errors=True)
            self.transition(job_id, "expired")
        with self.lock:
            self.conn.execute("DELETE FROM jobs WHERE status = 'expired' AND expires_at <= ?",
                              (iso(now - self.ttl),))
        return ids

    def sweep_orphans(self, min_age_s: float = 60) -> list[str]:
        with self.lock:
            known = {r["id"] for r in self.conn.execute("SELECT id FROM jobs").fetchall()}
        cutoff = time.time() - min_age_s
        orphans = [p for p in self.root.iterdir()
                   if p.name not in known and p.stat().st_mtime < cutoff]
        for p in orphans:
            shutil.rmtree(p, ignore_errors=True)
        return [p.name for p in orphans]

    def recover(self) -> list[str]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT id FROM jobs WHERE status NOT IN ('ready', 'failed', 'expired')"
            ).fetchall()
        for r in rows:
            self.fail(r["id"], "E_INTERRUPTED", "The server restarted while this job was running.",
                      "Upload the project again.")
        return [r["id"] for r in rows]

    def subscribe(self, fn: Callable[[str, dict], None]) -> Callable[[], None]:
        self.listeners.append(fn)
        return lambda: self.listeners.remove(fn)

    def emit_log(self, job_id: str, data: Any, kind: str = "log") -> None:
        self._emit(job_id, {"type": kind, "data": data})

    def _emit(self, job_id: str, event: dict) -> None:
        event = {**event, "ts": iso(self.clock())}
        for fn in list(self.listeners):
            fn(job_id, event)

    def close(self) -> None:
        with self.lock:
            self.conn.close()


class EventHub:
    """Fans job events out to SSE subscribers; safe to publish from worker threads."""

    def __init__(self, history: int = 500):
        self.loop: asyncio.AbstractEventLoop | None = None
        self.size = history
        self.history: dict[str, deque] = {}
        self.queues: dict[str, set[asyncio.Queue]] = {}

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop

    def publish(self, job_id: str, event: dict) -> None:
        if self.loop and not self.loop.is_closed():
            self.loop.call_soon_threadsafe(self._publish, job_id, event)

    def _publish(self, job_id: str, event: dict) -> None:
        self.history.setdefault(job_id, deque(maxlen=self.size)).append(event)
        for q in self.queues.get(job_id, ()):
            q.put_nowait(event)

    def subscribe(self, job_id: str) -> tuple[list[dict], asyncio.Queue]:
        q: asyncio.Queue = asyncio.Queue()
        self.queues.setdefault(job_id, set()).add(q)
        return list(self.history.get(job_id, ())), q

    def unsubscribe(self, job_id: str, q: asyncio.Queue) -> None:
        subs = self.queues.get(job_id)
        if subs:
            subs.discard(q)
            if not subs:
                del self.queues[job_id]

    def forget(self, job_id: str) -> None:
        for key in [k for k in self.history if k == job_id or k.startswith(f"{job_id}:")]:
            del self.history[key]


def write_atomic(path: Path, text: str) -> None:
    """Readers never see a half-written file; retries cover Windows sharing violations."""
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    tmp.write_text(text, encoding="utf-8")
    for attempt in range(20):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            time.sleep(0.01 * (attempt + 1))
    tmp.unlink(missing_ok=True)
    raise PermissionError(f"could not replace {path.name}")


def release_job(state, job_id: str) -> None:
    """Cancel the job's pipeline and verification tasks and drop its event histories."""
    for key in [k for k in state.tasks if k == job_id or k.startswith(f"{job_id}:")]:
        state.tasks.pop(key).cancel()
    state.hub.forget(job_id)
