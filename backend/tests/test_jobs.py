from datetime import UTC, datetime, timedelta

import pytest

from app.errors import AppError
from app.jobs import (
    JOB_FLOW,
    PROPOSAL_TRANSITIONS,
    IllegalTransition,
    JobStore,
    check_transition,
)


class Clock:
    def __init__(self):
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self):
        return self.now

    def advance(self, minutes):
        self.now += timedelta(minutes=minutes)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def store(tmp_path, clock):
    s = JobStore(tmp_path, ttl_min=60, clock=clock)
    yield s
    s.close()


def test_create_sets_queued_dir_and_expiry(store):
    job = store.create("upload", "app.zip")
    assert job["status"] == "queued" and job["filename"] == "app.zip"
    assert store.job_dir(job["id"]).is_dir()
    assert job["expires_at"] == "2026-01-01T01:00:00.000Z"
    assert job["summary"] == {} and job["warnings"] == [] and job["error"] is None


def test_full_lifecycle_emits_events(store):
    events = []
    store.subscribe(lambda jid, e: events.append(e))
    job_id = store.create("demo")["id"]
    for status in JOB_FLOW[1:]:
        job = store.transition(job_id, status)
        assert job["status"] == job["step"] == status
    assert [e["type"] for e in events][-2:] == ["status", "done"]
    assert all("ts" in e for e in events)


@pytest.mark.parametrize("old,new", [
    ("queued", "parsing"), ("queued", "ready"), ("extracting", "queued"),
])
def test_illegal_transition_raises(store, old, new):
    job_id = store.create("upload")["id"]
    for status in JOB_FLOW[1:JOB_FLOW.index(old) + 1]:
        store.transition(job_id, status)
    with pytest.raises(IllegalTransition):
        store.transition(job_id, new)
    assert store.get(job_id)["status"] == old


def test_ready_is_terminal_except_expiry(store):
    job_id = store.create("upload")["id"]
    for status in JOB_FLOW[1:]:
        store.transition(job_id, status)
    with pytest.raises(IllegalTransition):
        store.transition(job_id, "scanning")
    store.transition(job_id, "expired")
    with pytest.raises(IllegalTransition):
        store.transition(job_id, "failed")


def test_fail_keeps_step_and_records_error(store):
    events = []
    store.subscribe(lambda jid, e: events.append(e))
    job_id = store.create("upload")["id"]
    store.transition(job_id, "extracting")
    job = store.fail(job_id, "E_ZIP_BOMB", "Too compressed.", "Re-zip normally.")
    assert job["status"] == "failed" and job["step"] == "extracting"
    assert job["error"] == {"code": "E_ZIP_BOMB", "message": "Too compressed.",
                            "hint": "Re-zip normally."}
    assert events[-1]["type"] == "error"
    with pytest.raises(IllegalTransition):
        store.transition(job_id, "parsing")


def test_update_merges_summary_and_dedupes_warnings(store):
    job_id = store.create("upload")["id"]
    store.update(job_id, summary={"packages": 10})
    store.update(job_id, summary={"findings": 2}, warning={"code": "W_WORKSPACES"})
    job = store.update(job_id, warning={"code": "W_WORKSPACES"})
    assert job["summary"] == {"packages": 10, "findings": 2}
    assert job["warnings"] == [{"code": "W_WORKSPACES"}]


def test_ttl_expires_purges_files_then_row(store, clock):
    old = store.create("upload")["id"]
    clock.advance(30)
    fresh = store.create("upload")["id"]
    (store.job_dir(old) / "scan.json").write_text("{}")
    clock.advance(31)
    assert store.purge_expired() == [old]
    assert store.get(old)["status"] == "expired"
    assert not store.job_dir(old).exists()
    assert store.get(fresh)["status"] == "queued"
    assert store.purge_expired() == []
    clock.advance(61)
    store.purge_expired()
    with pytest.raises(AppError):
        store.get(old)


def test_delete_purges_row_and_files(store):
    job_id = store.create("upload")["id"]
    (store.job_dir(job_id) / "src").mkdir()
    store.delete(job_id)
    assert not store.job_dir(job_id).exists()
    with pytest.raises(AppError) as exc:
        store.get(job_id)
    assert exc.value.status == 404
    with pytest.raises(AppError):
        store.delete(job_id)


@pytest.mark.parametrize("bad", ["", "../etc", "ABC", "0" * 31, "0" * 32 + "/..", None])
def test_invalid_job_ids_rejected(store, bad):
    with pytest.raises(AppError) as exc:
        store.job_dir(bad)
    assert exc.value.code == "E_NOT_FOUND"


def test_store_survives_reopen(tmp_path, clock):
    a = JobStore(tmp_path, 60, clock)
    job_id = a.create("upload")["id"]
    a.close()
    b = JobStore(tmp_path, 60, clock)
    assert b.get(job_id)["status"] == "queued"
    b.close()


def test_proposal_transitions():
    for path in (["proposed", "approved", "resolving", "testing", "rescanning", "verified"],
                 ["proposed", "approved", "resolving", "verify_failed"]):
        for old, new in zip(path, path[1:], strict=False):
            check_transition(PROPOSAL_TRANSITIONS, old, new)
    with pytest.raises(IllegalTransition):
        check_transition(PROPOSAL_TRANSITIONS, "proposed", "testing")
    with pytest.raises(IllegalTransition):
        check_transition(PROPOSAL_TRANSITIONS, "verified", "approved")


def test_concurrent_access_is_serialised(store):
    import threading

    job_id = store.create("upload")["id"]
    errors = []

    def hammer(n):
        try:
            for i in range(150):
                store.get(job_id)
                store.update(job_id, summary={f"k{n}": i})
                store.purge_expired()
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=hammer, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert set(store.get(job_id)["summary"]) == {f"k{n}" for n in range(6)}
