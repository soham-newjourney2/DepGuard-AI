import json
import shutil

import pytest
from fastapi.testclient import TestClient
from helpers import ZIPS, upload, wait_job

from app.jobs import JobStore, iso, utcnow
from app.main import create_app
from app.routes.jobs import clean_filename


def test_upload_runs_to_ready(client):
    r = upload(client, "ok_root.zip")
    assert r.status_code == 202
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "ready" and job["source"] == "upload"
    assert job["filename"] == "ok_root.zip"
    sm = job["summary"]
    assert {k: sm[k] for k in ("files", "lockfile_version", "packages", "direct", "max_depth",
                               "unresolved", "findings")} == {
        "files": 3, "lockfile_version": 3, "packages": 1, "direct": 1, "max_depth": 1,
        "unresolved": 0, "findings": 0}
    assert sm["scan"]["scanner"] == "fixture" and sm["scan"]["source"] == "live"
    graph = json.loads((client.app.state.store.job_dir(job["id"]) / "graph.json").read_text())
    assert [n["label"] for n in graph["nodes"]] == ["root", "left-pad@1.3.0"]
    store = client.app.state.store
    assert not (store.job_dir(job["id"]) / "upload.zip").exists(), "upload deleted after extract"
    assert (store.job_dir(job["id"]) / "src" / "package.json").is_file()


def test_workspaces_warning_surfaces(client):
    job = wait_job(client, upload(client, "workspaces.zip").json()["job_id"])
    assert job["status"] == "ready"
    assert [w["code"] for w in job["warnings"]] == ["W_WORKSPACES"]


@pytest.mark.parametrize("name,code", [
    ("traversal.zip", "E_PATH_TRAVERSAL"),
    ("not_a_zip.zip", "E_NOT_ZIP"),
    ("lockfile_v1.zip", "E_LOCKFILE_VERSION"),
])
def test_bad_upload_fails_job_with_error(client, name, code):
    job = wait_job(client, upload(client, name).json()["job_id"])
    assert job["status"] == "failed" and job["step"] == "extracting"
    assert job["error"]["code"] == code and job["error"]["hint"]


def test_upload_too_large_rejected_early(settings):
    app = create_app(settings.model_copy(update={"max_upload_mb": 0}))
    with TestClient(app) as c:
        r = upload(c, "ok_root.zip")
        assert r.status_code == 413 and r.json()["error"]["code"] == "E_TOO_LARGE"
        assert list(c.app.state.store.root.iterdir()) == []


def test_upload_requires_file_field(client):
    r = client.post("/api/jobs", data={"x": "1"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "E_INVALID"


def test_filename_is_sanitised(client):
    data = (ZIPS / "ok_root.zip").read_bytes()
    r = client.post("/api/jobs", files={"file": ("..\\..\\evil.zip", data, "application/zip")})
    job = wait_job(client, r.json()["job_id"])
    assert job["filename"] == "evil.zip"
    assert clean_filename("a/b\\c\x07\x1b.zip") == "c.zip"
    assert clean_filename("") == "upload.zip"
    assert len(clean_filename("x" * 500)) == 200


def test_demo_unknown_and_missing(client):
    assert client.post("/api/jobs/demo/..%2F..%2Fetc").status_code == 404
    r = client.post("/api/jobs/demo/nope")
    assert r.status_code == 404 and r.json()["error"]["code"] == "E_NOT_FOUND"
    assert client.post("/api/jobs/demo/vuln-demo").status_code == 404


def test_demo_sample_runs(client, settings, tmp_path):
    sample = settings.samples_dir / "vuln-demo"
    sample.mkdir(parents=True)
    shutil.unpack_archive(ZIPS / "ok_root.zip", sample)
    (sample / "node_modules" / "x").mkdir(parents=True)
    (sample / "node_modules" / "x" / "index.js").write_text("1")
    r = client.post("/api/jobs/demo/vuln-demo")
    assert r.status_code == 202
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "ready" and job["source"] == "demo"
    assert job["summary"]["files"] == 3


@pytest.mark.parametrize("job_id", ["0" * 32, "nope", "..%2F..%2Fetc"])
def test_get_unknown_job(client, job_id):
    r = client.get(f"/api/jobs/{job_id}")
    assert r.status_code == 404 and r.json()["error"]["code"] == "E_NOT_FOUND"


def test_delete_purges_job(client):
    job = wait_job(client, upload(client, "ok_root.zip").json()["job_id"])
    path = client.app.state.store.job_dir(job["id"])
    assert client.delete(f"/api/jobs/{job['id']}").status_code == 204
    assert not path.exists()
    assert client.get(f"/api/jobs/{job['id']}").status_code == 404
    assert client.delete(f"/api/jobs/{job['id']}").status_code == 404


def test_rate_limit(settings):
    app = create_app(settings.model_copy(update={"rate_limit": "2/min"}))
    with TestClient(app) as c:
        assert upload(c, "ok_root.zip").status_code == 202
        assert c.post("/api/jobs/demo/nope").status_code == 404
        r = upload(c, "ok_root.zip")
        assert r.status_code == 429 and r.json()["error"]["code"] == "E_RATE_LIMIT"
        assert int(r.headers["retry-after"]) >= 1
        assert c.get("/api/health").status_code == 200


def test_ttl_cleanup_loop_expires_jobs(settings):
    app = create_app(settings.model_copy(update={"cleanup_interval_s": 0.05}))
    with TestClient(app) as c:
        job = wait_job(c, upload(c, "ok_root.zip").json()["job_id"])
        store = c.app.state.store
        store.conn.execute("UPDATE jobs SET expires_at = ? WHERE id = ?",
                           (iso(utcnow()), job["id"]))
        expired = wait_job(c, job["id"], {"expired"})
        assert expired["status"] == "expired"
        assert not store.job_dir(job["id"]).exists()


def test_restart_marks_running_jobs_interrupted(settings):
    store = JobStore(settings.data_dir, 60)
    job_id = store.create("upload")["id"]
    store.transition(job_id, "extracting")
    store.close()
    with TestClient(create_app(settings)) as c:
        job = c.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "failed" and job["error"]["code"] == "E_INTERRUPTED"


def test_upload_multi_project_auto_picks_and_accepts_choice(client):
    job = wait_job(client, upload(client, "multi_projects.zip").json()["job_id"])
    assert job["status"] == "ready"
    assert job["warnings"][0]["code"] == "W_MULTIPLE_PROJECTS"
    assert job["warnings"][0]["options"] == ["repo/client", "repo/server"]
    data = (ZIPS / "multi_projects.zip").read_bytes()
    r = client.post("/api/jobs", files={"file": ("m.zip", data, "application/zip")},
                    data={"project": "repo/client"})
    ok = wait_job(client, r.json()["job_id"])
    assert ok["status"] == "ready" and ok["warnings"][0]["chosen"] == "repo/client"


def test_nested_server_project_scans(client):
    job = wait_job(client, upload(client, "nested_server.zip").json()["job_id"])
    assert job["status"] == "ready" and job["summary"]["packages"] == 1
    assert "app-main/server/" in job["warnings"][0]["message"]


def test_choose_project_reuses_kept_archive(client):
    job = wait_job(client, upload(client, "multi_projects.zip").json()["job_id"])
    assert (client.app.state.store.job_dir(job["id"]) / "pending.zip").is_file()
    r = client.post(f"/api/jobs/{job['id']}/project", json={"project": "repo/nope"})
    assert r.status_code == 422
    r = client.post(f"/api/jobs/{job['id']}/project", json={"project": "repo/client"})
    assert r.status_code == 202
    ok = wait_job(client, r.json()["job_id"])
    assert ok["status"] == "ready" and ok["filename"] == job["filename"]
    assert ok["warnings"][0]["chosen"] == "repo/client"
    single = wait_job(client, upload(client, "ok_root.zip").json()["job_id"])
    r = client.post(f"/api/jobs/{single['id']}/project", json={"project": "repo/server"})
    assert r.status_code == 409
