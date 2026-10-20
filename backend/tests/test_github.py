import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from helpers import ZIPS, wait_job

from app import github
from app.errors import AppError
from app.main import create_app

BASE = "https://codeload.test"


@pytest.mark.parametrize("spec,want", [
    ("vercel/ms", ("vercel", "ms", "HEAD")),
    ("expressjs/express@4.17.1", ("expressjs", "express", "4.17.1")),
    ("o/r@refs/tags/v1.0.0", ("o", "r", "refs/tags/v1.0.0")),
    ("a-b/c.d_e@feature/x", ("a-b", "c.d_e", "feature/x")),
])
def test_parse_valid(spec, want):
    assert github.parse(spec) == want


@pytest.mark.parametrize("spec", [
    "", "vercel", "https://github.com/vercel/ms", "vercel/ms/extra", "-bad/repo", "o/..",
    "o/r@../../etc", "o/r@/abs", "o/r@-x", "o/r@a//b", "o/r@a b", "o/r.git", "o/r@x?y=1",
    "o/r@x#frag", "o/" + "r" * 101,
])
def test_parse_rejects(spec):
    with pytest.raises(AppError) as exc:
        github.parse(spec)
    assert exc.value.code == "E_INVALID"


@pytest.fixture
def gh(settings):
    s = settings.model_copy(update={"github_codeload_url": BASE})
    with TestClient(create_app(s), raise_server_exceptions=False) as c:
        yield c


def test_import_runs_pipeline(gh):
    with respx.mock(assert_all_called=True) as m:
        route = m.get(f"{BASE}/vercel/ms/zip/main").mock(return_value=httpx.Response(
            200, content=(ZIPS / "github_repo.zip").read_bytes(),
            headers={"content-type": "application/zip"}))
        r = gh.post("/api/jobs/github", json={"repo": "vercel/ms@main"})
        assert r.status_code == 202
        job = wait_job(gh, r.json()["job_id"])
    assert route.call_count == 1
    assert job["status"] == "ready" and job["source"] == "github"
    assert job["filename"] == "vercel/ms@main" and job["summary"]["packages"] == 1


def test_not_found_and_errors(gh):
    with respx.mock() as m:
        m.get(f"{BASE}/o/missing/zip/HEAD").mock(return_value=httpx.Response(404))
        r = gh.post("/api/jobs/github", json={"repo": "o/missing"})
        assert r.status_code == 404 and r.json()["error"]["code"] == "E_GITHUB_NOT_FOUND"
        m.get(f"{BASE}/o/moved/zip/HEAD").mock(return_value=httpx.Response(
            302, headers={"location": "https://evil.test/x.zip"}))
        r = gh.post("/api/jobs/github", json={"repo": "o/moved"})
        assert r.status_code == 502 and r.json()["error"]["code"] == "E_GITHUB_UNAVAILABLE"
        m.get(f"{BASE}/o/down/zip/HEAD").mock(side_effect=httpx.ConnectTimeout("t"))
        assert gh.post("/api/jobs/github", json={"repo": "o/down"}).status_code == 502
    assert list(gh.app.state.store.root.iterdir()) == [], "failed imports leave no jobs"


def test_size_limits(settings):
    s = settings.model_copy(update={"github_codeload_url": BASE, "max_upload_mb": 1})
    big = b"0" * (1024 * 1024 + 10)
    with TestClient(create_app(s), raise_server_exceptions=False) as c, respx.mock() as m:
        m.get(f"{BASE}/o/declared/zip/HEAD").mock(return_value=httpx.Response(
            200, headers={"content-length": str(len(big))}, content=big))
        r = c.post("/api/jobs/github", json={"repo": "o/declared"})
        assert r.status_code == 413 and r.json()["error"]["code"] == "E_TOO_LARGE"

        async def chunks():
            for _ in range(20):
                yield b"0" * 100_000

        m.get(f"{BASE}/o/streamed/zip/HEAD").mock(return_value=httpx.Response(
            200, content=chunks()))
        r = c.post("/api/jobs/github", json={"repo": "o/streamed"})
        assert r.status_code == 413


def test_invalid_spec_and_local_only(settings):
    with TestClient(create_app(settings), raise_server_exceptions=False) as c:
        r = c.post("/api/jobs/github", json={"repo": "not a repo"})
        assert r.status_code == 422 and r.json()["error"]["code"] == "E_INVALID"
    local = settings.model_copy(update={"local_only": True})
    with TestClient(create_app(local), raise_server_exceptions=False) as c:
        r = c.post("/api/jobs/github", json={"repo": "vercel/ms"})
        assert r.status_code == 403 and r.json()["error"]["code"] == "E_LOCAL_ONLY"
