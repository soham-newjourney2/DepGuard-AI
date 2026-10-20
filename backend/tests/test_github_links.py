import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from helpers import ZIPS, wait_job

from app import github
from app.errors import AppError
from app.main import create_app

BASE = "https://codeload.test"


@pytest.mark.parametrize("text,owner,repo,cands", [
    ("vercel/ms", "vercel", "ms", [("HEAD", None)]),
    ("vercel/ms@2.1.3", "vercel", "ms", [("2.1.3", None)]),
    ("https://github.com/vercel/ms", "vercel", "ms", [("HEAD", None)]),
    ("github.com/vercel/ms/", "vercel", "ms", [("HEAD", None)]),
    ("http://www.github.com/vercel/ms?tab=readme#top", "vercel", "ms", [("HEAD", None)]),
    ("https://github.com/vercel/ms.git", "vercel", "ms", [("HEAD", None)]),
    ("git@github.com:vercel/ms.git", "vercel", "ms", [("HEAD", None)]),
    ("ssh://git@github.com/vercel/ms.git", "vercel", "ms", [("HEAD", None)]),
    ("https://github.com/o/r/tree/main", "o", "r", [("main", None)]),
    ("https://github.com/o/r/tree/main/apps/api", "o", "r",
     [("main", "apps/api"), ("main/apps", "api"), ("main/apps/api", None)]),
    ("https://github.com/o/r/blob/dev/server/package.json", "o", "r",
     [("dev", "server"), ("dev/server", None)]),
    ("https://github.com/o/r/blob/main/requirements.txt", "o", "r", [("main", None)]),
    ("https://github.com/o/r/commit/0123abcd", "o", "r", [("0123abcd", None)]),
    ("https://github.com/o/r/releases/tag/v1.2.0", "o", "r", [("v1.2.0", None)]),
])
def test_links_parse_to_candidates(text, owner, repo, cands):
    link = github.parse_link(text)
    assert (link.owner, link.repo) == (owner, repo)
    assert link.candidates() == cands


@pytest.mark.parametrize("text", [
    "", "vercel", "https://gitlab.com/o/r", "https://github.com/o", "https://github.com/o/r/pull/1",
    "https://github.com/o/r/issues", "https://github.com/o/r/tree/main/../../etc",
    "https://github.com/-bad/r", "https://evil.test/github.com/o/r", "https://github.com/o/r/wat/x",
    "javascript:alert(1)",
])
def test_bad_links_rejected(text):
    with pytest.raises(AppError) as e:
        github.parse_link(text)
    assert e.value.code == "E_INVALID"


def test_candidates_capped_for_deep_paths():
    link = github.parse_link("https://github.com/o/r/tree/" + "/".join("abcdefgh"))
    assert len(link.candidates()) == github.MAX_REF_SEGMENTS


@pytest.fixture
def gh(settings):
    s = settings.model_copy(update={"github_codeload_url": BASE})
    with TestClient(create_app(s), raise_server_exceptions=False) as c:
        yield c


def test_tree_link_probes_refs_and_picks_subproject(gh):
    body = (ZIPS / "multi_projects.zip").read_bytes()
    with respx.mock() as m:
        miss = m.get(f"{BASE}/o/r/zip/feature").mock(return_value=httpx.Response(404))
        hit = m.get(f"{BASE}/o/r/zip/feature/x").mock(return_value=httpx.Response(200,
                                                                                   content=body))
        r = gh.post("/api/jobs/github",
                    json={"repo": "https://github.com/o/r/tree/feature/x/server"})
        assert r.status_code == 202, r.json()
        job = wait_job(gh, r.json()["job_id"])
    assert miss.call_count == 1 and hit.call_count == 1
    assert job["status"] == "ready", job.get("error")
    assert job["filename"] == "o/r@feature/x (server/)"
    assert job["warnings"][0]["chosen"] == "repo/server"


def test_plain_repo_link_imports_head(gh):
    with respx.mock(assert_all_called=True) as m:
        m.get(f"{BASE}/vercel/ms/zip/HEAD").mock(return_value=httpx.Response(
            200, content=(ZIPS / "github_repo.zip").read_bytes()))
        r = gh.post("/api/jobs/github", json={"repo": "https://github.com/vercel/ms.git"})
        job = wait_job(gh, r.json()["job_id"])
    assert job["status"] == "ready" and job["filename"] == "vercel/ms@HEAD"


def test_all_candidates_missing_is_not_found(gh):
    with respx.mock() as m:
        m.get(url__regex=rf"{BASE}/o/r/zip/.*").mock(return_value=httpx.Response(404))
        r = gh.post("/api/jobs/github", json={"repo": "https://github.com/o/r/tree/nope/x"})
    assert r.status_code == 404 and r.json()["error"]["code"] == "E_GITHUB_NOT_FOUND"
    assert list(gh.app.state.store.root.iterdir()) == []
