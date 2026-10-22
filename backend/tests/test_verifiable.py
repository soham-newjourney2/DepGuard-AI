import io
import shutil
import zipfile

import pytest
from fastapi.testclient import TestClient
from helpers import real, wait_job

from app.config import ROOT
from app.main import create_app
from app.verify.modes import verify_candidate

QS = "GHSA-hrpp-h998-j3pp"


def vuln_zip() -> bytes:
    buf = io.BytesIO()
    src = real(ROOT / "samples" / "vuln-demo")
    with zipfile.ZipFile(buf, "w") as zf:
        for path in src.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(src).as_posix())
    return buf.getvalue()


@pytest.fixture
def app_client(settings):
    shutil.copytree(ROOT / "samples" / "vuln-demo", settings.samples_dir / "vuln-demo")
    with TestClient(create_app(settings)) as c:
        yield c


def qs_proposals(c, job_id):
    fid = c.get(f"/api/jobs/{job_id}/findings", params={"q": QS}).json()["items"][0]["id"]
    return c.post(f"/api/jobs/{job_id}/findings/{fid}/proposal").json()["items"]


@pytest.mark.parametrize("job,ok", [
    ({"source": "demo", "filename": "vuln-demo.zip"}, True),
    ({"source": "demo", "filename": "messy-demo.zip"}, True),
    ({"source": "demo", "filename": "python-demo.zip"}, False),
    ({"source": "demo", "filename": "supplychain-demo.zip"}, False),
    ({"source": "upload", "filename": "vuln-demo.zip"}, False),
    ({"source": "github", "filename": "owner/repo@main"}, False),
])
def test_only_bundled_npm_demos_are_verify_candidates(job, ok):
    assert verify_candidate(job) is ok


def test_upload_proposals_are_never_offered_for_verification(app_client):
    c = app_client
    r = c.post("/api/jobs", files={"file": ("vuln-demo.zip", vuln_zip(), "application/zip")})
    job_id = wait_job(c, r.json()["job_id"])["id"]
    props = qs_proposals(c, job_id)
    assert props and all(p["verifiable"] is False for p in props if p["strategy"] != "none")
    assert any("bundled npm demos only" in w for w in props[0]["warnings"])
    approve = c.post(f"/api/jobs/{job_id}/proposals/{props[0]['pid']}/approve",
                     json={"confirm": True})
    assert approve.status_code == 409
    assert approve.json()["error"]["code"] == "E_VERIFY_UNSUPPORTED"
    plan = c.post(f"/api/jobs/{job_id}/plan").json()
    assert plan["verifiable"] is False


def test_demo_proposals_stay_verifiable(app_client):
    c = app_client
    job_id = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"])["id"]
    props = qs_proposals(c, job_id)
    assert props[0].get("verifiable") is not False
    assert not any("bundled npm demos only" in w for w in props[0]["warnings"])
