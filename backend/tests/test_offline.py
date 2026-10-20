import asyncio
import shutil
import time

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from helpers import wait_job

from app.config import ROOT, Settings
from app.main import create_app
from app.remediation import make_checker
from app.remediation.registry import Registry, RegistryError
from app.scanner.base import Package
from app.scanner.cache import DiskCache
from app.verify import modes

DEAD = "https://dead.test"


@respx.mock
async def test_registry_stops_calling_after_transport_failure(tmp_path):
    route = respx.get(url__startswith=DEAD).mock(side_effect=httpx.ConnectError("down"))
    reg = Registry(DEAD, DiskCache(tmp_path, 0), recorded=ROOT / "samples" / "_recorded" / "npm")
    assert "4.17.1" in (await reg.packument("express"))["versions"]
    calls = route.call_count
    await reg.packument("qs")
    with pytest.raises(RegistryError, match="unreachable"):
        await reg.packument("left-pad")
    assert route.call_count == calls and reg.down


@respx.mock
async def test_checker_falls_back_to_recording_for_demos(tmp_path):
    route = respx.post(f"{DEAD}/v1/querybatch").mock(side_effect=httpx.ConnectError("down"))
    s = Settings(_env_file=None, data_dir=tmp_path, scanner="osv-api", osv_api_url=DEAD)
    check = make_checker(s, demo=True)
    out = await check([Package("qs", "6.7.0"), Package("left-pad", "1.3.0")])
    assert "GHSA-hrpp-h998-j3pp" in out["qs@6.7.0"] and out["left-pad@1.3.0"] is None
    first = route.call_count
    await check([Package("qs", "6.16.1")])
    assert route.call_count == first, "circuit stays open"
    upload_check = make_checker(s, demo=False)
    assert await upload_check([Package("qs", "6.7.0")]) == {"qs@6.7.0": None}


@pytest.fixture
def offline_demo(tmp_path):
    shutil.copytree(ROOT / "samples" / "vuln-demo", tmp_path / "samples" / "vuln-demo")
    return Settings(_env_file=None, data_dir=tmp_path / "data", frontend_dir=tmp_path,
                    samples_dir=tmp_path / "samples", scanner="osv-api", osv_api_url=DEAD,
                    registry_url=DEAD, verify_mode="mock", rate_limit="1000/min")


def verify_qs(c):
    job_id = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"], timeout=30)["id"]
    fid = c.get(f"/api/jobs/{job_id}/findings",
                params={"q": "GHSA-hrpp-h998-j3pp"}).json()["items"][0]["id"]
    p = c.post(f"/api/jobs/{job_id}/findings/{fid}/proposal").json()["items"][0]
    c.post(f"/api/jobs/{job_id}/proposals/{p['pid']}/approve", json={"confirm": True})
    for _ in range(400):
        v = c.get(f"/api/jobs/{job_id}/proposals/{p['pid']}/verification").json()
        if v["status"] in ("verified", "verify_failed", "unable_to_verify"):
            return p, v
        time.sleep(0.05)
    raise AssertionError(v)


def test_offline_demo_rescans_from_recording(offline_demo):
    with respx.mock(assert_all_mocked=True) as m:
        m.route(url__startswith=DEAD).mock(side_effect=httpx.ConnectError("down"))
        with TestClient(create_app(offline_demo)) as c:
            p, v = verify_qs(c)
    assert p["strategy"] == "parent-bump"
    assert not any("not re-checked" in w for w in p["warnings"])
    assert v["status"] == "verified" and v["scan"]["source"] == "cache"
    assert any(x.startswith("Rescan used the recorded scan") for x in v["labels"])


def test_offline_rescan_refuses_unrecorded_target(offline_demo, monkeypatch):
    original = modes.MockExecutor.run

    async def bump_qs_further(self, stage, workspace, timeout, on_line, tag):
        for c in self.changes:
            if c["pkg"] == "qs":
                c["to"] = "6.99.0"
        return await original(self, stage, workspace, timeout, on_line, tag)

    monkeypatch.setattr(modes.MockExecutor, "run", bump_qs_further)
    with respx.mock() as m:
        m.route(url__startswith=DEAD).mock(side_effect=httpx.ConnectError("down"))
        with TestClient(create_app(offline_demo)) as c:
            _, v = verify_qs(c)
    assert v["status"] == "unable_to_verify"
    assert "qs@6.99.0 is not in the recorded scan" in v["reason"]


def test_offline_registry_without_recording_raises(tmp_path):
    reg = Registry(DEAD, DiskCache(tmp_path, 0), offline=True)
    with pytest.raises(RegistryError):
        asyncio.run(reg.packument("left-pad"))
