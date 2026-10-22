import asyncio
import shutil

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from helpers import wait_job

from app.config import RECORDED, ROOT, Settings
from app.main import create_app
from app.remediation import make_checker, make_registry
from app.remediation.registry import Registry, RegistryError
from app.scanner.base import Package
from app.scanner.cache import DiskCache

DEAD = "https://dead.test"


@respx.mock
async def test_registry_stops_calling_after_transport_failure(tmp_path):
    route = respx.get(url__startswith=DEAD).mock(side_effect=httpx.ConnectError("down"))
    reg = Registry(DEAD, DiskCache(tmp_path, 0), recorded=RECORDED / "npm")
    assert "4.17.1" in (await reg.packument("express"))["versions"]
    calls = route.call_count
    await reg.packument("qs")
    with pytest.raises(RegistryError, match="unreachable"):
        await reg.packument("left-pad")
    assert route.call_count == calls and reg.down


@respx.mock
async def test_checker_reports_unknown_when_osv_down(tmp_path):
    route = respx.post(f"{DEAD}/v1/querybatch").mock(side_effect=httpx.ConnectError("down"))
    s = Settings(_env_file=None, data_dir=tmp_path, scanner="osv-api", osv_api_url=DEAD)
    check = make_checker(s)
    out = await check([Package("qs", "6.7.0"), Package("left-pad", "1.3.0")])
    assert out == {"qs@6.7.0": None, "left-pad@1.3.0": None}
    first = route.call_count
    await check([Package("qs", "6.16.1")])
    assert route.call_count == first, "circuit stays open"


def test_offline_demo_fails_with_clear_message(tmp_path):
    shutil.copytree(ROOT / "samples" / "vuln-demo", tmp_path / "samples" / "vuln-demo")
    s = Settings(_env_file=None, data_dir=tmp_path / "data", frontend_dir=tmp_path,
                 samples_dir=tmp_path / "samples", scanner="osv-api", osv_api_url=DEAD,
                 registry_url=DEAD, verify_mode="mock", rate_limit="1000/min")
    with respx.mock(assert_all_mocked=True) as m:
        m.route(url__startswith=DEAD).mock(side_effect=httpx.ConnectError("down"))
        with TestClient(create_app(s)) as c:
            job = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"], timeout=30)
    assert job["status"] == "failed" and job["error"]["code"] == "E_SCAN_UNAVAILABLE"
    assert "Could not connect to OSV" in job["error"]["message"]
    assert job["warnings"] == [] or all(w["code"] != "W_CACHED_SCAN" for w in job["warnings"])


def test_live_registry_has_no_recorded_fallback(tmp_path):
    reg = make_registry(Settings(_env_file=None, data_dir=tmp_path, scanner="osv-api"))
    assert reg.recorded is None and not reg.offline


def test_offline_registry_without_recording_raises(tmp_path):
    reg = Registry(DEAD, DiskCache(tmp_path, 0), offline=True)
    with pytest.raises(RegistryError):
        asyncio.run(reg.packument("left-pad"))
