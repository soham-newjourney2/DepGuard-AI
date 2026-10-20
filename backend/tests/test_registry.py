import httpx
import pytest
import respx

from app.config import ROOT
from app.remediation.registry import ACCEPT, Registry, RegistryError, file_name, trim
from app.scanner.cache import DiskCache

BASE = "https://npm.test"
RECORDED = ROOT / "samples" / "_recorded" / "npm"
DOC = {"name": "@scope/pkg", "dist-tags": {"latest": "1.1.0"}, "versions": {
    "1.0.0": {"dependencies": {"a": "^1.0.0"}, "dist": {"tarball": "https://x"}},
    "1.1.0": {"deprecated": "use 2", "dist": {"tarball": "https://y"}, "engines": {"node": "*"}},
}}


def reg(tmp_path, **kw):
    return Registry(BASE, DiskCache(tmp_path / "npm", 3600), **kw)


@respx.mock
async def test_fetch_abbreviated_scoped_and_trimmed(tmp_path):
    route = respx.get(f"{BASE}/@scope%2Fpkg").mock(return_value=httpx.Response(200, json=DOC))
    doc = await reg(tmp_path).packument("@scope/pkg")
    assert route.calls[0].request.headers["accept"] == ACCEPT
    assert doc == {"name": "@scope/pkg", "dist-tags": {"latest": "1.1.0"}, "versions": {
        "1.0.0": {"dependencies": {"a": "^1.0.0"}}, "1.1.0": {"deprecated": "use 2"}}}


@respx.mock
async def test_memo_and_disk_cache(tmp_path):
    route = respx.get(f"{BASE}/qs").mock(return_value=httpx.Response(200, json=DOC))
    r = reg(tmp_path)
    await r.packument("qs")
    await r.packument("qs")
    await reg(tmp_path).packument("qs")
    assert route.call_count == 1


@respx.mock
async def test_5xx_retries_then_uses_stale_cache(tmp_path):
    now = [1000.0]
    cache = DiskCache(tmp_path / "npm", 60, clock=lambda: now[0])
    cache.put("npm:qs", trim(DOC))
    now[0] += 120
    route = respx.get(f"{BASE}/qs").mock(return_value=httpx.Response(503))
    r = Registry(BASE, cache)
    assert (await r.packument("qs"))["dist-tags"]["latest"] == "1.1.0"
    assert route.call_count == 2 and r.sources["qs"] == "cache"


@respx.mock
async def test_404_and_unavailable_raise(tmp_path):
    respx.get(f"{BASE}/nope").mock(return_value=httpx.Response(404))
    with pytest.raises(RegistryError, match="not on the registry"):
        await reg(tmp_path).packument("nope")
    respx.get(f"{BASE}/down").mock(side_effect=httpx.ConnectTimeout("t"))
    with pytest.raises(RegistryError, match="unavailable"):
        await reg(tmp_path).packument("down")


@respx.mock
async def test_live_failure_falls_back_to_recorded(tmp_path):
    respx.get(f"{BASE}/qs").mock(return_value=httpx.Response(500))
    r = reg(tmp_path, recorded=RECORDED)
    doc = await r.packument("qs")
    assert "6.7.0" in doc["versions"] and r.sources["qs"] == "recorded"


async def test_offline_reads_recorded_only(tmp_path):
    r = reg(tmp_path, recorded=RECORDED, offline=True)
    assert "4.17.1" in (await r.packument("express"))["versions"]
    with pytest.raises(RegistryError):
        await r.packument("left-pad")


@pytest.mark.parametrize("bad", ["", "../etc", "a b", "UPPER\x00", "x" * 215])
async def test_invalid_names_rejected(tmp_path, bad):
    with pytest.raises(RegistryError, match="invalid"):
        await reg(tmp_path, offline=True).packument(bad)


def test_file_name_for_scoped():
    assert file_name("@scope/pkg") == "@scope__pkg.json"
