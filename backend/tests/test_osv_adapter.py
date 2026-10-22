import json
from pathlib import Path

import httpx
import pytest
import respx

from app.config import RECORDED
from app.scanner.base import Package, ScanError
from app.scanner.cache import DiskCache
from app.scanner.fixture import RecordedScanner
from app.scanner.osv_api import OsvApiScanner
from app.scanner.osv_cli import OsvCliScanner

BASE = "https://osv.test"
QS_ID = "GHSA-hrpp-h998-j3pp"
QS = Package("qs", "6.7.0")
LP = Package("left-pad", "1.3.0")
VULNS = RECORDED / "osv" / "vulns"


def record(vid: str) -> dict:
    return json.loads((VULNS / f"{vid}.json").read_text(encoding="utf-8"))


def ok(vid: str) -> httpx.Response:
    return httpx.Response(200, json=record(vid))


def batch(*per_query) -> httpx.Response:
    return httpx.Response(200, json={"results": list(per_query)})


def hit(vid=QS_ID, modified="2025-04-29T15:41:43Z", **extra):
    return {"vulns": [{"id": vid, "modified": modified}], **extra}


@pytest.fixture
def scanner(tmp_path):
    return OsvApiScanner(BASE, DiskCache(tmp_path / "cache", 3600), backoff_s=0)


@respx.mock
async def test_ok_batch_then_details(scanner):
    q = respx.post(f"{BASE}/v1/querybatch").mock(return_value=batch({}, hit()))
    v = respx.get(f"{BASE}/v1/vulns/{QS_ID}").mock(return_value=ok(QS_ID))
    result = await scanner.scan([LP, QS])
    assert result.source == "live" and result.scanner["name"] == "osv-api"
    assert [r["id"] for r in result.vulns_for(QS)] == [QS_ID]
    assert result.vulns_for(LP) == []
    sent = json.loads(q.calls[0].request.content)["queries"]
    assert sent == [{"package": {"name": "left-pad", "ecosystem": "npm"}, "version": "1.3.0"},
                    {"package": {"name": "qs", "ecosystem": "npm"}, "version": "6.7.0"}]
    assert v.call_count == 1


@respx.mock
async def test_vuln_records_cached_by_modified(scanner):
    respx.post(f"{BASE}/v1/querybatch").mock(return_value=batch(hit()))
    v = respx.get(f"{BASE}/v1/vulns/{QS_ID}").mock(return_value=ok(QS_ID))
    await scanner.scan([QS])
    await scanner.scan([QS])
    assert v.call_count == 1


@respx.mock
async def test_pagination_follows_next_page_token(scanner):
    q = respx.post(f"{BASE}/v1/querybatch").mock(side_effect=[
        batch(hit(next_page_token="p2")),
        batch(hit("GHSA-6rw7-vpxm-498p", "x")),
    ])
    for vid in (QS_ID, "GHSA-6rw7-vpxm-498p"):
        respx.get(f"{BASE}/v1/vulns/{vid}").mock(return_value=httpx.Response(200, json=record(vid)))
    result = await scanner.scan([QS])
    assert sorted(r["id"] for r in result.vulns_for(QS)) == ["GHSA-6rw7-vpxm-498p", QS_ID]
    assert json.loads(q.calls[1].request.content)["queries"][0]["page_token"] == "p2"


@respx.mock
async def test_timeout_retries_then_fails_without_cache(scanner):
    q = respx.post(f"{BASE}/v1/querybatch").mock(side_effect=httpx.ConnectTimeout("slow"))
    with pytest.raises(ScanError, match="ConnectTimeout"):
        await scanner.scan([QS])
    assert q.call_count == 3


@respx.mock
async def test_5xx_retry_recovers(scanner):
    q = respx.post(f"{BASE}/v1/querybatch").mock(side_effect=[httpx.Response(503), batch({})])
    result = await scanner.scan([LP])
    assert result.source == "live" and q.call_count == 2


@respx.mock
async def test_5xx_falls_back_to_cache(tmp_path):
    cache = DiskCache(tmp_path / "cache", 3600)
    respx.post(f"{BASE}/v1/querybatch").mock(return_value=batch(hit()))
    respx.get(f"{BASE}/v1/vulns/{QS_ID}").mock(return_value=httpx.Response(200, json=record(QS_ID)))
    await OsvApiScanner(BASE, cache, backoff_s=0).scan([QS])
    respx.post(f"{BASE}/v1/querybatch").mock(return_value=httpx.Response(503))
    result = await OsvApiScanner(BASE, cache, backoff_s=0).scan([QS])
    assert result.source == "cache"
    assert [r["id"] for r in result.vulns_for(QS)] == [QS_ID]
    assert any("HTTP 503" in n for n in result.notes)


@respx.mock
async def test_partial_cache_is_not_used(scanner):
    respx.post(f"{BASE}/v1/querybatch").mock(return_value=batch({}))
    await scanner.scan([LP])
    respx.post(f"{BASE}/v1/querybatch").mock(return_value=httpx.Response(500))
    with pytest.raises(ScanError):
        await scanner.scan([LP, QS])


@respx.mock
async def test_client_error_not_retried(scanner):
    q = respx.post(f"{BASE}/v1/querybatch").mock(return_value=httpx.Response(400))
    with pytest.raises(ScanError, match="HTTP 400"):
        await scanner.scan([QS])
    assert q.call_count == 1


@respx.mock
async def test_mismatched_batch_rejected(scanner):
    respx.post(f"{BASE}/v1/querybatch").mock(return_value=batch({}))
    with pytest.raises(ScanError, match="mismatched"):
        await scanner.scan([QS, LP])


def test_cache_ttl(tmp_path):
    now = [1000.0]
    cache = DiskCache(tmp_path, 60, clock=lambda: now[0])
    cache.put("k", {"a": 1})
    assert cache.get("k") == {"a": 1}
    now[0] += 61
    assert cache.get("k") is None and cache.get("k", allow_stale=True) == {"a": 1}
    assert cache.get("other") is None


async def test_recorded_scanner_replays(tmp_path):
    result = await RecordedScanner(RECORDED / "osv").scan([QS, LP])
    assert QS_ID in [r["id"] for r in result.vulns_for(QS)] and result.vulns_for(LP) == []
    with pytest.raises(ScanError):
        await RecordedScanner(tmp_path).scan([QS])


async def test_osv_cli_adapter_parses_json(tmp_path):
    payload = {"results": [{"packages": [
        {"package": {"name": "qs", "version": "6.7.0", "ecosystem": "npm"},
         "vulnerabilities": [record(QS_ID), record(QS_ID)]},
        {"package": {"name": "x", "version": "1", "ecosystem": "PyPI"}, "vulnerabilities": [{}]},
    ]}]}
    calls = []

    async def runner(args, timeout):
        calls.append(args)
        if "--version" in args:
            return 0, "osv-scanner version: 1.9.2\n", ""
        return 1, json.dumps(payload), ""

    lock = tmp_path / "package-lock.json"
    result = await OsvCliScanner("osv-scanner", runner=runner).scan([QS, LP], lock)
    assert result.scanner == {"name": "osv-cli", "version": "1.9.2"}
    assert [r["id"] for r in result.vulns_for(QS)] == [QS_ID]
    assert calls[1] == ["osv-scanner", "--format", "json", "--lockfile", str(lock)]


async def test_osv_cli_errors():
    async def bad(args, timeout):
        return (0, "v1.0.0", "") if "--version" in args else (2, "", "boom")

    with pytest.raises(ScanError, match="exited 2"):
        await OsvCliScanner("osv-scanner", runner=bad).scan([QS], Path("x"))
    with pytest.raises(ScanError, match="not installed"):
        await OsvCliScanner("", runner=bad).scan([QS], Path("x"))
