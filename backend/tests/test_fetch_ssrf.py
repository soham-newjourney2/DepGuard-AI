import httpx
import pytest

from app.errors import AppError
from app.web.fetch import Fetcher, blocked, parse_target

PUBLIC = "93.184.216.34"
DNS = {"example.com": [PUBLIC], "evil.test": ["10.0.0.5"], "mixed.test": [PUBLIC, "127.0.0.1"],
       "mapped.test": ["::ffff:192.168.1.1"], "cdn.test": ["151.101.1.1"]}


async def resolve(host, port):
    return DNS.get(host, [])


def fetcher(handler, **kw) -> Fetcher:
    return Fetcher(resolver=resolve, transport=httpx.MockTransport(handler), **kw)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.10",
                                "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1",
                                "fd00::1", "::ffff:10.0.0.1", "2002:0a00:0001::1", "224.0.0.1",
                                "240.0.0.1", "not-an-ip"])
def test_blocked_addresses(ip):
    assert blocked(ip)


@pytest.mark.parametrize("ip", [PUBLIC, "8.8.8.8", "2606:4700:4700::1111"])
def test_public_addresses(ip):
    assert not blocked(ip)


@pytest.mark.parametrize("url,code", [
    ("ftp://example.com/", "E_URL_SCHEME"), ("file:///etc/passwd", "E_URL_SCHEME"),
    ("javascript:alert(1)", "E_URL_INVALID"), ("https://example.com:8080/", "E_URL_PORT"),
    ("https://user:pw@example.com/", "E_URL_INVALID"), ("http://localhost/", "E_URL_BLOCKED"),
    ("http://db.internal/", "E_URL_BLOCKED"), ("", "E_URL_INVALID"),
    ("https://exa mple.com", "E_URL_INVALID"), ("https://example.com:99999/", "E_URL_INVALID"),
])
def test_bad_urls_rejected(url, code):
    with pytest.raises(AppError) as e:
        parse_target(url)
    assert e.value.code == code


def test_scheme_defaults_to_https_and_normalises():
    t = parse_target("Example.COM/path?q=1#frag")
    assert t.url == "https://example.com/path?q=1" and t.port == 443


@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/",
                                 "http://evil.test/", "http://mixed.test/",
                                 "http://mapped.test/", "http://nowhere.test/"])
async def test_private_targets_never_requested(url):
    calls = []
    async with fetcher(lambda r: calls.append(r) or httpx.Response(200)) as f:
        with pytest.raises(AppError) as e:
            await f.get(url, 1000)
    assert e.value.code in ("E_URL_BLOCKED", "E_URL_DNS") and calls == []


async def test_connection_pinned_to_vetted_ip_with_host_and_sni():
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(200, headers={"content-type": "text/html; charset=utf-8"},
                              content=b"<html></html>")
    async with fetcher(handler) as f:
        page = await f.get("https://example.com/a?b=1", 1000)
    req = seen[0]
    assert req.url.host == PUBLIC and req.url.path == "/a" and req.url.query == b"b=1"
    assert req.headers["host"] == "example.com"
    assert req.extensions["sni_hostname"] == "example.com"
    assert page.content_type == "text/html" and page.url == "https://example.com/a?b=1"


async def test_redirect_to_private_is_blocked():
    def handler(req):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/"})
    async with fetcher(handler) as f:
        with pytest.raises(AppError) as e:
            await f.get("https://example.com/", 1000)
    assert e.value.code == "E_URL_BLOCKED"


async def test_redirect_chain_followed_and_capped():
    hops = iter(range(100))

    def handler(req):
        return httpx.Response(301, headers={"location": f"/r{next(hops)}"})
    async with fetcher(handler) as f:
        with pytest.raises(AppError) as e:
            await f.get("https://example.com/", 1000)
    assert e.value.code == "E_URL_REDIRECTS"


async def test_relative_redirect_then_ok():
    def handler(req):
        if req.url.path == "/":
            return httpx.Response(302, headers={"location": "https://cdn.test/final"})
        return httpx.Response(200, content=b"ok")
    async with fetcher(handler) as f:
        page = await f.get("https://example.com/", 1000)
    assert page.url == "https://cdn.test/final" and page.redirects == ["https://cdn.test/final"]


async def test_oversize_body_truncated_and_budget_shared():
    async with fetcher(lambda r: httpx.Response(200, content=b"x" * 5000),
                       total_bytes=6000) as f:
        a = await f.get("https://example.com/", 4000)
        b = await f.get("https://example.com/", 4000)
    assert (len(a.body), a.truncated) == (4000, True)
    assert (len(b.body), b.truncated) == (2000, True)


async def test_no_cookies_carried_between_requests():
    seen = []

    def handler(req):
        seen.append(req.headers.get("cookie"))
        return httpx.Response(200, headers={"set-cookie": "sid=secret; Path=/"})
    async with fetcher(handler) as f:
        await f.get("https://example.com/", 100)
        await f.get("https://example.com/", 100)
    assert seen == [None, None]


async def test_allow_private_is_opt_in():
    async with fetcher(lambda r: httpx.Response(200, content=b"ok"), allow_private=True) as f:
        assert (await f.get("http://127.0.0.1/", 10)).body == b"ok"
