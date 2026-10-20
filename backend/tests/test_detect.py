import httpx
import pytest

from app.config import ROOT, Settings
from app.errors import AppError
from app.web import detect
from app.web.site import build_graph, scan_site

SITE = ROOT / "backend" / "tests" / "fixtures" / "site"
PUBLIC = "93.184.216.34"


async def resolve(host, port):
    return [PUBLIC]


def serve(root=SITE, html_type="text/html; charset=utf-8"):
    """MockTransport serving the fixture folder for any host (CDN paths → 404 unless local)."""
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        host = req.headers["host"]
        calls.append(f"{host}{req.url.path}")
        if host != "acme.test":
            return httpx.Response(404)
        rel = req.url.path.lstrip("/") or "index.html"
        path = root / rel
        if not path.is_file():
            return httpx.Response(404)
        ctype = html_type if path.suffix == ".html" else "application/javascript"
        return httpx.Response(200, headers={"content-type": ctype}, content=path.read_bytes())
    return httpx.MockTransport(handler), calls


def by_name(dets) -> dict[str, detect.Detection]:
    return {d.name: d for d in dets}


@pytest.mark.parametrize("url,name,version,kind", [
    ("https://code.jquery.com/jquery-3.4.1.min.js", "jquery", "3.4.1", "cdn-url"),
    ("https://code.jquery.com/jquery-3.5.1.slim.min.js", "jquery", "3.5.1", "cdn-url"),
    ("https://code.jquery.com/ui/1.12.1/jquery-ui.min.js", "jquery-ui", "1.12.1", "cdn-url"),
    ("https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.29.1/moment.min.js", "moment", "2.29.1",
     "cdn-url"),
    ("https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js",
     "bootstrap", "3.3.7", "cdn-url"),
    ("https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js",
     "@popperjs/core", "2.9.2", "cdn-url"),
    ("https://unpkg.com/react-dom@16.8.6/umd/react-dom.production.min.js", "react-dom", "16.8.6",
     "cdn-url"),
    ("https://ajax.googleapis.com/ajax/libs/jqueryui/1.12.1/jquery-ui.min.js", "jquery-ui",
     "1.12.1", "cdn-url"),
    ("https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js", "bootstrap", "3.3.7",
     "cdn-url"),
    ("https://acme.test/js/jquery-1.12.4.min.js", "jquery", "1.12.4", "file-name"),
    ("https://acme.test/js/angular.1.5.8.min.js", "angular", "1.5.8", "file-name"),
    ("https://acme.test/wp-includes/js/jquery/jquery.min.js?ver=3.6.0", "jquery", "3.6.0",
     "version-param"),
])
def test_url_rules(url, name, version, kind):
    [d] = detect.from_url(url, 7, "<script>")
    assert (d.name, d.version, d.evidence[0]["kind"]) == (name, version, kind)
    assert d.evidence[0]["line"] == 7


@pytest.mark.parametrize("url", ["https://acme.test/js/app.js", "https://acme.test/main.3f2a.js",
                                 "https://cdn.jsdelivr.net/gh/user/repo@1.0/x.js",
                                 "https://ajax.googleapis.com/ajax/libs/unknownlib/1.0.0/x.js"])
def test_unversioned_or_unknown_urls_ignored(url):
    assert detect.from_url(url, 1, "") == []


@pytest.mark.parametrize("text,name,version", [
    ("/*! jQuery v3.4.1 | (c) JS Foundation */", "jquery", "3.4.1"),
    ("/*!\n * jQuery JavaScript Library v1.12.4\n */", "jquery", "1.12.4"),
    ("/*! jQuery UI - v1.12.1 - 2016-09-14 */", "jquery-ui", "1.12.1"),
    ("/**\n * @license AngularJS v1.7.8\n */", "angular", "1.7.8"),
    ("/*!\n * Vue.js v2.6.10\n */", "vue", "2.6.10"),
    ("/** @license React v16.8.6\n * react-dom.production.min.js", "react-dom", "16.8.6"),
    ("/** @license React v16.8.6\n * react.production.min.js", "react", "16.8.6"),
    ("/**\n * @license\n * Lodash <https://lodash.com/>\n */\n;(function() {\n"
     "  var VERSION = '4.17.15';", "lodash", "4.17.15"),
    ("/*! @license DOMPurify 2.0.8 */", "dompurify", "2.0.8"),
])
def test_banner_rules(text, name, version):
    dets = by_name(detect.from_text(text, "https://acme.test/x.js"))
    assert dets[name].version == version
    assert dets[name].evidence[0]["kind"] == "banner"


def test_lodash_banner_does_not_claim_underscore():
    text = "/** @license Lodash lodash.com/license | Underscore.js 1.8.3 underscorejs.org */"
    assert "underscore" not in by_name(detect.from_text(text, "u"))


def test_banner_only_near_top():
    text = "x\n" * 5000 + "/*! jQuery v3.4.1 */"
    assert detect.from_text(text, "u") == []


async def test_scan_fixture_site_end_to_end():
    transport, calls = serve()
    s = Settings(_env_file=None)
    site = await scan_site("acme.test", s, resolve, transport)
    d = by_name(site.detections)
    assert site.final_url == "https://acme.test/" and site.title == "Acme & Co"
    assert d["jquery"].version == "3.4.1" and d["jquery"].confidence == "high"
    assert d["jquery"].evidence[0] == {"url": "https://code.jquery.com/jquery-3.4.1.min.js",
                                       "line": 8, "kind": "cdn-url", "text":
                                       '<script src="https://code.jquery.com/jquery-3.4.1.min.js">'
                                       '</script>'}
    assert d["lodash"].version == "4.17.15" and d["vue"].version == "2.6.10"
    assert d["angular"].version == "1.7.8" and d["@popperjs/core"].version == "2.9.2"
    assert d["moment"].version == "2.24.0"
    assert {e["kind"] for e in d["moment"].evidence} == {"file-name", "banner"}
    assert d["jquery-migrate"].version == "3.3.2"
    assert d["bootstrap"].evidence[0]["url"] == "https://acme.test/static/js/vendor.js"
    assert d["handlebars"].version == "4.0.11" and "underscore" not in d
    assert d["dompurify"].evidence[0]["url"].endswith("(inline script)")
    assert d["WordPress"].ecosystem is None and d["WordPress"].version == "5.8.1"
    assert "code.jquery.com/jquery-3.4.1.min.js" not in calls, "versioned CDN URLs not fetched"
    assert any("missing.js: HTTP 404" in n for n in site.notes)
    assert all("data:" not in c for c in calls)
    g = build_graph(site)
    assert "jquery@3.4.1" in g.packages() and "WordPress@5.8.1" not in g.packages()
    assert all(g.direct(k) for keys in g.packages().values() for k in keys)


async def test_non_html_and_error_pages_rejected():
    s = Settings(_env_file=None)
    t = httpx.MockTransport(lambda r: httpx.Response(200, headers={"content-type": "image/png"}))
    with pytest.raises(AppError) as e:
        await scan_site("https://acme.test/", s, resolve, t)
    assert e.value.code == "E_URL_NOT_HTML"
    t = httpx.MockTransport(lambda r: httpx.Response(503))
    with pytest.raises(AppError) as e:
        await scan_site("https://acme.test/", s, resolve, t)
    assert e.value.code == "E_URL_STATUS"


async def test_script_count_capped():
    html = "".join(f'<script src="/s{i}.js"></script>' for i in range(10))
    t = httpx.MockTransport(lambda r: httpx.Response(
        200, headers={"content-type": "text/html"} if r.url.path == "/" else {},
        content=html.encode() if r.url.path == "/" else b"/*! jQuery v1.0.0 */"))
    s = Settings(_env_file=None, web_max_assets=3)
    site = await scan_site("https://acme.test/", s, resolve, t)
    assert site.fetched == 3 and any("first 3 of 10" in n for n in site.notes)


@pytest.fixture
def site_client(settings, tmp_path, monkeypatch):
    from functools import partial

    from fastapi.testclient import TestClient

    from app import pipeline
    from app.main import create_app
    from app.scanner.base import Package, build_result
    from app.scanner.fixture import record

    transport, _ = serve()
    monkeypatch.setattr(pipeline.web, "scan_site",
                        partial(pipeline.web.scan_site, resolver=resolve, transport=transport))
    adv = {"id": "GHSA-gxr4-xjj5-5px2", "summary": "jQuery XSS in htmlPrefilter",
           "modified": "2099-01-01T00:00:00Z",
           "affected": [{"package": {"ecosystem": "npm", "name": "jquery"},
                         "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.2.0"},
                                                                  {"fixed": "3.5.0"}]}]}]}
    record(build_result({Package("jquery", "3.4.1"): [adv]}, {"name": "fixture", "version": "t"},
                        "2099-01-01T00:00:00.000Z"), tmp_path / "rec")
    s = settings.model_copy(update={"recorded_dir": tmp_path / "rec"})
    with TestClient(create_app(s)) as c:
        yield c


def test_url_scan_api_end_to_end(site_client):
    from helpers import wait_job
    c = site_client
    r = c.post("/api/jobs/url", json={"url": "acme.test"})
    assert r.status_code == 202
    job = wait_job(c, r.json()["job_id"])
    assert job["status"] == "ready", job.get("error")
    assert job["source"] == "url" and job["summary"]["language"] == "Website"
    assert job["summary"]["site"]["title"] == "Acme & Co"
    assert {w["code"] for w in job["warnings"]} >= {"W_NOT_SCANNABLE"}
    [f] = c.get(f"/api/jobs/{job['id']}/findings").json()["items"]
    assert f["package"]["name"] == "jquery" and f["direct"]
    full = c.get(f"/api/jobs/{job['id']}/findings/{f['id']}").json()
    assert full["reachability"]["label"] == "Strong evidence"
    assert full["reachability"]["evidence"][0]["file"] == \
        "https://code.jquery.com/jquery-3.4.1.min.js"
    reach = next(e for e in full["evidence"] if e["kind"] == "reachability")
    assert "The page loads jquery 3.4.1" in reach["text"] and reach["source"] == "live page fetch"
    [p] = c.post(f"/api/jobs/{job['id']}/findings/{f['id']}/proposal").json()["items"]
    assert p["changes"][0]["to"] == "3.5.0"
    assert "+  <script src=\"https://code.jquery.com/jquery-3.5.0.min.js\"></script>" in p["diff"]
    assert "jquery-migrate.min.js?ver=3.3.2" in p["diff"] or "migrate" not in p["diff"]
    assert p["verifiable"] is False


@pytest.mark.parametrize("url,code", [("http://127.0.0.1/", "E_URL_BLOCKED"),
                                      ("ftp://x.test/", "E_URL_SCHEME"),
                                      ("https://x.test:8443/", "E_URL_PORT")])
def test_url_scan_rejects_bad_targets_up_front(client, url, code):
    r = client.post("/api/jobs/url", json={"url": url})
    if code == "E_URL_BLOCKED":
        assert r.status_code == 202
        from helpers import wait_job
        job = wait_job(client, r.json()["job_id"])
        assert job["status"] == "failed" and job["error"]["code"] == code
    else:
        assert r.status_code == 422 and r.json()["error"]["code"] == code


def test_url_scan_refused_in_local_only(settings):
    from fastapi.testclient import TestClient

    from app.main import create_app
    with TestClient(create_app(settings.model_copy(update={"local_only": True}))) as c:
        r = c.post("/api/jobs/url", json={"url": "https://example.com"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "E_LOCAL_ONLY"
