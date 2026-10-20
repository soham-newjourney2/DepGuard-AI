import pytest

from app.security import HEADERS


@pytest.mark.parametrize("path", ["/api/health", "/api/nope", "/", "/app.js", "/missing.css"])
def test_security_headers_on_every_response(client, path):
    r = client.get(path)
    for name, value in HEADERS.items():
        assert r.headers.get(name) == value, (path, name)


def test_csp_is_self_only(client):
    csp = client.get("/").headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp


def test_headers_not_duplicated(client):
    r = client.get("/api/health")
    assert len(r.headers.get_list("x-frame-options")) == 1


def test_cache_and_compression_headers(client):
    assert client.get("/api/health").headers["cache-control"] == "no-store"
    assert client.get("/app.js").headers["cache-control"] == "no-cache"
    big = client.get("/api/health", headers={"accept-encoding": "gzip"})
    assert big.status_code == 200


def test_immutable_assets_and_gzip(settings):
    from fastapi.testclient import TestClient

    from app.main import create_app

    (settings.frontend_dir / "vendor").mkdir()
    (settings.frontend_dir / "vendor" / "lib.js").write_text("x" * 5000)
    with TestClient(create_app(settings)) as c:
        r = c.get("/vendor/lib.js", headers={"accept-encoding": "gzip"})
        assert r.headers["cache-control"] == "public, max-age=31536000, immutable"
        assert r.headers["content-encoding"] == "gzip"
