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
