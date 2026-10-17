def test_index_served_at_root(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "DepGuard AI" in r.text


def test_static_asset_served(client):
    r = client.get("/app.js")
    assert r.status_code == 200 and "javascript" in r.headers["content-type"]


def test_static_traversal_blocked(client):
    for path in ("/../pyproject.toml", "/%2e%2e/pyproject.toml", "/..%2fpyproject.toml"):
        r = client.get(path)
        assert r.status_code == 404 and "tool.ruff" not in r.text


def test_api_routes_win_over_static(client):
    assert client.get("/api/health").headers["content-type"] == "application/json"
