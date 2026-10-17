from fastapi.testclient import TestClient

from app import __version__
from app.config import Settings
from app.errors import AppError
from app.main import create_app


def test_health_reports_config(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "version": __version__, "scanner": "fixture",
                        "ai": "template", "verify_mode": "mock"}


def test_ai_auto_uses_anthropic_when_key_set(settings):
    keyed = settings.model_copy(update={"anthropic_api_key": "sk-test"})
    assert keyed.ai_effective == "anthropic"
    off = settings.model_copy(update={"ai_provider": "off"})
    assert off.ai_effective == "off"


def test_env_overrides(monkeypatch, tmp_path):
    monkeypatch.setenv("SCANNER", "osv-cli")
    monkeypatch.setenv("MAX_UPLOAD_MB", "3")
    s = Settings(_env_file=None)
    assert (s.scanner, s.max_upload_mb) == ("osv-cli", 3)


def test_unknown_api_route_is_json_envelope(client):
    r = client.get("/api/nope")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "E_NOT_FOUND"


def test_wrong_method_envelope(client):
    r = client.post("/api/health")
    assert r.status_code == 405
    assert r.json()["error"]["code"] == "E_METHOD"


def test_validation_error_envelope(settings):
    app = create_app(settings.model_copy(update={"frontend_dir": settings.data_dir}))

    @app.get("/api/echo")
    def _echo(n: int):
        return {"n": n}

    r = TestClient(app).get("/api/echo?n=abc")
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "E_INVALID" and "query.n" in err["message"]


def test_app_error_and_crash_envelopes(settings):
    app = create_app(settings.model_copy(update={"frontend_dir": settings.data_dir}))

    @app.get("/boom/app")
    def _app():
        raise AppError("E_BAD_JSON", "bad", "fix it", 400)

    @app.get("/boom/crash")
    def _crash():
        raise RuntimeError("secret detail")

    c = TestClient(app, raise_server_exceptions=False)
    assert c.get("/boom/app").json() == {"error": {"code": "E_BAD_JSON", "message": "bad",
                                                   "hint": "fix it"}}
    r = c.get("/boom/crash")
    assert r.status_code == 500 and r.json()["error"]["code"] == "E_INTERNAL"
    assert "secret detail" not in r.text
