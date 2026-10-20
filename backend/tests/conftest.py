import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


@pytest.fixture
def settings(tmp_path) -> Settings:
    web = tmp_path / "frontend"
    web.mkdir()
    (web / "index.html").write_text("<!doctype html><title>DepGuard AI</title>", encoding="utf-8")
    (web / "app.js").write_text("export {};", encoding="utf-8")
    return Settings(_env_file=None, data_dir=tmp_path / "data", frontend_dir=web,
                    samples_dir=tmp_path / "samples",
                    scanner="fixture", ai_provider="auto", anthropic_api_key="",
                    verify_mode="mock")


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings), raise_server_exceptions=False) as c:
        yield c
