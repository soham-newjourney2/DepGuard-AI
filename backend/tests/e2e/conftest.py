import socket
import threading
import time

import pytest
import uvicorn

from app.config import ROOT, Settings
from app.main import create_app


@pytest.fixture(scope="session")
def base_url(tmp_path_factory):
    settings = Settings(_env_file=None, data_dir=tmp_path_factory.mktemp("data"),
                        frontend_dir=ROOT / "frontend", scanner="fixture",
                        ai_provider="template", verify_mode="mock")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_app(settings), host="127.0.0.1", port=port,
                                           log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("e2e server did not start")
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(5)


@pytest.fixture
def console_errors(page):
    errors: list[str] = []
    page.on("console", lambda m: m.type == "error" and errors.append(m.text))
    page.on("pageerror", lambda e: errors.append(str(e)))
    return errors
