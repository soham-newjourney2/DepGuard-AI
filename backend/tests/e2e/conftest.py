import functools
import shutil
import socket
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import uvicorn

from app.config import ROOT, Settings
from app.main import create_app

ZIPS = Path(__file__).parents[1] / "fixtures" / "zips"


@pytest.fixture(scope="session")
def base_url(tmp_path_factory):
    samples = tmp_path_factory.mktemp("samples")
    for name in ("vuln-demo", "clean-demo"):
        shutil.copytree(ROOT / "samples" / name, samples / name)
    settings = Settings(_env_file=None, data_dir=tmp_path_factory.mktemp("data"),
                        frontend_dir=ROOT / "frontend", samples_dir=samples, scanner="fixture",
                        ai_provider="template", verify_mode="mock", rate_limit="1000/min",
                        web_allow_private=True)
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


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@pytest.fixture(scope="session")
def site_url():
    """Static server for samples/site-demo (the e2e API runs with WEB_ALLOW_PRIVATE)."""
    handler = functools.partial(QuietHandler, directory=str(ROOT / "samples" / "site-demo"))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()
