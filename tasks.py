"""Cross-platform task runner: python tasks.py <setup|dev|check|e2e|docker|demo> [-k EXPR]."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
UNIT_MARKERS = "not e2e and not docker and not live"
PYTEST_QUIET = ["-q", "-x", "--tb=short"]


def venv_python() -> str:
    exe = VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    return str(exe) if exe.exists() else sys.executable


def run(*cmd: str, env: dict[str, str] | None = None) -> int:
    return subprocess.call(list(cmd), cwd=ROOT, env={**os.environ, **(env or {})})


def setup(_: argparse.Namespace) -> int:
    if not VENV.exists():
        venv.create(VENV, with_pip=True)
    py = venv_python()
    for step in (
        [py, "-m", "pip", "install", "-q", "--upgrade", "pip"],
        [py, "-m", "pip", "install", "-q", "-r", "requirements-dev.txt"],
        [py, "-m", "playwright", "install", "chromium"],
    ):
        if code := run(*step):
            return code
    return 0


def dev(_: argparse.Namespace) -> int:
    return run(venv_python(), "-m", "uvicorn", "app.main:app", "--reload",
               "--reload-dir", "backend", "--reload-dir", "frontend",
               "--timeout-graceful-shutdown", "2", "--port", "8000", "--app-dir", "backend")


def check(_: argparse.Namespace) -> int:
    py = venv_python()
    if code := run(py, "-m", "ruff", "check", "-q", "."):
        return code
    return run(py, "-m", "pytest", *PYTEST_QUIET, "-m", UNIT_MARKERS)


def e2e(args: argparse.Namespace) -> int:
    extra = ["-k", args.k] if args.k else []
    return run(venv_python(), "-m", "pytest", *PYTEST_QUIET, "-m", "e2e", *extra,
               "backend/tests/e2e")


def docker(_: argparse.Namespace) -> int:
    if code := run("docker", "build", "-q", "-t", "depguard-worker", "worker"):
        return code
    return run(venv_python(), "-m", "pytest", *PYTEST_QUIET, "-m", "docker")


def demo(_: argparse.Namespace) -> int:
    env = {"SCANNER": "fixture", "AI_PROVIDER": "template", "VERIFY_MODE": "auto"}
    return run(venv_python(), "-m", "uvicorn", "app.main:app", "--port", "8000",
               "--app-dir", "backend", env=env)


def record(_: argparse.Namespace) -> int:
    """Live-scan the bundled samples and refresh recorded OSV data + expected findings."""
    return run(venv_python(), "-c", "import sys; sys.path.insert(0, 'backend'); "
               "from app.scanner.record import main; main()")


def rehearse(args: argparse.Namespace) -> int:
    """Time the demo with OSV, registry and npm offline; --warm fills the npm cache first."""
    flags = ", '--warm'" if args.warm else ""
    return run(venv_python(), "-c", "import sys; sys.path.insert(0, 'backend'); "
               f"from app.rehearse import main; sys.exit(main([{flags.lstrip(', ')}]))")


COMMANDS = {f.__name__: f for f in (setup, dev, check, e2e, docker, demo, record, rehearse)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tasks.py")
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument("-k", help="pytest -k expression (e2e)")
    parser.add_argument("--warm", action="store_true", help="rehearse: online warm-up first")
    args = parser.parse_args(argv)
    return COMMANDS[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
