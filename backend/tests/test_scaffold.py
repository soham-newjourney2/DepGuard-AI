"""P0.1: repository layout, tooling config and env template match planning.md §3."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

REQUIRED_FILES = [
    "CLAUDE.md", "planning.md", "README.md", "SECURITY.md", "tasks.py", "pyproject.toml",
    "requirements.txt", "requirements-dev.txt", ".env.example", ".gitignore",
    "docs/log-archive.md", "LICENSE", ".gitattributes", ".github/workflows/ci.yml",
]
PACKAGES = ["app", "app/scanner", "app/ai", "app/remediation", "app/verify", "app/report",
            "app/routes"]
ENV_KEYS = {
    "SCANNER", "AI_PROVIDER", "ANTHROPIC_API_KEY", "AI_MODEL", "VERIFY_MODE", "MAX_UPLOAD_MB",
    "MAX_FILES", "MAX_UNZIPPED_MB", "MAX_RATIO", "JOB_TTL_MIN", "SCAN_TIMEOUT_S",
    "VERIFY_TIMEOUT_S", "RATE_LIMIT",
}


def test_required_files_exist():
    missing = [f for f in REQUIRED_FILES if not (ROOT / f).is_file()]
    assert not missing


def test_backend_packages_importable():
    for pkg in PACKAGES:
        assert (ROOT / "backend" / pkg / "__init__.py").is_file(), pkg


def test_pytest_markers_declared():
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    markers = {m.split(":")[0] for m in cfg["tool"]["pytest"]["ini_options"]["markers"]}
    assert {"e2e", "docker", "live"} <= markers


def test_env_example_has_all_config_keys():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    keys = set(re.findall(r"^([A-Z_]+)=", text, re.M))
    assert keys == ENV_KEYS


def test_gitignore_covers_runtime_and_secrets():
    lines = (ROOT / ".gitignore").read_text(encoding="utf-8").split()
    assert {"data/", ".env", ".venv/"} <= set(lines)


def test_tasks_exposes_commands():
    import importlib.util

    spec = importlib.util.spec_from_file_location("tasks", ROOT / "tasks.py")
    tasks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tasks)
    assert set(tasks.COMMANDS) == {"setup", "dev", "check", "e2e", "docker", "demo"}
