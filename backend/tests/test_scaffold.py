"""Repository layout, tooling config and env template."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

REQUIRED_FILES = [
    "README.md", "docs/SECURITY.md", "tasks.py", "pyproject.toml",
    "requirements.txt", "requirements-dev.txt", ".env.example", ".gitignore",
    ".gitattributes", ".github/workflows/ci.yml",
]
PACKAGES = ["app", "app/scanner", "app/ai", "app/remediation", "app/verify", "app/report",
            "app/routes", "app/stacks", "app/web"]
ENV_KEYS = {
    "SCANNER", "AI_PROVIDER", "ANTHROPIC_API_KEY", "AI_MODEL", "VERIFY_MODE", "MAX_UPLOAD_MB",
    "MAX_FILES", "MAX_UNZIPPED_MB", "MAX_RATIO", "JOB_TTL_MIN", "SCAN_TIMEOUT_S",
    "VERIFY_TIMEOUT_S", "RATE_LIMIT", "LOCAL_ONLY", "WEB_TIMEOUT_S", "WEB_MAX_PAGE_KB",
    "WEB_MAX_ASSET_KB", "WEB_MAX_ASSETS", "WEB_MAX_TOTAL_MB", "WEB_ALLOW_PRIVATE",
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
    assert set(tasks.COMMANDS) == {"setup", "dev", "check", "e2e", "docker", "demo", "record",
                                   "rehearse"}
