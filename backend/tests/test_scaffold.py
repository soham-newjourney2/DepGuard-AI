"""Repository layout, tooling config and env template."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

REQUIRED_FILES = [
    "README.md", "docs/walkthrough.md", "docs/structure.md", "tasks.py", "pyproject.toml",
    "requirements.txt", "requirements-dev.txt", ".env.example", ".gitignore",
    ".gitattributes",
]
PACKAGES = ["app", "app/scanner", "app/ai", "app/remediation", "app/verify", "app/report",
            "app/routes", "app/stacks"]
ENV_KEYS = {
    "SCANNER", "VERIFY_MODE", "MAX_UPLOAD_MB",
    "MAX_FILES", "MAX_UNZIPPED_MB", "MAX_RATIO", "JOB_TTL_MIN", "SCAN_TIMEOUT_S",
    "VERIFY_TIMEOUT_S", "RATE_LIMIT", "LOCAL_ONLY", "EXPLOIT_SIGNALS",
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
    assert {"e2e", "live"} <= markers


def test_env_example_has_all_config_keys():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    keys = set(re.findall(r"^([A-Z_]+)=", text, re.M))
    assert keys == ENV_KEYS


def test_gitignore_covers_runtime_and_secrets():
    lines = (ROOT / ".gitignore").read_text(encoding="utf-8").split()
    assert {"/data/", ".env", ".venv/"} <= set(lines)
    assert "data/" not in lines, "an unanchored data/ would also hide backend/app/data"


def test_tasks_exposes_commands():
    import importlib.util

    spec = importlib.util.spec_from_file_location("tasks", ROOT / "tasks.py")
    tasks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tasks)
    assert set(tasks.COMMANDS) == {"setup", "dev", "check", "e2e", "demo", "record",
                                   "rehearse", "answers", "doctor"}


MANIFEST = re.compile(r"^(package(-lock)?\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|"
                      r"pnpm-workspace\.yaml|.*requirements.*\.(txt|in)|Pipfile(\.lock)?|"
                      r"pyproject\.toml|poetry\.lock|uv\.lock|go\.(mod|sum)|Cargo\.(toml|lock)|"
                      r"composer\.(json|lock)|Gemfile(\.lock)?|packages\.lock\.json|.*\.csproj|"
                      r"build\.gradle(\.kts)?|.*\.lockfile)$")


def test_demo_and_fixture_manifests_are_stored_as_samples():
    # GitHub would raise dependency and malware alerts for these on purpose-vulnerable demos
    roots = [ROOT / "samples", ROOT / "backend" / "tests" / "fixtures"]
    found = [p.relative_to(ROOT).as_posix() for r in roots for p in r.rglob("*")
             if p.is_file() and MANIFEST.match(p.name) and "node_modules" not in p.parts]
    assert found == []
