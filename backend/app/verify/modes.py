import asyncio
import hashlib
import json
import os
import re
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from app.samples import real_name

NPM_FLAGS = ["--ignore-scripts", "--no-audit", "--no-fund"]
LOCAL_FLAGS = ["--prefer-offline"]
SKIP = {"node_modules", ".git", ".npm-cache"}

OnLine = Callable[[str], None]


@dataclass
class StageResult:
    exit_code: int | None
    timed_out: bool = False
    infra_error: str | None = None


def local_commands(stage: str, npm: str) -> list[list[str]]:
    if stage == "resolve":
        return [[npm, "install", "--package-lock-only", *NPM_FLAGS, *LOCAL_FLAGS],
                [npm, "ci", *NPM_FLAGS, *LOCAL_FLAGS]]
    if stage == "test":
        return [[npm, "test", "--if-present"]]
    raise ValueError(f"unknown stage {stage!r}")


def clean_env(workspace: Path, cache: Path | None = None) -> dict[str, str]:
    """Minimal environment: no tokens, keys or user config reach the verification process."""
    keep = {k: v for k, v in os.environ.items()
            if k.upper() in {"PATH", "SYSTEMROOT", "COMSPEC", "PATHEXT", "WINDIR", "TEMP", "TMP"}}
    return {**keep, "CI": "true", "HOME": str(workspace), "USERPROFILE": str(workspace),
            "npm_config_cache": str(cache or workspace / ".npm-cache"),
            "npm_config_userconfig": str(workspace / ".npmrc-none"),
            "npm_config_update_notifier": "false", "npm_config_fund": "false",
            "npm_config_audit": "false", "npm_config_ignore_scripts": "true"}


async def stream(argv: list[str], cwd: Path | None, env: dict | None, timeout: float,
                 on_line: OnLine) -> StageResult:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, cwd=cwd, env=env, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT)
    except OSError as exc:
        return StageResult(None, infra_error=f"could not start {Path(argv[0]).name}: {exc}")

    async def pump():
        while line := await proc.stdout.readline():
            on_line(line.decode("utf-8", "replace").rstrip("\r\n"))
        await proc.wait()

    try:
        await asyncio.wait_for(pump(), timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return StageResult(proc.returncode, timed_out=True)
    return StageResult(proc.returncode)


class LocalExecutor:
    """demo-local: bundled samples only, scripts disabled, minimal env, labelled in the UI."""

    name = "demo-local"

    def __init__(self, cache: Path | None = None):
        self.npm = shutil.which("npm") or "npm"
        self.cache = cache

    async def run(self, stage: str, workspace: Path, timeout: float,
                  on_line: OnLine) -> StageResult:
        deadline = time.monotonic() + timeout
        result = StageResult(0)
        for argv in local_commands(stage, self.npm):
            on_line("$ " + " ".join([Path(argv[0]).stem, *argv[1:]]))
            left = max(1.0, deadline - time.monotonic())
            result = await stream(argv, workspace, clean_env(workspace, self.cache), left, on_line)
            if result.exit_code != 0 or result.timed_out or result.infra_error:
                return result
        return result


class MockExecutor:
    """Test-only: rewrites the lockfile from the proposal's predicted changes; runs nothing."""

    name = "mock"

    def __init__(self, changes: list[dict], test_exit: int = 0):
        self.changes = changes
        self.test_exit = test_exit

    async def run(self, stage: str, workspace: Path, timeout: float,
                  on_line: OnLine) -> StageResult:
        await asyncio.sleep(0.05)
        if stage == "resolve":
            on_line("$ npm install --package-lock-only --ignore-scripts")
            lock_path = workspace / "package-lock.json"
            lock = json.loads(lock_path.read_text("utf-8"))
            for key, entry in (lock.get("packages") or {}).items():
                name = entry.get("name") or key.rsplit("node_modules/", 1)[-1]
                for c in self.changes:
                    if key and c["pkg"] == name and entry.get("version") == c["from"]:
                        entry["version"] = c["to"]
            lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
            on_line(f"added 0 packages, changed {len(self.changes)} packages in 0.1s")
            on_line("$ npm ci --ignore-scripts")
            on_line("\x1b[32madded 95 packages\x1b[0m in 0.2s")
            return StageResult(0)
        on_line("$ npm test --if-present")
        on_line("\x1b[32m✔\x1b[0m search parses nested query strings (12ms)")
        on_line(f"\x1b[{'32' if self.test_exit == 0 else '31'}mℹ tests 1\x1b[0m")
        return StageResult(self.test_exit)


def tree_hash(root: Path, stored: bool = False) -> str:
    """stored=True reads a bundled demo, whose manifests carry the .sample suffix."""
    files = []
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        if path.is_file() and not SKIP & set(rel.parts):
            files.append(((real_name(rel) if stored else rel).as_posix(), path))
    h = hashlib.sha256()
    for rel, path in sorted(files):
        h.update(rel.encode() + b"\0" + path.read_bytes().replace(b"\r\n", b"\n"))
    return h.hexdigest()


VERIFY_SAMPLES = re.compile(r"(vuln-demo|clean-demo|messy-demo)\.zip")


def verify_candidate(job: dict) -> bool:
    """Only a bundled npm demo can ever be verified; the hash check happens at approval."""
    return job.get("source") == "demo" and bool(VERIFY_SAMPLES.fullmatch(job.get("filename") or ""))


def sample_matches(project: Path, samples_dir: Path, filename: str | None) -> bool:
    m = VERIFY_SAMPLES.fullmatch(filename or "")
    if not m or not (samples_dir / m.group(1)).is_dir():
        return False
    return tree_hash(project) == tree_hash(samples_dir / m.group(1), stored=True)
