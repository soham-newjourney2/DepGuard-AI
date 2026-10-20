import asyncio
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

IMAGE = "depguard-worker"
HARDENING = ["--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL",
             "--security-opt", "no-new-privileges", "--pids-limit", "256",
             "--memory", "1g", "--cpus", "1", "--user", "node"]
STAGES = ("resolve", "test")
NPM_FLAGS = ["--ignore-scripts", "--no-audit", "--no-fund"]
LOCAL_FLAGS = ["--prefer-offline"]
SKIP = {"node_modules", ".git", ".npm-cache"}

OnLine = Callable[[str], None]


@dataclass
class StageResult:
    exit_code: int | None
    timed_out: bool = False
    infra_error: str | None = None


def docker_argv(stage: str, workspace: Path, name: str, image: str = IMAGE) -> list[str]:
    if stage not in STAGES:
        raise ValueError(f"unknown stage {stage!r}")
    argv = ["docker", "run", "--rm", "--name", name]
    if stage == "test":
        argv += ["--network", "none"]
    return argv + HARDENING + ["-v", f"{workspace.resolve()}:/work", "-w", "/work",
                               image, stage]


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
                 on_line: OnLine, on_timeout: Callable[[], None] | None = None) -> StageResult:
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
        if on_timeout:
            on_timeout()
        proc.kill()
        await proc.wait()
        return StageResult(proc.returncode, timed_out=True)
    return StageResult(proc.returncode)


class DockerExecutor:
    name = "docker"

    def __init__(self, image: str = IMAGE):
        self.image = image

    @staticmethod
    async def available() -> bool:
        docker = shutil.which("docker")
        if not docker:
            return False
        try:
            proc = await asyncio.create_subprocess_exec(
                docker, "image", "inspect", IMAGE, stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL)
            return await asyncio.wait_for(proc.wait(), 10) == 0
        except (OSError, TimeoutError):
            return False

    async def run(self, stage: str, workspace: Path, timeout: float, on_line: OnLine,
                  tag: str) -> StageResult:
        name = f"depguard-{tag}-{stage}-{int(time.time())}"
        argv = docker_argv(stage, workspace, name, self.image)

        def kill():
            subprocess.run(["docker", "kill", name], capture_output=True, timeout=15,
                           check=False)

        return await stream(argv, None, None, timeout, on_line, on_timeout=kill)


class LocalExecutor:
    """demo-local: bundled samples only, scripts disabled, minimal env, labelled in the UI."""

    name = "demo-local"

    def __init__(self, cache: Path | None = None):
        self.npm = shutil.which("npm") or "npm"
        self.cache = cache

    async def run(self, stage: str, workspace: Path, timeout: float, on_line: OnLine,
                  tag: str) -> StageResult:
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

    async def run(self, stage: str, workspace: Path, timeout: float, on_line: OnLine,
                  tag: str) -> StageResult:
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


def tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root)
        if SKIP & set(rel.parts):
            continue
        h.update(rel.as_posix().encode() + b"\0" + path.read_bytes().replace(b"\r\n", b"\n"))
    return h.hexdigest()


def sample_matches(project: Path, samples_dir: Path, filename: str | None) -> bool:
    m = re.fullmatch(r"(vuln-demo|clean-demo|messy-demo)\.zip", filename or "")
    if not m or not (samples_dir / m.group(1)).is_dir():
        return False
    return tree_hash(project) == tree_hash(samples_dir / m.group(1))
