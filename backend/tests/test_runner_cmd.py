from pathlib import Path

import pytest

from app.verify.modes import IMAGE, clean_env, docker_argv, local_commands

WS = Path("/data/jobs/abc/verify/p_1/work")
HARDENED = ["--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt",
            "no-new-privileges", "--pids-limit", "256", "--memory", "1g", "--cpus", "1",
            "--user", "node"]


def test_test_stage_exact_flags():
    argv = docker_argv("test", WS, "depguard-x-test")
    assert argv == ["docker", "run", "--rm", "--name", "depguard-x-test", "--network", "none",
                    *HARDENED, "-v", f"{WS.resolve()}:/work", "-w", "/work", IMAGE, "test"]


def test_resolve_stage_has_network_but_same_hardening():
    argv = docker_argv("resolve", WS, "n")
    assert "--network" not in argv
    assert argv[argv.index("--read-only"):argv.index("-v")] == HARDENED
    assert argv[-2:] == [IMAGE, "resolve"]


def test_no_env_or_user_command_reaches_container():
    for stage in ("resolve", "test"):
        argv = docker_argv(stage, WS, "n")
        assert "-e" not in argv and "--env" not in argv and "--privileged" not in argv
        assert argv[-1] in ("resolve", "test")


@pytest.mark.parametrize("stage", ["build", "sh -c 'rm -rf /'", ""])
def test_unknown_stage_rejected(stage):
    with pytest.raises(ValueError):
        docker_argv(stage, WS, "n")
    with pytest.raises(ValueError):
        local_commands(stage, "npm")


def test_local_commands_disable_scripts():
    resolve = local_commands("resolve", "npm")
    assert resolve == [["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit",
                        "--no-fund", "--prefer-offline"],
                       ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund",
                        "--prefer-offline"]]
    assert local_commands("test", "npm") == [["npm", "test", "--if-present"]]


def test_clean_env_strips_secrets(monkeypatch, tmp_path):
    for k in ("ANTHROPIC_API_KEY", "NPM_TOKEN", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY",
              "NODE_OPTIONS", "npm_config_registry"):
        monkeypatch.setenv(k, "secret")
    env = clean_env(tmp_path)
    assert not {"ANTHROPIC_API_KEY", "NPM_TOKEN", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY",
                "NODE_OPTIONS", "npm_config_registry"} & set(env)
    assert env["npm_config_ignore_scripts"] == "true" and env["CI"] == "true"
    assert env["npm_config_cache"].startswith(str(tmp_path))
    assert "secret" not in env.values()


def test_worker_files_pin_image_and_fix_stages():
    root = Path(__file__).resolve().parents[2] / "worker"
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM node:20." in dockerfile and "@sha256:" in dockerfile
    assert "USER node" in dockerfile and "npm_config_ignore_scripts=true" in dockerfile
    entry = (root / "entry.sh").read_text(encoding="utf-8")
    assert "npm install --package-lock-only --ignore-scripts" in entry
    assert "npm ci --ignore-scripts" in entry and "exec npm test --if-present" in entry
    assert "\r\n" not in entry
