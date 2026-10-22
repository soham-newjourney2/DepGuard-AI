import pytest

from app.verify.modes import clean_env, local_commands


@pytest.mark.parametrize("stage", ["build", "sh -c 'rm -rf /'", ""])
def test_unknown_stage_rejected(stage):
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

