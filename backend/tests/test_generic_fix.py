import shutil

import pytest
from helpers import real

from app.config import ROOT
from app.remediation import generic
from app.scanner.base import Package, build_result
from app.scanner.normalize import normalize
from app.stacks import BY_ID

FIX = real(ROOT / "backend" / "tests" / "fixtures" / "stacks")


def adv(vid: str, name: str, fixed: str | None, eco: str = "PyPI", introduced: str = "0") -> dict:
    events = [{"introduced": introduced}] + ([{"fixed": fixed}] if fixed else [])
    return {"id": vid, "summary": f"{name} issue", "modified": "2099-01-01T00:00:00Z",
            "affected": [{"package": {"ecosystem": eco, "name": name},
                          "ranges": [{"type": "ECOSYSTEM", "events": events}]}]}


def findings_for(stack: str, root, vulns: dict) -> list[dict]:
    graph = BY_ID[stack].load(root)
    result = build_result(vulns, {"name": "fixture", "version": "t"}, "2099-01-01T00:00:00.000Z")
    return normalize(result, graph)


async def clean(pkgs: list[Package]) -> dict:
    return {p.label: [] for p in pkgs}


@pytest.fixture
def pyproj(tmp_path):
    shutil.copytree(FIX / "pip-flat", tmp_path / "p")
    return tmp_path / "p"


@pytest.fixture
def pyfindings(pyproj):
    return findings_for("pip", pyproj, {
        Package("fastapi", "0.95.0", "PyPI"): [adv("PYSEC-1", "fastapi", "0.109.1")],
        Package("starlette", "0.26.1", "PyPI"): [adv("GHSA-s1", "starlette", "0.27.0"),
                                                 adv("GHSA-s2", "starlette", "0.36.2")],
    })


def by(findings, name, vid=None):
    return next(f for f in findings if f["package"]["name"] == name
                and (vid is None or f["advisory"]["id"] == vid))


async def test_direct_python_fix_has_real_diff_and_command(pyproj, pyfindings):
    [p] = await generic.plan(by(pyfindings, "fastapi"), pyfindings, pyproj, "pip", clean)
    assert p["strategy"] == "direct-bump" and p["changes"][0]["to"] == "0.109.1"
    assert "-fastapi==0.95.0" in p["diff"] and "+fastapi==0.109.1" in p["diff"]
    assert p["command"] == 'pip install "fastapi==0.109.1"'
    assert p["verifiable"] is False and p["resolves"] == ["PYSEC-1"]
    assert (pyproj / "requirements.txt").read_text("utf-8").count("0.95.0") == 1, "untouched"


async def test_transitive_target_clears_every_advisory(pyproj, pyfindings):
    [p] = await generic.plan(by(pyfindings, "starlette", "GHSA-s1"), pyfindings, pyproj, "pip",
                             clean)
    assert p["strategy"] == "lock-update" and p["changes"][0]["to"] == "0.36.2"
    assert p["resolves"] == ["GHSA-s1", "GHSA-s2"]
    assert any("transitive" in w for w in p["warnings"])
    assert p["changes"][0]["jump"] == "major"


async def test_recheck_hit_is_reported(pyproj, pyfindings):
    async def dirty(pkgs):
        return {p.label: ["GHSA-new"] for p in pkgs}
    [p] = await generic.plan(by(pyfindings, "fastapi"), pyfindings, pyproj, "pip", dirty)
    assert any("still matches 1 OSV advisory" in w for w in p["warnings"])
    assert p["resolves"] == ["PYSEC-1"]


async def test_no_fix_is_honest(pyproj):
    fs = findings_for("pip", pyproj, {
        Package("pydantic", "1.10.2", "PyPI"): [adv("GHSA-x", "pydantic", None)]})
    [p] = await generic.plan(fs[0], fs, pyproj, "pip", clean)
    assert p["strategy"] == "none" and not p["changes"] and not p["diff"]


async def test_batch_merges_per_package(pyproj, pyfindings):
    plan = await generic.plan_batch(pyfindings, pyproj, "pip", clean)
    assert [c["to"] for c in plan["changes"]] == ["0.109.1", "0.36.2"]
    assert "+starlette==0.36.2" in plan["diff"] and "+fastapi==0.109.1" in plan["diff"]
    assert plan["command"].splitlines() == ['pip install "fastapi==0.109.1"',
                                            'pip install "starlette==0.36.2"']
    statuses = {i["advisory"]: i["status"] for i in plan["items"]}
    assert set(statuses.values()) == {"included"} and len(statuses) == 3


async def test_go_fix_edits_go_mod(tmp_path):
    shutil.copytree(FIX / "go", tmp_path / "g")
    root = tmp_path / "g"
    fs = findings_for("go", root, {Package("golang.org/x/net", "0.10.0", "Go"):
                                   [adv("GO-1", "golang.org/x/net", "0.17.0", "Go")]})
    [p] = await generic.plan(fs[0], fs, root, "go", clean)
    assert "+\tgolang.org/x/net v0.17.0 // indirect" in p["diff"] or \
        "golang.org/x/net v0.17.0" in p["diff"]
    assert p["command"] == "go get golang.org/x/net@v0.17.0 && go mod tidy"


async def test_cargo_fix_is_command_only(tmp_path):
    fs = findings_for("cargo", FIX / "cargo", {Package("smallvec", "0.6.14", "crates.io"):
                                               [adv("RUSTSEC-1", "smallvec", "0.6.14-0",
                                                    "crates.io")]})
    fs[0]["fixed_versions"] = ["0.6.15"]
    fs[0]["affected_ranges"] = [{"introduced": "0", "fixed": "0.6.15"}]
    [p] = await generic.plan(fs[0], fs, FIX / "cargo", "cargo", clean)
    assert p["diff"] == "" and p["command"] == "cargo update -p smallvec@0.6.14 --precise 0.6.15"


def test_jump_classification():
    assert generic.jump("PyPI", "1.2.3", "1.2.4") == "patch"
    assert generic.jump("PyPI", "1.2.3", "1.3") == "minor"
    assert generic.jump("Go", "0.10.0", "0.17.0") == "major"
    assert generic.jump("RubyGems", "6.1.0", "7.0.0") == "major"


def test_python_upload_end_to_end(settings, tmp_path):
    import io
    import zipfile

    from fastapi.testclient import TestClient
    from helpers import wait_job

    from app.main import create_app
    from app.scanner.fixture import record

    rec = tmp_path / "rec"
    record(build_result({Package("requests", "2.25.0", "PyPI"):
                         [adv("PYSEC-R", "requests", "2.31.0")]},
                        {"name": "fixture", "version": "t"}, "2099-01-01T00:00:00.000Z"), rec)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("firstapi/requirements.txt", "fastapi\nrequests==2.25.0\n")
        z.writestr("firstapi/main.py", "import requests\n")
    s = settings.model_copy(update={"recorded_dir": rec})
    with TestClient(create_app(s)) as c:
        r = c.post("/api/jobs", files={"file": ("firstapi.zip", buf.getvalue(), "application/zip")})
        job = wait_job(c, r.json()["job_id"])
        assert job["status"] == "ready", job.get("error")
        assert job["summary"]["language"] == "Python" and job["summary"]["findings"] == 1
        assert {w["code"] for w in job["warnings"]} >= {"W_UNPINNED"}
        [f] = c.get(f"/api/jobs/{job['id']}/findings").json()["items"]
        items = c.post(f"/api/jobs/{job['id']}/findings/{f['id']}/proposal").json()["items"]
        assert items[0]["command"] == 'pip install "requests==2.31.0"'
        assert "+requests==2.31.0" in items[0]["diff"]
        r = c.post(f"/api/jobs/{job['id']}/proposals/{items[0]['pid']}/approve",
                   json={"confirm": True})
        assert r.status_code == 409 and r.json()["error"]["code"] == "E_VERIFY_UNSUPPORTED"
