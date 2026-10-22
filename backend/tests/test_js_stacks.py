import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import real, wait_job

from app.errors import AppError
from app.main import create_app
from app.risks import Inputs, integrity
from app.stacks import BY_ID, found_in

FIX = Path(__file__).parent / "fixtures"
STACKS = real(FIX / "stacks")
CASES = {"yarn-classic": "yarn", "yarn-berry": "yarn", "pnpm-v5": "pnpm", "pnpm-v6": "pnpm",
         "pnpm-v9": "pnpm"}


def key_of(g, name):
    return next(k for k, n in g.nodes.items() if n.name == name)


@pytest.mark.parametrize("case,stack", CASES.items())
def test_graph_paths_scopes_and_depth(case, stack):
    d = STACKS / case
    [s] = found_in(d)
    assert s.id == stack and s.ecosystem == "npm" and s.language == "Node.js"
    g = s.load(d)
    assert g.stats() == {"packages": 4, "direct": 2, "max_depth": 2, "unresolved": 0}
    qs, lodash = key_of(g, "qs"), key_of(g, "lodash")
    assert ["root", "express@4.17.1", "qs@6.7.0"] in g.paths_to(qs)
    assert ["root", "express@4.17.1", "body-parser@1.19.0", "qs@6.7.0"] in g.paths_to(qs)
    assert g.scope[qs] == "prod" and g.scope[lodash] == "dev" and g.direct(lodash)
    assert g.lockfile_name == s.lockfile


def test_pnpm_workspace_importers():
    d = STACKS / "pnpm-workspace"
    g = found_in(d)[0].load(d)
    qs = key_of(g, "qs")
    paths = g.paths_to(qs)
    assert ["root", "packages/shared@0.0.0-workspace", "qs@6.7.0"] in paths
    assert ["root", "packages/api@0.0.0-workspace", "express@4.17.1", "qs@6.7.0"] in paths
    assert not g.nodes["packages/api@0.0.0-workspace"].installed


def test_package_lock_still_wins_over_other_js_locks(tmp_path):
    for name in ("package.json", "yarn.lock"):
        (tmp_path / name).write_bytes((STACKS / "yarn-classic" / name).read_bytes())
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}')
    assert [s.id for s in found_in(tmp_path)] == ["npm"]


UNSAFE = "lockfileVersion: '9.0'\npackages: !!python/object:os.system {}\n"


@pytest.mark.parametrize("text", ["not: [valid", "- just\n- a list\n", UNSAFE])
def test_bad_or_unsafe_yaml_is_rejected(tmp_path, text):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "pnpm-lock.yaml").write_text(text)
    with pytest.raises(AppError) as exc:
        BY_ID["pnpm"].load(tmp_path)
    assert exc.value.code == "E_BAD_LOCKFILE"


def zip_of(d: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for f in d.iterdir():
            zf.write(f, f.name)
    return buf.getvalue()


@pytest.mark.parametrize("case,stack", [("yarn-classic", "yarn"), ("pnpm-v9", "pnpm")])
def test_upload_scans_end_to_end_with_package_manager_commands(settings, case, stack):
    with TestClient(create_app(settings)) as c:
        r = c.post("/api/jobs", files={"file": (f"{case}.zip", zip_of(STACKS / case),
                                                 "application/zip")})
        job = wait_job(c, r.json()["job_id"])
        assert job["status"] == "ready", job.get("error")
        assert job["summary"]["stack"] == stack and job["summary"]["language"] == "Node.js"
        items = c.get(f"/api/jobs/{job['id']}/findings", params={"q": "qs"}).json()["items"]
        qs = next(i for i in items if i["package"]["name"] == "qs")
        assert qs["path"] == ["root", "express@4.17.1", "qs@6.7.0"]
        props = c.post(f"/api/jobs/{job['id']}/findings/{qs['id']}/proposal").json()["items"]
    p = props[0]
    assert p["verifiable"] is False
    word = "resolutions" if stack == "yarn" else "overrides"
    assert word in p["command"]


@pytest.mark.parametrize("case,expected", [
    ("yarn-rules", [("high", "plain@1.0.0 is fetched over plain HTTP"),
                    ("medium", "gitdep@1.0.0 is resolved from a git URL"),
                    ("medium", "nohash@1.0.0 has no integrity hash in the lockfile"),
                    ("medium", "tarball@1.0.0 is resolved from a non-registry URL "
                               "(evil.example.com)")]),
    ("yarn-berry-rules", [("info", "shared@0.0.0-use.local is a local package"),
                          ("medium", "gitdep@1.0.0 is resolved from a git URL"),
                          ("medium", "nohash@1.0.0 has no integrity hash in the lockfile")]),
    ("pnpm-rules", [("high", "plain@1.0.0 is fetched over plain HTTP"),
                    ("medium", "gitdep@1.0.0 is resolved from a git URL"),
                    ("medium", "nohash@1.0.0 has no integrity hash in the lockfile"),
                    ("medium", "tarball@1.0.0 is resolved from a non-registry URL "
                               "(evil.example.com)")]),
])
def test_integrity_signals(case, expected):
    found = integrity.check(Inputs(real(FIX / "integrity") / case, "x", None, [], "upload"))
    assert sorted((r["severity"], r["title"]) for r in found) == sorted(expected)
    assert all(r["location"]["line"] for r in found)


@pytest.mark.parametrize("case", [*CASES, "pnpm-workspace"])
def test_clean_js_locks_raise_no_integrity_signals(case):
    assert integrity.check(Inputs(STACKS / case, "x", None, [], "upload")) == []
