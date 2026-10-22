import io
import zipfile

import pytest
from fastapi.testclient import TestClient
from helpers import real, wait_job

from app.config import ROOT
from app.errors import AppError
from app.main import create_app
from app.scanner.base import Package, build_result
from app.scanner.fixture import record
from app.stacks import BY_ID, found_in, unlocked_in

FIX = real(ROOT / "backend" / "tests" / "fixtures" / "stacks")


def load(stack: str, fixture: str):
    return BY_ID[stack].load(FIX / fixture)


def labels(g, keys) -> set[str]:
    return {g.nodes[k].label for k in keys}


def direct(g) -> dict[str, str]:
    return {g.nodes[e.dst].label: e.kind for e in g.out[""]}


def edges(g) -> set[tuple[str, str]]:
    return {(g.nodes[e.src].label, g.nodes[e.dst].label) for es in g.out.values() for e in es}


def codes(g) -> set[str]:
    return {w["code"] for w in g.lock.warnings}


def test_pip_compile_uses_via_annotations():
    g = load("pip", "pip-compiled")
    assert direct(g) == {"flask@2.2.2": "prod", "jinja2@3.1.2": "prod", "pytest@7.4.0": "dev"}
    assert ("flask@2.2.2", "click@8.1.7") in edges(g)
    assert ("jinja2@3.1.2", "markupsafe@2.1.3") in edges(g)
    assert ("werkzeug@2.2.2", "markupsafe@2.1.3") in edges(g)
    assert g.scope["pytest@7.4.0"] == "dev" and g.scope["click@8.1.7"] == "prod"
    assert {n.ecosystem for n in g.nodes.values()} == {"PyPI"}
    assert "W_FLAT_LOCK" not in codes(g)


def test_pip_flat_with_pyproject_marks_only_declared_direct():
    g = load("pip", "pip-flat")
    assert g.lock.root.name == "firstapi"
    assert set(direct(g)) == {"fastapi@0.95.0", "uvicorn@0.21.1"}
    assert g.depth.get("pydantic@1.10.2") is None
    assert "W_FLAT_LOCK" in codes(g)
    assert len(g.packages()) == 4


def test_pip_unpinned_is_reported_not_guessed():
    g = load("pip", "pip-unpinned")
    assert set(g.packages()) == {"requests@2.25.0"}
    msg = next(w["message"] for w in g.lock.warnings if w["code"] == "W_UNPINNED")
    assert "fastapi" in msg and "uvicorn" in msg


def test_poetry_edges_and_groups():
    g = load("poetry", "poetry")
    assert g.lock.root.name == "poetry-app"
    assert direct(g) == {"django@3.2.4": "prod", "pytest@7.4.0": "dev"}
    assert {("django@3.2.4", "asgiref@3.6.0"), ("django@3.2.4", "sqlparse@0.4.3")} <= edges(g)
    assert g.paths_to("pytz@2023.3") == [["root", "django@3.2.4", "pytz@2023.3"]]


def test_uv_lock_root_and_dev_group():
    g = load("uv", "uv")
    assert g.lock.root.name == "uv-app"
    assert direct(g) == {"requests@2.25.0": "prod", "pytest@8.0.0": "dev"}
    assert g.scope["urllib3@1.26.4"] == "prod" and g.depth["urllib3@1.26.4"] == 2


def test_pipenv_lock():
    g = load("pipenv", "pipenv")
    assert direct(g) == {"requests@2.25.0": "prod", "pytest@7.4.0": "dev"}
    assert g.nodes["urllib3@1.26.4"].version == "1.26.4" and "W_FLAT_LOCK" in codes(g)


def test_go_mod_direct_indirect_and_replace():
    g = load("go", "go")
    assert g.lock.root.name == "example.com/shop"
    assert set(direct(g)) == {"github.com/gin-gonic/gin@1.9.0", "github.com/new/lib@1.2.0"}
    assert "golang.org/x/net@0.10.0" in g.packages()
    assert all(n.ecosystem == "Go" for n in g.nodes.values())


def test_cargo_multiple_versions_and_dev():
    g = load("cargo", "cargo")
    assert direct(g) == {"smallvec@1.6.0": "prod", "tempfile@3.3.0": "dev"}
    assert ("tempfile@3.3.0", "smallvec@0.6.14") in edges(g)
    assert g.scope["smallvec@0.6.14"] == "dev" and g.scope["smallvec@1.6.0"] == "prod"


def test_composer_skips_platform_and_strips_v():
    g = load("composer", "composer")
    assert direct(g) == {"guzzlehttp/guzzle@7.4.0": "prod", "phpunit/phpunit@9.5.0": "dev"}
    assert ("guzzlehttp/guzzle@7.4.0", "guzzlehttp/psr7@2.1.0") in edges(g)
    assert not g.unresolved


def test_bundler_platform_versions_and_groups():
    g = load("bundler", "bundler")
    assert direct(g) == {"rails@6.1.0": "prod", "rspec@3.12.0": "dev", "pry@0.14.1": "dev"}
    assert ("rails@6.1.0", "nokogiri@1.13.10") in edges(g)
    assert ("nokogiri@1.13.10", "racc@1.6.0") in edges(g)


def test_nuget_lock():
    g = load("nuget", "nuget")
    assert g.lock.root.name == "Web"
    assert direct(g) == {"Newtonsoft.Json@12.0.1": "prod"}
    assert ("Newtonsoft.Json@12.0.1", "System.Runtime@4.3.0") in edges(g)


def test_gradle_lockfile():
    g = load("gradle", "gradle")
    assert set(g.packages()) == {"com.fasterxml.jackson.core:jackson-databind@2.9.10",
                                 "junit:junit@4.12"}
    assert g.scope["junit:junit@4.12"] == "dev"


def test_detection_picks_best_lock_per_language():
    assert [s.id for s in found_in(FIX / "poetry")] == ["poetry"]
    assert [s.id for s in found_in(FIX / "pip-flat")] == ["pip"]
    assert [s.id for s in found_in(FIX / "cargo")] == ["cargo"]
    assert found_in(FIX) == []


def test_manifest_without_lock_is_explained(tmp_path):
    (tmp_path / "Cargo.toml").write_text("[package]\nname='x'\n", encoding="utf-8")
    (tmp_path / "pom.xml").write_text("<project/>", encoding="utf-8")
    assert [s.language for s in unlocked_in(tmp_path)] == ["Rust", "Java"]


def test_corrupt_lock_is_a_clean_error(tmp_path):
    (tmp_path / "Cargo.lock").write_text("[[package]\nname=", encoding="utf-8")
    with pytest.raises(AppError) as e:
        BY_ID["cargo"].load(tmp_path)
    assert e.value.code == "E_BAD_LOCKFILE"


@pytest.mark.parametrize("stack,fixture", [
    ("pip", "pip-compiled"), ("poetry", "poetry"), ("uv", "uv"), ("go", "go"),
    ("cargo", "cargo"), ("composer", "composer"), ("bundler", "bundler"), ("nuget", "nuget")])
def test_graph_json_is_serialisable(stack, fixture):
    data = load(stack, fixture).to_json()
    assert data["nodes"] and all(n["ecosystem"] != "npm" for n in data["nodes"] if n["id"])


STACK_HITS = [
    ("pip-compiled", "Python", Package("flask", "2.2.2", "PyPI")),
    ("poetry", "Python", Package("django", "3.2.4", "PyPI")),
    ("uv", "Python", Package("urllib3", "1.26.4", "PyPI")),
    ("pipenv", "Python", Package("requests", "2.25.0", "PyPI")),
    ("go", "Go", Package("github.com/gin-gonic/gin", "1.9.0", "Go")),
    ("cargo", "Rust", Package("smallvec", "1.6.0", "crates.io")),
    ("composer", "PHP", Package("guzzlehttp/guzzle", "7.4.0", "Packagist")),
    ("bundler", "Ruby", Package("nokogiri", "1.13.10", "RubyGems")),
    ("nuget", ".NET", Package("Newtonsoft.Json", "12.0.1", "NuGet")),
    ("gradle", "Java", Package("com.fasterxml.jackson.core:jackson-databind", "2.9.10", "Maven")),
]


@pytest.mark.parametrize("fixture,language,pkg", STACK_HITS)
def test_offline_scan_every_stack(settings, tmp_path, fixture, language, pkg):
    record(build_result({pkg: [{
        "id": f"TEST-{fixture}", "summary": "test advisory", "modified": "2099-01-01T00:00:00Z",
        "affected": [{"package": {"ecosystem": pkg.ecosystem, "name": pkg.name},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": "0"}, {"fixed": "99.0.0"}]}]}]}]},
        {"name": "fixture", "version": "t"}, "2099-01-01T00:00:00.000Z"), tmp_path / "rec")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for path in (FIX / fixture).rglob("*"):
            z.write(path, f"{fixture}/{path.relative_to(FIX / fixture).as_posix()}")
    s = settings.model_copy(update={"recorded_dir": tmp_path / "rec"})
    with TestClient(create_app(s)) as c:
        r = c.post("/api/jobs", files={"file": ("p.zip", buf.getvalue(), "application/zip")})
        job = wait_job(c, r.json()["job_id"])
        assert job["status"] == "ready", job.get("error")
        assert job["summary"]["language"] == language and job["summary"]["findings"] == 1
        [f] = c.get(f"/api/jobs/{job['id']}/findings").json()["items"]
        assert f["package"] == {"name": pkg.name, "version": pkg.version,
                                "ecosystem": pkg.ecosystem}
        assert f["fixed_versions"] == ["99.0.0"]
        sbom = c.get(f"/api/jobs/{job['id']}/sbom").json()
        assert sbom["components"] and sbom["vulnerabilities"][0]["id"] == f"TEST-{fixture}"
