import asyncio
import io
import zipfile
from pathlib import Path

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from helpers import real, wait_job

from app import flatedges
from app.config import RECORDED, Settings
from app.main import create_app
from app.stacks import found_in

STACKS = real(Path(__file__).parent / "fixtures" / "stacks")
PYPI_DOC = {"fastapi": ["pydantic (>=1.6.2,<2.0.0)", "starlette (==0.26.1)",
                        "pytest ; extra == 'test'"],
            "starlette": ["anyio (<5,>=3.4.0)"], "pydantic": ["typing-extensions>=4.2.0"],
            "uvicorn": ["click (>=7.0)", "h11 (>=0.8)"]}


def load(case):
    d = STACKS / case
    s = found_in(d)[0]
    return s, s.load(d)


def test_pypi_requires_dist_parsing():
    doc = {"info": {"requires_dist": ["requests (>=2)", "pytest ; extra == 'dev'",
                                      "colorama ; sys_platform == 'win32'", "not a ((req"]}}
    assert flatedges.pypi_deps(doc) == ["requests", "colorama"]
    assert flatedges.pypi_deps({"info": {"requires_dist": None}}) == []


def test_go_mod_parsing_and_escaping():
    text = ("module github.com/gin-gonic/gin\n\ngo 1.20\n\nrequire (\n"
            "\tgithub.com/a/b v1.2.3\n\tgolang.org/x/net v0.10.0 // indirect\n)\n"
            "require github.com/single/one v0.1.0\n// require github.com/commented/out v1.0.0\n")
    assert flatedges.go_deps(text) == ["github.com/a/b", "github.com/single/one",
                                       "golang.org/x/net"]
    assert flatedges.go_escape("github.com/Azure/SDK") == "github.com/!azure/!s!d!k"


@respx.mock
async def test_live_pypi_adds_edges_only_between_locked_packages(tmp_path):
    for name, deps in PYPI_DOC.items():
        respx.get(url__regex=rf"https://pypi\.org/pypi/{name}/[^/]+/json").mock(
            return_value=httpx.Response(200, json={"info": {"requires_dist": deps}}))
    stack, g = load("pip-flat")
    assert any(w["code"] == "W_FLAT_LOCK" for w in g.lock.warnings)
    new, note = await flatedges.infer(g, stack.id, flatedges.Metadata(tmp_path, 3600))
    assert new is not None and "Inferred dependency paths from PyPI" in note
    pyd = next(k for k, n in new.nodes.items() if n.name == "pydantic")
    assert new.paths_to(pyd)[0][:2] == ["root", "fastapi@0.95.0"]
    assert set(new.nodes) == set(g.nodes), "metadata never adds packages"
    codes = [w["code"] for w in new.lock.warnings]
    assert "W_EDGES_INFERRED" in codes and "W_FLAT_LOCK" not in codes


@respx.mock
async def test_registry_down_keeps_the_flat_graph(tmp_path):
    respx.route(host="pypi.org").mock(side_effect=httpx.ConnectError("down"))
    stack, g = load("pip-flat")
    new, note = await flatedges.infer(g, stack.id, flatedges.Metadata(tmp_path, 3600))
    assert new is None and "unavailable" in note


async def test_recorded_go_metadata_places_indirect_modules():
    stack, g = load("go")
    new, _ = await flatedges.infer(g, stack.id,
                                   flatedges.RecordedMetadata(RECORDED / "deps.json"))
    net = next(k for k, n in new.nodes.items() if n.name == "golang.org/x/net")
    assert new.paths_to(net)[0] == ["root", "github.com/gin-gonic/gin@1.9.0", net]


def test_non_flat_stacks_are_left_alone():
    stack, g = load("cargo")
    assert asyncio.run(flatedges.infer(g, stack.id, None)) == (None, "")


def test_local_only_never_fetches(tmp_path):
    assert flatedges.make_provider(Settings(_env_file=None, local_only=True)) is None
    fixture = flatedges.make_provider(Settings(_env_file=None, scanner="fixture"))
    assert isinstance(fixture, flatedges.RecordedMetadata)


@pytest.mark.parametrize("case", ["pip-flat", "pipenv"])
def test_pipeline_uses_inferred_paths(settings, case):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for f in (STACKS / case).iterdir():
            zf.write(f, f.name)
    with TestClient(create_app(settings)) as c:
        r = c.post("/api/jobs", files={"file": (f"{case}.zip", buf.getvalue(), "application/zip")})
        job = wait_job(c, r.json()["job_id"])
        graph = c.get(f"/api/jobs/{job['id']}/graph").json()
    codes = {w["code"] for w in job["warnings"]}
    assert job["status"] == "ready" and "W_EDGES_INFERRED" in codes and "W_FLAT_LOCK" not in codes
    assert job["summary"]["max_depth"] == 2
    assert graph["nodes"]
