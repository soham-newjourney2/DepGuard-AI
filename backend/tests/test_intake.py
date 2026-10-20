from pathlib import Path

import pytest

from app.errors import AppError
from app.intake import extract_project, locate_root

ZIPS = Path(__file__).parent / "fixtures" / "zips"


@pytest.fixture
def dest(tmp_path):
    return tmp_path / "job" / "src"


def run(name, dest, settings, **overrides):
    s = settings.model_copy(update=overrides) if overrides else settings
    return extract_project(ZIPS / name, dest, s)


def code_of(name, dest, settings, **overrides):
    with pytest.raises(AppError) as exc:
        run(name, dest, settings, **overrides)
    assert exc.value.hint, "every intake error carries a hint"
    return exc.value.code


@pytest.mark.parametrize("name,code", [
    ("not_a_zip.zip", "E_NOT_ZIP"),
    ("truncated.zip", "E_NOT_ZIP"),
    ("traversal.zip", "E_PATH_TRAVERSAL"),
    ("traversal_backslash.zip", "E_PATH_TRAVERSAL"),
    ("absolute.zip", "E_PATH_TRAVERSAL"),
    ("drive_letter.zip", "E_PATH_TRAVERSAL"),
    ("ads_stream.zip", "E_PATH_TRAVERSAL"),
    ("reserved_name.zip", "E_PATH_TRAVERSAL"),
    ("symlink.zip", "E_SYMLINK"),
    ("bomb.zip", "E_ZIP_BOMB"),
    ("no_manifest.zip", "E_NO_MANIFEST"),
    ("nested_yarn.zip", "E_NO_LOCKFILE"),
    ("no_lockfile.zip", "E_NO_LOCKFILE"),
    ("lockfile_v1.zip", "E_LOCKFILE_VERSION"),
    ("bad_json.zip", "E_BAD_JSON"),
    ("array_json.zip", "E_BAD_JSON"),
])
def test_hostile_and_malformed_rejected(name, code, dest, settings):
    assert code_of(name, dest, settings) == code
    assert not dest.exists(), "partial extraction must be cleaned up"
    assert not (dest.parent / "evil.txt").exists()


def test_too_many_files(dest, settings):
    assert code_of("many_files.zip", dest, settings, max_files=50) == "E_TOO_MANY_FILES"


def test_upload_size_limit(dest, settings):
    assert code_of("ok_root.zip", dest, settings, max_upload_mb=0) == "E_TOO_LARGE"


def test_unzipped_size_limit(dest, settings):
    code = code_of("bomb.zip", dest, settings, max_unzipped_mb=1, max_ratio=100_000)
    assert code == "E_TOO_LARGE"


def test_valid_root_project(dest, settings):
    intake = run("ok_root.zip", dest, settings)
    assert intake.root == dest and intake.lockfile_version == 3
    assert intake.manifest["name"] == "fixture-app" and intake.files == 3
    assert (dest / "src" / "index.js").read_text() == "module.exports = 1;\n"
    assert intake.warnings == []


def test_single_top_folder_and_skips(dest, settings):
    intake = run("ok_nested.zip", dest, settings)
    assert intake.root == dest / "my-app"
    assert not (dest / "my-app" / "vendor.zip").exists(), "nested archives ignored"
    assert not (dest / "my-app" / "node_modules").exists()
    assert not (dest / "__MACOSX").exists()


def test_v2_with_utf8_bom(dest, settings):
    assert run("ok_v2_bom.zip", dest, settings).lockfile_version == 2


def test_workspaces_warning(dest, settings):
    intake = run("workspaces.zip", dest, settings)
    assert [w["code"] for w in intake.warnings] == ["W_WORKSPACES"]


def test_existing_destination_refused(dest, settings):
    dest.mkdir(parents=True)
    with pytest.raises(FileExistsError):
        run("ok_root.zip", dest, settings)


def test_single_nested_project_is_selected(dest, settings):
    intake = run("nested_server.zip", dest, settings)
    assert intake.root == dest / "app-main" / "server"
    assert intake.warnings[0] == {"code": "W_SUBPROJECT", "message":
                                  "Analysed the npm project in app-main/server/ (the only one "
                                  "with a package-lock.json)."}


def test_multiple_projects_auto_pick_and_can_be_switched(dest, settings, tmp_path):
    intake = run("multi_projects.zip", dest, settings)
    assert intake.root == dest / "repo" / "server", "server preferred over client"
    note = intake.warnings[0]
    assert note["code"] == "W_MULTIPLE_PROJECTS" and note["chosen"] == "repo/server"
    assert note["options"] == ["repo/client", "repo/server"]
    other = extract_project(ZIPS / "multi_projects.zip", tmp_path / "x", settings, "repo/client")
    assert other.root == tmp_path / "x" / "repo" / "client"
    assert other.warnings[0]["chosen"] == "repo/client"


def test_two_top_folders_pick_first(dest, settings):
    intake = run("two_tops.zip", dest, settings)
    assert intake.root == dest / "a" and intake.warnings[0]["options"] == ["a", "b"]


@pytest.mark.parametrize("project", ["../etc", "repo/../..", "/abs", "repo/missing", "a\b"])
def test_bad_project_choice(dest, settings, project):
    with pytest.raises(AppError) as exc:
        extract_project(ZIPS / "multi_projects.zip", dest, settings, project)
    assert exc.value.code in ("E_INVALID", "E_NO_MANIFEST")


def test_yarn_hint(dest, settings):
    with pytest.raises(AppError) as exc:
        run("nested_yarn.zip", dest, settings)
    assert "yarn.lock is not supported" in exc.value.hint


def test_python_project_is_detected(dest, settings):
    intake = run("python_project.zip", dest, settings)
    assert intake.stack == "pip" and intake.root == dest / "firstapi"


def build(dest, files: dict[str, str]):
    for name, body in files.items():
        (dest / name).parent.mkdir(parents=True, exist_ok=True)
        (dest / name).write_text(body, encoding="utf-8")


def test_mixed_stacks_offer_language_options(tmp_path):
    build(tmp_path, {"web/package.json": "{}", "web/package-lock.json": "{}",
                     "api/requirements.txt": "flask==2.0.0\n", "api/.venv/pyvenv.cfg": "",
                     "api/.venv/lib/requirements.txt": "x==1\n", "vendor/go.mod": "module x\n"})
    root, stack, note = locate_root(tmp_path)
    assert (root.name, stack.id) == ("api", "pip"), "api preferred over web"
    assert note["options"] == ["api#Python", "web"]
    root, stack, note = locate_root(tmp_path, "web")
    assert (root, stack.id) == ((tmp_path / "web").resolve(), "npm") and note["chosen"] == "web"
    with pytest.raises(AppError):
        locate_root(tmp_path, "api#Cobol")


@pytest.mark.parametrize("files,code,needle", [
    ({"svc/Cargo.toml": "[package]"}, "E_NO_LOCKFILE", "cargo generate-lockfile"),
    ({"pyproject.toml": "[project]"}, "E_NO_LOCKFILE", "pip freeze"),
    ({"pom.xml": "<project/>"}, "E_NO_LOCKFILE", "gradle"),
    ({"mix.exs": ""}, "E_UNSUPPORTED_ECOSYSTEM", "Python"),
    ({"index.html": ""}, "E_NO_MANIFEST", "URL"),
])
def test_unlocked_and_unsupported_explained(tmp_path, files, code, needle):
    build(tmp_path, files)
    with pytest.raises(AppError) as exc:
        locate_root(tmp_path)
    assert exc.value.code == code and needle in exc.value.hint
