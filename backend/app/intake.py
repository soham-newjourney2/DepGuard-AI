import json
import re
import shutil
import stat
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from app.config import Settings
from app.errors import AppError
from app.stacks import BY_ID, LANGUAGES, Stack, found_in, unlocked_in

MB = 1024 * 1024
CHUNK = 64 * 1024
SKIP_DIRS = {"node_modules", ".git", "__MACOSX"}
ARCHIVE_EXT = (".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war")
WIN_RESERVED = re.compile(r"^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$", re.I)
LOCK_VERSIONS = {2, 3}


@dataclass
class Intake:
    root: Path
    manifest: dict
    lockfile: dict
    lockfile_version: int
    files: int
    warnings: list[dict] = field(default_factory=list)
    stack: str = "npm"


def fail(code: str, message: str, hint: str, status: int = 400,
         options: list[str] | None = None) -> AppError:
    return AppError(code, message, hint, status, options=options)


def entry_parts(name: str) -> list[str]:
    if "\x00" in name:
        raise fail("E_PATH_TRAVERSAL", "Archive entry has an invalid name.",
                   "Re-create the zip with your OS's built-in compressor.")
    norm = name.replace("\\", "/")
    if norm.startswith("/") or re.match(r"^[A-Za-z]:", norm):
        raise fail("E_PATH_TRAVERSAL", f"Archive entry uses an absolute path: {name[:120]}",
                   "Zip the project folder itself, not absolute paths.")
    parts = [p for p in norm.split("/") if p not in ("", ".")]
    for p in parts:
        if p == ".." or ":" in p or p.endswith((".", " ")) or WIN_RESERVED.match(p):
            raise fail("E_PATH_TRAVERSAL", f"Archive entry escapes the project: {name[:120]}",
                       "Remove entries containing '..' or special names and re-zip.")
    return parts


def is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(info.external_attr >> 16)


def skipped(parts: list[str]) -> bool:
    return (any(p in SKIP_DIRS for p in parts[:-1]) or parts[-1] in SKIP_DIRS
            or parts[-1].lower().endswith(ARCHIVE_EXT))


def plan(zf: zipfile.ZipFile, archive_size: int, s: Settings) -> list[tuple[zipfile.ZipInfo, list]]:
    entries, total = [], 0
    for info in zf.infolist():
        parts = entry_parts(info.filename)
        if not parts:
            continue
        if is_symlink(info):
            raise fail("E_SYMLINK", f"Archive contains a symlink: {info.filename[:120]}",
                       "Replace symlinks with real files before zipping.")
        if info.flag_bits & 0x1:
            raise fail("E_NOT_ZIP", "Encrypted archives are not supported.",
                       "Upload an unencrypted zip.")
        if skipped(parts):
            continue
        total += info.file_size
        if info.file_size >= MB and info.file_size > s.max_ratio * max(info.compress_size, 1):
            raise bomb()
        entries.append((info, parts))
    files = sum(1 for i, _ in entries if not i.is_dir())
    if files > s.max_files:
        raise fail("E_TOO_MANY_FILES", f"Archive has {files} files (limit {s.max_files}).",
                   "Exclude node_modules, build output and assets; only manifests are needed.")
    if total > s.max_unzipped_mb * MB:
        raise too_large_unzipped(s)
    if total > s.max_ratio * max(archive_size, 1) and total >= MB:
        raise bomb()
    return entries


def bomb() -> AppError:
    return fail("E_ZIP_BOMB", "Archive expands far beyond its size and was rejected.",
                "Upload a normal zip of your project source.")


def too_large_unzipped(s: Settings) -> AppError:
    return fail("E_TOO_LARGE", f"Project is larger than {s.max_unzipped_mb} MB unzipped.",
                "Exclude node_modules and build output.", 413)


def extract(zf: zipfile.ZipFile, entries: list, dest: Path, s: Settings) -> int:
    base = dest.resolve()
    budget, files = s.max_unzipped_mb * MB, 0
    for info, parts in entries:
        target = base.joinpath(*parts).resolve()
        if not target.is_relative_to(base) or target == base:
            raise fail("E_PATH_TRAVERSAL", "Archive entry escapes the project.",
                       "Remove entries containing '..' and re-zip.")
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(target, "xb") as out:
            while chunk := src.read(CHUNK):
                budget -= len(chunk)
                if budget < 0:
                    raise too_large_unzipped(s)
                out.write(chunk)
        files += 1
    return files


MAX_PROJECT_DEPTH = 4
PROJECT_SPEC = re.compile(r"^[A-Za-z0-9._@ -]+(?:/[A-Za-z0-9._@ -]+)*$")
OTHER_LOCKS = ("yarn.lock", "pnpm-lock.yaml", "bun.lockb")
DISCOVERY_SKIP = SKIP_DIRS | {"vendor", ".venv", "venv", "site-packages", "target", "__pycache__",
                              "bower_components", ".tox", "dist", "build", "obj", "bin", ".next"}
UNSUPPORTED = (("Elixir", "mix.exs"), ("Dart/Flutter", "pubspec.yaml"), ("Swift", "Package.swift"),
               ("C/C++", "CMakeLists.txt"), ("Haskell", "stack.yaml"))


def rel(path: Path, dest: Path) -> str:
    return path.relative_to(dest).as_posix() or "."


def walk_dirs(dest: Path) -> list[Path]:
    """Project directories breadth-first, skipping dependency/build folders and virtualenvs."""
    out, frontier = [dest], [dest]
    for _ in range(MAX_PROJECT_DEPTH):
        nxt = [c for d in frontier for c in sorted(d.iterdir())
               if c.is_dir() and not c.is_symlink() and c.name not in DISCOVERY_SKIP
               and not (c / "pyvenv.cfg").exists()]
        out += nxt
        frontier = nxt
    return out


def candidates(dest: Path) -> list[tuple[Path, Stack]]:
    return [(d, s) for d in walk_dirs(dest) for s in found_in(d)]


def option(d: Path, s: Stack, dest: Path) -> str:
    return rel(d, dest) if s.id == "npm" else f"{rel(d, dest)}#{s.language}"


def detect_ecosystem(dest: Path) -> str | None:
    for d in walk_dirs(dest):
        for name, marker in UNSUPPORTED:
            if (d / marker).is_file():
                return name
    return None


def chosen(dest: Path, project: str) -> tuple[Path, Stack, dict]:
    path, _, language = project.partition("#")
    path = path or "."
    if (not PROJECT_SPEC.fullmatch(path) or ".." in path.split("/")
            or (language and language not in LANGUAGES)):
        raise fail("E_INVALID", "That project path is not allowed.", "", 422)
    root = (dest / path).resolve()
    tops = [p for p in dest.iterdir() if p.is_dir()]
    if not root.is_dir() and len(tops) == 1 and (tops[0] / path).is_dir():
        root = (tops[0] / path).resolve()
    if not root.is_relative_to(dest.resolve()) or not root.is_dir():
        raise fail("E_NO_MANIFEST", f"No project in {path}.",
                   "Pick one of the projects found in the archive.")
    stacks = [s for s in found_in(root) if s.language == (language or "Node.js")]
    if not stacks and not language and (root / "package.json").is_file():
        stacks = [BY_ID["npm"]]
    if not stacks:
        raise fail("E_NO_MANIFEST", f"No {language or 'package.json'} project in {path}.",
                   "Pick one of the projects found in the archive.")
    return root, stacks[0], {"code": "W_SUBPROJECT", "message": f"Analysed the project in {path}/."}


def located(d: Path, s: Stack, dest: Path, only: bool) -> tuple[Path, Stack, dict | None]:
    if d == dest:
        return d, s, None
    tops = [p for p in dest.iterdir() if p.is_dir()]
    if len(tops) == 1 and d == tops[0]:
        return d, s, None
    what = "npm project" if s.id == "npm" else f"{s.language} project"
    why = f" (the only one with a {s.lockfile})" if only and s.id == "npm" else ""
    return d, s, {"code": "W_SUBPROJECT",
                  "message": f"Analysed the {what} in {rel(d, dest)}/{why}."}


PREFERRED = ("backend", "server", "api", "app", "service", "src", "web", "frontend", "client")


def preference(d: Path, dest: Path) -> tuple:
    name = d.name.lower()
    rank = next((i for i, p in enumerate(PREFERRED) if name == p or name.startswith(p)),
                len(PREFERRED))
    return len(d.relative_to(dest).parts), rank, rel(d, dest)


def multi_note(found: list[tuple[Path, Stack]], picked: str, dest: Path) -> dict:
    options = [option(d, s, dest) for d, s in found][:12]
    return {"code": "W_MULTIPLE_PROJECTS",
            "message": f"This archive contains {len(found)} projects; analysed "
                       f"{picked.split('#')[0]}/. Switch to another below.",
            "options": options, "chosen": picked}


def locate_root(dest: Path, project: str | None = None) -> tuple[Path, Stack, dict | None]:
    """Find the lockfile-backed project (any stack); with several, pick the likeliest one."""
    found = candidates(dest)
    if project:
        root, stack, note = chosen(dest, project)
        picked = option(root, stack, dest.resolve())
        return root, stack, multi_note(found, picked, dest) if len(found) > 1 else note
    if len(found) == 1:
        return located(*found[0], dest, True)
    if len(found) > 1:
        d, s = min(found, key=lambda f: preference(f[0], dest))
        return d, s, multi_note(found, option(d, s, dest), dest)
    dirs = walk_dirs(dest)
    npm = [d for d in dirs if (d / "package.json").is_file()]
    if npm:
        where = ", ".join(rel(d, dest) for d in npm[:3])
        other = next((f for d in npm for f in OTHER_LOCKS if (d / f).is_file()), None)
        hint = (f"{other} is not supported yet; run `npm install --package-lock-only` to "
                "create package-lock.json." if other else
                "Run `npm install --package-lock-only` and include package-lock.json.")
        raise fail("E_NO_LOCKFILE", f"package.json found in {where} but no package-lock.json.",
                   hint)
    unlocked = [(d, s) for d in dirs for s in unlocked_in(d)]
    if unlocked:
        d, s = unlocked[0]
        raise fail("E_NO_LOCKFILE", f"Found a {s.language} project in {rel(d, dest)} but no "
                   "lockfile with exact versions.", s.fix_hint)
    other = detect_ecosystem(dest)
    if other:
        raise fail("E_UNSUPPORTED_ECOSYSTEM",
                   f"This looks like a {other} project, which DepGuard cannot analyse yet.",
                   "Supported: " + ", ".join(LANGUAGES) + ".", 422)
    raise fail("E_NO_MANIFEST", "No supported project found in the archive.",
               "Zip the folder that contains your lockfile (package-lock.json, poetry.lock, "
               "requirements.txt, go.mod, Cargo.lock, composer.lock, Gemfile.lock…). "
               "For a live website, paste its URL instead.")


def read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_bytes().decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise fail("E_BAD_JSON", f"{path.name} is not valid JSON ({exc.__class__.__name__}).",
                   f"Fix {path.name} or regenerate it with npm.") from None
    if not isinstance(data, dict):
        raise fail("E_BAD_JSON", f"{path.name} must be a JSON object.",
                   f"Regenerate {path.name} with npm.")
    return data


def validate(root: Path, files: int) -> Intake:
    manifest = read_json(root / "package.json")
    lock_path = root / "package-lock.json"
    if not lock_path.is_file():
        raise fail("E_NO_LOCKFILE", "package-lock.json not found next to package.json.",
                   "Run `npm install` (npm 7+) and include package-lock.json in the zip.")
    lockfile = read_json(lock_path)
    version = lockfile.get("lockfileVersion")
    if version not in LOCK_VERSIONS or isinstance(version, bool):
        raise fail("E_LOCKFILE_VERSION",
                   f"lockfileVersion {version!r} is not supported (need 2 or 3).",
                   "Regenerate with npm 7+: `npm install --package-lock-only`.")
    warnings = []
    if manifest.get("workspaces"):
        warnings.append({"code": "W_WORKSPACES", "message":
                         "Workspaces detected; only the root package graph is analysed."})
    return Intake(root, manifest, lockfile, version, files, warnings)


def extract_project(archive: Path, dest: Path, s: Settings,
                    project: str | None = None) -> Intake:
    size = archive.stat().st_size
    if size > s.max_upload_mb * MB:
        raise fail("E_TOO_LARGE", f"Upload is larger than {s.max_upload_mb} MB.",
                   "Exclude node_modules and build output.", 413)
    if not zipfile.is_zipfile(archive):
        raise fail("E_NOT_ZIP", "File is not a zip archive.", "Upload a .zip of your project.")
    dest.mkdir(parents=True, exist_ok=False)
    try:
        with zipfile.ZipFile(archive) as zf:
            files = extract(zf, plan(zf, size, s), dest, s)
        root, stack, note = locate_root(dest, project)
        if stack.id == "npm":
            intake = validate(root, files)
        else:
            intake = Intake(root, {}, {}, 0, files, [], stack.id)
        if note:
            intake.warnings.insert(0, note)
        return intake
    except AppError:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, EOFError, OSError,
            zlib.error):
        shutil.rmtree(dest, ignore_errors=True)
        raise fail("E_NOT_ZIP", "Archive is corrupt or uses an unsupported format.",
                   "Re-create the zip with your OS's built-in compressor.") from None
