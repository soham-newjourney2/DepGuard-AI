"""Lockfile tampering signals: where each package comes from and whether a hash pins it."""

import json
import re
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

from app.risks import Inputs, risk

NPM_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com"}
GIT = re.compile(r"^(git\+|git:|github:|gitlab:|bitbucket:|git@)", re.I)
GIT_URL = re.compile(r"\.git(#|$)")
PIN = "Pin a published registry release (with an integrity hash) and regenerate the lockfile."
LOCAL = "Local or workspace package; not fetched from a registry, so no hash is expected."


def line_of(text: str, needle: str) -> int | None:
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else None


def where(rel: str, text: str, needle: str) -> dict:
    return {"file": rel, "line": line_of(text, needle)}


def flag(rel, text, needle, severity, title, evidence, rec, package, confidence="high"):
    return risk("integrity", severity, title, rec, confidence=confidence, evidence=evidence,
                package=package, location=where(rel, text, needle))


def npmrc_registry(root: Path) -> str | None:
    try:
        text = (root / ".npmrc").read_text("utf-8", errors="replace")
    except OSError:
        return None
    m = re.search(r"^\s*registry\s*=\s*(\S+)", text, re.M)
    return urlsplit(m.group(1)).hostname if m else None


def npm(root: Path, rel: str, text: str) -> list[dict]:
    lock = json.loads(text)
    hosts = NPM_HOSTS | ({h} if (h := npmrc_registry(root)) else set())
    out = []
    for key, e in (lock.get("packages") or {}).items():
        if not key or not isinstance(e, dict) or e.get("inBundle") or e.get("link"):
            continue
        name = e.get("name") or key.rsplit("node_modules/", 1)[-1]
        label = f"{name}@{e.get('version', '?')}"
        needle = f'"{key}": {{'
        res, integ = str(e.get("resolved") or ""), str(e.get("integrity") or "")
        if "node_modules/" not in key:
            out.append(flag(rel, text, needle, "info", f"{label} is a workspace package",
                            [f"{key} (workspace folder)"], LOCAL, label))
            continue
        if res.startswith("http://"):
            out.append(flag(rel, text, needle, "high", f"{label} is fetched over plain HTTP",
                            [f"resolved: {res}"], PIN, label))
        elif GIT.match(res):
            out.append(flag(rel, text, needle, "medium", f"{label} is resolved from a git URL",
                            [f"resolved: {res}", "git sources can change without the lockfile "
                             "changing"], PIN, label))
        elif res.startswith("file:"):
            out.append(flag(rel, text, needle, "low", f"{label} is installed from a local file",
                            [f"resolved: {res}"], PIN, label))
        elif res and urlsplit(res).hostname not in hosts:
            out.append(flag(rel, text, needle, "medium",
                            f"{label} is resolved from a non-registry URL "
                            f"({urlsplit(res).hostname})", [f"resolved: {res}"], PIN, label))
        if res and not GIT.match(res) and not res.startswith("file:"):
            if not integ:
                out.append(flag(rel, text, needle, "medium",
                                f"{label} has no integrity hash in the lockfile",
                                [f"resolved: {res}", "integrity: missing"],
                                "Regenerate the lockfile so every registry package carries an "
                                "integrity hash.", label))
            elif all(i.startswith("sha1-") for i in integ.split()):
                out.append(flag(rel, text, needle, "low", f"{label} is pinned only by a SHA-1 hash",
                                [f"integrity: {integ[:20]}…"], "Regenerate the lockfile with a "
                                "current npm to get sha512 hashes.", label))
    return out


def uv(root: Path, rel: str, text: str) -> list[dict]:
    out = []
    for p in tomllib.loads(text).get("package", []):
        label, src = f"{p.get('name')}@{p.get('version', '?')}", p.get("source") or {}
        needle = f'name = "{p.get("name")}"'
        if src.get("editable") == "." or src.get("virtual") == ".":
            continue
        if any(k in src for k in ("editable", "virtual", "directory", "path")):
            out.append(flag(rel, text, needle, "info", f"{label} is a local package", [str(src)],
                            LOCAL, label))
        elif "git" in src:
            out.append(flag(rel, text, needle, "medium", f"{label} is resolved from a git URL",
                            [f"source: git = {src['git']}"], PIN, label))
        elif "url" in src and "pypi.org" not in (urlsplit(src["url"]).hostname or ""):
            out.append(flag(rel, text, needle, "medium", f"{label} is resolved from a non-PyPI URL",
                            [f"source: url = {src['url']}"], PIN, label))
        elif "registry" in src and not (p.get("sdist") or p.get("wheels")):
            out.append(flag(rel, text, needle, "medium", f"{label} has no hashes in uv.lock",
                            ["no sdist/wheels entries"], "Run `uv lock` to record hashes.", label))
    return out


def poetry(root: Path, rel: str, text: str) -> list[dict]:
    doc = tomllib.loads(text)
    legacy = (doc.get("metadata") or {}).get("files") or {}
    out = []
    for p in doc.get("package", []):
        name, src = p.get("name"), p.get("source") or {}
        label, needle = f"{name}@{p.get('version', '?')}", f'name = "{name}"'
        kind = src.get("type")
        if kind in ("directory", "file"):
            out.append(flag(rel, text, needle, "info", f"{label} is a local package",
                            [f"source: {kind} {src.get('url', '')}"], LOCAL, label))
        elif kind == "git":
            out.append(flag(rel, text, needle, "medium", f"{label} is resolved from a git URL",
                            [f"source: git {src.get('url', '')}"], PIN, label))
        elif kind == "url":
            out.append(flag(rel, text, needle, "medium", f"{label} is resolved from a direct URL",
                            [f"source: url {src.get('url', '')}"], PIN, label))
        elif not (p.get("files") or legacy.get(name)):
            out.append(flag(rel, text, needle, "medium", f"{label} has no hashes in poetry.lock",
                            ["files: missing"], "Run `poetry lock` to record hashes.", label))
    return out


def cargo(root: Path, rel: str, text: str) -> list[dict]:
    out = []
    for p in tomllib.loads(text).get("package", []):
        label, src = f"{p.get('name')}@{p.get('version', '?')}", str(p.get("source") or "")
        needle = f'name = "{p.get("name")}"'
        if src.startswith("git+"):
            out.append(flag(rel, text, needle, "medium", f"{label} is resolved from a git URL",
                            [f"source: {src}"], PIN, label))
        elif src.startswith("registry+") and not p.get("checksum"):
            out.append(flag(rel, text, needle, "medium", f"{label} has no checksum in Cargo.lock",
                            [f"source: {src}", "checksum: missing"],
                            "Run `cargo generate-lockfile` to record checksums.", label))
    return out


def gemfile(root: Path, rel: str, text: str) -> list[dict]:
    out = []
    for m in re.finditer(r"^(GIT|PATH)\n((?:  .*\n?)+)", text, re.M):
        remote = re.search(r"remote: (\S+)", m.group(2))
        for spec in re.finditer(r"^    (\S+) \(([^)]+)\)", m.group(2), re.M):
            label = f"{spec.group(1)}@{spec.group(2)}"
            needle = spec.group(0)
            if m.group(1) == "GIT":
                out.append(flag(rel, text, needle, "medium", f"{label} is resolved from a git URL",
                                [f"GIT remote: {remote.group(1) if remote else '?'}"], PIN, label))
            else:
                out.append(flag(rel, text, needle, "info", f"{label} is a local path gem",
                                [f"PATH remote: {remote.group(1) if remote else '?'}"], LOCAL,
                                label))
    return out


def composer(root: Path, rel: str, text: str) -> list[dict]:
    doc = json.loads(text)
    out = []
    for p in [*(doc.get("packages") or []), *(doc.get("packages-dev") or [])]:
        label, dist = f"{p.get('name')}@{p.get('version', '?')}", p.get("dist") or {}
        needle = f'"name": "{p.get("name")}"'
        url = str(dist.get("url") or "")
        if dist.get("type") == "path":
            out.append(flag(rel, text, needle, "info", f"{label} is a local path package",
                            [f"dist: path {url}"], LOCAL, label))
        elif not dist:
            src = (p.get("source") or {}).get("url", "?")
            out.append(flag(rel, text, needle, "medium", f"{label} has no dist archive",
                            [f"source: {src}"], PIN, label))
        elif url.startswith("http://"):
            out.append(flag(rel, text, needle, "high", f"{label} is fetched over plain HTTP",
                            [f"dist: {url}"], PIN, label))
    return out


def gomod(root: Path, rel: str, text: str) -> list[dict]:
    out = []
    for m in re.finditer(r"^\s*(?:replace\s+)?(\S+)(?:\s+v\S+)?\s+=>\s+(\S+)(?:\s+(v\S+))?",
                         text, re.M):
        old, new = m.group(1), m.group(2)
        needle = m.group(0).strip()
        if new.startswith((".", "/")):
            out.append(flag(rel, text, needle, "medium", f"{old} is replaced with a local path",
                            [f"replace {old} => {new}"], "Make sure the local copy is reviewed; "
                            "builds elsewhere will not use the published module.", old))
        elif new != old:
            out.append(flag(rel, text, needle, "low", f"{old} is replaced with another module",
                            [f"replace {old} => {new} {m.group(3) or ''}".strip()],
                            "Confirm the replacement module is the fork you intend to trust.",
                            old, confidence="medium"))
    return out


def source_risk(rel, text, needle, label, url, hosts) -> dict | None:
    """Plain HTTP, git or non-registry tarball for one JS package (None when it is fine)."""
    if url.startswith("http://"):
        return flag(rel, text, needle, "high", f"{label} is fetched over plain HTTP",
                    [f"resolved: {url}"], PIN, label)
    host = urlsplit(url).hostname or ""
    if (GIT.match(url) or GIT_URL.search(url)
            or host in ("github.com", "gitlab.com", "bitbucket.org", "codeload.github.com")):
        return flag(rel, text, needle, "medium", f"{label} is resolved from a git URL",
                    [f"resolved: {url}", "git sources can change without the lockfile changing"],
                    PIN, label)
    if url.startswith("https://") and host not in hosts:
        return flag(rel, text, needle, "medium",
                    f"{label} is resolved from a non-registry URL ({host})", [f"resolved: {url}"],
                    PIN, label)
    return None


def no_hash(rel, text, needle, label, why) -> dict:
    return flag(rel, text, needle, "medium", f"{label} has no integrity hash in the lockfile",
                [why], "Regenerate the lockfile so every registry package carries a hash.", label)


def yarn(root: Path, rel: str, text: str) -> list[dict]:
    from app.stacks import yarn as y
    from app.stacks.base import read_yaml
    hosts = NPM_HOSTS | ({h} if (h := npmrc_registry(root)) else set())
    berry = "__metadata:" in text
    entries = y.berry_entries(read_yaml(root / rel, text)) if berry else y.parse_classic(text)
    out, seen = [], set()
    for spec, e in entries.items():
        if id(e) in seen:
            continue
        seen.add(id(e))
        label = f"{y.spec_name(spec)}@{e.get('version') or '?'}"
        needle = str(e["header"]).strip().rstrip(":").split(",")[0]
        if berry:
            res = str(e.get("resolution") or "")
            proto = res[res.find("@", 1) + 1:] if res.find("@", 1) > 0 else ""
            if proto.startswith(("workspace:", "link:", "portal:", "file:")):
                if not proto.startswith("workspace:."):
                    out.append(flag(rel, text, needle, "info", f"{label} is a local package",
                                    [f"resolution: {res}"], LOCAL, label))
                continue
            if proto.startswith("npm:"):
                if not e.get("checksum"):
                    out.append(no_hash(rel, text, needle, label, "checksum: missing"))
                continue
            r = source_risk(rel, text, needle, label, proto, hosts)
            if r:
                out.append(r)
            continue
        url = str(e.get("resolved") or "")
        r = source_risk(rel, text, needle, label, url, hosts) if url else None
        if r:
            out.append(r)
        elif url and not e.get("integrity") and not url.startswith("file:"):
            out.append(no_hash(rel, text, needle, label, "integrity: missing"))
    return out


def pnpm(root: Path, rel: str, text: str) -> list[dict]:
    from app.stacks import pnpm as p
    from app.stacks.base import read_yaml
    hosts = NPM_HOSTS | ({h} if (h := npmrc_registry(root)) else set())
    doc = read_yaml(root / rel, text)
    out = []
    for key, body in (doc.get("packages") or {}).items():
        nv = p.split_key(str(key))
        if nv is None:
            continue
        version = (body or {}).get("version") if "://" in nv[1] else nv[1]
        label, needle = f"{nv[0]}@{version or '?'}", f"{key}:"
        res = (body or {}).get("resolution") or {}
        if res.get("directory") or res.get("type") == "directory":
            out.append(flag(rel, text, needle, "info", f"{label} is a local package",
                            [f"resolution: {res}"], LOCAL, label))
        elif res.get("type") == "git" or res.get("repo"):
            out.append(source_risk(rel, text, needle, label,
                                   "git+" + str(res.get("repo", "")), hosts))
        elif res.get("tarball"):
            r = source_risk(rel, text, needle, label, str(res["tarball"]), hosts)
            if r:
                out.append(r)
            elif not res.get("integrity"):
                out.append(no_hash(rel, text, needle, label, f"tarball: {res['tarball']}"))
        elif not res.get("integrity"):
            out.append(no_hash(rel, text, needle, label, "resolution.integrity: missing"))
    return out


READERS = {"package-lock.json": npm, "yarn.lock": yarn, "pnpm-lock.yaml": pnpm, "uv.lock": uv,
           "poetry.lock": poetry, "Cargo.lock": cargo, "Gemfile.lock": gemfile,
           "composer.lock": composer, "go.mod": gomod}


def check(inputs: Inputs) -> list[dict]:
    out = []
    for name, reader in READERS.items():
        path = inputs.root / name
        if path.is_file():
            out += reader(inputs.root, name, path.read_text("utf-8", errors="replace"))
    return out
