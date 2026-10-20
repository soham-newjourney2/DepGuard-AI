"""Regenerate intake fixtures: python backend/tests/fixtures/make_zips.py"""

import json
import stat
import zipfile
from pathlib import Path

OUT = Path(__file__).parent / "zips"
DEPS = {"left-pad": "^1.3.0"}
PKG = json.dumps({"name": "fixture-app", "version": "1.0.0", "dependencies": DEPS})
LOCK = json.dumps({
    "name": "fixture-app", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
    "packages": {
        "": {"name": "fixture-app", "version": "1.0.0", "dependencies": DEPS},
        "node_modules/left-pad": {"version": "1.3.0", "license": "WTFPL"},
    },
})


def write(name: str, entries: list[tuple]) -> None:
    with zipfile.ZipFile(OUT / name, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry in entries:
            if isinstance(entry[0], zipfile.ZipInfo):
                zf.writestr(entry[0], entry[1])
            else:
                zf.writestr(*entry)


def symlink_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    return info


def main() -> None:
    OUT.mkdir(exist_ok=True)
    good = [("package.json", PKG), ("package-lock.json", LOCK)]
    write("ok_root.zip", good + [("src/index.js", "module.exports = 1;\n")])
    write("ok_nested.zip", [
        ("my-app/", ""), ("my-app/package.json", PKG), ("my-app/package-lock.json", LOCK),
        ("my-app/vendor.zip", "PK"), ("my-app/node_modules/left-pad/index.js", "x"),
        ("__MACOSX/my-app/._package.json", "junk"), ("my-app/src/a.js", "1"),
    ])
    lock_v2 = LOCK.replace('"lockfileVersion": 3', '"lockfileVersion": 2')
    write("ok_v2_bom.zip", [("package.json", "\ufeff" + PKG), ("package-lock.json", lock_v2)])
    mono = json.dumps({"name": "mono", "workspaces": ["packages/*"]})
    write("workspaces.zip", [("package.json", mono), ("package-lock.json", LOCK)])
    (OUT / "not_a_zip.zip").write_bytes(b"this is plain text pretending to be a zip\n")
    (OUT / "truncated.zip").write_bytes((OUT / "ok_root.zip").read_bytes()[:150])
    write("traversal.zip", good + [("../evil.txt", "pwned")])
    write("traversal_backslash.zip", good + [("src\\..\\..\\evil.txt", "pwned")])
    write("absolute.zip", good + [("/etc/cron.d/evil", "pwned")])
    write("drive_letter.zip", good + [("C:/Windows/evil.txt", "pwned")])
    write("ads_stream.zip", good + [("package.json:evil", "pwned")])
    write("reserved_name.zip", good + [("src/CON.js", "x")])
    write("symlink.zip", good + [(symlink_info("src/secrets"), "/etc/passwd")])
    write("bomb.zip", good + [("big.bin", b"\0" * (20 * 1024 * 1024))])
    write("many_files.zip", good + [(f"src/f{i}.js", "1") for i in range(60)])
    write("no_manifest.zip", [("README.md", "# hi"), ("src/index.js", "1")])
    write("two_tops.zip", [("a/package.json", PKG), ("a/package-lock.json", LOCK),
                           ("b/package.json", PKG), ("b/package-lock.json", LOCK)])
    write("no_lockfile.zip", [("package.json", PKG)])
    lock_v1 = json.dumps({"lockfileVersion": 1, "dependencies": {}})
    write("lockfile_v1.zip", [("package.json", PKG), ("package-lock.json", lock_v1)])
    write("bad_json.zip", [("package.json", PKG), ("package-lock.json", '{"lockfileVersion": 3,')])
    write("array_json.zip", [("package.json", "[1, 2]"), ("package-lock.json", LOCK)])
    write("nested_server.zip", [("app-main/README.md", "# app"),
                                ("app-main/public/index.html", "<h1>hi</h1>"),
                                ("app-main/server/package.json", PKG),
                                ("app-main/server/package-lock.json", LOCK)])
    write("multi_projects.zip", [("repo/client/package.json", PKG),
                                 ("repo/client/package-lock.json", LOCK),
                                 ("repo/server/package.json", PKG),
                                 ("repo/server/package-lock.json", LOCK)])
    write("nested_yarn.zip", [("repo/web/package.json", PKG), ("repo/web/yarn.lock", "# yarn")])
    write("python_project.zip", [("firstapi/requirements.txt", "fastapi==0.110.0\nuvicorn\n"),
                                 ("firstapi/main.py", "from fastapi import FastAPI\n")])
    write("github_repo.zip", [("ms-main/package.json", PKG), ("ms-main/package-lock.json", LOCK),
                              ("ms-main/index.js", "module.exports = require('left-pad');\n")])


if __name__ == "__main__":
    main()
