"""Build the demo answer keys with independent tools (npm audit, pip-audit, osv-scanner)."""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import semantic_version as sv

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
OUT = SAMPLES / "_answers"
DEMOS = {"vuln-demo": "package-lock.json", "clean-demo": "package-lock.json",
         "messy-demo": "package-lock.json", "python-demo": "requirements.txt",
         "supplychain-demo": "package-lock.json"}


# Signals planted on purpose in the scan-only supply-chain demo (see its README).
PLANTED = {"supplychain-demo": [
    {"kind": "malware", "package": "loadyaml@1.0.2", "note": "OSV MAL-2025-25475"},
    {"kind": "integrity", "package": "loadyaml@1.0.2",
     "note": "no integrity hash (version removed from npm; its hash is unknown)"},
    {"kind": "integrity", "package": "left-pad@1.3.0", "note": "git dependency"},
    {"kind": "typosquat", "package": "expresss@0.0.0", "note": "look-alike of express"},
    {"kind": "secret", "file": "config/db.js", "note": "hard-coded database password"},
]}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(argv: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                          timeout=300, check=False)


def version_of(argv: list[str]) -> str:
    out = run(argv, ROOT).stdout.strip().split()
    return out[-1] if out else "unknown"


def affected(spec: str, version: str) -> bool:
    try:
        return sv.NpmSpec(spec).match(sv.Version(version))
    except ValueError:
        return True


def npm_audit(demo: Path) -> tuple[dict, list[dict]] | None:
    npm = shutil.which("npm")
    if npm is None:
        return None
    lock = json.loads((demo / "package-lock.json").read_text("utf-8"))
    with tempfile.TemporaryDirectory() as tmp:
        for name in ("package.json", "package-lock.json"):
            shutil.copyfile(demo / name, Path(tmp) / name)
        res = run([npm, "audit", "--package-lock-only", "--json"], Path(tmp))
    report = json.loads(res.stdout)
    if "error" in report:
        raise SystemExit(f"npm audit failed for {demo.name}: {report['error']}")
    rows = []
    for vuln in report.get("vulnerabilities", {}).values():
        versions = {lock["packages"][n]["version"] for n in vuln.get("nodes", [])
                    if lock["packages"].get(n, {}).get("version")}
        for via in vuln.get("via", []):
            if not isinstance(via, dict) or "/advisories/" not in via.get("url", ""):
                continue
            for ver in sorted(versions):
                if affected(via.get("range", "*"), ver):
                    rows.append({"id": via["url"].rsplit("/", 1)[-1], "aliases": [],
                                 "package": via["name"], "version": ver,
                                 "severity": via.get("severity")})
    return {"name": "npm audit", "version": version_of([npm, "--version"])}, rows


def osv_scanner(demo: Path, lockfile: str) -> tuple[dict, list[dict]] | None:
    exe = shutil.which("osv-scanner")
    if exe is None:
        return None
    res = run([exe, "--format", "json", "--lockfile", str(demo / lockfile)], ROOT)
    rows = []
    for result in json.loads(res.stdout or "{}").get("results", []):
        for pkg in result.get("packages", []):
            p = pkg["package"]
            for v in pkg.get("vulnerabilities", []):
                rows.append({"id": v["id"], "aliases": v.get("aliases", []), "package": p["name"],
                             "version": p["version"]})
    return {"name": "osv-scanner", "version": version_of([exe, "--version"])}, rows


def pip_audit(demo: Path) -> tuple[dict, list[dict]] | None:
    probe = run([sys.executable, "-m", "pip_audit", "--version"], ROOT)
    if probe.returncode != 0:
        return None
    res = run([sys.executable, "-m", "pip_audit", "-r", str(demo / "requirements.txt"),
               "--no-deps", "--disable-pip", "--format", "json", "--progress-spinner", "off"],
              ROOT)
    try:
        report = json.loads(res.stdout)
    except ValueError:
        raise SystemExit(f"pip-audit failed for {demo.name}: {res.stderr.strip()[-300:]}") from None
    rows = [{"id": v["id"], "aliases": v.get("aliases", []), "package": d["name"],
             "version": d["version"]}
            for d in report.get("dependencies", []) for v in d.get("vulns", [])]
    return {"name": "pip-audit", "version": probe.stdout.split()[-1]}, rows


def merge(runs: list[tuple[dict, list[dict]]]) -> list[dict]:
    """One row per advisory + package + version; ids and aliases from any tool are pooled."""
    merged: list[dict] = []
    for tool, rows in runs:
        for r in rows:
            ids = {r["id"], *r["aliases"]}
            same = next((m for m in merged if m["package"] == r["package"]
                         and m["version"] == r["version"]
                         and ids & {m["id"], *m["aliases"]}), None)
            if same is None:
                same = {"id": r["id"], "aliases": [], "package": r["package"],
                        "version": r["version"], "reported_by": []}
                merged.append(same)
            same["aliases"] = sorted((set(same["aliases"]) | ids) - {same["id"]})
            if r.get("severity") and not same.get("severity"):
                same["severity"] = r["severity"]
            if tool["name"] not in same["reported_by"]:
                same["reported_by"].append(tool["name"])
    return sorted(merged, key=lambda m: (m["package"], m["version"], m["id"]))


def build(name: str, demo: Path, lockfile: str) -> dict:
    candidates = ([("npm audit", lambda: npm_audit(demo))] if lockfile == "package-lock.json"
                  else [("pip-audit", lambda: pip_audit(demo))])
    candidates.append(("osv-scanner", lambda: osv_scanner(demo, lockfile)))
    runs = []
    for tool, fn in candidates:
        out = fn()
        if out is None:
            print(f"{name}: {tool} not installed, skipped")
        else:
            runs.append(out)
    if not runs:
        raise SystemExit(f"{name}: no independent tool available; no answer key written")
    advisories = merge(runs)
    shared = sum(1 for a in advisories if len(a["reported_by"]) > 1)
    print(f"{name}: {len(advisories)} advisories from {', '.join(t['name'] for t, _ in runs)}"
          + (f" ({shared} reported by more than one tool)" if len(runs) > 1 else ""))
    key = {"demo": name, "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "lockfile_sha256": sha256(demo / lockfile), "tools": [t for t, _ in runs],
           "advisories": advisories}
    if name in PLANTED:
        key["expected_risks"] = [{**r, "source": "planted-by-design"} for r in PLANTED[name]]
    return key


def main() -> None:
    OUT.mkdir(exist_ok=True)
    only = set(sys.argv[1:])
    for name, lockfile in DEMOS.items():
        if only and name not in only:
            continue
        with tempfile.TemporaryDirectory() as tmp:
            # demos store manifests as <name>.sample; the audit tools need the real names
            demo = Path(tmp) / name
            shutil.copytree(SAMPLES / name, demo)
            for f in list(demo.rglob("*.sample")):
                f.rename(f.with_name(f.name.removesuffix(".sample")))
            key = build(name, demo, lockfile)
        (OUT / f"{name}.json").write_text(json.dumps(key, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
