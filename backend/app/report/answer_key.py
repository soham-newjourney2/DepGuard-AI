"""Side-by-side check of a demo's live scan against its independent answer key."""

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())


def when(ts: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(ts) if ts else None
    except ValueError:
        return None


def load(samples_dir: Path, demo: str) -> dict | None:
    try:
        return json.loads((samples_dir / "_answers" / f"{demo}.json").read_text("utf-8"))
    except (OSError, ValueError):
        return None


def lock_matches(key: dict, lockfile: Path) -> bool:
    try:
        return hashlib.sha256(lockfile.read_bytes()).hexdigest() == key.get("lockfile_sha256")
    except OSError:
        return False


def same(entry: dict, finding: dict) -> bool:
    """Shared advisory id or alias, same package name, same version when the key has one."""
    adv, pkg = finding["advisory"], finding["package"]
    ids = {entry["id"], *entry.get("aliases", [])}
    return (bool(ids & {adv["id"], *adv.get("aliases", [])})
            and norm(entry["package"]) == norm(pkg["name"])
            and (not entry.get("version") or entry["version"] == pkg["version"]))


def row(advisory: str, package: str, version: str | None, status: str, severity: str | None,
        note: str | None = None) -> dict:
    out = {"advisory": advisory, "package": f"{package}@{version}" if version else package,
           "status": status, "severity": severity}
    if note:
        out["note"] = note
    return out


def compare(key: dict, findings: list[dict]) -> dict:
    rows, used = [], set()
    for entry in key["advisories"]:
        hit = next((i for i, f in enumerate(findings) if same(entry, f)), None)
        if hit is None:
            rows.append(row(entry["id"], entry["package"], entry.get("version"), "missed",
                            entry.get("severity"),
                            f"Reported by {', '.join(entry['reported_by'])}"))
            continue
        used.add(hit)
        f = findings[hit]
        alias = f["advisory"]["id"] != entry["id"]
        rows.append(row(entry["id"], f["package"]["name"], f["package"]["version"], "matched",
                        f["advisory"]["severity"]["label"],
                        f"DepGuard lists it as {f['advisory']['id']} (alias)" if alias else None))
        rows[-1]["scan_advisory"] = f["advisory"]["id"]
    cutoff, new = when(key["generated_at"]), 0
    for i, f in enumerate(findings):
        if i in used:
            continue
        published = when(f["advisory"].get("published"))
        after = bool(cutoff and published and published > cutoff)
        new += after
        rows.append(row(f["advisory"]["id"], f["package"]["name"], f["package"]["version"],
                        "extra", f["advisory"]["severity"]["label"],
                        "New since answer key" if after
                        else "Not reported by the reference tools"))
        rows[-1]["scan_advisory"] = f["advisory"]["id"]
    matched = sum(r["status"] == "matched" for r in rows)
    missed = sum(r["status"] == "missed" for r in rows)
    total = len(key["advisories"])
    return {"rows": rows, "totals": {
        "key": total, "scan": len(findings), "matched": matched, "missed": missed,
        "extra": len(rows) - matched - missed, "extra_new": new, "scan_matched": len(used),
        "found_pct": round(100 * matched / total) if total else None}}


def risk_matches(expected: dict, r: dict) -> bool:
    if expected["kind"] != r["kind"]:
        return False
    if expected.get("package"):
        return expected["package"] == r.get("package")
    return expected.get("file") == (r.get("location") or {}).get("file")


def compare_risks(expected: list[dict], risks: list[dict]) -> dict:
    """Planted-by-design signals beside the risks DepGuard raised (info-level noise excluded)."""
    rows, used = [], set()
    for e in expected:
        hit = next((i for i, r in enumerate(risks) if i not in used and risk_matches(e, r)), None)
        where = e.get("package") or e.get("file")
        if hit is None:
            rows.append({"kind": e["kind"], "where": where, "status": "missed",
                         "planted": e["note"], "signal": None})
            continue
        used.add(hit)
        rows.append({"kind": e["kind"], "where": where, "status": "matched",
                     "planted": e["note"], "signal": risks[hit]["title"]})
    for i, r in enumerate(risks):
        if i not in used and r["severity"] != "info":
            rows.append({"kind": r["kind"], "where": r.get("package") or
                         (r.get("location") or {}).get("file"), "status": "extra",
                         "planted": None, "signal": r["title"]})
    n = {s: sum(x["status"] == s for x in rows) for s in ("matched", "missed", "extra")}
    return {"rows": rows, "totals": {"planted": len(expected), **n}}

