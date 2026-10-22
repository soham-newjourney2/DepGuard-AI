"""Fixes for non-npm stacks: smallest fixed version, the right command, a diff where possible."""

import hashlib
import json
import re
from pathlib import Path

from app import versions
from app.remediation import patch
from app.risks import malware
from app.scanner.base import Package
from app.scanner.normalize import contains_in
from app.stacks import BY_ID, python
from app.stacks.base import norm_name

COMMANDS = {
    "pip": ('pip install "{name}=={to}"', 'pip install "{name}=={to}"'),
    "uv": ('uv add "{name}>={to}"', "uv lock --upgrade-package {name}=={to}"),
    "poetry": ('poetry add "{name}@^{to}"', "poetry update {name}"),
    "pipenv": ('pipenv install "{name}=={to}"', "pipenv update {name}"),
    "go": ("go get {name}@v{to} && go mod tidy",) * 2,
    "cargo": ("cargo update -p {name}@{frm} --precise {to}",) * 2,
    "composer": ('composer require "{name}:^{to}"',
                 "composer update {name} --with-dependencies"),
    "bundler": ("bundle update {name} --conservative",) * 2,
    "nuget": ("dotnet add package {name} --version {to}",) * 2,
    "gradle": ("add a dependency constraint {name}:{to}, then ./gradlew dependencies "
               "--write-locks",) * 2,
    "yarn": ("yarn up {name}@{to}  (Yarn 1: yarn upgrade {name}@{to})",
             'add "resolutions": {{"{name}": "{to}"}} to package.json, then yarn install'),
    "pnpm": ("pnpm update {name}@{to}",
             'add "pnpm": {{"overrides": {{"{name}": "{to}"}}}} to package.json, then '
             "pnpm install"),
}
NOT_VERIFIED = ("Verification runs on the bundled npm demos only; apply this change and run "
                "your own tests before merging.")


def jump(ecosystem: str, old: str, new: str) -> str:
    a = [int(x) for x in re.findall(r"\d+", old)[:3]]
    b = [int(x) for x in re.findall(r"\d+", new)[:3]]
    if versions.compare(ecosystem, old, new) == 0:
        return "none"
    if not a or not b or a[0] != b[0] or (a[0] == 0 and a[1:2] != b[1:2]):
        return "major"
    return "minor" if a[1:2] != b[1:2] else "patch"


def same_package(f: dict, x: dict) -> bool:
    return (x["package"]["version"] == f["package"]["version"]
            and versions.same_name(f["package"]["ecosystem"], x["package"]["name"],
                                   f["package"]["name"]))


def still_affected(x: dict, ecosystem: str, version: str) -> bool:
    return any(contains_in(r, ecosystem, version) for r in x["affected_ranges"])


def target_for(f: dict, findings: list[dict]) -> tuple[str | None, list[str]]:
    """Smallest fixed version that clears every advisory on this package, else the best one."""
    eco, cur = f["package"]["ecosystem"], f["package"]["version"]
    peers = [x for x in findings if same_package(f, x)]
    fixes = sorted({v for x in peers for v in x["fixed_versions"]
                    if versions.compare(eco, v, cur) > 0}, key=lambda v: versions.key(eco, v))
    own = [v for v in fixes if not still_affected(f, eco, v)]
    for v in own:
        if not any(still_affected(x, eco, v) for x in peers):
            return v, []
    if own:
        return own[-1], [f"No single fixed version clears every advisory on "
                         f"{f['package']['name']}@{cur}; {own[-1]} fixes this one."]
    return None, []


def swap_requirement(text: str, name: str, old: str, new: str) -> str:
    want = norm_name("PyPI", name)
    pin = re.compile(r"^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\s*(?:\[[^\]]*\])?\s*===?\s*)"
                     + re.escape(old) + r"(?=[\s;#\\]|$)", re.M)
    return pin.sub(lambda m: m.group(1) + m.group(2) + m.group(3) + new
                   if norm_name("PyPI", m.group(2)) == want else m.group(0), text)


def swap_gomod(text: str, name: str, old: str, new: str) -> str:
    return re.sub(rf"(^|\s){re.escape(name)}\s+v{re.escape(old)}(?=\s|$)",
                  lambda m: f"{m.group(1)}{name} v{new}", text, flags=re.M)


def pinned_files(stack: str, root: Path) -> list[Path]:
    if stack == "pip":
        return python.requirement_files(root)
    if stack == "go" and (root / "go.mod").is_file():
        return [root / "go.mod"]
    return []


def apply_changes(stack: str, root: Path, changes: list[dict]) -> str:
    """Unified diff of every plain-text pin the changes touch."""
    swap = {"pip": swap_requirement}.get(stack, swap_gomod)
    out = []
    for path in pinned_files(stack, root):
        before = path.read_text("utf-8")
        after = before
        for c in changes:
            after = swap(after, c["pkg"], c["from"], c["to"])
        if after != before:
            out.append(patch.unified(before, after, path.relative_to(root).as_posix()))
    return "".join(out)


def command(stack: str, c: dict, direct: bool) -> str:
    direct_cmd, transitive_cmd = COMMANDS.get(stack, ("", ""))
    tpl = direct_cmd if direct else transitive_cmd
    return tpl.format(name=c["pkg"], to=c["to"], frm=c["from"]) if tpl else ""


def pid_of(*parts) -> str:
    return "p_" + hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()[:12]


async def plan(f: dict, findings: list[dict], root: Path, stack: str, checker) -> list[dict]:
    if f.get("malicious"):
        return [malware.remove_proposal(f)]
    eco = f["package"]["ecosystem"]
    name, cur = f["package"]["name"], f["package"]["version"]
    target, notes = target_for(f, findings)
    if target is None:
        return [{
            "pid": pid_of(f["id"], "none"), "finding_id": f["id"], "strategy": "none",
            "title": "No safe upgrade available", "changes": [], "resolves": [],
            "warnings": ["No fixed version is published for the affected range.",
                         f"Consider replacing {name} or applying the advisory's mitigations."],
            "diff": "", "edits": [], "confidence": "n/a", "command": "", "verifiable": False}]
    change = {"pkg": name, "from": cur, "to": target, "jump": jump(eco, cur, target)}
    warnings = list(notes)
    checks = await checker([Package(name, target, eco)])
    ids = checks.get(f"{name}@{target}")
    if ids is None:
        warnings.append(f"{name}@{target} was not re-checked against OSV (offline).")
    elif ids:
        warnings.append(f"{name}@{target} still matches {len(ids)} OSV advisor"
                        f"{'y' if len(ids) == 1 else 'ies'}: {', '.join(ids[:4])}.")
    if change["jump"] == "major":
        warnings.append(f"Major version jump for {name} ({cur} → {target}): expect breaking "
                        "changes.")
    if not f["direct"]:
        warnings.append(f"{name} is transitive; if a parent's version constraint blocks "
                        f"{target}, upgrade that parent instead.")
    warnings.append(NOT_VERIFIED)
    resolves = sorted({x["advisory"]["id"] for x in findings if same_package(f, x)
                       and not still_affected(x, eco, target)
                       and x["advisory"]["id"] not in (ids or [])})
    strategy = "direct-bump" if f["direct"] else "lock-update"
    title = (f"Upgrade {name} to {target}" if f["direct"]
             else f"Update {name} to {target} in the lockfile")
    return [{
        "pid": pid_of(f["id"], strategy, change), "finding_id": f["id"], "strategy": strategy,
        "title": title, "changes": [change], "resolves": resolves, "warnings": warnings,
        "diff": apply_changes(stack, root, [change]), "edits": [],
        "confidence": "low" if change["jump"] == "major" else "medium",
        "command": command(stack, change, f["direct"]), "verifiable": False,
        "ecosystem": eco, "stack": BY_ID[stack].language if stack in BY_ID else stack}]


async def plan_batch(findings: list[dict], root: Path, stack: str, checker) -> dict:
    items, chosen = [], []
    for f in findings:
        p = (await plan(f, findings, root, stack, checker))[0]
        entry = {"finding_id": f["id"], "advisory": f["advisory"]["id"],
                 "package": f"{f['package']['name']}@{f['package']['version']}",
                 "severity": f["advisory"]["severity"]["label"],
                 "strategy": p["strategy"], "title": p["title"]}
        if p["strategy"] == "none":
            items.append({**entry, "status": "no_fix", "note": p["warnings"][0]})
        else:
            chosen.append((f, p, entry))
    best: dict[str, dict] = {}
    direct: dict[str, bool] = {}
    for f, p, _ in chosen:
        c = p["changes"][0]
        k = f"{c['pkg']}@{c['from']}"
        direct[k] = direct.get(k, False) or f["direct"]
        if k not in best or versions.compare(f["package"]["ecosystem"], c["to"],
                                             best[k]["to"]) > 0:
            best[k] = c
    for _, p, entry in chosen:
        c = p["changes"][0]
        top = best[f"{c['pkg']}@{c['from']}"]["to"]
        merged = top != c["to"]
        items.append({**entry, "status": "merged" if merged else "included",
                      "note": f"superseded by {top} for {c['pkg']}" if merged else ""})
    changes = sorted(best.values(), key=lambda c: c["pkg"])
    commands = [command(stack, c, direct[f"{c['pkg']}@{c['from']}"]) for c in changes]
    order = {"included": 0, "merged": 1, "conflict": 2, "no_fix": 3}
    items.sort(key=lambda i: (order[i["status"]], i["package"], i["advisory"]))
    included = [p for _, p, _ in chosen]
    warnings = list(dict.fromkeys(w for p in included for w in p["warnings"]
                                  if "not re-checked" not in w and w != NOT_VERIFIED))
    return {
        "pid": pid_of("batch", changes), "strategy": "batch",
        "title": f"Batch plan: {len(included)} of {len(findings)} findings",
        "finding_id": chosen[0][0]["id"] if chosen else None,
        "finding_ids": sorted(f["id"] for f, _, _ in chosen),
        "changes": changes,
        "resolves": sorted({r for p in included for r in p["resolves"]}),
        "warnings": warnings + [NOT_VERIFIED],
        "diff": apply_changes(stack, root, changes), "edits": [],
        "confidence": "low" if any(c["jump"] == "major" for c in changes) else
        ("medium" if changes else "n/a"),
        "items": items, "conflicts": [], "command": "\n".join(c for c in commands if c),
        "verifiable": False,
    }
