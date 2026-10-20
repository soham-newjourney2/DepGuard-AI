import hashlib
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

import semantic_version as sv

from app.remediation import patch
from app.remediation.registry import Registry, RegistryError
from app.scanner.base import Package
from app.scanner.normalize import contains, parse_ver

JUMP_RANK = {"none": 0, "patch": 1, "minor": 2, "major": 3}
STRATEGY_RANK = {"direct-bump": 0, "parent-bump": 1, "override": 2, "none": 3}
MAX_PARENT_TRIES = 150
DEP_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")

Checker = Callable[[list[Package]], Awaitable[dict[str, list[str] | None]]]


def split_label(label: str) -> tuple[str, str]:
    name, _, version = label.rpartition("@")
    return name, version


def parse_spec(spec: str | None) -> sv.NpmSpec | None:
    if spec is None:
        return None
    spec = spec.strip()
    if spec.startswith("npm:"):
        spec = spec.rpartition("@")[2]
    spec = re.sub(r"([<>]=?|=)\s+", r"\1", spec)
    try:
        return sv.NpmSpec(spec)
    except ValueError:
        return None


def jump(old: str, new: str) -> str:
    a, b = parse_ver(old), parse_ver(new)
    if a is None or b is None or a == b:
        return "none" if old == new else "major"
    if a.major != b.major or (a.major == 0 and a.minor != b.minor):
        return "major"
    return "minor" if a.minor != b.minor else "patch"


def compatible(v: sv.Version, base: sv.Version) -> bool:
    return v.major == base.major and (base.major > 0 or v.minor == base.minor)


def stable(doc: dict) -> list[tuple[sv.Version, str]]:
    out = []
    for raw in doc.get("versions", {}):
        v = parse_ver(raw)
        if v is not None and not v.prerelease:
            out.append((v, raw))
    return sorted(out)


def max_satisfying(doc: dict, spec_text: str | None) -> str | None:
    spec = parse_spec(spec_text)
    if spec is None:
        return None
    latest = (doc.get("dist-tags") or {}).get("latest")
    if latest and (lv := parse_ver(latest)) and spec.match(lv):
        return latest
    hits = [raw for v, raw in stable(doc) if spec.match(v)]
    return hits[-1] if hits else None


def deps_of(doc: dict, version: str) -> dict[str, str]:
    meta = doc.get("versions", {}).get(version, {})
    merged: dict[str, str] = {}
    for f in DEP_FIELDS:
        for k, v in (meta.get(f) or {}).items():
            merged.setdefault(k, v)
    return merged


@dataclass
class Advisories:
    this: list[dict]
    others: dict[str, list[dict]] = field(default_factory=dict)

    def status(self, version: str) -> str:
        v = parse_ver(version)
        if v is None:
            return "unknown"
        if any(contains(r, v) for r in self.this):
            return "affected"
        if any(contains(r, v) for rs in self.others.values() for r in rs):
            return "fixes-this"
        return "clean"


def pick(versions: list[tuple[sv.Version, str]], base: sv.Version, ok: Callable[[str], str],
         deprecated: Callable[[str], bool]) -> str | None:
    """Least change that clears the advisory: clean in-major, fixed in-major, then any major."""
    newer = [(v, raw) for v, raw in versions if v > base]
    same = [(v, raw) for v, raw in newer if compatible(v, base)]
    for pool, want in ((same, "clean"), (same, "fixes-this"), (newer, "clean"),
                       (newer, "fixes-this")):
        hits = [raw for _, raw in pool if ok(raw) == want]
        if hits:
            return next((h for h in hits if not deprecated(h)), hits[0])
    return None


class Planner:
    def __init__(self, finding: dict, findings: list[dict], graph: dict, manifest_text: str,
                 registry: Registry, checker: Checker):
        self.f = finding
        self.findings = findings
        self.graph = graph
        self.text = manifest_text
        self.manifest = json.loads(manifest_text.lstrip("﻿"))
        self.registry = registry
        self.checker = checker
        self.name = finding["package"]["name"]
        self.version = finding["package"]["version"]
        same_pkg = [x for x in findings if x["package"]["name"] == self.name]
        self.adv = Advisories(
            this=finding["affected_ranges"],
            others={x["advisory"]["id"]: x["affected_ranges"] for x in same_pkg
                    if x["advisory"]["id"] != finding["advisory"]["id"]})
        self.labels = {n["label"]: n for n in graph["nodes"]}
        self.notes: list[str] = []

    async def plan(self) -> list[dict]:
        try:
            doc = await self.registry.packument(self.name)
        except RegistryError as exc:
            return [self.none([f"Registry metadata unavailable: {exc}"])]
        base = parse_ver(self.version)
        target = pick(stable(doc), base, self.adv.status, lambda v: self.deprecated(doc, v)) \
            if base else None
        if target is None:
            return [self.none(self.no_fix_notes(doc))]
        out = []
        direct_paths = [p for p in self.f["paths"] if len(p) == 2]
        if direct_paths:
            out.append(await self.direct(doc, target))
        groups: dict[str, list[list[str]]] = {}
        for p in self.f["paths"]:
            if len(p) > 2:
                groups.setdefault(split_label(p[1])[0], []).append(p)
        if groups:
            parent = await self.parent_bump(groups)
            if parent:
                out.append(parent)
            out.append(await self.override(target, groups))
        out = [c for c in out if c]
        out.sort(key=lambda c: (max((JUMP_RANK[ch["jump"]] for ch in c["changes"]), default=0),
                                STRATEGY_RANK[c["strategy"]]))
        return out

    def deprecated(self, doc: dict, version: str) -> bool:
        return bool(doc.get("versions", {}).get(version, {}).get("deprecated"))

    def no_fix_notes(self, doc: dict) -> list[str]:
        notes = [f"No published version of {self.name} is outside the affected range of "
                 f"{self.f['advisory']['id']}."]
        latest = (doc.get("dist-tags") or {}).get("latest")
        msg = doc.get("versions", {}).get(latest or "", {}).get("deprecated")
        if msg:
            notes.append(f"{self.name}@{latest} is deprecated by its maintainers: {msg}")
        notes.append("Options: replace the dependency, remove the code path that uses it, or "
                     "accept the risk and monitor the advisory.")
        return notes

    def none(self, warnings: list[str]) -> dict:
        return self.finish("none", [], [], warnings, "n/a", "No safe upgrade available")

    async def direct(self, doc: dict, target: str) -> dict:
        section = patch.section_of(self.manifest, self.name) or "dependencies"
        old_spec = (self.manifest.get(section) or {}).get(self.name, "")
        edits = [{"op": "set", "section": section, "name": self.name,
                  "value": patch.bump_spec(old_spec, target)}]
        changes = [self.change(self.name, self.version, target)]
        warnings = []
        if any(len(p) > 2 for p in self.f["paths"]):
            warnings.append(f"Other copies of {self.name}@{self.version} reached through "
                            "parents keep their own range; check them after the bump.")
        return await self.build("direct-bump", changes, edits, warnings)

    async def parent_bump(self, groups: dict[str, list[list[str]]]) -> dict | None:
        edits, changes = [], []
        for parent, paths in groups.items():
            section = patch.section_of(self.manifest, parent)
            if section is None:
                return None
            installed = split_label(paths[0][1])[1]
            found = await self.bump_parent(parent, installed, paths)
            if found is None:
                return None
            new_ver, delta = found
            old_spec = self.manifest[section][parent]
            edits.append({"op": "set", "section": section, "name": parent,
                          "value": patch.bump_spec(old_spec, new_ver)})
            changes += delta
        uniq = {(c["pkg"], c["from"]): c for c in changes}
        return await self.build("parent-bump", list(uniq.values()), edits, [
            "Versions of transitive packages are predicted from the registry (highest version "
            "satisfying each declared range); verification confirms the real tree."])

    async def bump_parent(self, parent: str, installed: str, paths: list[list[str]]):
        try:
            doc = await self.registry.packument(parent)
        except RegistryError as exc:
            self.notes.append(str(exc))
            return None
        base = parse_ver(installed)
        if base is None:
            return None
        newer = [(v, raw) for v, raw in stable(doc) if v > base][:MAX_PARENT_TRIES]
        same = [(v, raw) for v, raw in newer if compatible(v, base)]
        results: dict[str, tuple[str, list[dict]]] = {}
        for pool in (same, newer):
            for _, raw in pool:
                if raw not in results:
                    results[raw] = await self.simulate(parent, doc, raw, paths)
            for want in ("clean", "fixes-this"):
                for _, raw in pool:
                    if results[raw][0] == want and not self.deprecated(doc, raw):
                        return raw, results[raw][1]
        return None

    async def simulate(self, parent: str, doc: dict, version: str,
                       paths: list[list[str]]) -> tuple[str, list[dict]]:
        worst, delta = "clean", [self.change(parent, split_label(paths[0][1])[1], version)]
        order = {"clean": 0, "fixes-this": 1, "dropped": 0, "affected": 3, "unknown": 3}
        for path in paths:
            cur_doc, cur_ver = doc, version
            status = "dropped"
            for label in path[2:]:
                name, old = split_label(label)
                spec = deps_of(cur_doc, cur_ver).get(name)
                if spec is None:
                    status = "dropped"
                    break
                try:
                    nxt = await self.registry.packument(name)
                except RegistryError:
                    status = "unknown"
                    break
                resolved = max_satisfying(nxt, spec)
                if resolved is None:
                    status = "unknown"
                    break
                if resolved != old:
                    delta.append(self.change(name, old, resolved))
                cur_doc, cur_ver = nxt, resolved
                if name == self.name:
                    status = self.adv.status(resolved)
            if order[status] > order[worst]:
                worst = status
        return worst, delta

    async def override(self, target: str, groups: dict[str, list[list[str]]]) -> dict:
        edits = [{"op": "override", "path": [parent, self.name], "value": target}
                 for parent in groups]
        warnings, confidence = [], "medium"
        for p in {tuple(path[-2:]) for paths in groups.values() for path in paths}:
            spec = self.declared(p[0], p[1])
            parsed = parse_spec(spec)
            tv = parse_ver(target)
            if parsed is not None and tv is not None and not parsed.match(tv):
                warnings.append(f"{target} is outside {p[0]}'s declared range \"{spec}\" for "
                                f"{self.name}; the parent was not tested with it.")
                confidence = "low"
        changes = [self.change(self.name, self.version, target)]
        c = await self.build("override", changes, edits, warnings)
        if confidence == "low":
            c["confidence"] = "low"
        return c

    def declared(self, parent_label: str, child_label: str) -> str | None:
        parent = self.labels.get(parent_label)
        child = self.labels.get(child_label)
        if not parent or not child:
            return None
        for e in self.graph["edges"]:
            if e["from"] == parent["id"] and e["to"] == child["id"]:
                return e.get("spec")
        return None

    def change(self, pkg: str, old: str, new: str) -> dict:
        return {"pkg": pkg, "from": old, "to": new, "jump": jump(old, new)}

    async def build(self, strategy: str, changes: list[dict], edits: list[dict],
                    warnings: list[str]) -> dict:
        checks = await self.checker([Package(c["pkg"], c["to"]) for c in changes])
        warnings = list(warnings)
        for c in changes:
            label = f"{c['pkg']}@{c['to']}"
            ids = checks.get(label)
            if ids is None:
                warnings.append(f"{label} was not re-checked against OSV (offline).")
            elif ids:
                warnings.append(f"{label} still matches {len(ids)} OSV advisor"
                                f"{'y' if len(ids) == 1 else 'ies'}: {', '.join(ids[:4])}.")
            if c["jump"] == "major":
                warnings.append(f"Major version jump for {c['pkg']} ({c['from']} → {c['to']}): "
                                "expect breaking changes.")
            try:
                doc = await self.registry.packument(c["pkg"])
            except RegistryError:
                continue
            meta = doc.get("versions", {}).get(c["to"], {})
            if meta.get("deprecated"):
                warnings.append(f"{label} is deprecated: {meta['deprecated']}")
            for peer, spec in (meta.get("peerDependencies") or {}).items():
                optional = (meta.get("peerDependenciesMeta") or {}).get(peer, {}).get("optional")
                have = [n["version"] for n in self.labels.values() if n["name"] == peer]
                parsed = parse_spec(spec)
                if not optional and parsed and have and not any(
                        (v := parse_ver(h)) and parsed.match(v) for h in have):
                    warnings.append(f"{label} expects peer {peer}@{spec}; installed "
                                    f"{', '.join(sorted(set(have)))}.")
        resolves = self.resolved(changes, checks)
        confidence = "high" if strategy == "direct-bump" and all(
            c["jump"] in ("patch", "minor") for c in changes) else "medium"
        after = patch.apply(self.text, edits) if edits else self.text
        return self.finish(strategy, changes, resolves, warnings, confidence,
                           title(strategy, changes, self.name), patch.unified(self.text, after),
                           edits)

    def resolved(self, changes: list[dict], checks: dict) -> list[str]:
        out = []
        for c in changes:
            ids = checks.get(f"{c['pkg']}@{c['to']}") or []
            v = parse_ver(c["to"])
            for x in self.findings:
                if (x["package"]["name"], x["package"]["version"]) != (c["pkg"], c["from"]):
                    continue
                still = v is None or any(contains(r, v) for r in x["affected_ranges"]) \
                    or x["advisory"]["id"] in ids
                if not still:
                    out.append(x["advisory"]["id"])
        return sorted(set(out))

    def finish(self, strategy, changes, resolves, warnings, confidence, title_text, diff="",
               edits=None) -> dict:
        raw = json.dumps([self.f["id"], strategy, changes], sort_keys=True)
        return {
            "pid": "p_" + hashlib.sha256(raw.encode()).hexdigest()[:12],
            "finding_id": self.f["id"], "strategy": strategy, "title": title_text,
            "changes": changes, "resolves": resolves,
            "warnings": list(dict.fromkeys(warnings + self.notes)), "diff": diff,
            "edits": edits or [], "confidence": confidence,
        }


def title(strategy: str, changes: list[dict], name: str) -> str:
    head = changes[0] if changes else None
    if strategy == "direct-bump":
        return f"Upgrade {name} to {head['to']}"
    if strategy == "parent-bump":
        return f"Upgrade {head['pkg']} to {head['to']} (pulls a fixed {name})"
    if strategy == "override":
        return f"Override {name} to {head['to']}"
    return "No safe upgrade available"
