import hashlib
import json

from app.remediation import patch
from app.remediation.candidates import Planner, jump
from app.scanner.normalize import parse_ver

CONF_RANK = {"high": 0, "medium": 1, "low": 2, "n/a": 3}


def spec_version(value: str):
    return parse_ver(value.lstrip("^~=v"))


def edit_key(e: dict) -> tuple:
    return ("set", e["section"], e["name"]) if e["op"] == "set" else ("override", *e["path"])


def item(f: dict, status: str, proposal: dict | None = None, note: str = "") -> dict:
    return {"finding_id": f["id"], "advisory": f["advisory"]["id"],
            "package": f"{f['package']['name']}@{f['package']['version']}",
            "severity": f["advisory"]["severity"]["label"], "status": status,
            "strategy": proposal["strategy"] if proposal else None,
            "title": proposal["title"] if proposal else None, "note": note}


async def plan_all(findings: list[dict], graph: dict, manifest_text: str, registry,
                   checker) -> dict:
    """Best candidate per finding, merged into one manifest change; conflicts are reported."""
    chosen, items = [], []
    for f in findings:
        props = await Planner(f, findings, graph, manifest_text, registry, checker).plan()
        best = props[0]
        if best["strategy"] == "remove":
            items.append(item(f, "remove", best, best["warnings"][0]))
        elif best["strategy"] == "none":
            items.append(item(f, "no_fix", best, best["warnings"][0] if best["warnings"] else ""))
        else:
            chosen.append((f, best))

    edits: dict[tuple, tuple[dict, list[str]]] = {}
    status: dict[str, tuple[str, str]] = {}
    for f, p in chosen:
        for e in p["edits"]:
            k = edit_key(e)
            if k not in edits:
                edits[k] = (e, [f["id"]])
                continue
            old, owners = edits[k]
            if old["value"] == e["value"]:
                owners.append(f["id"])
                continue
            a, b = spec_version(old["value"]), spec_version(e["value"])
            if a is None or b is None:
                status[f["id"]] = ("conflict", f"{k[-1]}: {old['value']} vs {e['value']}")
            elif b > a:
                for o in owners:
                    status[o] = ("merged", f"superseded by {e['value']} for {k[-1]}")
                edits[k] = (e, [f["id"]])
            else:
                status[f["id"]] = ("merged", f"superseded by {old['value']} for {k[-1]}")

    bumped = {k[2] for k in edits if k[0] == "set"}
    lifted: dict[str, list] = {}
    for f, p in chosen:
        if any(edit_key(e) in edits and edits[edit_key(e)][1].count(f["id"])
               for e in p["edits"] if e["op"] == "set"):
            for c in p["changes"]:
                lifted.setdefault(c["pkg"], []).append(spec_version(c["to"]))
    for k in [k for k in edits if k[0] == "override" and k[1] in bumped]:
        e, owners = edits.pop(k)
        target = spec_version(e["value"])
        covered = target is not None and any(v is not None and v >= target
                                             for v in lifted.get(k[-1], []))
        for o in owners:
            status[o] = (("merged", f"covered by the {k[1]} upgrade in this plan (predicted)")
                         if covered else
                         ("conflict", f"{k[1]} is upgraded in this plan, so the override under "
                                      f"it was dropped; re-plan after verifying."))

    final_edits = [e for e, _ in edits.values()]
    included_ids = set()
    for f, p in chosen:
        st, note = status.get(f["id"], ("included", ""))
        items.append(item(f, st, p, note))
        if st != "conflict":
            included_ids.add(f["id"])

    changes: dict[str, dict] = {}
    for f, p in chosen:
        if f["id"] not in included_ids:
            continue
        for c in p["changes"]:
            prev = changes.get(c["pkg"] + "@" + c["from"])
            if prev is None or (spec_version(c["to"]) or parse_ver("0.0.0")) > \
                    (spec_version(prev["to"]) or parse_ver("0.0.0")):
                changes[c["pkg"] + "@" + c["from"]] = {**c, "jump": jump(c["from"], c["to"])}
    included = [(f, p) for f, p in chosen if f["id"] in included_ids]
    warnings = list(dict.fromkeys(
        [f"Conflict: {i['package']} {i['advisory']} — {i['note']}" for i in items
         if i["status"] == "conflict"]
        + [w for _, p in included for w in p["warnings"] if "not re-checked" not in w]))
    after = patch.apply(manifest_text, final_edits) if final_edits else manifest_text
    raw = json.dumps(sorted(json.dumps(e, sort_keys=True) for e in final_edits))
    order = {"included": 0, "merged": 1, "conflict": 2, "no_fix": 3}
    items.sort(key=lambda i: (order[i["status"]], i["package"], i["advisory"]))
    return {
        "pid": "p_" + hashlib.sha256(("batch" + raw).encode()).hexdigest()[:12],
        "strategy": "batch",
        "title": f"Batch plan: {len(included)} of {len(findings)} findings",
        "finding_id": included[0][0]["id"] if included else None,
        "finding_ids": sorted(included_ids),
        "changes": sorted(changes.values(), key=lambda c: c["pkg"]),
        "resolves": sorted({r for _, p in included for r in p["resolves"]}),
        "warnings": warnings,
        "diff": patch.unified(manifest_text, after) if final_edits else "",
        "edits": final_edits,
        "confidence": max((p["confidence"] for _, p in included), key=CONF_RANK.get,
                          default="n/a"),
        "items": items,
        "conflicts": [i for i in items if i["status"] == "conflict"],
    }
