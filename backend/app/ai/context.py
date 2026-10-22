import json
import re

from app import cwe
from app.ai import quotes
from app.evidence import fix_versions
from app.security import redact

MAX_BYTES = 6 * 1024


def exploit_ctx(x: dict | None) -> dict | None:
    if not x:
        return None
    return {"status": x["status"], "cves": x["cves"], "as_of": x["as_of"],
            "kev_date_added": (x["kev"] or {}).get("dateAdded"),
            "epss": (x["epss"] or {}).get("epss"),
            "epss_percentile": (x["epss"] or {}).get("percentile")}


def weakness_ctx(cwes: list[str]) -> dict | None:
    w = cwe.weakness(cwes)
    if w is None:
        return None
    named = re.search(r"\('([^']+)'\)", w["name"] or "")
    short = named.group(1) if named else (w["name"] or w["id"])
    return {"id": w["id"], "name": w["name"], "short": short, "plain": w["plain"],
            "impact": w["impact"], "matters_when": w["matters_when"],
            "mitigation": w["mitigation"], "source": w["source"]}


def build(finding: dict, candidates: list[dict] | None = None) -> dict:
    adv, pkg = finding["advisory"], finding["package"]
    weakness = weakness_ctx(adv.get("cwes") or [])
    ctx = {
        "finding_id": finding["id"],
        "package": {"name": pkg["name"], "version": pkg["version"], "ecosystem": pkg["ecosystem"]},
        "advisory": {
            "id": adv["id"], "aliases": adv["aliases"][:4], "summary": adv["summary"],
            "severity": {k: adv["severity"].get(k) for k in ("label", "score", "source")},
            "published": adv.get("published"), "details": (adv.get("details") or "")[:1200],
        },
        "affected_ranges": [r["text"] for r in finding["affected_ranges"]][:8],
        "installed_in_range": [r["text"] for r in finding["affected_ranges"] if r.get("contains")],
        "fix_versions": fix_versions(finding),
        "scope": finding["scope"], "direct": finding["direct"], "depth": finding["depth"],
        "paths": [" > ".join(p) for p in finding["paths"][:3]],
        "path_count": finding["path_count"],
        "reachability": finding["reachability"]["label"],
        "priority": {k: finding["priority"][k] for k in ("score", "band", "band_label", "flags")},
        "exploit": exploit_ctx(finding.get("exploit")),
        "malicious": bool(finding.get("malicious")),
        "weakness": weakness,
        "quote": quotes.pick(adv, pkg["name"], [weakness["name"]] if weakness and
                             weakness["name"] else []),
        "evidence": [{"eid": e["eid"], "kind": e["kind"], "label": e["label"], "text": e["text"]}
                     for e in finding["evidence"]],
        "candidates": [{k: c.get(k) for k in ("strategy", "changes", "warnings", "confidence")}
                       for c in (candidates or [])][:3],
    }
    return shrink(redact(ctx))


def size(ctx: dict) -> int:
    return len(dumps(ctx).encode("utf-8"))


def dumps(ctx: dict) -> str:
    return json.dumps(ctx, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def shrink(ctx: dict) -> dict:
    steps = [
        lambda c: c["advisory"].update(details=c["advisory"]["details"][:400]),
        lambda c: c.update(paths=c["paths"][:1], affected_ranges=c["affected_ranges"][:3]),
        lambda c: c["advisory"].update(details=""),
        lambda c: c.update(candidates=c["candidates"][:1]),
        lambda c: [e.update(text=e["text"][:200]) for e in c["evidence"]],
    ]
    for step in steps:
        if size(ctx) <= MAX_BYTES:
            break
        step(ctx)
    return ctx
