from app import evidence as ev
from app.scanner.normalize import SEV_ORDER

SEVERITY_POINTS = {"critical": 40, "high": 30, "medium": 18, "low": 8, "unknown": 15}
SCOPE_POINTS = {"prod": 20, "optional": 8, "peer": 8, "dev": 0}
REACH_POINTS = {"Strong evidence": 12, "Possible": 6, "Not observed": 0, "Unknown": 0}
BANDS = [(70, "P1", "Fix now"), (50, "P2", "Fix soon"), (30, "P3", "Plan"), (0, "P4", "Monitor")]


def depth_points(finding: dict) -> tuple[int, str]:
    if finding["direct"]:
        return 8, "direct"
    depth = finding["depth"]
    if depth is None:
        return 5, "unknown"
    return (5, f"depth {depth}") if depth <= 2 else (2, f"depth {depth}")


def band(score: int) -> tuple[str, str]:
    return next((b, label) for floor, b, label in BANDS if score >= floor)


def prioritize(finding: dict) -> dict:
    evidence = finding["evidence"]
    sev = finding["advisory"]["severity"]["label"]
    fixes = ev.fix_versions(finding)
    reach = finding["reachability"]["label"]
    dpts, dlabel = depth_points(finding)
    distinct = finding["path_count"]
    signals = [
        ("severity", "Severity", sev, SEVERITY_POINTS[sev], "advisory"),
        ("scope", "Scope", finding["scope"], SCOPE_POINTS[finding["scope"]], "scope"),
        ("fix", "Fix available", "yes" if fixes else "no", 10 if fixes else 0, "fix"),
        ("depth", "Depth", dlabel, dpts, "path"),
        ("reachability", "Reachability", reach, REACH_POINTS.get(reach, 0), "reachability"),
        ("exposure", "Exposure", f"{distinct} path{'s' if distinct != 1 else ''}",
         3 if distinct >= 3 else 0, "path"),
    ]
    score = sum(s[3] for s in signals)
    code, label = band(score)
    flags = [f for f, on in (("severity unknown", sev == "unknown"), ("no fix", not fixes),
                             ("depth unknown", dlabel == "unknown")) if on]
    return {
        "score": score, "band": code, "band_label": label, "flags": flags,
        "signals": [{"key": k, "label": lab, "value": v, "points": p,
                     "eid": ev.eid_for(evidence, kind)} for k, lab, v, p, kind in signals],
    }


def sort_key(finding: dict) -> tuple:
    sev = finding["advisory"]["severity"]
    return (-finding["priority"]["score"], -SEV_ORDER[sev["label"]], -(sev["score"] or 0),
            finding["package"]["name"], finding["advisory"]["id"])


def enrich(findings: list[dict]) -> list[dict]:
    for f in findings:
        f["evidence"] = ev.build(f)
        f["priority"] = prioritize(f)
        f["fix_available"] = bool(ev.fix_versions(f))
    return sorted(findings, key=sort_key)
