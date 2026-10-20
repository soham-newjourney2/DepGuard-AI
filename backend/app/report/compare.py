CLASSES = ("resolved", "still_present", "newly_detected", "unable_to_verify")


def key(f: dict) -> tuple[str, str]:
    return f["advisory"]["id"], f["package"]["name"]


def item(f: dict, after_versions: list[str] | None = None) -> dict:
    pkg = f["package"]
    out = {"advisory": f["advisory"]["id"], "summary": f["advisory"]["summary"],
           "severity": f["advisory"]["severity"]["label"], "package": pkg["name"],
           "version": pkg["version"], "scope": f["scope"],
           "band": (f.get("priority") or {}).get("band")}
    if after_versions is not None:
        out["versions_after"] = after_versions
    return out


def classify(before: list[dict], after: list[dict] | None, status: str | None,
             targeted: set[str] | None = None) -> dict:
    """Compare by (advisory id, package name). Test outcome is reported separately."""
    out = {c: [] for c in CLASSES}
    targeted = targeted or set()
    if after is None or status in (None, "unable_to_verify"):
        for f in before:
            bucket = ("unable_to_verify" if status == "unable_to_verify"
                      and f["advisory"]["id"] in targeted else "still_present")
            out[bucket].append(item(f))
        return out
    after_by: dict[tuple[str, str], list[str]] = {}
    for f in after:
        after_by.setdefault(key(f), [])
        if f["package"]["version"] not in after_by[key(f)]:
            after_by[key(f)].append(f["package"]["version"])
    before_keys = {key(f) for f in before}
    for f in before:
        if key(f) in after_by:
            out["still_present"].append(item(f, after_by[key(f)]))
        else:
            out["resolved"].append(item(f))
    out["newly_detected"] = [item(f) for f in after if key(f) not in before_keys]
    return out
