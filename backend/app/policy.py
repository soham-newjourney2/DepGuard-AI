import json
from pathlib import Path

FILE = "depguard.policy.json"
DEFAULT = {"fail_on": "critical", "prod_only": False, "require_fix": False,
           "fail_on_risks": "none"}
THRESHOLD = {"low": 1, "medium": 2, "high": 3, "critical": 4, "none": 99}
SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def load(root: Path) -> tuple[dict, str, str | None]:
    """Read the project's policy; invalid files fall back to the default with a warning."""
    path = root / FILE
    if not path.is_file():
        return dict(DEFAULT), "default", None
    try:
        data = json.loads(path.read_text("utf-8-sig"))
    except (OSError, ValueError):
        return dict(DEFAULT), "default", f"{FILE} is not valid JSON; using the default policy."
    if not isinstance(data, dict):
        return dict(DEFAULT), "default", f"{FILE} must be a JSON object; using the default policy."
    problems = [k for k in data if k not in DEFAULT]
    policy = dict(DEFAULT)
    if "fail_on" in data:
        if data["fail_on"] in THRESHOLD:
            policy["fail_on"] = data["fail_on"]
        else:
            problems.append("fail_on")
    if "fail_on_risks" in data:
        if data["fail_on_risks"] in THRESHOLD:
            policy["fail_on_risks"] = data["fail_on_risks"]
        else:
            problems.append("fail_on_risks")
    for key in ("prod_only", "require_fix"):
        if key in data:
            if isinstance(data[key], bool):
                policy[key] = data[key]
            else:
                problems.append(key)
    warning = (f"{FILE}: ignored invalid or unknown keys {', '.join(sorted(set(problems)))}."
               if problems else None)
    return policy, FILE, warning


def evaluate(findings: list[dict], policy: dict, source: str,
             risks: list[dict] | None = None) -> dict:
    """Unknown severity always counts: missing data is never treated as safe."""
    limit = THRESHOLD[policy["fail_on"]]
    risk_limit = THRESHOLD[policy.get("fail_on_risks", "none")]
    violations = []
    for f in findings:
        if policy["prod_only"] and f["scope"] != "prod":
            continue
        if policy["require_fix"] and not f.get("fix_available"):
            continue
        sev = f["advisory"]["severity"]["label"]
        rank = SEVERITY.get(sev)
        if limit == THRESHOLD["none"]:
            continue
        if rank is None or rank >= limit:
            violations.append({"finding_id": f["id"], "advisory": f["advisory"]["id"],
                               "package": f"{f['package']['name']}@{f['package']['version']}",
                               "severity": sev, "scope": f["scope"]})
    for r in risks or []:
        if SEVERITY.get(r["severity"], 0) >= risk_limit:
            violations.append({"risk_id": r["id"], "kind": r["kind"], "title": r["title"],
                               "severity": r["severity"]})
    return {"status": "fail" if violations else "pass", "policy": policy, "source": source,
            "violations": violations, "count": len(violations)}


def describe(policy: dict) -> str:
    parts = ["never fails" if policy["fail_on"] == "none"
             else f"fails on {policy['fail_on']} or worse"]
    if policy["prod_only"]:
        parts.append("production scope only")
    if policy["require_fix"]:
        parts.append("only when a fix exists")
    if policy.get("fail_on_risks", "none") != "none":
        parts.append(f"supply-chain signals at {policy['fail_on_risks']} or worse")
    return ", ".join(parts)
