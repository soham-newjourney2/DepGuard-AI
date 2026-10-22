from app import cwe, versions

REACHABILITY_UNKNOWN = ("Reachability not determined — static import analysis can miss "
                        "dynamic usage.")
SCOPE_TEXT = {
    "prod": "reachable through production dependencies, so it ships with the app",
    "optional": "reachable only through optional dependencies",
    "peer": "reachable only through peer dependencies",
    "dev": "reachable only through devDependencies, so it is not installed in production",
}


def fix_versions(finding: dict) -> list[str]:
    eco = finding["package"].get("ecosystem", "npm")
    current = finding["package"]["version"]
    ranges = [r for r in finding["affected_ranges"] if r.get("contains") and r.get("fixed")]
    fixes = [r["fixed"] for r in ranges]
    if not fixes:
        fixes = [v for v in finding["fixed_versions"] if versions.compare(eco, v, current) > 0]
    return sorted(set(fixes), key=lambda v: versions.key(eco, v))


def reach_text(finding: dict) -> tuple[str, str, str]:
    r = finding.get("reachability") or {}
    label, ev = r.get("label", "Unknown"), r.get("evidence") or []
    name = finding["package"]["name"]
    first = ev[0] if ev else None
    loc = f"{first['file']}:{first['line']}" if first else ""
    if label in ("Strong evidence", "Possible") and not first:
        text = f"Import analysis labelled {name} \"{label}\" but recorded no location."
    elif label == "Strong evidence" and first["kind"] == "loaded":
        text = (f"The page loads {name} {finding['package']['version']} at {loc} "
                f"({first['text']}); whether the vulnerable code path runs is not determined.")
    elif label == "Strong evidence":
        text = (f"{name} is imported directly in project source at {loc} ({first['text']}); "
                "whether the vulnerable code path runs is not determined.")
    elif label == "Possible":
        text = (f"{first['module']}, which pulls in {name}, is imported at {loc}; {name} itself "
                "is not imported directly.")
    elif label == "Not observed":
        tests = f" (only in tests, e.g. {loc})" if first else ""
        text = (f"No import of {name} or the packages that pull it in was found in project "
                f"source{tests}; static analysis can miss dynamic usage.")
    else:
        text = REACHABILITY_UNKNOWN
        if first and first["kind"] == "dynamic":
            text += f" Dynamic require/import seen at {loc}."
    if first and first["kind"] == "loaded":
        return text, "live page fetch", label
    return text, ("import scan of project source" if label != "Unknown" or ev
                  else "not analysed"), label


def ordinal(n: int) -> str:
    suffix = "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def epss_text(e: dict) -> str:
    return (f"EPSS {e['epss']:.3f} ({ordinal(int(e['percentile'] * 100))} percentile) on "
            f"{e['date']} for {e['cve']}. EPSS is a model's estimate of exploitation in the next "
            "30 days, not an observation.")


def exploit_text(x: dict) -> tuple[str, str, str]:
    absent = (f"Not in CISA KEV as of {x['as_of']}. Absence from the list is not proof it is "
              "not exploited.")
    if x["status"] == "listed":
        k = x["kev"]
        text = (f"{k['cve']} is in CISA KEV since {k['dateAdded']} (known ransomware use: "
                f"{k.get('knownRansomwareCampaignUse') or 'Unknown'}).")
        if x["epss"]:
            return f"{text} {epss_text(x['epss'])}", "cisa.gov KEV · first.org EPSS", "Confirmed"
        return text, "cisa.gov KEV", "Confirmed"
    if x["status"] == "scored":
        kev = absent if x["checked"]["kev"] else "CISA KEV could not be checked."
        return f"{epss_text(x['epss'])} {kev}", "first.org EPSS", "Possible"
    if x["status"] == "none":
        return (f"{absent} No EPSS score is published for {', '.join(x['cves'])}.",
                "cisa.gov KEV · first.org EPSS", "Not observed")
    if x["status"] == "unknown":
        return "No CVE id, so exploit data is unknown.", "advisory aliases", "Unknown"
    if x["status"] == "unavailable":
        return ("CISA KEV and FIRST EPSS could not be reached; exploitation status is unknown.",
                "not available", "Unknown")
    return ("Exploit signals are off (local-only mode or EXPLOIT_SIGNALS=off); exploitation "
            "status is unknown.", "not checked", "Unknown")


def weakness_text(cwes: list[str]) -> tuple[str, str, str]:
    w = cwe.weakness(cwes)
    if w is None:
        return cwe.NONE, "advisory", "Unknown"
    others = [c for c in cwes if c != w["id"]]
    also = f" Also listed: {', '.join(others[:3])}." if others else ""
    if not w["known"]:
        return (f"The advisory classifies it as {w['id']}.{also}", w["source"], "Confirmed")
    return (f"The advisory classifies it as {w['id']} ({w['name']}): {w['plain']}{also}",
            w["source"], "Confirmed")


def chain(path: list[str]) -> str:
    return " → ".join(path)


def build(finding: dict) -> list[dict]:
    adv, pkg = finding["advisory"], finding["package"]
    label = f"{pkg['name']}@{pkg['version']}"
    sev = adv["severity"]
    score = f" {sev['score']:.1f}" if sev.get("score") is not None else ""
    matched = [r["text"] for r in finding["affected_ranges"] if r.get("contains")]
    rng = f" Installed {pkg['version']} is inside affected range {matched[0]}." if matched else ""
    aliases = f" ({', '.join(adv['aliases'][:3])})" if adv["aliases"] else ""
    paths = finding["paths"]
    depth = finding["depth"]
    if finding["direct"]:
        where = "a direct dependency"
    elif depth is not None:
        where = f"a transitive dependency at depth {depth}"
    else:
        where = "in the lockfile, but its path from the root is not recorded"
    fixes = fix_versions(finding)
    lockfile = finding.get("lockfile") or "package-lock.json"
    scan = finding["scan"]
    cached = " (cached)" if scan["source"] == "cache" else ""
    items = [
        ("advisory", f"{adv['id']}{aliases}: {adv['summary'].rstrip('.')}. "
                     f"Severity {sev['label']}{score}"
                     f"{' from ' + sev['source'] if sev.get('source') else ''}.{rng}",
         f"OSV · modified {adv.get('modified') or 'unknown'}", "Confirmed"),
        ("path", f"{label} is {where}; {finding['path_count']} path(s) from the root"
                 f"{', shortest: ' + chain(paths[0]) if paths else ''}.",
         lockfile, "Confirmed"),
        ("scope", f"Scope {finding['scope']}: {SCOPE_TEXT[finding['scope']]}.",
         lockfile, "Confirmed"),
        ("fix", f"Fixed in {', '.join(fixes)} according to the advisory." if fixes
                else "No fixed version is published for the affected range.",
         "OSV affected ranges", "Confirmed" if fixes else "Unknown"),
        ("reachability", *reach_text(finding)),
        ("scan", f"Scanned with {scan['scanner']} ({scan['version']}) at {scan['ts']}{cached}.",
         scan["scanner"], "Confirmed"),
    ]
    if finding.get("exploit"):
        items.append(("exploit", *exploit_text(finding["exploit"])))
    items.append(("weakness", *weakness_text(adv.get("cwes") or [])))
    return [{"eid": f"E{i}", "kind": kind, "text": text, "source": source, "label": lab}
            for i, (kind, text, source, lab) in enumerate(items, 1)]


def eid_for(evidence: list[dict], kind: str) -> str | None:
    return next((e["eid"] for e in evidence if e["kind"] == kind), None)
