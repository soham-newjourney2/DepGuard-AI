"""Decision-tree explanations: every sentence comes from the evidence and cites it."""

import hashlib

from app.ai.base import coerce

SCOPE_WHY = {
    "prod": ("It is reachable through production dependencies, so it ships with the app",
             "It sits on a production dependency path, so it is part of what you deploy",
             "Production dependencies pull it in, so it runs wherever the app runs"),
    "optional": ("It is reachable only through optional dependencies, so it is installed only on "
                 "some platforms",
                 "Only optional dependencies pull it in, so some installs will not include it"),
    "peer": ("It is reachable only through peer dependencies",
             "It arrives only as a peer dependency, so the host project decides its version"),
    "dev": ("It is reachable only through devDependencies, so it is not installed in production "
            "builds",
            "Only devDependencies pull it in, so production installs leave it out"),
}
REACH_WHY = {
    "Strong evidence": ("Your source imports {name} directly.",
                        "Project code imports {name} itself."),
    "Possible": ("A package your code imports pulls in {name}.",
                 "Your code imports a parent of {name}, not {name} itself."),
    "Not observed": ("No import of {name} or its parents was found in project source, which lowers "
                     "urgency.",
                     "Static analysis found no import path from your code to {name}."),
}
REACH_UNCERTAINTY = {
    "Strong evidence": "The package is imported directly, but whether the vulnerable code path "
                       "runs is not determined.",
    "Possible": "A parent package is imported; whether it exercises the vulnerable code is not "
                "determined.",
    "Not observed": "No import was found in project source, but static analysis can miss "
                    "dynamic usage.",
    "Unknown": "Reachability not determined — static import analysis can miss dynamic usage.",
}
EXPLOIT_UNKNOWN = {
    "unknown": "The advisory has no CVE id, so exploitation data is unknown.",
    "unavailable": "CISA KEV and EPSS could not be reached, so exploitation status is unknown.",
    "off": "Exploit signals were not checked (local-only mode or EXPLOIT_SIGNALS=off).",
}
SUMMARY = ("{pkg} matches advisory {id}: {summary}.",
           "{id} applies to the installed {pkg}: {summary}.",
           "The installed {pkg} falls inside the affected range of {id}: {summary}.")
WHERE_DIRECT = ("Severity is {sev}{score} and {name} is a direct dependency.",
                "It is rated {sev}{score}, and you depend on {name} directly.")
WHERE_TRANSITIVE = ("Severity is {sev}{score} and the package is a transitive dependency at "
                    "depth {depth}, pulled in via {path}.",
                    "It is rated {sev}{score}; {name} arrives transitively (depth {depth}) "
                    "via {path}.",
                    "Rated {sev}{score}, it is not a direct dependency: the path is {path}.")
WHERE_UNKNOWN = ("Severity is {sev}{score}; the lockfile does not record how {name} is reached.",)
FIX_DIRECT = ("Upgrade {name} to {target} or later and re-run your tests.",
              "Raise {name} to {target} or newer, then run your test suite.")
FIX_TRANSITIVE = ("Move {name} to {target} or later, by upgrading the parent that pins it or "
                  "adding an override, then re-run your tests.",
                  "Get {name} to {target} or newer, preferably by upgrading the parent that "
                  "pulls it in (or with an override), then run your tests.")
NO_FIX = ("No fixed version is published for the affected range; consider replacing the "
          "dependency or limiting how it is used.",
          "There is no fixed release for this range yet; replacing {name} or reducing how it is "
          "used are the options.")


def variant(ctx: dict, family: str, options: tuple[str, ...]) -> str:
    h = hashlib.sha256(f"{ctx.get('finding_id', '')}|{family}".encode()).digest()
    return options[h[0] % len(options)]


def ordinal(n: int) -> str:
    suffix = "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def eid(ctx: dict, kind: str) -> str:
    return next((e["eid"] for e in ctx["evidence"] if e["kind"] == kind), "")


def cite(ctx: dict, kind: str) -> str:
    e = eid(ctx, kind)
    return f" [{e}]" if e else ""


def exploit_line(ctx: dict) -> str:
    x = ctx.get("exploit")
    if not x:
        return ""
    if x["status"] == "listed":
        return (f" It is in the CISA Known Exploited Vulnerabilities catalog since "
                f"{x['kev_date_added']}." + cite(ctx, "exploit"))
    if x["status"] == "scored":
        return (f" EPSS, a model estimate, puts it at the "
                f"{ordinal(int(x['epss_percentile'] * 100))} percentile for exploitation in the "
                "next 30 days." + cite(ctx, "exploit"))
    return ""


def weakness_line(ctx: dict) -> str:
    w = ctx.get("weakness")
    if not w or not w.get("impact"):
        return ""
    return f" As {w['id']} ({w['short']}), the usual impact is: {w['impact']}" + cite(
        ctx, "weakness")


def render_malicious(ctx: dict) -> dict:
    name = ctx["package"]["name"]
    pkg = f"{name}@{ctx['package']['version']}"
    e1 = cite(ctx, "advisory")
    return coerce({
        "summary": f"OSV lists {pkg} as a malicious package ({ctx['advisory']['id']})." + e1,
        "why_it_matters": "A malicious package can run code on every machine that installs or "
                          "imports it, so the risk is the package itself, not one bug in it." + e1,
        "recommended_action": f"Remove {name} from the project, reinstall from a cleaned "
                              "lockfile, and rotate secrets on machines where it was installed.",
        "tradeoffs": [],
        "uncertainties": ["Which machines or CI runners installed it is not known to DepGuard."],
        "citations": [eid(ctx, "advisory")] if eid(ctx, "advisory") else [],
    })


def render(ctx: dict) -> dict:
    if ctx.get("malicious"):
        return render_malicious(ctx)
    name = ctx["package"]["name"]
    pkg = f"{name}@{ctx['package']['version']}"
    adv = ctx["advisory"]
    sev = adv["severity"]
    facts = {"name": name, "pkg": pkg, "id": adv["id"], "summary": adv["summary"].rstrip("."),
             "sev": sev["label"], "depth": ctx["depth"],
             "score": f" ({sev['score']:.1f})" if sev.get("score") is not None else "",
             "path": ctx["paths"][0] if ctx["paths"] else ""}
    if ctx["direct"]:
        where = variant(ctx, "where", WHERE_DIRECT)
    elif ctx["depth"] is not None and ctx["paths"]:
        where = variant(ctx, "where", WHERE_TRANSITIVE)
    else:
        where = variant(ctx, "where", WHERE_UNKNOWN)
    why = where.format(**facts) + cite(ctx, "path")
    why += " " + variant(ctx, "scope", SCOPE_WHY[ctx["scope"]]) + "." + cite(ctx, "scope")
    reach = REACH_WHY.get(ctx["reachability"])
    if reach:
        why += " " + variant(ctx, "reach", reach).format(**facts) + cite(ctx, "reachability")
    if ctx["path_count"] >= 3:
        why += (f" It is reachable through {ctx['path_count']} dependency paths, so one parent "
                "upgrade may not remove every copy." + cite(ctx, "path"))
    why += weakness_line(ctx) + exploit_line(ctx)

    fixes = ctx["fix_versions"]
    if fixes:
        facts["target"] = fixes[0]
        family = FIX_DIRECT if ctx["direct"] else FIX_TRANSITIVE
        action = variant(ctx, "fix", family).format(**facts) + cite(ctx, "fix")
    else:
        action = variant(ctx, "fix", NO_FIX).format(**facts) + cite(ctx, "fix")
        w = ctx.get("weakness")
        if w and w.get("mitigation"):
            action += f" General guidance for {w['id']}: {w['mitigation']}" + cite(ctx, "weakness")

    tradeoffs = []
    if fixes and not ctx["direct"]:
        tradeoffs.append("An override is the smallest change but bypasses the parent's declared "
                         "range; upgrading the parent is cleaner but may be a larger jump.")
    if fixes:
        tradeoffs.append("Any upgrade can change behaviour; run the test suite before shipping.")
    if ctx["scope"] == "dev":
        tradeoffs.append("Because it is dev-only, deferring the fix carries less production risk.")
    uncertainties = [REACH_UNCERTAINTY.get(ctx["reachability"], REACH_UNCERTAINTY["Unknown"])
                     + cite(ctx, "reachability")]
    if sev["label"] == "unknown":
        uncertainties.append("The advisory has no severity score, so impact is unclear.")
    x = ctx.get("exploit")
    if x and x["status"] in EXPLOIT_UNKNOWN:
        uncertainties.append(EXPLOIT_UNKNOWN[x["status"]] + cite(ctx, "exploit"))
    w = ctx.get("weakness")
    if w and w.get("matters_when"):
        uncertainties.append(f"This matters most when {w['matters_when'][0].lower()}"
                             f"{w['matters_when'][1:]}" + cite(ctx, "weakness"))
    out = {
        "summary": variant(ctx, "summary", SUMMARY).format(**facts) + cite(ctx, "advisory"),
        "why_it_matters": why,
        "recommended_action": action,
        "tradeoffs": tradeoffs,
        "uncertainties": uncertainties,
    }
    text = " ".join([out["summary"], why, action, *uncertainties])
    out["citations"] = sorted({e["eid"] for e in ctx["evidence"] if f"[{e['eid']}]" in text},
                              key=lambda x: int(x[1:]))
    return coerce(out)
