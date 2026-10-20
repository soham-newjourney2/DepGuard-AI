from app.ai.base import coerce

SCOPE_WHY = {
    "prod": "It is reachable through production dependencies, so it ships with the app",
    "optional": "It is reachable only through optional dependencies, so it is installed only on "
                "some platforms",
    "peer": "It is reachable only through peer dependencies",
    "dev": "It is reachable only through devDependencies, so it is not installed in production "
           "builds",
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


def eid(ctx: dict, kind: str) -> str:
    return next((e["eid"] for e in ctx["evidence"] if e["kind"] == kind), "")


def cite(ctx: dict, kind: str) -> str:
    e = eid(ctx, kind)
    return f" [{e}]" if e else ""


class TemplateProvider:
    """Deterministic explanation built only from context fields; the demo never needs an API key."""

    name = "template"
    model = None

    async def explain(self, context: dict) -> dict:
        return render(context)


def render(ctx: dict) -> dict:
    pkg = f"{ctx['package']['name']}@{ctx['package']['version']}"
    adv = ctx["advisory"]
    sev = adv["severity"]
    score = f" ({sev['score']:.1f})" if sev.get("score") is not None else ""
    where = "a direct dependency" if ctx["direct"] else (
        f"a transitive dependency at depth {ctx['depth']}" if ctx["depth"] is not None
        else "a package not reachable from the root")
    via = f", pulled in via {ctx['paths'][0]}" if ctx["paths"] and not ctx["direct"] else ""
    fixes = ctx["fix_versions"]
    if fixes:
        target = fixes[0]
        if ctx["direct"]:
            action = f"Upgrade {ctx['package']['name']} to {target} or later and re-run your tests."
        else:
            action = (f"Move {ctx['package']['name']} to {target} or later, by upgrading the "
                      "parent that pins it or adding an override, then re-run your tests.")
        action += cite(ctx, "fix")
    else:
        action = ("No fixed version is published for the affected range; consider replacing the "
                  "dependency or limiting how it is used." + cite(ctx, "fix"))
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
    citations = sorted({e["eid"] for e in ctx["evidence"]
                        if e["kind"] in ("advisory", "path", "scope", "fix", "reachability")},
                       key=lambda x: int(x[1:]))
    return coerce({
        "summary": f"{pkg} matches advisory {adv['id']}: {adv['summary'].rstrip('.')}."
                   + cite(ctx, "advisory"),
        "why_it_matters": f"Severity is {sev['label']}{score} and the package is {where}{via}."
                          + cite(ctx, "path") + f" {SCOPE_WHY[ctx['scope']]}."
                          + cite(ctx, "scope"),
        "recommended_action": action,
        "tradeoffs": tradeoffs,
        "uncertainties": uncertainties,
        "citations": citations,
    })
