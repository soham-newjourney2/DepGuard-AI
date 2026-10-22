import html
import json

from app import policy as policy_mod
from app.jobs import iso, utcnow
from app.report.compare import CLASSES, classify
from app.risks import counts as risk_counts
from app.verify.modes import NPM_FLAGS

TITLES = {"resolved": "Resolved", "still_present": "Still present",
          "newly_detected": "Newly detected", "unable_to_verify": "Unable to verify"}
SEALS = {
    "verified": ("verified", "VERIFIED"),
    "partial": ("partial", "Partially verified"),
    "failed": ("failed", "Verification failed"),
    "none": ("none", "Scan only"),
}
RISK_NOTE = ("Static signals, not verdicts. Only OSV MAL- records are called malicious; "
             "secret values are never stored or shown.")
LIMITS = [
    "Reachability not determined — static import analysis can miss dynamic usage.",
    "Findings are matched by advisory range against lockfile versions: presence, not proof of "
    "exploitability.",
    "OSV coverage is not complete; no findings is not proof the project is secure.",
    "Exploit signals: a CISA KEV listing is observed exploitation; EPSS is a model's estimate. "
    "Absence from KEV is not proof a vulnerability is not exploited.",
]


def commands() -> list[str]:
    flags = " ".join(NPM_FLAGS)
    return [f"npm install --package-lock-only {flags}", f"npm ci {flags}",
            "npm test --if-present"]


def seal(verification: dict | None) -> tuple[str, str]:
    if not verification:
        return SEALS["none"]
    status = verification.get("status")
    tests = verification.get("tests") or {}
    resolved = (verification.get("comparison") or {}).get("target_resolved")
    if status == "verified" and resolved and tests.get("present") and tests.get("exit_code") == 0:
        return SEALS["verified"]
    if status == "verify_failed":
        return SEALS["failed"]
    return SEALS["partial"]


def build(job: dict, findings: list[dict], proposal: dict | None, verification: dict | None,
          after: list[dict] | None, ai: dict, policy: dict | None = None,
          risks: list[dict] | None = None) -> dict:
    status = verification.get("status") if verification else None
    targeted = set((proposal or {}).get("resolves") or [])
    classes = classify(findings, after if status in ("verified", "verify_failed") else None,
                       status, targeted)
    kind, label = seal(verification)
    scan_before = job["summary"].get("scan") or {}
    tests = (verification or {}).get("tests") or {}
    limitations = list(LIMITS)
    limitations += (verification or {}).get("labels") or []
    if scan_before.get("source") == "cache":
        limitations.append(f"Cached scan from {scan_before.get('ts')} — live scanner unavailable.")
    if ai.get("provider") == "evidence-based":
        limitations.append("Explanations are evidence-based: decision-tree templates, a CWE "
                           "knowledge base and verbatim advisory quotes. No language model is "
                           "used.")
    return {
        "report_version": 1,
        "generated_at": iso(utcnow()),
        "project": {"job_id": job["id"], "filename": job["filename"], "source": job.get("source"),
                    "packages": job["summary"].get("packages"),
                    "lockfile_version": job["summary"].get("lockfile_version")},
        "seal": {"kind": kind, "label": label, "mode": (verification or {}).get("mode")},
        "counts": {"before": len(findings),
                   "after": len(after) if after is not None and status in ("verified",
                                                                           "verify_failed")
                   else None,
                   **{c: len(classes[c]) for c in CLASSES}},
        "classes": classes,
        "policy": policy_block(findings, after if status in ("verified", "verify_failed")
                               else None, policy, risks),
        "risks": None if risks is None else {"counts": risk_counts(risks), "items": risks},
        "tests": {"present": tests.get("present"), "exit_code": tests.get("exit_code"),
                  "status": next((s["status"] for s in (verification or {}).get("stages", [])
                                  if s["name"] == "test"), None)},
        "fix": None if not proposal else {
            k: proposal.get(k) for k in ("pid", "strategy", "title", "changes", "resolves",
                                         "warnings", "diff", "confidence", "status", "command")},
        "verification": None if not verification else {
            "status": status, "reason": verification.get("reason"),
            "mode": verification.get("mode"), "started": verification.get("started"),
            "finished": verification.get("finished"),
            "target_resolved": (verification.get("comparison") or {}).get("target_resolved"),
            "tree_delta": verification.get("tree_delta"),
        },
        "audit": {
            "scan_before": scan_before,
            "scan_after": (verification or {}).get("scan"),
            "commands": commands() if verification else [],
            "stages": [{k: s.get(k) for k in ("name", "status", "exit_code", "duration_ms",
                                               "started", "finished")}
                       for s in (verification or {}).get("stages", [])],
            "ai": ai,
            "limitations": limitations,
        },
    }


def policy_block(before: list[dict], after: list[dict] | None, policy: dict | None,
                 risks: list[dict] | None = None):
    if not policy:
        return None
    p, src = policy["policy"], policy["source"]
    b = policy_mod.evaluate(before, p, src, risks)
    a = policy_mod.evaluate(after, p, src, risks) if after is not None else None
    return {"policy": p, "source": src, "describe": policy_mod.describe(p),
            "before": {"status": b["status"], "count": b["count"]},
            "after": None if a is None else {"status": a["status"], "count": a["count"],
                                             "violations": a["violations"]}}


def where(r: dict) -> str:
    loc = r.get("location")
    if loc:
        return f"{loc['file']}:{loc['line']}" if loc.get("line") else loc["file"]
    return r.get("package") or ""


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def moved(i: dict) -> str:
    after = i.get("versions_after") or []
    if not after or i["version"] in after:
        return ""
    return f" (still matched at {', '.join(after)})"


def md_cell(value) -> str:
    text = "" if value is None else str(value)
    return (text.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`")
            .replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;"))


def to_markdown(r: dict) -> str:
    p, s = r["project"], r["seal"]
    out = [f"# DepGuard AI report — {md_cell(p['filename'])}", "",
           f"**{s['label']}**" + (f" · mode `{s['mode']}`" if s["mode"] else ""), "",
           f"- Job: `{p['job_id']}` · packages: {p['packages']} · "
           f"lockfile v{p['lockfile_version']}",
           f"- Generated: {r['generated_at']}",
           f"- Findings before: {r['counts']['before']} · after: "
           f"{r['counts']['after'] if r['counts']['after'] is not None else 'not rescanned'}", ""]
    if r["fix"]:
        f = r["fix"]
        out += [f"## Fix: {md_cell(f['title'])}", "",
                f"Strategy `{f['strategy']}` · confidence {f['confidence']} · status {f['status']}",
                ""]
        if f.get("command"):
            out += ["```sh", f["command"].replace("```", "ʼʼʼ"), "```", ""]
        if f["diff"]:
            out += ["```diff", f["diff"].rstrip("\n").replace("```", "ʼʼʼ"), "```", ""]
    if r.get("policy"):
        pol = r["policy"]
        after_txt = (f"{pol['after']['status'].upper()} ({pol['after']['count']})"
                     if pol["after"] else "not rescanned")
        out += ["## Policy", "", f"- {md_cell(pol['source'])}: {md_cell(pol['describe'])}",
                f"- Before: {pol['before']['status'].upper()} ({pol['before']['count']}) · "
                f"after: {after_txt}", ""]
    if r.get("risks") is not None:
        items = r["risks"]["items"]
        out += [f"## Supply-chain & hygiene ({len(items)})", "", f"_{RISK_NOTE}_", ""]
        if items:
            out += ["| Kind | Severity | Confidence | Signal | Where |", "|---|---|---|---|---|"]
            out += [f"| {md_cell(x['kind'])} | {md_cell(x['severity'])} | "
                    f"{md_cell(x['confidence'])} | {md_cell(x['title'])} | {md_cell(where(x))} |"
                    for x in items]
        else:
            out.append("_No supply-chain signals._")
        out.append("")
    t = r["tests"]
    out += ["## Tests (reported separately from the scan)", "",
            "- No verification ran." if t["exit_code"] is None and t["status"] is None else
            f"- Test stage: {t['status']} · exit {t['exit_code']} · test script present: "
            f"{t['present']}", ""]
    for c in CLASSES:
        items = r["classes"][c]
        out += [f"## {TITLES[c]} ({len(items)})", ""]
        if items:
            out += ["| Advisory | Package | Severity | Scope | Exploitation | Summary |",
                    "|---|---|---|---|---|---|"]
            for i in items:
                ver = i["version"] + moved(i)
                out.append(f"| {md_cell(i['advisory'])} | {md_cell(i['package'])}@{md_cell(ver)}"
                           f" | {md_cell(i['severity'])} | {md_cell(i['scope'])} | "
                           f"{md_cell(xlabel(i))} | {md_cell(i['summary'])} |")
        else:
            out.append("_None._")
        out.append("")
    a = r["audit"]
    out += ["## Audit trail", "",
            f"- Scan before: {md_cell(json.dumps(a['scan_before']))}",
            f"- Scan after: {md_cell(json.dumps(a['scan_after']))}",
            f"- AI: {md_cell(json.dumps(a['ai']))}"]
    out += [f"- Command: `{md_cell(cmd)}`" for cmd in a["commands"]]
    out += [f"- Stage {st['name']}: {st['status']} · exit {st['exit_code']} · "
            f"{st['duration_ms']} ms" for st in a["stages"]]
    out += ["", "## Limitations", ""] + [f"- {md_cell(x)}" for x in a["limitations"]]
    return "\n".join(out) + "\n"


CSS = """
:root{color-scheme:dark}
body{margin:0;background:#06080D;color:#EEF2F8;
font:15px/1.55 -apple-system,"Segoe UI",system-ui,sans-serif;font-variant-numeric:tabular-nums}
main{max-width:980px;margin:0 auto;padding:48px 24px 80px}
h1,h2{font-family:"Instrument Serif",Georgia,serif;font-style:italic;font-weight:400}
h1{font-size:40px;margin:8px 0}
h2{font-size:26px;margin:40px 0 12px}
.eyebrow,code,.mono{font-family:ui-monospace,Consolas,monospace;font-size:13px}
.eyebrow{color:#A7B0C0;text-transform:uppercase;letter-spacing:.08em}
.seal{display:inline-block;margin:16px 0;padding:10px 18px;border:2px solid currentColor;
border-radius:10px;font:600 22px/1 ui-monospace,Consolas,monospace;letter-spacing:.12em;
transform:rotate(-2deg)}
.seal.verified{color:#C8FF4D}
.seal.partial{color:#FFC94D}
.seal.failed{color:#FF3B5C}
.seal.none{color:#A7B0C0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.kpi{padding:14px 16px;border:1px solid rgba(255,255,255,.1);border-radius:12px;
background:#0B0F17}
.kpi b{display:block;font-size:30px;font-weight:500}
.kpi span{color:#A7B0C0;font-size:12px;text-transform:uppercase}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:8px 10px;border-bottom:1px solid rgba(255,255,255,.07);text-align:left;
vertical-align:top}
th{color:#A7B0C0;font-weight:500}
.sev-critical{color:#FF3B5C}
.sev-high{color:#FF8A3D}
.sev-medium{color:#FFC94D}
.sev-low{color:#5CC8FF}
.sev-unknown{color:#8A93A6}
pre{overflow:auto;padding:14px;border-radius:10px;background:#0B0F17;
border:1px solid rgba(255,255,255,.1);font:12px/1.6 ui-monospace,Consolas,monospace}
.add{color:#C8FF4D}
.del{color:#FF6B81}
.muted{color:#A7B0C0}
ul{padding-left:20px}
.resolved h2{color:#C8FF4D}
.newly_detected h2{color:#FF6B81}
.unable_to_verify h2{color:#FFC94D}
"""


def e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def xlabel(i: dict) -> str:
    x = i.get("exploit")
    return x["label"] if x else "—"


def table(items: list[dict]) -> str:
    if not items:
        return '<p class="muted">None.</p>'
    rows = []
    for i in items:
        ver = e(i["version"] + moved(i))
        e7 = e((i.get("exploit") or {}).get("evidence"))
        rows.append(f"<tr><td><code>{e(i['advisory'])}</code></td><td><code>{e(i['package'])}"
                    f"@{ver}</code></td><td class=\"sev-{e(i['severity'])}\">{e(i['severity'])}"
                    f"</td><td>{e(i['scope'])}</td><td title=\"{e7}\">"
                    f"{e(xlabel(i))}</td><td>{e(i['summary'])}</td></tr>")
    return ("<table><thead><tr><th>Advisory</th><th>Package</th><th>Severity</th><th>Scope</th>"
            "<th>Exploitation</th><th>Summary</th></tr></thead><tbody>" + "".join(rows)
            + "</tbody></table>")


def diff_html(diff: str) -> str:
    lines = []
    for line in diff.rstrip("\n").split("\n"):
        cls = "add" if line.startswith("+") and not line.startswith("+++") else \
            "del" if line.startswith("-") and not line.startswith("---") else ""
        lines.append(f'<span class="{cls}">{e(line)}</span>' if cls else e(line))
    return "<pre>" + "\n".join(lines) + "</pre>"


def to_html(r: dict) -> str:
    p, s, c, t, a = r["project"], r["seal"], r["counts"], r["tests"], r["audit"]
    parts = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        f"<title>DepGuard AI report — {e(p['filename'])}</title><style>{CSS}</style></head>"
        "<body><main>",
        f"<p class=\"eyebrow\">DepGuard AI · job {e(p['job_id'])} · {e(r['generated_at'])}</p>",
        f"<h1>{e(p['filename'])}</h1>",
        f"<div class=\"seal {e(s['kind'])}\">{e(s['label'])}</div>",
        "<div class=\"grid\">",
        f"<div class=\"kpi\"><b>{e(c['before'])}</b><span>Findings before</span></div>",
        f"<div class=\"kpi\"><b>{e(c['after'] if c['after'] is not None else '—')}</b>"
        "<span>Findings after</span></div>",
        f"<div class=\"kpi\"><b>{e(c['resolved'])}</b><span>Resolved</span></div>",
        f"<div class=\"kpi\"><b>{e(c['newly_detected'])}</b><span>Newly detected</span></div>",
        "</div>",
    ]
    if r["fix"]:
        f = r["fix"]
        parts += [f"<h2>Fix: {e(f['title'])}</h2>",
                  f"<p class=\"muted\">Strategy {e(f['strategy'])} · confidence "
                  f"{e(f['confidence'])} · status {e(f['status'])}</p>"]
        if f.get("command"):
            parts.append(f"<pre class=\"cmd\"><code>{e(f['command'])}</code></pre>")
        if f.get("diff"):
            parts.append(diff_html(f["diff"]))
    test_line = ("No verification ran." if t["status"] is None else
                 f"Test stage {e(t['status'])}, exit {e(t['exit_code'])}; test script present: "
                 f"{e(t['present'])}.")
    if r.get("policy"):
        pol = r["policy"]
        after_txt = (f"{pol['after']['status'].upper()} ({pol['after']['count']})"
                     if pol["after"] else "not rescanned")
        parts += ["<h2>Policy</h2>", f"<p>{e(pol['source'])}: {e(pol['describe'])}. Before: "
                  f"{e(pol['before']['status'].upper())} ({e(pol['before']['count'])}) · after: "
                  f"{e(after_txt)}</p>"]
    if r.get("risks") is not None:
        items = r["risks"]["items"]
        rows = "".join(f"<tr><td>{e(x['kind'])}</td><td class=\"sev-{e(x['severity'])}\">"
                       f"{e(x['severity'])}</td><td>{e(x['confidence'])}</td><td>{e(x['title'])}"
                       f"</td><td><code>{e(where(x))}</code></td></tr>" for x in items)
        parts += [f"<h2>Supply-chain &amp; hygiene ({len(items)})</h2>",
                  f"<p class=\"muted\">{e(RISK_NOTE)}</p>",
                  "<table><thead><tr><th>Kind</th><th>Severity</th><th>Confidence</th>"
                  "<th>Signal</th><th>Where</th></tr></thead><tbody>" + rows + "</tbody></table>"
                  if items else "<p class=\"muted\">No supply-chain signals.</p>"]
    parts += ["<h2>Tests</h2>", f"<p>{test_line}</p>",
              "<p class=\"muted\">Reported separately from the scan result.</p>"]
    for cls in CLASSES:
        parts += [f"<section class=\"{cls}\"><h2>{TITLES[cls]} ({len(r['classes'][cls])})</h2>",
                  table(r["classes"][cls]), "</section>"]
    parts += ["<h2>Audit trail</h2><ul>",
              f"<li>Scan before: <code>{e(json.dumps(a['scan_before']))}</code></li>",
              f"<li>Scan after: <code>{e(json.dumps(a['scan_after']))}</code></li>",
              f"<li>AI: <code>{e(json.dumps(a['ai']))}</code></li>"]
    parts += [f"<li>Command: <code>{e(cmd)}</code></li>" for cmd in a["commands"]]
    parts += [f"<li>Stage {e(st['name'])}: {e(st['status'])} · exit {e(st['exit_code'])} · "
              f"{e(st['duration_ms'])} ms</li>" for st in a["stages"]]
    parts += ["</ul><h2>Limitations</h2><ul>"]
    parts += [f"<li>{e(x)}</li>" for x in a["limitations"]]
    parts += ["</ul></main></body></html>"]
    return "\n".join(parts) + "\n"
