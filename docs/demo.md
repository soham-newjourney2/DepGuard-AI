# Demo runbook

A five-minute walkthrough that works with the network off. Everything it needs ships in the repo: the pinned `samples/vuln-demo` lockfile, recorded OSV advisories (`samples/_recorded/osv`), recorded npm metadata (`samples/_recorded/npm`) and the deterministic template explainer.

## Before the demo

```
python tasks.py setup
python tasks.py rehearse --warm   # online once: fills the local npm cache used by demo-local
python tasks.py rehearse          # offline: OSV, npm registry and npm installs all cut off
python tasks.py dev               # or: python tasks.py demo
```

`rehearse` drives the full flow through the API with OSV and the registry pointed at a dead host and npm forced into `--offline`, then prints step timings and the checklist below. Any unticked item exits non-zero.

## Script

| Time | Beat | What to show |
|---|---|---|
| 0:00 | Problem | Landing constellation: a vulnerable leaf ignites and its path to the project lights up. |
| 0:40 | Upload | *Try the demo project*. The scan rail shows real timestamps; offline it is labelled “Cached scan from … — live scanner unavailable.” |
| 1:30 | Evidence | Findings → `qs@6.7.0` · GHSA-hrpp-h998-j3pp. Paths via express and body-parser, E1–E6, priority breakdown, grounded explanation with citation chips. |
| 2:15 | Fix | *Propose a fix* → parent bump of express, GitHub-style diff, warnings. *Approve & verify* lists exactly what will run. |
| 3:15 | Proof | Verification terminal: resolve → test → rescan, exit-code chips. |
| 4:20 | Report | VERIFIED seal, Resolved vs Still present, test result reported separately, downloads (JSON, Markdown, HTML, .patch, SBOM). |
| backup | Honesty | `request@2.88.2` → “No safe upgrade”: no invented replacement, only real options. |
| extra | Any stack | *Python demo*: 38 findings in a Flask app from a pip-compile `requirements.txt`; `pyyaml` shows a real `requirements.txt` diff plus `pip install` command, labelled “not verified”. |
| extra | Live site | Paste a public URL (chip shows “Website”): Fetch → Detect; findings cite the exact `<script>` line, the fix is an include diff. Needs network. |
| extra | GitHub link | Paste `github.com/<owner>/<repo>/tree/<branch>/<folder>`: the folder becomes the analysed project. Needs network. |

Keyboard: `Ctrl/⌘ K` opens the command palette (jump to findings, graph, report, plan all fixes); `?` shows shortcuts.

## Checklist

- [x] Pinned lockfile (lockfileVersion 3, every entry has version + integrity)
- [x] Findings match `samples/_recorded/vuln-demo.expected.json`
- [x] Cached scan is labelled
- [x] Works offline (demo-local verification reaches VERIFIED)
- [x] Template explanation (no API key needed)
- [x] No-fix backup (`request`) present

## Last rehearsal (2026-10-20, offline, Windows laptop)

| Step | API time | Budget |
|---|---|---|
| Scan to ready | 8.0 s | 40 s |
| Evidence + explanation | 0.1 s | 45 s |
| Fix proposal | 12.4 s | 45 s |
| Verification (demo-local) | 20.7 s | 65 s |
| Report + HTML export | 0.1 s | 40 s |

Offline scan and planning times are dominated by connection attempts to the unreachable services before falling back to recorded data; with Wi-Fi on they drop to a few seconds.
