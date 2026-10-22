# Project structure

DepGuard AI is a student hackathon project. This page is a map of the repository for teammates and anyone curious: what lives where, how a scan moves through the code, and where to look when you want to change something. For what the project does, see [walkthrough.md](walkthrough.md).

## Top level

```
backend/        the API server and all scanning logic (Python, FastAPI)
frontend/       the web interface (plain HTML, CSS and JavaScript, no build step)
samples/        demo projects and their independent answer keys
tools/          maintainer scripts that live outside the server
docs/           this file and the walkthrough
tasks.py        one entry point for every command
README.md       quick start
pyproject.toml  test and lint settings
requirements.txt / requirements-dev.txt   runtime and development dependencies
.env.example    every setting, with its default
```

Two folders are created at runtime and never committed: `.venv/` (the Python environment made by `tasks.py setup`) and `data/` (scan jobs, which are deleted after an hour, plus a 24-hour cache of OSV and registry answers).

## Commands

Everything goes through `tasks.py`, so the same commands work on Windows, macOS and Linux:

| Command | What it does |
|---|---|
| `python tasks.py setup` | Create `.venv`, install dependencies and the test browser |
| `python tasks.py dev` | Run the app at http://localhost:8000, reloading on changes |
| `python tasks.py demo` | Run the app the way you'd present it |
| `python tasks.py check` | Lint the code and run the unit and API tests |
| `python tasks.py e2e` | Run the browser tests |
| `python tasks.py doctor` | Check this machine is ready for the demo |
| `python tasks.py rehearse` | Run the whole live demo once and time each step |
| `python tasks.py answers` | Rebuild the demo answer keys with npm audit and pip-audit |
| `python tasks.py record` | Refresh the recorded data the tests replay (needs internet) |

## How a scan moves through the code

When you upload a zip, the request travels roughly like this:

1. `routes/jobs.py` accepts the upload (or a GitHub link, via `github.py`) and creates a job in `jobs.py`.
2. `pipeline.py` runs the steps in order and streams progress to the browser.
3. `intake.py` checks and extracts the zip and finds the project inside.
4. `lockfile.py` and `graph.py` read an npm lockfile into a dependency graph; every other format is read by a module in `stacks/`. For lockfiles without dependency edges, `flatedges.py` fills in the paths.
5. `scanner/` asks OSV about every package, and `scanner/normalize.py` turns the answers into findings.
6. `reachability.py` checks your source for imports, `exploit.py` adds the CISA KEV and EPSS signals, `evidence.py` writes the evidence items, and `prioritize.py` scores each finding.
7. `risks/` runs the supply-chain checks, and `policy.py` applies the project's pass/fail policy.

Everything after that happens on request. When you open a finding, `ai/` writes the explanation. When you ask for a fix, `remediation/` plans it. When you approve, `verify/` proves it (bundled demos only). And `report/` builds the before/after report, the exports, the SBOM and the answer-key comparison.

## backend/app

```
main.py            builds the FastAPI app, security headers and static files
config.py          every setting, read from the environment or .env
pipeline.py        the scan steps, in order
jobs.py, db.py     job storage (SQLite), states, and live progress events
intake.py          safe zip extraction and project discovery
github.py          GitHub link parsing and archive download
security.py        security headers, rate limiting, request size limits, secret masking
errors.py          the JSON error format and error codes

lockfile.py        npm package-lock.json reader
graph.py           the dependency graph: paths, depth, scope
stacks/            lockfile readers for Yarn, pnpm, Python, Go, Rust, PHP, Ruby, .NET and Gradle
flatedges.py       dependency paths for lockfiles that don't record them
samples.py         load a project's graph and package list
versions.py        version ordering for each ecosystem

scanner/           OSV lookups (API or the osv-scanner tool), caching, recorded replay for tests
reachability.py    import detection in project source
exploit.py         CISA KEV and FIRST EPSS signals
evidence.py        the evidence items E1 to E8
prioritize.py      the priority score and bands
policy.py          depguard.policy.json: when a scan should count as failed
cwe.py             plain-language weakness lookups
data/              cwe.json and the popular-package lists used for typosquat checks

risks/             supply-chain checks: malware, integrity, typosquat, secrets
ai/                explanations: context building, the decision-tree templates, advisory quotes, the fact check
remediation/       fix planning: npm planner, batch plan, other ecosystems, patch writing, registry lookups
verify/            proving a fix on a bundled demo: the fixed command list and the runner
report/            before/after comparison, answer keys, JSON/Markdown/HTML export, CycloneDX SBOM
routes/            the HTTP API: jobs, findings, graph, risks, verification, reports
```

## frontend

```
index.html         the single page
css/               design tokens, base styles, layout, components and views
js/main.js         starts the app, the navigation rail and the routes
js/views/          one file per screen: landing, scan progress, findings, graph, fix, plan,
                   verification, report, answer key, supply chain
js/components/     reusable pieces: drawer, modal, diff viewer, terminal, gauge, toast, command palette
js/dom.js          builds HTML elements safely (no innerHTML with outside text)
vendor/            d3, used only for the dependency graph
assets/            fonts, icon and background texture
```

There's no bundler or framework. The browser loads the ES modules directly, which keeps the app easy to read and audit.

## samples

```
vuln-demo/         small Express app with known advisories (the main demo, can be verified)
clean-demo/        a project with nothing to report
messy-demo/        a larger, messier npm project (can be verified)
python-demo/       a Flask app with a pip-compile requirements.txt
supplychain-demo/  scan-only project with planted supply-chain problems (never installed)
_answers/          one answer key per demo, built with independent tools
```

The demo folders are compared file by file before any verification runs, so they must stay exactly as committed. Their manifests (`package.json`, `package-lock.json`, `requirements.txt` and so on) are stored with a `.sample` suffix, so GitHub doesn't raise dependency alerts for projects that are vulnerable on purpose. DepGuard puts the real names back whenever it scans or verifies a demo, and the lockfiles under `backend/tests/fixtures/` follow the same rule.

## backend/tests

```
test_*.py          unit and API tests, one file per area (intake, graph, scanner, priority, ...)
e2e/               browser tests with Playwright
fixtures/          test inputs: hostile and valid zips, lockfiles for every format, and
                   recorded OSV, npm, KEV/EPSS and dependency data so tests run offline
```

`python tasks.py check` runs the unit and API tests without a network. `python tasks.py e2e` starts the app and drives a real browser through every screen.

## tools

```
answers.py   builds the demo answer keys with npm audit and pip-audit, never with DepGuard
record.py    refreshes the recorded test data from live sources
rehearse.py  runs the full live demo and prints timings and a checklist
doctor.py    checks Python, Node, the test browser, a writable data folder and network access
```

These stay outside `backend/app` on purpose: they call external tools and the network in ways the server itself never does.

## Where to change things

- **A new lockfile format:** add a reader in `backend/app/stacks/` and register it in `stacks/__init__.py`.
- **How urgency is scored:** `backend/app/prioritize.py`.
- **Explanation wording:** `backend/app/ai/template_provider.py`; weakness notes live in `backend/app/data/cwe.json`.
- **A new supply-chain check:** a module in `backend/app/risks/`, added to the list at the bottom of `risks/__init__.py`.
- **A new screen:** a file in `frontend/js/views/` and a route in `frontend/js/main.js`.
- **Settings:** `backend/app/config.py`, with the matching line in `.env.example`.
