# DepGuard AI

Most dependency scanners hand you a long list of CVEs and leave the rest to you. Which ones actually affect your app? How did that package even get into your project? What's the smallest change that fixes it, and will that change break anything?

DepGuard tries to answer those questions. You give it a project, a GitHub link or a live website. It shows every vulnerable dependency, the exact path from your code to it, and how urgent it really is. Then it proposes the smallest fix it can justify. For npm projects it can apply that fix in a throwaway Docker container, run your tests and rescan, so you know it worked before you touch your own code.

It works with npm, Python, Go, Rust, PHP, Ruby, .NET and Gradle lockfiles, and it can check a public website for outdated JavaScript libraries.

A finding means an installed version falls inside a published advisory's range. That's a strong reason to look, but it isn't proof your app is exploitable, and DepGuard says so in every report.

## Try it in two minutes

You need Python 3.11 or newer. Docker is optional.

```bash
python tasks.py setup    # creates .venv, installs dependencies and Playwright's Chromium
python tasks.py dev      # starts the app at http://localhost:8000
```

Open the app and click **Try the demo project**. It scans a small Express app with 22 known advisories, and works offline because the advisory data is recorded in the repo. There are also a **Messy demo** (73 issues) and a **Python demo** (a Flask app with 38).

To scan your own work, drop a zip of your project on the page, or paste a GitHub link or a website address into the box below it.

## How a scan works

1. **Upload or link.** Zips are checked for size, zip bombs and path tricks before anything is extracted. DepGuard then searches the folders for lockfiles. If it finds several projects (say a `backend/` and a `frontend/`), it scans the most likely one and lets you switch to the others with one click.
2. **Build the dependency graph.** The lockfile becomes a graph, so every vulnerable package comes with the chain that pulls it in, such as `your app → express → body-parser → qs`.
3. **Check advisories.** Every installed version is checked against [OSV](https://osv.dev), which covers GitHub advisories, CVEs and the ecosystems' own databases.
4. **Rank by real risk.** Each finding gets a score from severity, whether it ships to production, whether a fix exists, how deep it sits and whether your code imports it. Every point in the score links to the evidence behind it.
5. **Explain.** With an Anthropic API key, Claude writes a short plain-English explanation. It sees only the evidence, never your source code, and anything it says that isn't backed by that evidence is removed. Without a key, a template does the job.
6. **Fix.** For npm, DepGuard compares upgrading the package directly, upgrading the parent that pulls it in, or pinning it with an override, and picks the smallest change. For other ecosystems you get the lowest safe version, the command to run (`pip install`, `go get`, `cargo update` and so on) and a diff where the version lives in a plain file. If nothing safe exists, it tells you instead of guessing.
7. **Verify (npm).** Only after you approve: the change is applied to a copy, dependencies are installed with scripts disabled, your tests run with no network access, and the project is scanned again.
8. **Report.** You see what was resolved, what's still there and what's new, with downloads as JSON, Markdown, HTML, a `.patch` file or a CycloneDX SBOM.

## What it can read

| Ecosystem | Files it understands |
|---|---|
| Node.js | `package-lock.json` (v2 and v3) |
| Python | `uv.lock`, `poetry.lock`, `Pipfile.lock`, pinned `requirements*.txt` (including pip-compile output) |
| Go | `go.mod` |
| Rust | `Cargo.lock` |
| PHP | `composer.lock` |
| Ruby | `Gemfile.lock` |
| .NET | `packages.lock.json` |
| Java | `gradle.lockfile` |
| Websites | `<script>` tags pointing at CDNs (cdnjs, jsDelivr, unpkg, Google, code.jquery.com, bootstrapcdn), versioned file names, and license banners inside the scripts |

If a project has a manifest but no lockfile (just `pyproject.toml`, or a `requirements.txt` without pinned versions), DepGuard tells you which command creates one. It never guesses versions.

GitHub links can point at a repo, a branch, a folder (`/tree/main/server`), a file, a commit or a release tag. `owner/repo@ref` works too.

## Keeping untrusted code at arm's length

DepGuard is built to look at code you don't trust, so the server never runs anything from an upload. Lockfiles are read as plain data. Only the disposable worker container installs packages or runs tests, with no extra privileges, a read-only filesystem and no network during tests.

Website scans read the page as text and never execute its JavaScript. They refuse to reach private or internal addresses, even through redirects or DNS tricks.

Everything about a scan is deleted after an hour, or right away if you delete the job.

The full details are in [docs/SECURITY.md](docs/SECURITY.md).

## Configuration

Copy `.env.example` to `.env` and change what you need. The settings you're most likely to touch:

| Setting | Default | What it does |
|---|---|---|
| `ANTHROPIC_API_KEY` | empty | Turns on Claude explanations |
| `VERIFY_MODE` | `auto` | `docker` for real isolation, `off` to disable verification |
| `LOCAL_ONLY` | `false` | Only advisory lookups leave your machine: no AI, no GitHub imports, no website scans |
| `MAX_UPLOAD_MB` | `15` | Largest zip accepted |
| `JOB_TTL_MIN` | `60` | Minutes before a scan and its files are deleted |

The rest are listed in `.env.example`.

To verify fixes for your own uploads, build the worker image once:

```bash
docker build -t depguard-worker worker
```

## Project layout

```
backend/app/
  intake.py, github.py   safe zip handling, project discovery, GitHub links
  lockfile.py, graph.py  npm lockfile parsing and the dependency graph
  stacks/                lockfile readers for Python, Go, Rust, PHP, Ruby, .NET and Gradle
  web/                   website fetching and library detection
  scanner/               OSV lookups, caching, recorded data for demos
  prioritize.py, evidence.py, reachability.py   scoring and the evidence behind it
  ai/                    explanation prompts and the fact-checking validator
  remediation/           fix planning and patch generation
  verify/                runs the worker container
  report/                before/after comparison, exports, SBOM
frontend/                the web UI (plain JavaScript modules, no build step)
worker/                  Dockerfile and entrypoint for the verification sandbox
samples/                 demo projects and recorded advisory data
docs/                    security notes, demo script, project walkthrough
```

## Working on it

```bash
python tasks.py check     # lint plus the unit and API tests
python tasks.py e2e       # browser tests with Playwright
python tasks.py docker    # build the worker image and run the Docker tests
python tasks.py record    # refresh the recorded demo data from OSV (needs internet)
python tasks.py rehearse  # run the full demo offline and time each step
```

In the app, `Ctrl/⌘ K` opens a command palette and `?` lists the keyboard shortcuts.

## Known limits

- Import detection looks at the code as written. Dynamic imports and code paths inside packages aren't traced, and PHP, .NET and Java imports aren't analysed yet.
- Sandbox verification only exists for npm. For other ecosystems you get the command and diff, and should run your own tests.
- Some lockfiles (`go.mod`, `Pipfile.lock`, `gradle.lockfile`, `pip freeze` output) don't record which package depends on which, so those findings show the package without a path.
- A website scan sees one page. Libraries bundled into minified app code without a version banner, loaded after the page runs, or behind a login won't show up.
- Passing tests are good evidence, but they don't guarantee there are no regressions.

## More reading

- [docs/walkthrough.html](docs/walkthrough.html): a step-by-step tour of the whole system, plus ideas for what to build next
- [docs/demo.md](docs/demo.md): a five-minute demo script and offline rehearsal checklist
- [docs/SECURITY.md](docs/SECURITY.md): the security model in detail
