# Walkthrough

This is a tour of DepGuard AI, a student hackathon project: what it does, how a scan works from start to finish, how to run the demo, and the safety rules it follows. For a map of the code itself, see [structure.md](structure.md).

## The idea

Most dependency scanners hand you a long list of CVEs and stop there. You're left asking which of them actually matter, how a package you've never heard of ended up in your project, and what the smallest safe change would be.

DepGuard tries to answer those questions for every vulnerable package it finds:

- **What** is wrong: the advisory that matches the installed version.
- **How** it got there: the exact chain of dependencies from your project to it.
- **How urgent** it is: a score you can read line by line, where every point points back to a piece of evidence.
- **What to do**: the smallest fix it can justify, and on the bundled demos, proof that the fix works.

A finding means an installed version falls inside an advisory's range. That's a good reason to look, but it isn't proof your app can be attacked, and DepGuard says so wherever it matters.

## Trying it

You need Python 3.11 or newer. Node.js 18+ is only needed for the verification step on the demos.

```
python tasks.py setup     # creates .venv and installs everything
python tasks.py doctor    # checks Python, Node, the browser for tests, and network access
python tasks.py dev       # starts the app at http://localhost:8000
```

The demos are scanned live, so you need an internet connection. Without one, the scan stops with "Could not connect to OSV" rather than showing old results.

To scan your own work, drop a zip of the project on the start page or paste a public GitHub link. Links can point at a repo, a branch, a folder, a file, a commit or a tag, and `owner/repo@ref` works too.

## The five-minute demo

1. **Start the scan.** Click *Try the demo project*. It's a small Express app with known problems. The progress rail shows each step with real timings.
2. **Check it against an answer key.** Click *Compare with answer key*. You'll see DepGuard's live result next to a list built independently with `npm audit`, marked matched, missed or extra. Extras explain themselves, for example "new since the answer key" or "not reported by the reference tool".
3. **Open a finding.** In the findings list, open `qs@6.7.0` (GHSA-hrpp-h998-j3pp). The drawer shows both paths it arrives by (through express and through body-parser), the priority breakdown, the evidence items, a plain-English explanation, the weakness behind it, and a sentence quoted straight from the advisory.
4. **Propose a fix.** DepGuard suggests upgrading express, the parent that pins qs, rather than forcing qs directly. You get a diff of `package.json` and a list of warnings, and the approval dialog shows exactly what will run.
5. **Watch it get proved.** Approve it. A terminal view shows the install (with scripts disabled), the test run and a fresh scan.
6. **Read the report.** You get a VERIFIED seal only if the target advisory is gone *and* the tests passed. The report separates what was resolved from what's still present, and downloads as JSON, Markdown, HTML, a `.patch` file or a CycloneDX SBOM.

Worth showing if there's time:

- **No safe upgrade.** `request@2.88.2` has no fixed version. DepGuard says so plainly instead of inventing a replacement.
- **Python demo.** A Flask app with a pip-compile `requirements.txt`, compared against a `pip-audit` answer key. Its fixes come as a real `requirements.txt` diff plus the `pip install` command, labelled "not verified".
- **Supply-chain demo.** A scan-only project with five problems planted on purpose: a real malicious package (`loadyaml@1.0.2`, already removed from npm), a git dependency, a missing hash, a look-alike of `express`, and a database password left in the code. The answer key lists all five, and the live scan finds them all.

Press `Ctrl/⌘ K` anywhere for the command palette and `?` for keyboard shortcuts.

Before presenting, run `python tasks.py rehearse`. It drives the whole demo through the API, times each step and ticks off a checklist. A full run usually takes 10 to 20 seconds.

## What happens during a scan

1. **Unpack safely.** The zip is checked before anything is extracted (size, file count, compression ratio, unsafe paths), then DepGuard finds the project inside it. If there are several, it asks which one.
2. **Read the lockfile.** It builds a graph of every installed package: who depends on whom, how deep each one sits, and whether it's a production, dev, optional or peer dependency. It understands npm, Yarn and pnpm, Python (uv, poetry, Pipfile, pinned requirements), Go, Rust, PHP, Ruby, .NET and Gradle.
3. **Fill in missing paths.** Some lockfiles (`requirements.txt` from pip freeze, `Pipfile.lock`, `go.mod`) don't say who depends on whom. DepGuard reads each locked package's declared dependencies from PyPI or the Go module proxy and connects packages that are already locked. It never adds a package. Offline, those findings simply have no path.
4. **Scan.** Every package goes to OSV, the open vulnerability database.
5. **Check whether you use it.** A static scan of your source looks for imports of each package or of the packages that pull it in.
6. **Check for real-world attacks.** CVE ids are looked up in CISA's Known Exploited Vulnerabilities list (attacks that have actually happened) and in FIRST's EPSS (a machine-learning estimate of how likely an attack is in the next 30 days).
7. **Rank.** Each finding gets a score and a band, from P1 (fix now) to P4 (monitor).
8. **Look for supply-chain trouble.** Four static checks run over the files: malware, lockfile tampering, typosquats and committed secrets.

## How urgency is decided

The score is just points added up, and the finding drawer shows every line with the evidence it came from:

| Signal | Points |
|---|---|
| Severity | critical 40, high 30, medium 18, low 8, unknown 15 (flagged) |
| Scope | production 20, optional or peer 8, dev 0 |
| A fix exists | 10 |
| Depth | direct 8, two levels or unknown 5, deeper 2 |
| You import it | directly 12, through a parent 6 |
| Many paths | 3 or more paths, 3 |
| Exploitation | in CISA KEV 15, EPSS 95th percentile or higher 8, 80th or higher 4 |
| Malicious package | 70, which always means P1 |

70 or more is P1, 50 to 69 is P2, 30 to 49 is P3, and anything lower is P4. Missing data never counts as safe: an unknown severity still scores, and unknown exploit data is flagged.

## Explanations without a language model

DepGuard doesn't use a chatbot or any paid API. Each explanation is written by a set of rules from the finding's own evidence: whether the package is direct or transitive, its scope, whether you import it, whether a fix exists, how many paths lead to it, what kind of weakness it is, and what's known about attacks. Every sentence cites the evidence it comes from, and the same finding always gets the same explanation.

Two extra pieces sit underneath:

- **A weakness card**, from a small hand-written guide to common weakness types (CWE), each linked to MITRE's page.
- **A quote from the advisory**: the one sentence that best describes the impact, copied word for word with a link to osv.dev. If no sentence fits, nothing is shown rather than a paraphrase.

As a safety net, every explanation is checked one more time. Any version number or advisory id that isn't in the evidence would be removed. In practice the rules never produce one, and the tests check that for every recorded finding.

## Fixes and proof

For npm projects DepGuard looks for the smallest change that clears the advisory: bump the package directly, bump the parent that pins it, or add an override. You get a real `package.json` diff. For Yarn, pnpm and every other ecosystem, you get the exact package-manager command, plus a diff wherever the version lives in a plain file. These are marked "not verified".

Verification only ever runs for the three bundled npm demos, and only after checking that every file still matches the copy shipped in the repo. It installs with scripts disabled, in a stripped environment, with a timeout on every step, then runs the tests and scans again. For anything else, DepGuard never offers the *Approve & verify* button, because it would only end in "Unable to verify".

## Supply-chain checks

These run on every scan and raise signals, not verdicts. Nothing is installed or run to produce them.

- **Malware.** Only an OSV `MAL-` record can make DepGuard call a package malicious. Such a package goes straight to P1, and the advice is to remove it and rotate secrets, never to upgrade.
- **Lockfile integrity.** Packages fetched over plain HTTP, from git or from a non-registry URL, and packages without a strong hash.
- **Typosquats.** Names one keystroke away from one of the 5,000 most-downloaded npm or PyPI packages. Popular names are never flagged.
- **Secrets.** Keys and tokens committed to the project. DepGuard keeps only the kind, the file and line, and a masked hint. The value itself is never stored, shown or exported.

You can make the project policy fail on these signals by adding `"fail_on_risks": "high"` to `depguard.policy.json`.

## Safety rules

Even as a hackathon project, DepGuard looks at code nobody trusts, so we set a few rules that never bend:

- **Nothing from an upload ever runs.** Lockfiles are read as data. The server never calls npm, node or any package manager for uploaded code; the only thing it ever installs is one of its own demos, after the file check described above.
- **Uploads are handled carefully.** Limits on size, file count and compression stop zip bombs. Absolute paths, `..`, drive letters, symlinks and reserved device names are rejected. YAML lockfiles are read with a safe loader, so they can't create objects.
- **The browser never treats data as code.** Advisory text, package names and file contents are always inserted as plain text. A strict content security policy blocks outside scripts, and the HTML report carries its own.
- **Approval is explicit.** Nothing changes until you confirm, and the dialog lists exactly what will run.
- **Secrets stay hidden.** Tokens and keys are masked in logs, reports and the API.

## What leaves your machine

DepGuard only talks to a fixed set of services, and never fetches a web address you give it:

- **OSV**, for scanning.
- **The npm registry**, for planning npm fixes.
- **PyPI and the Go module proxy**, only to read the dependencies of versions you already have locked, when the lockfile doesn't list them.
- **CISA and FIRST**, for the exploit signals (CVE ids only).
- **GitHub**, only when you import a repository.

With `LOCAL_ONLY=true`, only OSV lookups leave the machine. Scan results and uploaded files are deleted after an hour, or right away when you delete the job.

## Known limits

- Import detection reads code as written. Dynamic imports aren't traced, and PHP, .NET and Java imports aren't analysed.
- Gradle lockfiles don't record dependency paths, so Java findings show none.
- Only the bundled npm demos are verified end to end. For everything else, apply the change and run your own tests.
- OSV doesn't know about every vulnerability, so "no findings" is never proof a project is safe.
- Passing tests are good evidence, but they don't guarantee nothing else broke.
- It's a hackathon prototype built by students. It hasn't had a professional security review, so use it as a second opinion, not your only check.

## Found a problem?

We're students and this is our hackathon project, so there's no formal security process. If you spot a bug or a security issue, please tell one of us directly (see the team in the [README](../README.md#team)). We'd really appreciate it.
