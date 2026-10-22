# DepGuard AI

It's late, the release is tomorrow, and you run one last audit. Forty-seven vulnerabilities. A few are critical. Most are in packages you've never heard of, buried four levels deep. Which ones actually matter? How did they get in? And if you bump something, what breaks?

You can upgrade everything and hope for the best, or you can ship and hope nobody notices. We're three students, and we built DepGuard AI at a hackathon to see if there was a better way than hoping.

## What it does

Give it a project zip or a GitHub link. For every vulnerable dependency, DepGuard tells you:

- **What's wrong:** the advisory that matches the exact version you have installed.
- **How it got there:** the full chain, like `your app → express → body-parser → qs`.
- **How urgent it is:** a score you can read line by line. It looks at severity, whether the package ships to production, whether your code imports it, and whether attackers are actually using the flaw (CISA KEV and FIRST EPSS).
- **What to do:** the smallest fix it can justify. On the bundled demos it applies that fix to a copy, runs the tests and scans again, so you can watch the whole loop.

It also flags malicious packages, tampered lockfiles, look-alike package names and secrets committed to the code.

It reads npm, Yarn, pnpm, Python, Go, Rust, PHP, Ruby, .NET and Gradle lockfiles.

There's no chatbot and no paid API. Explanations are written from the evidence by fixed rules, so they never invent a version number or an advisory.

## Try it

You need Python 3.11+. Node.js 18+ is only needed to verify fixes on the demos.

```bash
python tasks.py setup    # create the environment and install everything
python tasks.py dev      # open http://localhost:8000
```

Click **Try the demo project** to scan a small Express app live against [OSV](https://osv.dev). Then open **Compare with answer key** to check DepGuard's results against a list built independently with `npm audit`. The start page also has a Python demo, a messy demo and a supply-chain demo with problems planted on purpose.

To scan your own project, drop its zip on the start page or paste a GitHub link.

Before a presentation, `python tasks.py doctor` checks your machine and `python tasks.py rehearse` runs the whole demo once.

## Safe by design

Even as a hackathon project, DepGuard has to look at code nobody trusts, so we were strict about it. It never runs anything from an upload: lockfiles are read as plain data. The only project it ever installs is one of its own demos, and only after it checks every file against the copy in the repo. Install scripts are turned off. Uploads are deleted after an hour.

A finding means your installed version falls inside an advisory's range. That's a good reason to look, but it isn't proof your app can be attacked, and DepGuard says so in every report.

DepGuard is a student project, not a commercial security product. It's great for learning and for a second opinion, but don't make it the only thing standing between your code and production.

## Learn more

- [Walkthrough](docs/walkthrough.md): how a scan works, the five-minute demo, scoring and the safety rules
- [Project structure](docs/structure.md): a map of the code and where to change things

## Team

<table>
  <tr>
    <td align="center" width="33%">
      <a href="https://github.com/soham-newjourney2">
        <img src="https://github.com/soham-newjourney2.png?size=200" width="110" alt="Soham Chowdhury">
      </a>
      <h3>Soham Chowdhury</h3>
      <sub><b>Team Lead</b> · AI · Backend support</sub><br>
      <a href="https://github.com/soham-newjourney2">@soham-newjourney2</a>
    </td>
    <td align="center" width="33%">
      <a href="https://github.com/Arkoprabho-Roy">
        <img src="https://github.com/Arkoprabho-Roy.png?size=200" width="110" alt="Arkoprabho Roy">
      </a>
      <h3>Arkoprabho Roy</h3>
      <sub>Backend</sub><br>
      <a href="https://github.com/Arkoprabho-Roy">@Arkoprabho-Roy</a>
    </td>
    <td align="center" width="33%">
      <a href="https://github.com/Saswata427">
        <img src="https://github.com/Saswata427.png?size=200" width="110" alt="Saswata Biswas">
      </a>
      <h3>Saswata Biswas</h3>
      <sub>UI · Testing</sub><br>
      <a href="https://github.com/Saswata427">@Saswata427</a>
    </td>
  </tr>
</table>
