"""Check this machine is ready for the demo; exits 1 if something required is missing."""

import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import httpx

from app.config import ROOT, Settings

TIMEOUT = 6
MIN_NODE = 18
PACKAGES = ("fastapi", "uvicorn", "httpx", "pydantic_settings", "semantic_version", "cvss",
            "packaging", "multipart")


@dataclass
class Result:
    name: str
    ok: bool
    detail: str
    required: bool = True

    def mark(self, unicode: bool = True) -> str:
        marks = ("✓", "!", "✗") if unicode else ("ok", "--", "XX")
        return marks[0] if self.ok else (marks[2] if self.required else marks[1])


def version_of(argv: list[str]) -> str | None:
    exe = shutil.which(argv[0])
    if exe is None:
        return None
    try:
        out = subprocess.run([exe, *argv[1:]], capture_output=True, text=True, timeout=15,
                             check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return (out.stdout or out.stderr).strip() or None


def check_python() -> Result:
    ok = sys.version_info >= (3, 11)
    return Result("Python", ok, f"{sys.version.split()[0]}" + ("" if ok else " (3.11+ needed)"))


def check_packages() -> Result:
    missing = [p for p in PACKAGES if importlib.util.find_spec(p) is None]
    return Result("Python packages", not missing,
                  "installed" if not missing else f"missing {', '.join(missing)} — run "
                                                  "`python tasks.py setup`")


def check_node() -> Result:
    v = version_of(["node", "--version"])
    m = re.match(r"v?(\d+)", v or "")
    ok = bool(m) and int(m.group(1)) >= MIN_NODE
    detail = (v if ok else f"{v or 'not found'} — Node.js {MIN_NODE}+ is needed to verify the "
              "demo (scanning works without it)")
    return Result("Node.js", ok, detail)


def check_npm() -> Result:
    v = version_of(["npm", "--version"])
    return Result("npm", v is not None, v or "not found — it ships with Node.js")


def check_playwright() -> Result:
    if importlib.util.find_spec("playwright") is None:
        return Result("Playwright Chromium", False, "not installed (only needed for e2e tests)",
                      required=False)
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            ok = Path(p.chromium.executable_path).exists()
    except Exception:
        ok = False
    return Result("Playwright Chromium", ok,
                  "installed" if ok else "missing — run `python -m playwright install chromium` "
                                         "(only needed for e2e tests)", required=False)


def check_data_dir(s: Settings) -> Result:
    try:
        s.data_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=s.data_dir):
            pass
    except OSError as exc:
        return Result("Data folder", False, f"{s.data_dir} is not writable ({exc})")
    return Result("Data folder", True, str(s.data_dir))


def endpoints(s: Settings) -> list[tuple[str, str, str, dict | None, bool]]:
    """(name, method, url, json body, required): every host the demo talks to."""
    return [
        ("OSV", "POST", f"{s.osv_api_url.rstrip('/')}/v1/query",
         {"package": {"name": "left-pad", "ecosystem": "npm"}, "version": "1.3.0"}, True),
        ("npm registry", "GET", f"{s.registry_url.rstrip('/')}/left-pad", None, True),
        ("CISA KEV", "HEAD", s.kev_url, None, False),
        ("FIRST EPSS", "GET", f"{s.epss_url}?cve=CVE-2021-44228", None, False),
        ("PyPI", "GET", "https://pypi.org/pypi/requests/json", None, False),
        ("GitHub codeload", "HEAD", s.github_codeload_url, None, False),
    ]


def check_network(s: Settings, client: httpx.Client) -> list[Result]:
    out = []
    for name, method, url, body, required in endpoints(s):
        try:
            r = client.request(method, url, json=body)
            ok = r.status_code < 500
            detail = f"reachable (HTTP {r.status_code})"
        except httpx.HTTPError as exc:
            ok, detail = False, f"unreachable ({exc.__class__.__name__})"
        if not ok:
            detail += (" — demos scan live and need it" if required
                       else " — the feature degrades gracefully")
        out.append(Result(name, ok, detail, required))
    return out


def run_checks(s: Settings, client: httpx.Client) -> list[Result]:
    return [check_python(), check_packages(), check_node(), check_npm(), check_playwright(),
            check_data_dir(s), *check_network(s, client)]


def main() -> int:
    s = Settings()
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False,
                      headers={"User-Agent": "DepGuard-AI doctor"}) as client:
        results = run_checks(s, client)
    width = max(len(r.name) for r in results)
    uni = "utf" in (sys.stdout.encoding or "").lower()
    print(f"DepGuard AI doctor - {ROOT}\n")
    for r in results:
        line = f"  {r.mark(uni)} {r.name:<{width}}  {r.detail}"
        print(line if uni else line.encode("ascii", "replace").decode())
    failed = [r for r in results if not r.ok and r.required]
    print("\nReady for the demo." if not failed else
          f"\n{len(failed)} required check(s) failed; fix them before presenting.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
