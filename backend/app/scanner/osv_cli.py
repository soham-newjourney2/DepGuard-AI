import asyncio
import json
import re
import shutil
from collections.abc import Awaitable, Callable
from pathlib import Path

from app.jobs import iso, utcnow
from app.scanner.base import ECOSYSTEM, Package, ScanError, ScanResult, build_result

Runner = Callable[[list[str], float], Awaitable[tuple[int, str, str]]]


async def run_process(args: list[str], timeout: float) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        proc.kill()
        raise ScanError("osv-scanner timed out") from None
    return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


class OsvCliScanner:
    """Runs the trusted osv-scanner binary on the lockfile; nothing from the upload executes."""

    name = "osv-cli"

    def __init__(self, binary: str | None = None, timeout_s: float = 60,
                 runner: Runner = run_process):
        self.binary = binary or shutil.which("osv-scanner") or ""
        self.timeout = timeout_s
        self.runner = runner

    @staticmethod
    def available() -> bool:
        return shutil.which("osv-scanner") is not None

    async def version(self) -> str:
        code, out, err = await self.runner([self.binary, "--version"], self.timeout)
        m = re.search(r"(\d+\.\d+\.\d+)", out + err)
        return m.group(1) if m else "unknown"

    async def scan(self, packages: list[Package], lockfile: Path | None = None) -> ScanResult:
        if not self.binary:
            raise ScanError("osv-scanner is not installed")
        if lockfile is None:
            raise ScanError("osv-scanner needs the lockfile path")
        started = iso(utcnow())
        version = await self.version()
        code, out, err = await self.runner(
            [self.binary, "--format", "json", "--lockfile", str(lockfile)], self.timeout)
        if code not in (0, 1):
            raise ScanError(f"osv-scanner exited {code}: {err.strip()[:200]}")
        try:
            data = json.loads(out or "{}")
        except ValueError as exc:
            raise ScanError("osv-scanner produced invalid JSON") from exc
        wanted = set(packages)
        results: dict[Package, list[dict]] = {p: [] for p in packages}
        for source in data.get("results") or []:
            for entry in source.get("packages") or []:
                pkg = entry.get("package") or {}
                p = Package(pkg.get("name", ""), pkg.get("version", ""),
                            pkg.get("ecosystem") or ECOSYSTEM)
                if p not in wanted:
                    continue
                seen = {v["id"] for v in results[p]}
                for v in entry.get("vulnerabilities") or []:
                    if v.get("id") and v["id"] not in seen:
                        seen.add(v["id"])
                        results[p].append(v)
        return build_result(results, {"name": self.name, "version": version}, started)
