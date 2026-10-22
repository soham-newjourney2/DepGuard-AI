from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Protocol

from app.jobs import iso, utcnow

ECOSYSTEM = "npm"


@dataclass(frozen=True, order=True)
class Package:
    name: str
    version: str
    ecosystem: str = ECOSYSTEM

    @property
    def label(self) -> str:
        return f"{self.name}@{self.version}"

    @property
    def key(self) -> str:
        """Stable id across ecosystems; npm keeps the bare label for compatibility."""
        return self.label if self.ecosystem == ECOSYSTEM else f"{self.ecosystem}:{self.label}"


@dataclass
class ScanResult:
    """Scan output; raw holds the OSV records found for each package."""

    raw: dict
    scanner: dict
    started: str
    finished: str
    source: str = "live"
    notes: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        return asdict(self)

    def vulns_for(self, pkg: Package) -> list[dict]:
        for r in self.raw.get("results", []):
            p = r.get("package", {})
            if (p.get("name") == pkg.name and p.get("version") == pkg.version
                    and p.get("ecosystem", ECOSYSTEM) == pkg.ecosystem):
                return r.get("vulns", [])
        return []


class ScanError(Exception):
    pass


class Scanner(Protocol):
    name: str

    async def scan(self, packages: list[Package], lockfile: Path | None = None) -> ScanResult: ...


def build_result(results: dict[Package, list[dict]], scanner: dict, started: str,
                 source: str = "live", notes: list[str] | None = None) -> ScanResult:
    raw = {"results": [
        {"package": {"name": p.name, "version": p.version, "ecosystem": p.ecosystem},
         "vulns": sorted(v, key=lambda r: r.get("id", ""))}
        for p, v in sorted(results.items())
    ]}
    return ScanResult(raw, scanner, started, iso(utcnow()), source, notes or [])
