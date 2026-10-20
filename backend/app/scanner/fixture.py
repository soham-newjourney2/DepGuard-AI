import json
from pathlib import Path

from app.jobs import iso, utcnow
from app.scanner.base import Package, ScanError, ScanResult, build_result

SAFE_ID = str.maketrans({c: "_" for c in '/\\:*?"<>|'})


class RecordedScanner:
    """Replays OSV records captured by `record()`; packages not in the index have no vulns."""

    name = "fixture"

    def __init__(self, db: Path, source: str = "live"):
        self.db = db
        self.source = source

    def _index(self) -> dict:
        try:
            return json.loads((self.db / "index.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ScanError(f"recorded scan data missing at {self.db.name}") from exc

    async def scan(self, packages: list[Package], lockfile: Path | None = None) -> ScanResult:
        index = self._index()
        results = {}
        for p in packages:
            ids = index["packages"].get(p.key, [])
            results[p] = [self._vuln(i) for i in ids]
        meta = {"name": self.name, "version": f"recorded {index.get('recorded_at', '')}".strip()}
        if self.source == "cache":
            meta = index.get("scanner", meta)
        started = index.get("recorded_at") if self.source == "cache" else iso(utcnow())
        return build_result(results, meta, started or iso(utcnow()), source=self.source)

    def known(self, pkg: Package) -> bool:
        index = self._index()
        return pkg.key in index["packages"] or pkg.key in index.get("clean", [])

    def _vuln(self, vid: str) -> dict:
        return json.loads((self.db / "vulns" / f"{vid.translate(SAFE_ID)}.json")
                          .read_text(encoding="utf-8"))


def record(result: ScanResult, db: Path) -> None:
    (db / "vulns").mkdir(parents=True, exist_ok=True)
    for stale in (db / "vulns").glob("*.json"):
        stale.unlink()
    packages, clean = {}, []
    for r in result.raw["results"]:
        p = r["package"]
        label = Package(p["name"], p["version"], p.get("ecosystem", "npm")).key
        ids = [v["id"] for v in r["vulns"]]
        if ids:
            packages[label] = ids
        else:
            clean.append(label)
        for v in r["vulns"]:
            (db / "vulns" / f"{v['id'].translate(SAFE_ID)}.json").write_text(
                json.dumps(v, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    index = {"recorded_at": result.finished, "scanner": result.scanner,
             "packages": dict(sorted(packages.items())), "clean": sorted(clean)}
    (db / "index.json").write_text(json.dumps(index, indent=1) + "\n", encoding="utf-8")
