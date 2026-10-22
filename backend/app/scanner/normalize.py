import hashlib
from decimal import Decimal

import semantic_version as sv
from cvss import CVSS3, CVSS4

from app import versions
from app.graph import RANK, Graph
from app.risks import malware
from app.scanner.base import ECOSYSTEM, Package, ScanResult

DB_LABELS = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium",
             "LOW": "low"}
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
MAX_DETAILS = 6000
MAX_REFS = 12


def parse_ver(v: str | None) -> sv.Version | None:
    if not v:
        return None
    try:
        return sv.Version(v.lstrip("v"))
    except ValueError:
        try:
            return sv.Version.coerce(v.lstrip("v"))
        except ValueError:
            return None


def score_label(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def severity(record: dict) -> dict:
    vectors = {s.get("type"): s.get("score") for s in record.get("severity") or []}
    for typ, cls in (("CVSS_V3", CVSS3), ("CVSS_V4", CVSS4)):
        vec = vectors.get(typ)
        if not vec:
            continue
        try:
            score = cls(vec).base_score
        except Exception:
            continue
        score = float(score if isinstance(score, Decimal) else Decimal(str(score)))
        return {"label": score_label(score), "score": score, "vector": vec, "source": typ}
    db = str((record.get("database_specific") or {}).get("severity") or "").upper()
    if db in DB_LABELS:
        return {"label": DB_LABELS[db], "score": None, "vector": None,
                "source": "database_specific"}
    return {"label": "unknown", "score": None, "vector": None, "source": None}


def ids_of(record: dict) -> tuple[str, list[str]]:
    ids = [record["id"], *(record.get("aliases") or [])]
    primary = next((i for i in ids if i.startswith("GHSA-")), record["id"])
    return primary, sorted(set(ids) - {primary})


def cwes_of(record: dict) -> list[str]:
    ids = set((record.get("database_specific") or {}).get("cwe_ids") or [])
    for aff in record.get("affected") or []:
        ids |= set((aff.get("database_specific") or {}).get("cwe_ids") or [])
    return sorted(i for i in ids if isinstance(i, str) and i.startswith("CWE-"))


def ranges_for(record: dict, name: str, version: str,
               ecosystem: str = ECOSYSTEM) -> tuple[list[dict], list[str]]:
    ranges, fixed, listed = [], set(), set()
    for aff in record.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != ecosystem or not versions.same_name(
                ecosystem, pkg.get("name") or "", name):
            continue
        listed.update(str(v) for v in aff.get("versions") or [])
        for r in aff.get("ranges") or []:
            if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            low = None
            for ev in r.get("events") or []:
                if "introduced" in ev:
                    low = ev["introduced"]
                elif "fixed" in ev or "last_affected" in ev:
                    end = "fixed" if "fixed" in ev else "last_affected"
                    ranges.append({"introduced": low or "0", end: ev[end]})
                    if end == "fixed":
                        fixed.add(ev["fixed"])
                    low = None
            if low is not None:
                ranges.append({"introduced": low})
    current = parse_ver(version) if ecosystem == ECOSYSTEM else None
    for r in ranges:
        r["text"] = range_text(r)
        r["contains"] = (contains(r, current) if ecosystem == ECOSYSTEM
                         else contains_in(r, ecosystem, version))
    if version in listed and not any(r["contains"] for r in ranges):
        ranges.append({"introduced": version, "last_affected": version,
                       "text": f"={version} (listed by the advisory)", "contains": True})
    return ranges, sorted(fixed, key=lambda v: versions.key(ecosystem, v))


def contains_in(r: dict, ecosystem: str, version: str) -> bool:
    """Range check for non-npm ecosystems using that ecosystem's version ordering."""
    low = r.get("introduced")
    if low not in (None, "0") and versions.compare(ecosystem, version, low) < 0:
        return False
    if "fixed" in r:
        return versions.compare(ecosystem, version, r["fixed"]) < 0
    if "last_affected" in r:
        return versions.compare(ecosystem, version, r["last_affected"]) <= 0
    return True


def range_text(r: dict) -> str:
    low = f">={r['introduced']}" if r.get("introduced") not in (None, "0") else ">=0"
    if "fixed" in r:
        return f"{low} <{r['fixed']}"
    if "last_affected" in r:
        return f"{low} <={r['last_affected']}"
    return low


def contains(r: dict, v: sv.Version | None) -> bool | None:
    if v is None:
        return None
    low = parse_ver(r.get("introduced")) if r.get("introduced") not in (None, "0") else None
    if low and v < low:
        return False
    if "fixed" in r:
        hi = parse_ver(r["fixed"])
        return None if hi is None else v < hi
    if "last_affected" in r:
        hi = parse_ver(r["last_affected"])
        return None if hi is None else v <= hi
    return True


def refs_of(record: dict) -> list[dict]:
    out = []
    for ref in record.get("references") or []:
        url = str(ref.get("url") or "")
        if url.startswith(("https://", "http://")) and url not in {r["url"] for r in out}:
            out.append({"type": ref.get("type", "WEB"), "url": url})
    return out[:MAX_REFS]


def graph_info(graph: Graph, keys: list[str]) -> dict:
    infos = [graph.info(k) for k in keys]
    paths, seen = [], set()
    for info in infos:
        for p in info["paths"]:
            if tuple(p) not in seen:
                seen.add(tuple(p))
                paths.append(p)
    paths.sort(key=len)
    depths = [i["depth"] for i in infos if i["depth"] is not None]
    return {"scope": min((i["scope"] for i in infos), key=RANK.get),
            "direct": any(i["direct"] for i in infos), "depth": min(depths, default=None),
            "paths": paths[:20], "path_count": sum(i["path_count"] for i in infos),
            "lockfile": graph.lockfile_name}


def finding_id(advisory: str, label: str) -> str:
    return "f_" + hashlib.sha256(f"{advisory}|{label}".encode()).hexdigest()[:12]


def make_finding(record: dict, pkg: Package, info: dict, scan: dict) -> dict:
    primary, aliases = ids_of(record)
    ranges, fixed = ranges_for(record, pkg.name, pkg.version, pkg.ecosystem)
    details = str(record.get("details") or "")
    summary = str(record.get("summary") or details.split("\n", 1)[0] or primary)[:300]
    return {
        "id": finding_id(primary, pkg.label),
        "advisory": {
            "id": primary, "aliases": aliases, "summary": summary,
            "details": details[:MAX_DETAILS], "severity": severity(record),
            "published": record.get("published"), "modified": record.get("modified"),
            "refs": refs_of(record), "source": "osv", "cwes": cwes_of(record),
        },
        "package": {"name": pkg.name, "version": pkg.version, "ecosystem": pkg.ecosystem},
        "affected_ranges": ranges, "fixed_versions": fixed,
        **info,
        "reachability": {"label": "Unknown", "evidence": []},
        "priority": None, "evidence": [], "scan": scan,
    }


def merge(existing: dict, record: dict) -> None:
    primary, aliases = ids_of(record)
    adv = existing["advisory"]
    adv["aliases"] = sorted((set(adv["aliases"]) | set(aliases) | {primary}) - {adv["id"]})
    adv["cwes"] = sorted(set(adv.get("cwes", [])) | set(cwes_of(record)))


def normalize(scan: ScanResult, graph: Graph) -> list[dict]:
    meta = {"scanner": scan.scanner.get("name"), "version": scan.scanner.get("version"),
            "ts": scan.finished if scan.source == "live" else scan.started,
            "source": scan.source}
    findings: list[dict] = []
    for _, keys in sorted(graph.packages().items()):
        node = graph.nodes[keys[0]]
        pkg = Package(node.name, node.version, node.ecosystem)
        records = [r for r in scan.vulns_for(pkg) if not r.get("withdrawn") and r.get("id")]
        if not records:
            continue
        info = graph_info(graph, keys)
        local: list[tuple[set, dict]] = []
        for record in sorted(records, key=lambda r: (not r["id"].startswith("GHSA-"), r["id"])):
            ids = {record["id"], *(record.get("aliases") or [])}
            hit = next((f for s, f in local if s & ids), None)
            if hit:
                merge(hit, record)
                next(s for s, f in local if f is hit).update(ids)
            else:
                local.append((ids, make_finding(record, pkg, info, meta)))
        findings += [f for _, f in local]
    malware.mark(findings)
    findings.sort(key=lambda f: (-SEV_ORDER[f["advisory"]["severity"]["label"]],
                                 -(f["advisory"]["severity"]["score"] or 0),
                                 f["package"]["name"], f["advisory"]["id"]))
    return findings
