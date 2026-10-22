"""Supply-chain checks over the extracted project; they flag, they don't judge."""

import hashlib
import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from app.graph import Graph

log = logging.getLogger("depguard.risks")
KINDS = ("malware", "integrity", "typosquat", "secret")
SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCE = ("high", "medium", "low")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Inputs:
    root: Path
    stack: str
    graph: Graph
    findings: list[dict]
    source: str


Check = Callable[[Inputs], list[dict]]
CHECKS: list[Check] = []


def risk(kind: str, severity: str, title: str, recommendation: str, *, confidence: str,
         evidence: list[str], package: str | None = None,
         location: dict | None = None) -> dict:
    assert kind in KINDS and severity in SEVERITIES and confidence in CONFIDENCE
    where = f"{location['file']}:{location.get('line') or 0}" if location else ""
    rid = hashlib.sha1(f"{kind}|{package}|{where}|{title}".encode()).hexdigest()[:12]
    return {"id": f"r_{rid}", "kind": kind, "severity": severity, "title": title,
            "package": package, "location": location, "evidence": evidence,
            "recommendation": recommendation, "confidence": confidence}


def sort_key(r: dict) -> tuple:
    return SEV_RANK[r["severity"]], KINDS.index(r["kind"]), r["package"] or "", r["title"]


def collect(inputs: Inputs, checks: list[Check] | None = None) -> tuple[list[dict], list[str]]:
    """Run every check; a crashing check is reported by name instead of failing the scan."""
    out, seen, failed = [], set(), []
    for check in CHECKS if checks is None else checks:
        try:
            found = check(inputs)
        except Exception:
            log.exception("risk check %s failed", check.__name__)
            failed.append(check.__name__)
            continue
        for r in found:
            if r["id"] not in seen:
                seen.add(r["id"])
                out.append(r)
    return sorted(out, key=sort_key), failed


def counts(risks: list[dict]) -> dict:
    return {"total": len(risks),
            "by_kind": {k: sum(r["kind"] == k for r in risks) for k in KINDS},
            "by_severity": {s: sum(r["severity"] == s for r in risks) for s in SEVERITIES}}


from app.risks import integrity, malware, secrets, typosquat  # noqa: E402  (they use risk())

CHECKS.extend([malware.check, integrity.check, typosquat.check, secrets.check])
