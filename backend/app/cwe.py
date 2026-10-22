"""Plain-language CWE notes; unknown ids still link to MITRE."""

import json
import re
from functools import lru_cache
from pathlib import Path

KB = Path(__file__).with_name("data") / "cwe.json"
MITRE = "https://cwe.mitre.org/data/definitions/{n}.html"
CWE = re.compile(r"^CWE-(\d+)$")
NONE = "The advisory does not publish a weakness type (CWE)."


@lru_cache
def entries() -> dict[str, dict]:
    doc = json.loads(KB.read_text(encoding="utf-8"))
    return {e["id"]: e for e in doc["entries"]}


def source(cwe_id: str) -> str:
    m = CWE.match(cwe_id)
    return MITRE.format(n=m.group(1)) if m else "https://cwe.mitre.org"


def lookup(cwe_id: str) -> dict:
    entry = entries().get(cwe_id)
    if entry:
        return {**entry, "source": source(cwe_id), "known": True}
    return {"id": cwe_id, "name": None, "known": False, "source": source(cwe_id),
            "plain": "DepGuard has no plain-language summary for this weakness type yet; MITRE's "
                     "page describes it.",
            "impact": None, "matters_when": None, "mitigation": None}


def weakness(cwes: list[str]) -> dict | None:
    """The best-described CWE of an advisory (known entries first), or None when none is listed."""
    found = [lookup(c) for c in cwes if CWE.match(c)]
    if not found:
        return None
    return next((w for w in found if w["known"]), found[0])
