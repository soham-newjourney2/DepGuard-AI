import json
import re

from app.ai.base import LIST_FIELDS

VERSION = re.compile(r"(?<![\w.])v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(?![\w])")
ADVISORY = re.compile(r"\b(GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|CVE-\d{4}-\d{4,})\b", re.I)
EID = re.compile(r"\bE\d{1,2}\b")
SENTENCE = re.compile(r"(?<=[.!?])\s+")
TEXT_FIELDS = ("summary", "why_it_matters", "recommended_action")


def allowed(context: dict) -> tuple[set[str], set[str], set[str]]:
    blob = json.dumps(context)
    versions = {m.group(1) for m in VERSION.finditer(blob)}
    ids = {m.group(1).upper() for m in ADVISORY.finditer(blob)}
    eids = {e["eid"] for e in context.get("evidence", [])}
    return versions, ids, eids


def unverified(text: str, versions: set[str], ids: set[str], eids: set[str]) -> list[str]:
    bad = [m.group(1) for m in VERSION.finditer(text) if m.group(1) not in versions]
    bad += [m.group(1) for m in ADVISORY.finditer(text) if m.group(1).upper() not in ids]
    bad += [e for e in EID.findall(text) if e not in eids]
    return bad


def clean_text(text: str, rules) -> tuple[str, list[str]]:
    kept, dropped = [], []
    for sentence in SENTENCE.split(text):
        bad = unverified(sentence, *rules)
        if bad:
            dropped += bad
        elif sentence.strip():
            kept.append(sentence.strip())
    return " ".join(kept), dropped


def validate(explanation: dict, context: dict, fallback: dict) -> tuple[dict, str, list[str]]:
    """Strip claims whose versions, advisory ids or citations are absent from the context."""
    rules = allowed(context)
    out, stripped = {}, []
    for key in TEXT_FIELDS:
        text, dropped = clean_text(explanation[key], rules)
        stripped += dropped
        out[key] = text or fallback[key]
    for key in LIST_FIELDS:
        if key == "citations":
            continue
        items = []
        for item in explanation[key]:
            text, dropped = clean_text(item, rules)
            stripped += dropped
            if text:
                items.append(text)
        out[key] = items
    eids = rules[2]
    cited = [c for c in explanation["citations"] if c in eids]
    stripped += [c for c in explanation["citations"] if c not in eids]
    inline = {e for key in (*TEXT_FIELDS, "tradeoffs", "uncertainties")
              for text in ([out[key]] if isinstance(out[key], str) else out[key])
              for e in EID.findall(text)}
    out["citations"] = sorted(set(cited) | inline, key=lambda x: int(x[1:]))
    return out, ("partial" if stripped else "full"), sorted(set(stripped))
