"""Explanations built from the evidence with fixed rules; no language model involved."""

import hashlib
import json
import logging
from pathlib import Path

from app.ai import context as ctxmod
from app.ai import grounding
from app.ai.template_provider import render

log = logging.getLogger("depguard.ai")
ENGINE = "evidence-based"
VERSION = "3"


def cache_key(context: dict) -> str:
    raw = ctxmod.dumps(context) + "|" + ENGINE + "|" + VERSION
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate(context: dict) -> dict:
    out = render(context)
    clean, level, stripped = grounding.validate(out, context, out)
    if stripped:
        log.warning("template produced unverified values %s for %s", stripped,
                    context.get("finding_id"))
    return {**clean, "grounding": "evidence" if level == "full" else level, "provider": ENGINE,
            "model": None, "stripped": stripped, "note": None,
            "weakness": context.get("weakness"), "quote": context.get("quote")}


async def explain(finding: dict, cache_dir: Path, candidates: list[dict] | None = None) -> dict:
    context = ctxmod.build(finding, candidates)
    path = cache_dir / f"{cache_key(context)}.json"
    try:
        return {**json.loads(path.read_text(encoding="utf-8")), "cached": True}
    except (OSError, ValueError):
        pass
    result = generate(context)
    cache_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result), encoding="utf-8")
    return {**result, "cached": False}
