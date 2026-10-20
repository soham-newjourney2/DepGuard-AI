import hashlib
import json
import logging
from pathlib import Path

from app.ai import context as ctxmod
from app.ai import grounding
from app.ai.anthropic_provider import AnthropicProvider
from app.ai.base import InvalidOutput, Provider, ProviderError
from app.ai.template_provider import TemplateProvider, render
from app.config import Settings

log = logging.getLogger("depguard.ai")


def make_provider(s: Settings) -> Provider:
    if s.ai_effective == "anthropic" and s.anthropic_api_key:
        return AnthropicProvider(s.anthropic_api_key, s.ai_model)
    return TemplateProvider()


def cache_key(context: dict, provider: Provider) -> str:
    raw = ctxmod.dumps(context) + "|" + provider.name + "|" + (provider.model or "")
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


async def explain(finding: dict, provider: Provider, cache_dir: Path,
                  candidates: list[dict] | None = None) -> dict:
    context = ctxmod.build(finding, candidates)
    path = cache_dir / f"{cache_key(context, provider)}.json"
    try:
        return {**json.loads(path.read_text(encoding="utf-8")), "cached": True}
    except (OSError, ValueError):
        pass
    fallback = render(context)
    result = await generate(context, provider, fallback)
    if not result["note"]:
        cache_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result), encoding="utf-8")
    return {**result, "cached": False}


async def generate(context: dict, provider: Provider, fallback: dict) -> dict:
    if isinstance(provider, TemplateProvider):
        return {**fallback, "grounding": "template", "provider": "template", "model": None,
                "stripped": [], "note": None}
    note = None
    for attempt in (1, 2):
        try:
            raw = await provider.explain(context)
        except InvalidOutput as exc:
            note = str(exc)
            log.warning("AI attempt %d returned unusable output: %s", attempt, exc)
            continue
        except ProviderError as exc:
            note = str(exc)
            log.warning("AI request failed: %s", exc)
            break
        clean, level, stripped = grounding.validate(raw, context, fallback)
        return {**clean, "grounding": level, "provider": provider.name, "model": provider.model,
                "stripped": stripped, "note": None}
    return {**fallback, "grounding": "template", "provider": "template", "model": None,
            "stripped": [], "note": f"AI unavailable ({note}); showing the template explanation."}
