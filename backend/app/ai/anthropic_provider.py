import json

import anthropic

from app.ai import context as ctxmod
from app.ai.base import SCHEMA, InvalidOutput, ProviderError, coerce

MAX_TOKENS = 700


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str, model: str, client=None, timeout_s: float = 30):
        self.model = model
        self.client = client or anthropic.AsyncAnthropic(api_key=api_key, timeout=timeout_s,
                                                         max_retries=1)

    def request(self, context: dict) -> dict:
        params = {
            "model": self.model,
            "max_tokens": MAX_TOKENS,
            "system": ctxmod.SYSTEM,
            "messages": [{"role": "user", "content": ctxmod.user_message(context)}],
            "output_config": {"effort": "low",
                              "format": {"type": "json_schema", "schema": SCHEMA}},
        }
        if self.model.startswith("claude-haiku"):
            params["thinking"] = {"type": "disabled"}
        return params

    async def explain(self, context: dict) -> dict:
        try:
            response = await self.client.messages.create(**self.request(context))
        except anthropic.APIStatusError as exc:
            raise ProviderError(f"Anthropic API returned HTTP {exc.status_code}") from None
        except anthropic.APIConnectionError:
            raise ProviderError("Anthropic API unreachable") from None
        if response.stop_reason == "refusal":
            raise ProviderError("model declined the request")
        if response.stop_reason == "max_tokens":
            raise ProviderError("response truncated at max_tokens")
        text = next((b.text for b in response.content if b.type == "text"), "")
        try:
            return coerce(json.loads(text))
        except ValueError:
            raise InvalidOutput("model returned invalid JSON") from None
