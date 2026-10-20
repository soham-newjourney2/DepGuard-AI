from typing import Protocol

FIELDS = ("summary", "why_it_matters", "recommended_action", "tradeoffs", "uncertainties",
          "citations")
LIST_FIELDS = ("tradeoffs", "uncertainties", "citations")

SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "why_it_matters": {"type": "string"},
        "recommended_action": {"type": "string"},
        "tradeoffs": {"type": "array", "items": {"type": "string"}},
        "uncertainties": {"type": "array", "items": {"type": "string"}},
        "citations": {"type": "array", "items": {"type": "string"}},
    },
    "required": list(FIELDS),
    "additionalProperties": False,
}


class ProviderError(Exception):
    pass


class InvalidOutput(ProviderError):
    """The model answered, but not with a valid Explanation; worth one retry."""


class Provider(Protocol):
    name: str
    model: str | None

    async def explain(self, context: dict) -> dict: ...


def coerce(data: object) -> dict:
    """Validate the Explanation shape; raises ProviderError on anything unexpected."""
    if not isinstance(data, dict) or set(data) != set(FIELDS):
        raise InvalidOutput("explanation does not match the schema")
    out = {}
    for key in FIELDS:
        value = data[key]
        if key in LIST_FIELDS:
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise InvalidOutput(f"{key} must be a list of strings")
            out[key] = [v.strip()[:400] for v in value if v.strip()][:6]
        else:
            if not isinstance(value, str):
                raise InvalidOutput(f"{key} must be a string")
            out[key] = value.strip()[:800]
    return out
