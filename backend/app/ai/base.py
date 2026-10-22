FIELDS = ("summary", "why_it_matters", "recommended_action", "tradeoffs", "uncertainties",
          "citations")
LIST_FIELDS = ("tradeoffs", "uncertainties", "citations")


class InvalidOutput(Exception):
    """An explanation that does not match the Explanation shape."""


def coerce(data: object) -> dict:
    """Validate the Explanation shape and cap field sizes."""
    if not isinstance(data, dict) or set(data) != set(FIELDS):
        raise InvalidOutput("explanation does not match the schema")
    out = {}
    for key in FIELDS:
        value = data[key]
        if key in LIST_FIELDS:
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise InvalidOutput(f"{key} must be a list of strings")
            cap = 12 if key == "citations" else 6
            out[key] = [v.strip()[:400] for v in value if v.strip()][:cap]
        else:
            if not isinstance(value, str):
                raise InvalidOutput(f"{key} must be a string")
            out[key] = value.strip()[:800]
    return out
