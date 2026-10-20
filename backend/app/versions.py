import re

import semantic_version as sv
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

SEMVER_LIKE = {"npm", "Go", "crates.io", "Packagist", "NuGet", "Pub", "Hex", "SwiftURL"}
TOKEN = re.compile(r"\d+|[A-Za-z]+")


def generic(v: str) -> tuple:
    """Numbers compare numerically; letters sort before the end marker so 1.0.beta < 1.0."""
    parts = [(2, int(tok), "") if tok.isdigit() else (0, 0, tok.lower())
             for tok in TOKEN.findall(v)]
    return (*parts, (1, 0, ""))


def key(ecosystem: str, version: str | None):
    """Sort key for versions within one ecosystem (keys of different ecosystems never mix)."""
    v = str(version or "").strip()
    if not v:
        return (0, ())
    if ecosystem == "PyPI":
        try:
            return (2, Version(v))
        except InvalidVersion:
            return (1, generic(v))
    if ecosystem in SEMVER_LIKE:
        s = v[1:] if v[:1] in ("v", "V") else v
        try:
            return (2, sv.Version(s))
        except ValueError:
            try:
                return (2, sv.Version.coerce(s))
            except ValueError:
                return (1, generic(s))
    return (1, generic(v))


def compare(ecosystem: str, a: str, b: str) -> int:
    ka, kb = key(ecosystem, a), key(ecosystem, b)
    if ka[0] != kb[0]:
        ka, kb = (1, generic(str(a))), (1, generic(str(b)))
    return (ka > kb) - (ka < kb)


def same_name(ecosystem: str, a: str, b: str) -> bool:
    if ecosystem == "PyPI":
        return canonicalize_name(a) == canonicalize_name(b)
    if ecosystem in ("Packagist", "NuGet"):
        return a.lower() == b.lower()
    return a == b
