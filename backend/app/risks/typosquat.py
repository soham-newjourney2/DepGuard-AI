"""Typosquat signals: non-popular names one keystroke away from a popular package."""

import re
from functools import lru_cache
from itertools import combinations
from pathlib import Path

from app.risks import Inputs, risk

DATA = Path(__file__).resolve().parents[1] / "data" / "popular"
LISTS = {"npm": "npm.txt", "PyPI": "pypi.txt"}
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "i": "l", "3": "e", "4": "a", "5": "s",
                            "7": "t"})
AFFIXES = {"npm": (("node-", "js-"), ("-js", ".js", "js", "-node")),
           "PyPI": (("python-", "py-", "py"), ("-python", "-py", "py"))}
MIN_LEN = 5


def norm(eco: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower()) if eco == "PyPI" else name.lower()


def bare(name: str) -> str:
    return re.sub(r"[-_.]", "", name)


@lru_cache
def popular(eco: str) -> dict[str, int]:
    """Popular name → download rank (1 = most downloaded)."""
    try:
        lines = (DATA / LISTS[eco]).read_text("utf-8").splitlines()
    except (KeyError, OSError):
        return {}
    names = [norm(eco, x.strip()) for x in lines if x.strip() and not x.startswith("#")]
    return {n: i for i, n in enumerate(dict.fromkeys(names), 1)}


def warm() -> None:
    """Build the indexes early so the first scan doesn't pay the ~3 s cost."""
    for eco in LISTS:
        index(eco)


def deletes(word: str, k: int) -> set[str]:
    return {"".join(c for i, c in enumerate(word) if i not in drop)
            for drop in combinations(range(len(word)), k)}


@lru_cache
def index(eco: str) -> dict[str, set[str]]:
    """Symmetric-delete index: every popular name under its 0-, 1- and (long names) 2-deletions."""
    out: dict[str, set[str]] = {}
    for p in popular(eco):
        variants = {p} | deletes(p, 1) | (deletes(p, 2) if len(p) >= 8 else set())
        for v in variants:
            out.setdefault(v, set()).add(p)
    return out


def distance(a: str, b: str) -> int:
    """Optimal string alignment (Damerau-Levenshtein with adjacent transpositions)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def same_scope(a: str, b: str) -> bool:
    """Only the scope owner can publish under @scope/, so look-alikes inside it are not squats."""
    return (a.startswith("@") and b.startswith("@")
            and a.split("/", maxsplit=1)[0] == b.split("/", maxsplit=1)[0])


def near(eco: str, name: str) -> tuple[str, str] | None:
    """(popular name, reason) for the most-downloaded look-alike, or None."""
    pop = popular(eco)
    if not pop or name in pop:
        return None
    hits: list[tuple[str, str]] = []
    if eco == "npm" and not name.startswith("@"):
        hits += [(p, f"drops the scope of {p}") for p in pop
                 if p.startswith("@") and p[1:].replace("/", "") == name]
    if len(name) >= 4:
        hits += [(p, f"differs from {p} only by - _ . separators") for p in pop
                 if len(p) == len(name) or abs(len(p) - len(name)) <= 2
                 if p != name and bare(p) == bare(name)]
        glyph = name.translate(HOMOGLYPHS)
        if glyph != name or any(c in name for c in "il"):
            hits += [(p, f"swaps look-alike characters of {p}") for p in pop
                     if len(p) == len(name) and p != name and p.translate(HOMOGLYPHS) == glyph]
    prefixes, suffixes = AFFIXES.get(eco, ((), ()))
    for a in prefixes:
        if name.startswith(a) and len(stem := name[len(a):]) >= 4 and stem in pop:
            hits.append((stem, f"adds the prefix '{a}' to {stem}"))
    for a in suffixes:
        if name.endswith(a) and len(stem := name[:-len(a)]) >= 4 and stem in pop:
            hits.append((stem, f"adds the suffix '{a}' to {stem}"))
    if len(name) >= MIN_LEN:
        limit = 2 if len(name) >= 10 else 1
        keys = {name} | deletes(name, 1) | (deletes(name, 2) if limit == 2 else set())
        found = {p for k in keys for p in index(eco).get(k, ())}
        for p in found:
            if (len(p) >= MIN_LEN and p.startswith("@") == name.startswith("@")
                    and (d := distance(name, p)) <= limit):
                hits.append((p, f"edit distance {d} from {p}"))
    hits = [h for h in hits if not same_scope(name, h[0])]
    return min(hits, key=lambda h: pop[h[0]]) if hits else None


def check(inputs: Inputs) -> list[dict]:
    if inputs.graph is None:
        return []
    out = []
    for label, keys in inputs.graph.packages().items():
        node = inputs.graph.nodes[keys[0]]
        if node.ecosystem not in LISTS:
            continue
        hit = near(node.ecosystem, norm(node.ecosystem, node.name))
        if hit is None:
            continue
        target, reason = hit
        direct = any(inputs.graph.direct(k) for k in keys)
        rank = popular(node.ecosystem)[target]
        out.append(risk(
            "typosquat", "medium" if direct else "low",
            f"{label} looks like a typosquat of {target}",
            f"Confirm you meant {node.name}. If you meant {target}, replace it and review what "
            f"{node.name} ran at install time.",
            confidence="medium", package=label,
            evidence=[f"{node.name} {reason}.",
                      f"{target} is #{rank} by downloads on {node.ecosystem}; {node.name} is not "
                      f"in the top {len(popular(node.ecosystem))}.",
                      "direct dependency" if direct else "transitive dependency"]))
    return out
