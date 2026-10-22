"""Pick the advisory's own impact sentence; showing nothing beats paraphrasing."""

import re

MIN, MAX = 40, 300
STOP_SECTIONS = re.compile(r"(?i)^#+\s*(patches|workarounds?|references|credits?|resources|"
                           r"timeline|for more information|fix|remediation|acknowledg)")
FENCE = re.compile(r"```.*?```", re.S)
LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
URL = re.compile(r"(?:https?|ftp)://\S+")
TAG_LINE = re.compile(r"^\s*(#+\s|\|)")
LIST = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9`\"'(])")
IMPACT = re.compile(r"(?i)\b(allow(?:s|ing)?|could|lead(?:s|ing)? to|result(?:s|ing)? in|"
                    r"cause[sd]?|execut\w*|bypass\w*|inject\w*|denial of service|crash\w*|"
                    r"hang\w*|exhaust\w*|leak\w*|expos\w*|overwrit\w*|pollut\w*|redirect\w*|"
                    r"forg\w*|arbitrary|attacker\w*|vulnerable to)\b")
REMEDY = re.compile(r"(?i)(upgrade to|patched in|fixed in|backported|users should|"
                    r"thanks to|reported by|^for example|^see )")
NOISE = {"improper", "neutralization", "special", "elements", "input", "during", "control",
         "output", "using", "without", "resource", "incorrect", "generation"}


def clean(details: str) -> list[list[str]]:
    """Paragraphs of prose with code, links, URLs, tables and fix/reference sections removed."""
    text = FENCE.sub(" ", details.replace("\r\n", "\n"))
    paras, current = [], []
    for raw in text.split("\n"):
        if STOP_SECTIONS.match(raw.strip()):
            break
        if not raw.strip() or TAG_LINE.match(raw):
            if current:
                paras.append(" ".join(current))
                current = []
            continue
        prose = URL.sub("", LINK.sub(r"\1", LIST.sub("", raw))).replace("`", "")
        current.append(" ".join(prose.split()))
    if current:
        paras.append(" ".join(current))
    return [[s.strip() for s in SPLIT.split(p) if s.strip()] for p in paras]


def keywords(cwe_names: list[str]) -> set[str]:
    words = set()
    for name in cwe_names:
        words |= {w for w in re.findall(r"[a-z]{5,}", name.lower()) if w not in NOISE}
    return words


def score(sentence: str, index: int, package: str, words: set[str]) -> int:
    hits = {m.lower() for m in IMPACT.findall(sentence)}
    if not hits:
        return 0
    s = 2 * min(len(hits), 4)
    low = sentence.lower()
    if package.lower() in low:
        s += 2
    s += min(2, sum(1 for w in words if w in low))
    s += max(0, 3 - index)
    if REMEDY.search(sentence):
        s -= 3
    return s


def pick(advisory: dict, package: str, cwe_names: list[str] | None = None) -> dict | None:
    """Best one or two adjacent sentences (40-300 chars), or None."""
    words = keywords(cwe_names or [])
    paras = clean(str(advisory.get("details") or "")) or [[str(advisory.get("summary") or "")]]
    best, best_score, n = None, 3, 0
    for para in paras:
        for i, sentence in enumerate(para):
            sc = score(sentence, n, package, words)
            n += 1
            if MIN <= len(sentence) <= MAX and sc > best_score:
                best, best_score = (para, i), sc
    if best is None:
        return None
    para, i = best
    text = para[i]
    if len(text) < 120 and i + 1 < len(para) and score(para[i + 1], 9, package, words) > 0 \
            and len(text) + 1 + len(para[i + 1]) <= MAX:
        text = f"{text} {para[i + 1]}"
    return {"text": text, "source": f"https://osv.dev/vulnerability/{advisory['id']}"}
