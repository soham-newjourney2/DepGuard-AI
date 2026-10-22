"""Find committed secrets; keep only the kind, file:line and a mask, never the value."""

import re
from pathlib import Path

from app.risks import Inputs, risk

MAX_FILES = 2000
MAX_BYTES = 1024 * 1024
SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", ".venv", "venv", "__pycache__", "vendor",
             "target", "dist", "build", ".next", ".tox", "site-packages"}
LOW_DIRS = {"test", "tests", "__tests__", "spec", "fixtures", "fixture", "examples", "example",
            "testdata", "docs"}
ENV_FILE = re.compile(r"^(\.env(\..+)?|.+\.env|\.npmrc|\.pypirc|\.netrc)$")
PLACEHOLDER = re.compile(r"(?i)^(x+|\*+|changeme|change_me|your[_-].*|<.*>|\$\{.*\}|\$[A-Z_]+|"
                         r"example|dummy|placeholder|redacted|none|null|true|false|todo|\.\.\.)$")
AWS_EXAMPLE = "AKIA" + "IOSFODNN7EXAMPLE"
SAMPLE_HINT = re.compile(r"(?i)(demo|example|sample|test|dummy|fake)")

# name, label, severity, confidence, pattern (group "v" is the secret value)
RULES = [
    ("private_key", "Private key", "high", "high",
     re.compile(r"(?P<v>-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY"
                r"(?: BLOCK)?-----)")),
    ("aws_access_key_id", "AWS access key id", "high", "high",
     re.compile(r"\b(?P<v>(?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("github_token", "GitHub token", "high", "high",
     re.compile(r"\b(?P<v>gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("npm_token", "npm token", "high", "high", re.compile(r"\b(?P<v>npm_[A-Za-z0-9]{36})\b")),
    ("anthropic_key", "Anthropic API key", "high", "high",
     re.compile(r"\b(?P<v>sk-ant-[A-Za-z0-9_-]{20,})")),
    ("api_key", "API secret key (sk-…)", "high", "medium",
     re.compile(r"\b(?P<v>sk-(?:proj-)?[A-Za-z0-9]{32,})\b")),
    ("slack_token", "Slack token", "high", "high",
     re.compile(r"\b(?P<v>xox[abprs]-[A-Za-z0-9-]{10,})")),
    ("jwt", "JSON Web Token", "medium", "medium",
     re.compile(r"\b(?P<v>eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")),
    ("url_credentials", "Password in a URL", "high", "medium",
     re.compile(r"\bhttps?://[^\s/:@'\"]+:(?P<v>[^\s/@'\"]{3,})@")),
    ("npmrc_auth", "Registry auth token", "high", "high",
     re.compile(r"(?i)_auth(?:Token)?\s*=\s*(?P<v>[^\s'\"]{8,})")),
]
ENV_RULE = ("env_secret", "Secret in an env/config file", "high", "medium",
            re.compile(r"(?i)^\s*(?:export\s+)?(?P<k>[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|"
                       r"API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)[A-Z0-9_]*)\s*=\s*['\"]?"
                       r"(?P<v>[^\s'\"#]{6,})"))
CODE_RULE = ("hardcoded_secret", "Hard-coded secret", "medium", "medium",
             re.compile(r"(?i)\b(?P<k>[a-z0-9_]*(?:secret|token|password|passwd|api_?key)"
                        r"[a-z0-9_]*)\s*[:=]\s*['\"](?P<v>[A-Za-z0-9+/_\-.=]{12,})['\"]"))


def mask(rule: str, value: str) -> str:
    if rule == "private_key":
        return "-----BEGIN … PRIVATE KEY----- (key body not shown)"
    prefix = re.match(r"^(AKIA|ASIA|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|npm_|sk-ant-|sk-|xox.-|"
                      r"eyJ)", value)
    return f"{prefix.group(1) if prefix else ''}… ({len(value)} chars, value not shown)"


def files(root: Path):
    count = 0
    stack = [root]
    while stack and count < MAX_FILES:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for p in entries:
            if p.is_symlink():
                continue
            if p.is_dir():
                if p.name not in SKIP_DIRS:
                    stack.append(p)
            elif p.is_file():
                count += 1
                if count > MAX_FILES:
                    return
                yield p


def text_of(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\0" in raw[:8192]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def scan_text(rel: str, text: str) -> list[tuple]:
    """(rule tuple, line number, value) per secret; one hit per span."""
    rules = [*RULES, ENV_RULE if ENV_FILE.match(Path(rel).name) else CODE_RULE]
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        taken: list[tuple[int, int]] = []
        for rule in rules:
            for m in rule[4].finditer(line):
                span = m.span("v")
                v = m.group("v")
                if any(a < span[1] and span[0] < b for a, b in taken):
                    continue
                if rule in (ENV_RULE, CODE_RULE) and PLACEHOLDER.match(v):
                    continue
                taken.append(span)
                hits.append((rule, n, v))
    return hits


def check(inputs: Inputs) -> list[dict]:
    out = []
    public = inputs.source == "github"
    for path in files(inputs.root):
        text = text_of(path)
        if text is None:
            continue
        rel = path.relative_to(inputs.root).as_posix()
        low = bool(LOW_DIRS & {p.lower() for p in Path(rel).parts[:-1]})
        for (name, label, severity, rule_confidence, _), line, value in scan_text(rel, text):
            confidence = rule_confidence
            evidence = [f"{rel}:{line}: {mask(name, value)}", f"rule: {name}"]
            if value == AWS_EXAMPLE:
                confidence = "low"
                evidence.append("This is AWS's documented example key id, not a live key.")
            elif low:
                confidence = "low"
                evidence.append("Found under a test/fixture/example folder.")
            elif SAMPLE_HINT.search(value):
                confidence = "low"
                evidence.append("The value looks like a sample or placeholder.")
            rec = ("Remove it from the code, rotate it at the provider, and load it from the "
                   "environment or a secret manager instead.")
            if public:
                rec = "This repository is public — treat the secret as leaked and rotate it now. " \
                      + rec
            out.append(risk("secret", severity, f"{label} in {rel}", rec, confidence=confidence,
                            evidence=evidence, location={"file": rel, "line": line}))
    return out
