import re
from dataclasses import dataclass, field
from pathlib import Path

EXTS = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", ".next", "vendor"}
MAX_FILES = 3000
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 30 * 1024 * 1024
MAX_EVIDENCE = 5
IMPORT = re.compile(
    r"""(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s+|\bimport\s+|\bexport\s+\*\s+from\s+)"""
    r"""(['"])([^'"\s]+)\1""")
DYNAMIC = re.compile(r"""\b(?:require|import)\s*\(\s*(?!['"`])[\w$.]""")
TEST_PART = re.compile(r"^(?:test|tests|__tests__|spec|specs|e2e)$", re.I)
TEST_FILE = re.compile(r"\.(?:test|spec)\.[cm]?[jt]sx?$", re.I)
BUILTIN = re.compile(r"^(?:node:|\.|/)")

LABELS = ("Strong evidence", "Possible", "Not observed", "Unknown")

PY_FROM = re.compile(r"^\s*from\s+([A-Za-z_][\w.]*)\s+import\b")
PY_IMPORT = re.compile(r"^\s*import\s+([A-Za-z_][\w.]*(?:\s+as\s+\w+)?"
                       r"(?:\s*,\s*[A-Za-z_][\w.]*(?:\s+as\s+\w+)?)*)\s*(?:#.*)?$")
PY_DYNAMIC = re.compile(r"""\b(?:__import__|importlib\.import_module)\s*\(\s*(?!['"])""")
GO_SINGLE = re.compile(r'^\s*import\s+(?:[\w.]+\s+)?"([^"\s]+)"')
GO_IN_BLOCK = re.compile(r'^\s*(?:[\w.]+\s+)?"([^"\s]+)"')
RS_USE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:use|extern\s+crate)\s+:{0,2}([A-Za-z_]\w*)")
RB_REQUIRE = re.compile(r"""^\s*require\s*\(?\s*['"]([^'"]+)['"]""")
RS_BUILTIN = {"crate", "self", "super", "std", "core", "alloc"}
PY_ALIASES = {
    "pyyaml": "yaml", "beautifulsoup4": "bs4", "pillow": "PIL", "python-dateutil": "dateutil",
    "scikit-learn": "sklearn", "opencv-python": "cv2", "opencv-python-headless": "cv2",
    "protobuf": "google", "pyjwt": "jwt", "python-jose": "jose", "psycopg2-binary": "psycopg2",
    "python-multipart": "multipart", "pycryptodome": "Crypto", "pycryptodomex": "Cryptodome",
    "pyopenssl": "OpenSSL", "python-dotenv": "dotenv", "djangorestframework": "rest_framework",
    "attrs": "attr", "msgpack-python": "msgpack", "dnspython": "dns", "pyzmq": "zmq",
    "gitpython": "git", "pyserial": "serial", "pyusb": "usb", "ruamel-yaml": "ruamel",
    "setuptools": "pkg_resources", "websocket-client": "websocket",
}


@dataclass(frozen=True)
class Lang:
    exts: frozenset[str]
    test_file: re.Pattern


LANGS = {
    "npm": Lang(frozenset(EXTS), TEST_FILE),
    "PyPI": Lang(frozenset({".py", ".pyi"}), re.compile(r"(^test_.*|_test)\.py$|^conftest\.py$")),
    "Go": Lang(frozenset({".go"}), re.compile(r"_test\.go$")),
    "crates.io": Lang(frozenset({".rs"}), re.compile(r"^tests?\.rs$")),
    "RubyGems": Lang(frozenset({".rb", ".rake"}), re.compile(r"_(?:spec|test)\.rb$")),
}


@dataclass
class Hit:
    file: str
    line: int
    text: str
    test: bool


@dataclass
class SourceIndex:
    files: int = 0
    dynamic: list[Hit] = field(default_factory=list)
    modules: dict[str, list[Hit]] = field(default_factory=dict)
    truncated: bool = False


def module_root(spec: str) -> str | None:
    if BUILTIN.match(spec):
        return None
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") and len(parts) > 1 else parts[0]


def is_test(rel: Path, lang: Lang | None = None) -> bool:
    pattern = (lang or LANGS["npm"]).test_file
    return any(TEST_PART.match(p) for p in rel.parts[:-1]) or bool(pattern.search(rel.name))


def go_line(line: str, state: dict) -> list[str]:
    s = line.strip()
    if state.get("block"):
        if s.startswith(")"):
            state["block"] = False
            return []
        m = GO_IN_BLOCK.match(line)
        return [m.group(1)] if m else []
    if s.startswith("import") and s.endswith("("):
        state["block"] = True
        return []
    m = GO_SINGLE.match(line)
    return [m.group(1)] if m else []


def line_modules(eco: str, line: str, state: dict) -> tuple[list[str], bool]:
    """Imported module names on one line, and whether the line imports dynamically."""
    if eco == "npm":
        if "require" not in line and "import" not in line and "from" not in line:
            return [], False
        return ([n for m in IMPORT.finditer(line) if (n := module_root(m.group(2)))],
                bool(DYNAMIC.search(line)))
    if eco == "PyPI":
        if m := PY_FROM.match(line):
            return [m.group(1).split(".")[0]], False
        if m := PY_IMPORT.match(line):
            return [part.split()[0].split(".")[0] for part in m.group(1).split(",")], False
        return [], bool(PY_DYNAMIC.search(line))
    if eco == "Go":
        return go_line(line, state), False
    if eco == "crates.io":
        m = RS_USE.match(line)
        return ([m.group(1)] if m and m.group(1) not in RS_BUILTIN else []), False
    if eco == "RubyGems":
        m = RB_REQUIRE.match(line)
        return ([m.group(1)] if m else []), False
    return [], False


def norm(s: str) -> str:
    return re.sub(r"[-_.]", "", s).lower()


def hits_for(idx: "SourceIndex", name: str, eco: str) -> list[Hit]:
    """Source hits whose import resolves to this package (per-ecosystem naming rules)."""
    if eco == "npm":
        return idx.modules.get(name, [])
    if eco == "Go":
        return [h for mod, hs in idx.modules.items()
                if mod == name or mod.startswith(name + "/") for h in hs]
    if eco == "PyPI":
        low = name.lower().replace("_", "-")
        wanted = {norm(PY_ALIASES.get(low, low)), norm(low.removesuffix("-binary"))}
        for prefix in ("python-", "py-"):
            if low.startswith(prefix):
                wanted.add(norm(low[len(prefix):]))
        return [h for mod, hs in idx.modules.items() if norm(mod) in wanted for h in hs]
    if eco == "crates.io":
        return idx.modules.get(name.replace("-", "_"), [])
    if eco == "RubyGems":
        want = norm(name)
        return [h for mod, hs in idx.modules.items()
                if norm(mod.split("/")[0]) == want or norm(mod) == want for h in hs]
    return []


def index_sources(root: Path, ecosystem: str = "npm") -> SourceIndex:
    idx, total = SourceIndex(), 0
    lang = LANGS.get(ecosystem)
    if lang is None:
        return idx
    skip = SKIP_DIRS | {".venv", "venv", "site-packages", "__pycache__", "target"}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if skip & set(rel.parts) or path.suffix.lower() not in lang.exts or not path.is_file():
            continue
        if idx.files >= MAX_FILES or total >= MAX_TOTAL_BYTES:
            idx.truncated = True
            break
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            continue
        total += size
        idx.files += 1
        test = is_test(rel, lang)
        text = path.read_text("utf-8", errors="replace")
        state: dict = {}
        for n, line in enumerate(text.splitlines(), 1):
            names, dynamic = line_modules(ecosystem, line, state)
            if not names and not dynamic:
                continue
            hit = Hit(rel.as_posix(), n, line.strip()[:160], test)
            for name in names:
                idx.modules.setdefault(name, []).append(hit)
            if dynamic:
                idx.dynamic.append(hit)
    return idx


def evidence(hits: list[Hit], module: str, kind: str) -> list[dict]:
    return [{"file": h.file, "line": h.line, "text": h.text, "module": module, "kind": kind,
             "test": h.test} for h in hits[:MAX_EVIDENCE]]


def assess(finding: dict, idx: SourceIndex) -> dict:
    name = finding["package"]["name"]
    eco = finding["package"].get("ecosystem", "npm")
    parents = sorted({p[1].rpartition("@")[0] for p in finding["paths"] if len(p) > 2})
    own = hits_for(idx, name, eco)
    prod_own = [h for h in own if not h.test]
    if prod_own:
        return {"label": "Strong evidence", "evidence": evidence(prod_own, name, "direct")}
    via = [(p, [h for h in hits_for(idx, p, eco) if not h.test]) for p in parents]
    via = [(p, hs) for p, hs in via if hs]
    if via:
        found = [e for p, hs in via for e in evidence(hs, p, "ancestor")]
        return {"label": "Possible", "evidence": found[:MAX_EVIDENCE]}
    if idx.files == 0:
        return {"label": "Unknown", "evidence": []}
    test_only = own + [h for p in parents for h in hits_for(idx, p, eco)]
    if idx.dynamic and not idx.truncated:
        return {"label": "Unknown",
                "evidence": evidence([h for h in idx.dynamic if not h.test], "(dynamic)",
                                     "dynamic") + evidence(test_only, name, "test")}
    if idx.truncated:
        return {"label": "Unknown", "evidence": evidence(test_only, name, "test")}
    return {"label": "Not observed", "evidence": evidence(test_only, name, "test")}


def annotate(findings: list[dict], root: Path, ecosystem: str = "npm") -> SourceIndex:
    idx = index_sources(root, ecosystem)
    for f in findings:
        f["reachability"] = assess(f, idx)
    return idx
