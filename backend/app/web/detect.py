"""Client-side library detection from a page's HTML and the scripts it loads (text only)."""

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import unquote, urljoin, urlsplit

VERSION = r"v?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]+)?)"
BANNER_WINDOW = 4096
MAX_EVIDENCE = 5

CDNJS = {
    "jquery": "jquery", "lodash.js": "lodash", "moment.js": "moment", "vue": "vue",
    "angular.js": "angular", "twitter-bootstrap": "bootstrap", "bootstrap": "bootstrap",
    "handlebars.js": "handlebars", "dompurify": "dompurify", "underscore.js": "underscore",
    "jqueryui": "jquery-ui", "jquery-ui": "jquery-ui", "d3": "d3", "axios": "axios",
    "react": "react", "react-dom": "react-dom", "knockout": "knockout", "Chart.js": "chart.js",
    "select2": "select2", "prism": "prismjs", "highlight.js": "highlight.js", "marked": "marked",
    "socket.io": "socket.io-client", "jquery-validate": "jquery-validation",
    "mustache.js": "mustache", "js-cookie": "js-cookie", "sweetalert2": "sweetalert2",
    "datatables": "datatables.net", "popper.js": "popper.js", "backbone.js": "backbone",
    "ember.js": "ember-source", "jquery-migrate": "jquery-migrate", "font-awesome": "font-awesome",
    "swiper": "swiper", "tinymce": "tinymce", "three.js": "three", "pdf.js": "pdfjs-dist",
}
GOOGLE = {"jquery": "jquery", "jqueryui": "jquery-ui", "angularjs": "angular", "d3js": "d3",
          "threejs": "three", "dojo": "dojo", "hammerjs": "hammerjs"}
KNOWN_FILES = (
    "jquery", "jquery-ui", "jquery-migrate", "bootstrap", "angular", "vue", "react", "react-dom",
    "lodash", "moment", "handlebars", "underscore", "knockout", "dompurify", "d3", "axios",
    "backbone", "select2", "highlight", "swiper", "popper",
)
FILE_ALIASES = {"jquery.ui": "jquery-ui", "purify": "dompurify", "highlight": "highlight.js",
                "popper": "popper.js"}

URL_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/" + VERSION + "/"), "cdnjs"),
    (re.compile(r"^ajax\.googleapis\.com/ajax/libs/([^/]+)/" + VERSION + "/"), "google"),
    (re.compile(r"^(?:cdn|fastly|gcore)\.jsdelivr\.net/npm/((?:@[^/@]+/)?[^/@]+)@"
                + VERSION + r"(?:/|$)"), "npm"),
    (re.compile(r"^unpkg\.com/((?:@[^/@]+/)?[^/@]+)@" + VERSION + r"(?:/|$)"), "npm"),
    (re.compile(r"^code\.jquery\.com/(jquery(?:-migrate)?)-" + VERSION + r"(?:\.slim)?(?:\.min)?"
                r"\.js$"), "same"),
    (re.compile(r"^code\.jquery\.com/ui/" + VERSION + r"/"), "jquery-ui"),
    (re.compile(r"^(?:stackpath|maxcdn|netdna)\.bootstrapcdn\.com/(bootstrap|twitter-bootstrap|"
                r"font-awesome)/" + VERSION + "/"), "cdnjs"),
]
FILE_RULE = re.compile(r"(?:^|/)(" + "|".join(re.escape(n) for n in KNOWN_FILES)
                       + r"|jquery\.ui|purify)[-.@]" + VERSION
                       + r"(?:[.-](?:min|slim|bundle|esm|prod|production|umd))*\.js$", re.I)
WP_VER = re.compile(r"(?:^|/)(" + "|".join(re.escape(n) for n in KNOWN_FILES)
                    + r")(?:\.min)?\.js$", re.I)


@dataclass(frozen=True)
class Banner:
    name: str
    pattern: re.Pattern
    unless: re.Pattern | None = None


BANNERS = [
    Banner("jquery", re.compile(r"jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)")),
    Banner("jquery-ui", re.compile(r"jQuery UI - v(\d+\.\d+\.\d+)")),
    Banner("jquery-migrate", re.compile(r"jQuery Migrate - v(\d+\.\d+\.\d+)")),
    Banner("jquery-validation", re.compile(r"jQuery Validation Plugin - v(\d+\.\d+\.\d+)")),
    Banner("bootstrap", re.compile(r"Bootstrap v(\d+\.\d+\.\d+) \(https?://getbootstrap\.com")),
    Banner("angular", re.compile(r"@license AngularJS v(\d+\.\d+\.\d+)")),
    Banner("vue", re.compile(r"Vue\.js v(\d+\.\d+\.\d+)")),
    Banner("react", re.compile(r"@license React v(\d+\.\d+\.\d+)\s*\*?\s*react\."
                               r"(?:production|development)")),
    Banner("react-dom", re.compile(r"@license React v(\d+\.\d+\.\d+)\s*\*?\s*react-dom\.")),
    Banner("moment", re.compile(r"moment\.js[\s\S]{0,40}?version\s*:\s*(\d+\.\d+\.\d+)")),
    Banner("handlebars", re.compile(r"handlebars v(\d+\.\d+\.\d+)", re.I)),
    Banner("dompurify", re.compile(r"DOMPurify (\d+\.\d+\.\d+)")),
    Banner("underscore", re.compile(r"Underscore\.js (\d+\.\d+\.\d+)"), re.compile(r"[Ll]odash")),
    Banner("lodash", re.compile(r"[Ll]odash[\s\S]{0,600}?VERSION\s*=\s*['\"](\d+\.\d+\.\d+)['\"]")),
    Banner("knockout", re.compile(r"Knockout JavaScript library v(\d+\.\d+\.\d+)")),
    Banner("d3", re.compile(r"https://d3js\.org v(\d+\.\d+\.\d+)")),
    Banner("chart.js", re.compile(r"Chart\.js v(\d+\.\d+\.\d+)")),
    Banner("axios", re.compile(r"axios v(\d+\.\d+\.\d+)")),
    Banner("select2", re.compile(r"Select2 (\d+\.\d+\.\d+)")),
    Banner("backbone", re.compile(r"Backbone\.js (\d+\.\d+\.\d+)")),
    Banner("highlight.js", re.compile(r"Highlight\.js v?(\d+\.\d+\.\d+)")),
    Banner("js-cookie", re.compile(r"JavaScript Cookie v(\d+\.\d+\.\d+)")),
    Banner("datatables.net", re.compile(r"DataTables (\d+\.\d+\.\d+)")),
    Banner("socket.io-client", re.compile(r"Socket\.IO v(\d+\.\d+\.\d+)")),
    Banner("marked", re.compile(r"marked v(\d+\.\d+\.\d+)")),
    Banner("swiper", re.compile(r"Swiper (\d+\.\d+\.\d+)")),
    Banner("@popperjs/core", re.compile(r"@popperjs/core v(\d+\.\d+\.\d+)")),
]
GENERATOR = re.compile(r"^\s*([A-Za-z][\w .-]*?)\s+v?(\d+(?:\.\d+){0,3})\b")


@dataclass
class Detection:
    name: str
    version: str
    confidence: str
    evidence: list[dict] = field(default_factory=list)
    ecosystem: str | None = "npm"

    @property
    def key(self) -> tuple[str, str]:
        return self.name, self.version

    def to_json(self) -> dict:
        return {"name": self.name, "version": self.version, "confidence": self.confidence,
                "ecosystem": self.ecosystem, "evidence": self.evidence}


@dataclass
class Page:
    scripts: list[tuple[str, int]] = field(default_factory=list)
    styles: list[tuple[str, int]] = field(default_factory=list)
    inline: list[tuple[str, int]] = field(default_factory=list)
    generators: list[tuple[str, int]] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)


class PageParser(HTMLParser):
    def __init__(self, base: str):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.page = Page()
        self.in_script: int | None = None
        self.buf: list[str] = []

    def absolute(self, ref: str) -> str | None:
        ref = (ref or "").strip()
        if not ref or ref.startswith(("data:", "javascript:", "blob:", "#")):
            return None
        url = urljoin(self.base, ref)
        return url if urlsplit(url).scheme in ("http", "https") else None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        line = self.getpos()[0]
        if tag == "base" and a.get("href") and (b := self.absolute(a["href"])):
            self.base = b
        elif tag == "script":
            if url := self.absolute(a.get("src", "")):
                self.page.scripts.append((url, line))
            else:
                self.in_script, self.buf = line, []
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower():
            if url := self.absolute(a.get("href", "")):
                self.page.styles.append((url, line))
        elif tag == "meta" and a.get("name", "").lower() == "generator" and a.get("content"):
            self.page.generators.append((a["content"][:120], line))

    def handle_data(self, data):
        if self.in_script is not None:
            self.buf.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self.in_script is not None:
            text = "".join(self.buf)
            if text.strip():
                self.page.inline.append((text, self.in_script))
            self.in_script = None


def parse_page(html: str, base: str) -> Page:
    p = PageParser(base)
    try:
        p.feed(html)
        p.close()
    except (AssertionError, ValueError):
        pass
    p.page.lines = html.splitlines()
    return p.page


def evidence(url: str, line: int, text: str, kind: str) -> dict:
    return {"url": url, "line": line, "text": text.strip()[:200], "kind": kind}


def from_url(url: str, line: int, snippet: str) -> list[Detection]:
    """Library and version stated by a script/style URL (CDN path or versioned file name)."""
    parts = urlsplit(url)
    hostpath = (parts.hostname or "") + unquote(parts.path)
    for rule, kind in URL_RULES:
        if m := rule.search(hostpath):
            if kind == "jquery-ui":
                name, version = "jquery-ui", m.group(1)
            else:
                lib, version = m.group(1), m.group(2)
                name = {"cdnjs": CDNJS.get(lib, lib if not lib.endswith(".js") else None),
                        "google": GOOGLE.get(lib), "npm": lib, "same": lib}[kind]
            if name:
                return [Detection(name, version, "high",
                                  [evidence(url, line, snippet, "cdn-url")])]
    if m := FILE_RULE.search(unquote(parts.path)):
        name = m.group(1).lower()
        return [Detection(FILE_ALIASES.get(name, name), m.group(2), "medium",
                          [evidence(url, line, snippet, "file-name")])]
    ver = re.search(r"(?:^|&)ver=(\d+\.\d+\.\d+)(?:&|$)", parts.query)
    if ver and (m := WP_VER.search(parts.path)):
        name = m.group(1).lower()
        return [Detection(FILE_ALIASES.get(name, name), ver.group(1), "medium",
                          [evidence(url, line, snippet, "version-param")])]
    return []


def from_text(text: str, url: str, first_line: int = 1, whole: bool = False) -> list[Detection]:
    """License banners near the top of a script (or anywhere in inline code when whole=True)."""
    window = text if whole else text[:BANNER_WINDOW]
    out = []
    for b in BANNERS:
        m = b.pattern.search(window)
        if not m or (b.unless and b.unless.search(window[:max(m.start(), 400)])):
            continue
        line_no = window.count("\n", 0, m.start())
        line_text = window.splitlines()[line_no] if window.splitlines() else ""
        out.append(Detection(b.name, m.group(1), "high",
                             [evidence(url, first_line + line_no, line_text, "banner")]))
    return out


def from_generators(page: Page, url: str) -> list[Detection]:
    out = []
    for content, line in page.generators:
        if m := GENERATOR.match(content):
            out.append(Detection(m.group(1).strip(), m.group(2), "high",
                                 [evidence(url, line, f'<meta name="generator" content="'
                                                      f'{content}">', "generator")], None))
    return out


def source_line(page: Page, line: int) -> str:
    return page.lines[line - 1] if 0 < line <= len(page.lines) else ""


def merge(found: list[Detection]) -> list[Detection]:
    out: dict[tuple[str, str], Detection] = {}
    rank = {"high": 0, "medium": 1, "low": 2}
    for d in found:
        cur = out.get(d.key)
        if cur is None:
            out[d.key] = Detection(d.name, d.version, d.confidence, list(d.evidence), d.ecosystem)
            continue
        if rank[d.confidence] < rank[cur.confidence]:
            cur.confidence = d.confidence
        for e in d.evidence:
            if e not in cur.evidence and len(cur.evidence) < MAX_EVIDENCE:
                cur.evidence.append(e)
    return sorted(out.values(), key=lambda d: (d.ecosystem is None, d.name.lower(), d.version))
