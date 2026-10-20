"""Live website scan: fetch one page and its scripts as text, detect client-side libraries."""

import re
from dataclasses import dataclass, field
from html import unescape
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from app.config import Settings
from app.errors import AppError
from app.graph import Graph
from app.stacks.base import Builder
from app.web import detect
from app.web.fetch import Fetcher, Resolver, system_resolve, url_error

HTML_TYPES = {"text/html", "application/xhtml+xml", ""}
SCRIPT_PEEK = 256 * 1024
TITLE = re.compile(r"<title[^>]*>([^<]{1,200})</title>", re.I)


@dataclass
class SiteScan:
    url: str
    final_url: str
    title: str
    html: str
    detections: list[detect.Detection]
    scripts: int
    fetched: int
    notes: list[str] = field(default_factory=list)
    redirects: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def host(self) -> str:
        return urlsplit(self.final_url).hostname or "site"

    def to_json(self) -> dict:
        return {"url": self.url, "final_url": self.final_url, "title": self.title,
                "scripts": self.scripts, "fetched": self.fetched, "notes": self.notes,
                "redirects": self.redirects, "truncated": self.truncated,
                "detections": [d.to_json() for d in self.detections]}


async def scan_site(url: str, s: Settings, resolver: Resolver = system_resolve,
                    transport: httpx.AsyncBaseTransport | None = None) -> SiteScan:
    async with Fetcher(timeout_s=s.web_timeout_s, total_bytes=s.web_max_total_mb * 1024 * 1024,
                       resolver=resolver, transport=transport,
                       allow_private=s.web_allow_private) as f:
        page = await f.get(url, s.web_max_page_kb * 1024,
                           accept="text/html,application/xhtml+xml;q=0.9,*/*;q=0.5")
        if page.status >= 400:
            raise url_error("E_URL_STATUS", f"The site answered HTTP {page.status}.",
                            "Check the address; pages behind a login cannot be scanned.", 502)
        if page.content_type not in HTML_TYPES:
            raise url_error("E_URL_NOT_HTML", f"That address returned {page.content_type}, "
                            "not an HTML page.", "Use the address of a web page.")
        html = page.text
        parsed = detect.parse_page(html, page.url)
        found: list[detect.Detection] = []
        settled: set[str] = set()
        for src, line in parsed.scripts:
            hits = detect.from_url(src, line, detect.source_line(parsed, line))
            found += hits
            if any(h.confidence == "high" for h in hits):
                settled.add(src)
        for text, line in parsed.inline:
            found += detect.from_text(text, f"{page.url} (inline script)", line)
        found += detect.from_generators(parsed, page.url)
        notes, fetched = [], 0
        queue = list(dict.fromkeys(src for src, _ in parsed.scripts if src not in settled))
        if len(queue) > s.web_max_assets:
            notes.append(f"Only the first {s.web_max_assets} of {len(queue)} scripts were read.")
            queue = queue[:s.web_max_assets]
        for src in queue:
            if f.budget <= 0:
                notes.append("Download budget reached; remaining scripts were not read.")
                break
            try:
                r = await f.get(src, min(SCRIPT_PEEK, s.web_max_asset_kb * 1024))
            except AppError as exc:
                notes.append(f"{src}: {exc.message}")
                continue
            if r.status != 200:
                notes.append(f"{src}: HTTP {r.status}")
                continue
            fetched += 1
            found += detect.from_text(r.text, src)
    title = TITLE.search(html)
    return SiteScan(url, page.url, unescape(title.group(1)).strip() if title else "", html,
                    detect.merge(found), len(parsed.scripts), fetched, notes, page.redirects,
                    page.truncated)


def scan_files(root: Path, base: str = "https://site-demo.test/") -> SiteScan:
    """Offline scan of a saved site folder (bundled sample): index.html plus local scripts."""
    html = (root / "index.html").read_text("utf-8")
    parsed = detect.parse_page(html, base)
    found, fetched = [], 0
    for src, line in parsed.scripts:
        found += detect.from_url(src, line, detect.source_line(parsed, line))
        local = urlsplit(src)
        if local.hostname == urlsplit(base).hostname and (root / local.path.lstrip("/")).is_file():
            fetched += 1
            found += detect.from_text((root / local.path.lstrip("/")).read_text("utf-8"), src)
    for text, line in parsed.inline:
        found += detect.from_text(text, f"{base} (inline script)", line)
    found += detect.from_generators(parsed, base)
    title = TITLE.search(html)
    return SiteScan(base, base, unescape(title.group(1)).strip() if title else "", html,
                    detect.merge(found), len(parsed.scripts), fetched)


def build_graph(site: SiteScan) -> Graph:
    b = Builder("npm", site.host)
    for d in site.detections:
        if d.ecosystem == "npm":
            b.edges.append(("", b.add(d.name, d.version), "prod"))
    g = b.graph()
    g.lockfile_name = site.final_url
    return g


def loaded_evidence(d: detect.Detection) -> list[dict]:
    return [{"file": e["url"], "line": e["line"], "text": e["text"], "module": d.name,
             "kind": "loaded", "test": False} for e in d.evidence]


def annotate_site(findings: list[dict], site: SiteScan) -> None:
    by_key = {(d.name, d.version): d for d in site.detections}
    for f in findings:
        d = by_key.get((f["package"]["name"], f["package"]["version"]))
        f["reachability"] = ({"label": "Strong evidence", "evidence": loaded_evidence(d)}
                             if d else {"label": "Unknown", "evidence": []})
