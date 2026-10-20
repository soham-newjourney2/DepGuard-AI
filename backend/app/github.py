import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import httpx

from app.errors import AppError

SPEC = re.compile(r"^(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/(?P<repo>[A-Za-z0-9._-]{1,100})"
                  r"(?:@(?P<ref>[A-Za-z0-9._/-]{1,200}))?$")
CHUNK = 64 * 1024


def parse(spec: str) -> tuple[str, str, str]:
    m = SPEC.fullmatch((spec or "").strip())
    if not m or m["repo"] in (".", "..") or m["repo"].endswith(".git"):
        raise AppError("E_INVALID", "Use the form owner/repo or owner/repo@ref.",
                       "Example: expressjs/express@4.17.1", 422)
    ref = m["ref"] or "HEAD"
    if ".." in ref or ref.startswith(("/", "-")) or ref.endswith("/") or "//" in ref:
        raise AppError("E_INVALID", "That ref is not allowed.", "Use a branch, tag or commit.",
                       422)
    return m["owner"], m["repo"], ref


LINK = re.compile(r"^(?:(?:https?://)?(?:www\.)?github\.com/|git@github\.com:|"
                  r"ssh://git@github\.com/)(?P<owner>[^/\s]+)/(?P<repo>[^/\s?#]+?)(?:\.git)?"
                  r"(?P<rest>/[^?#\s]*)?/?(?:[?#]\S*)?$", re.I)
SEGMENT = re.compile(r"^[A-Za-z0-9._@ -]{1,100}$")
MAX_REF_SEGMENTS = 4
UNSUPPORTED = {"pull", "issues", "actions", "wiki", "discussions", "compare", "settings"}


@dataclass(frozen=True)
class RepoLink:
    owner: str
    repo: str
    ref: str | None = None
    tail: tuple[str, ...] = ()
    blob: bool = False

    def candidates(self) -> list[tuple[str, str | None]]:
        """(ref, project path) pairs to try in order; refs may contain slashes."""
        if self.ref or not self.tail:
            return [(self.ref or "HEAD", None)]
        out = []
        for i in range(1, min(len(self.tail), MAX_REF_SEGMENTS) + 1):
            rest = list(self.tail[i:])
            if self.blob:
                if not rest:
                    continue
                rest = rest[:-1]
            out.append(("/".join(self.tail[:i]), "/".join(rest) or None))
        return out or [("/".join(self.tail), None)]


def invalid_link(message: str = "That GitHub link is not supported.") -> AppError:
    return AppError("E_INVALID", message, "Use github.com/owner/repo, a /tree/<branch>/<folder> "
                    "link, or owner/repo@ref.", 422)


def parse_link(text: str) -> RepoLink:
    """owner/repo[@ref], or a github.com URL (repo, tree, blob, commit, tag, .git, git@)."""
    value = (text or "").strip()
    if SPEC.fullmatch(value):
        owner, repo, ref = parse(value)
        return RepoLink(owner, repo, None if ref == "HEAD" else ref)
    m = LINK.match(value)
    if not m:
        raise invalid_link("Use owner/repo, owner/repo@ref or a github.com link.")
    owner, repo = m["owner"], m["repo"]
    parse(f"{owner}/{repo}")
    segs = [s for s in (m["rest"] or "").split("/") if s]
    if not segs:
        return RepoLink(owner, repo)
    kind, args = segs[0].lower(), segs[1:]
    if any(s in (".", "..") or not SEGMENT.fullmatch(s) for s in args):
        raise invalid_link("That link contains a path DepGuard cannot use.")
    if kind in ("tree", "blob") and args:
        return RepoLink(owner, repo, None, tuple(args), kind == "blob")
    if kind == "commit" and len(args) == 1:
        return RepoLink(owner, repo, args[0])
    if kind == "releases" and len(args) >= 2 and args[0] == "tag":
        return RepoLink(owner, repo, "/".join(args[1:]))
    if kind in UNSUPPORTED:
        raise invalid_link(f"GitHub {kind} pages cannot be scanned; link the repository or a "
                           "branch instead.")
    raise invalid_link()


async def download(owner: str, repo: str, ref: str, dest: Path, limit: int, base_url: str,
                   timeout_s: float = 30,
                   transport: httpx.AsyncBaseTransport | None = None) -> None:
    """Public archives only: fixed host, no auth, no redirects, size-capped stream."""
    url = f"{base_url.rstrip('/')}/{owner}/{repo}/zip/{quote(ref, safe='/')}"
    mb = limit // (1024 * 1024)
    try:
        async with httpx.AsyncClient(timeout=timeout_s, transport=transport, follow_redirects=False,
                                     headers={"User-Agent": "DepGuard-AI"}) as client:
            async with client.stream("GET", url) as resp:
                if resp.status_code == 404:
                    raise AppError("E_GITHUB_NOT_FOUND", f"{owner}/{repo}@{ref} was not found.",
                                   "Only public repositories are supported; check the ref.", 404)
                if resp.status_code != 200:
                    raise AppError("E_GITHUB_UNAVAILABLE",
                                   f"GitHub returned HTTP {resp.status_code}.",
                                   "Try again in a minute.", 502)
                length = resp.headers.get("content-length", "")
                if length.isdigit() and int(length) > limit:
                    raise too_large(mb)
                written = 0
                with open(dest, "wb") as out:
                    async for chunk in resp.aiter_bytes(CHUNK):
                        written += len(chunk)
                        if written > limit:
                            raise too_large(mb)
                        out.write(chunk)
    except (httpx.TimeoutException, httpx.TransportError):
        raise AppError("E_GITHUB_UNAVAILABLE", "Could not reach GitHub.",
                       "Check your connection and try again.", 502) from None


def too_large(mb: int) -> AppError:
    return AppError("E_TOO_LARGE", f"The repository archive is larger than {mb} MB.",
                    "Import a smaller repository or upload a zip without assets.", 413)
