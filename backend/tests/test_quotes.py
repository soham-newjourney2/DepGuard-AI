import json

import pytest

from app.ai import quotes
from app.config import RECORDED

V = RECORDED / "osv" / "vulns"


def adv(vid):
    return json.loads((V / f"{vid}.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("vid,pkg,start", [
    ("GHSA-hrpp-h998-j3pp", "qs", "qs before 6.10.3 allows attackers to cause a Node process hang"),
    ("GHSA-rv95-896h-c2vc", "express", "This can cause malformed URLs to be evaluated"),
    ("GHSA-qwcr-r2fm-qrc7", "body-parser",
     "body-parser <1.20.3 is vulnerable to denial of service"),
])
def test_picks_the_impact_sentence_on_real_advisories(vid, pkg, start):
    q = quotes.pick(adv(vid), pkg)
    assert q["text"].startswith(start)
    assert q["source"] == f"https://osv.dev/vulnerability/{vid}"
    assert 40 <= len(q["text"]) <= 300


def test_quote_is_verbatim_text_from_the_advisory():
    for vid in ("GHSA-hrpp-h998-j3pp", "GHSA-rv95-896h-c2vc", "GHSA-qwcr-r2fm-qrc7"):
        details = " ".join(adv(vid)["details"].replace("`", "").split())
        for sentence in quotes.SPLIT.split(quotes.pick(adv(vid), "x")["text"]):
            assert sentence in details


def test_strips_markdown_code_urls_tables_and_fix_sections():
    a = {"id": "GHSA-x", "summary": "s", "details": (
        "### Impact\n\n| Version | Fixed |\n|---|---|\n| 1.0 | 2.0 |\n\n"
        "```js\nrequire('lib').exploit()  // allows attackers to execute code\n```\n\n"
        "The [`parse`](https://example.com/parse) function allows attackers to execute arbitrary "
        "code via crafted input, see https://evil.example.com/x for details.\n\n"
        "### Patches\n\nUpgrade to 2.0 which prevents attackers from executing code.")}
    q = quotes.pick(a, "lib")
    assert q["text"] == ("The parse function allows attackers to execute arbitrary code via "
                         "crafted input, see for details.")
    assert "http" not in q["text"] and "`" not in q["text"] and "Upgrade" not in q["text"]


def test_hostile_html_stays_plain_text():
    a = {"id": "GHSA-x", "summary": "s",
         "details": "<img src=x onerror=alert(1)> lets a remote attacker execute script in "
                    "the victim's browser through the widget."}
    q = quotes.pick(a, "widget")
    assert q["text"].startswith("<img src=x onerror=alert(1)>")


def test_deterministic():
    a = adv("GHSA-rv95-896h-c2vc")
    assert quotes.pick(a, "express") == quotes.pick(a, "express")


@pytest.mark.parametrize("details", [
    "Upgrade to 1.2.3.",
    "A bad regular expression is generated for some routes. See the linked commit.",
    "x" * 500,
    "",
])
def test_omits_when_nothing_qualifies(details):
    assert quotes.pick({"id": "GHSA-x", "summary": "Short", "details": details}, "lib") is None


def test_most_recorded_advisories_get_a_quote():
    files = list(V.glob("*.json"))
    picked = sum(1 for f in files if quotes.pick(json.loads(f.read_text("utf-8")), "x"))
    assert picked / len(files) > 0.75
