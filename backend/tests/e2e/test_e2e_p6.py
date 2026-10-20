import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e

QS = "GHSA-hrpp-h998-j3pp"


def open_qs(page, base_url):
    page.goto(base_url + "/")
    page.get_by_role("button", name="Try the demo project").click()
    expect(page.locator(".card--ready")).to_be_visible()
    page.locator('[data-nav="findings"]').click()
    page.locator(".frow").filter(has_text="qs@6.7.0").filter(has_text=QS).click()
    drawer = page.get_by_role("dialog", name="Finding detail")
    expect(drawer.locator(".xp__summary")).to_be_visible()
    return drawer


def test_p6_template_explanation_with_badge_and_citations(page, base_url, console_errors):
    drawer = open_qs(page, base_url)
    expect(drawer.locator(".aibadge")).to_have_text("Template")
    expect(drawer.locator(".xp__summary")).to_contain_text("qs@6.7.0")
    action = drawer.locator(".xp__block").filter(has_text="Recommended action")
    expect(action).to_contain_text("6.7.3")
    expect(drawer.locator(".xp__block").filter(has_text="Uncertainties")).to_contain_text(
        "A parent package is imported")
    assert drawer.locator(".cite").count() >= 4
    assert console_errors == []


def test_p6_citation_chip_highlights_evidence(page, base_url):
    drawer = open_qs(page, base_url)
    drawer.locator(".xp__cites .cite", has_text="E4").click()
    evidence = page.locator("#ev-E4")
    expect(evidence).to_have_class(re.compile(r"\bis-flash\b"))
    expect(evidence).to_be_in_viewport()
    expect(evidence).to_contain_text("6.7.3")


def test_p6_explanation_in_graph_drawer(page, base_url):
    open_qs(page, base_url)
    page.keyboard.press("Escape")
    page.keyboard.press("g")
    expect(page.locator(".gsvg")).to_have_attribute("data-settled", "true", timeout=10_000)
    page.locator('.gnode[data-label="minimist@0.0.8"]').dispatch_event("click")
    drawer = page.get_by_role("dialog", name="Finding detail")
    expect(drawer.locator(".aibadge")).to_have_text("Template")
    expect(drawer.locator(".xp__block").filter(has_text="Why it matters")).to_contain_text(
        "devDependencies")
