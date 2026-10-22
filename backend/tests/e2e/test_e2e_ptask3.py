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


def test_ptask3_evidence_based_explanation_without_any_model(page, base_url, console_errors):
    drawer = open_qs(page, base_url)
    expect(page.locator(".pill").filter(has_text="evidence-based")).to_be_visible()
    expect(drawer.locator(".aibadge")).to_have_text("Evidence-based (no AI)")
    expect(drawer.locator(".xp__model")).to_have_count(0)
    quote = drawer.locator(".xp__quote")
    expect(quote.locator("blockquote")).to_contain_text("qs before 6.10.3 allows attackers")
    expect(quote.get_by_role("link", name="osv.dev ↗")).to_have_attribute(
        "href", f"https://osv.dev/vulnerability/{QS}")
    weak = drawer.locator(".xp__weak")
    expect(weak).to_contain_text("CWE-1321")
    expect(weak).to_contain_text("Prototype Pollution")
    expect(weak.get_by_role("link", name="MITRE ↗")).to_have_attribute(
        "href", "https://cwe.mitre.org/data/definitions/1321.html")
    expect(drawer.locator(".xp__block").filter(has_text="Why it matters")).to_contain_text(
        "As CWE-1321 (Prototype Pollution)")
    assert console_errors == []
