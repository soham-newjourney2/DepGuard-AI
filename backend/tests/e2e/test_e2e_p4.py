import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e

QS = "GHSA-hrpp-h998-j3pp"


def start_demo(page, base_url, sample="vuln-demo"):
    page.goto(base_url + "/")
    if sample == "vuln-demo":
        page.get_by_role("button", name="Try the demo project").click()
    else:
        page.evaluate("s => fetch('/api/jobs/demo/' + s, {method: 'POST'}).then(r => r.json())"
                      ".then(d => { location.hash = '#/jobs/' + d.job_id; })", sample)
    expect(page.locator(".card--ready")).to_be_visible()


def open_findings(page, base_url):
    start_demo(page, base_url)
    page.locator(".card--ready").get_by_role("link", name=re.compile(r"View \d+ findings")).click()
    expect(page).to_have_url(re.compile(r"#/jobs/[0-9a-f]{32}/findings$"))
    expect(page.locator(".frow").first).to_be_visible()


def test_p4_demo_qs_finding_path_and_drawer(page, base_url, console_errors):
    open_findings(page, base_url)
    expect(page.get_by_role("heading", level=1)).to_have_text("22 findings")
    expect(page.locator(".fhead__meta")).to_have_text(
        re.compile(r"^95 packages · scanned with fixture at \d{4}-\d\d-\d\d \d\d:\d\d UTC"))
    row = page.locator(".frow").filter(has_text="qs@6.7.0").filter(has_text=QS)
    expect(row).to_have_count(1)
    row.click()
    drawer = page.get_by_role("dialog", name="Finding detail")
    expect(drawer).to_be_visible()
    expect(drawer.locator(".detail__chips")).to_contain_text(QS)
    chain = drawer.locator(".pathchain").filter(has_text="express@4.17.1").first
    expect(chain).to_contain_text("qs@6.7.0")
    expect(drawer.locator(".signal").first).to_contain_text("+30")
    expect(drawer.locator(".ev")).to_have_count(6)
    expect(drawer.locator(".fixline .ver:not(.ver--dim)")).to_have_text("6.7.3")
    page.keyboard.press("Escape")
    expect(drawer).to_be_hidden()
    assert console_errors == []


def test_p4_kpis_filters_and_search(page, base_url):
    open_findings(page, base_url)
    expect(page.locator('.kpistrip__cell[data-sev="critical"] .kpistrip__v')).to_have_text("2")
    page.locator(".fchip", has_text="critical").click()
    expect(page.locator(".frow")).to_have_count(2)
    page.locator(".fchip", has_text="critical").click()
    page.locator(".fchip", has_text="no fix").click()
    expect(page.locator(".frow")).to_have_count(1)
    expect(page.locator(".frow")).to_contain_text("request@2.88.2")
    page.locator(".fchip", has_text="no fix").click()
    page.keyboard.press("/")
    expect(page.locator(".search__input")).to_be_focused()
    page.keyboard.type("minimist")
    rows = page.locator(".frow")
    expect(rows).to_have_count(2)
    expect(rows.first.locator(".scope")).to_have_text("dev")
    page.keyboard.type("zzz-nothing")
    expect(page.get_by_text("No findings match these filters.")).to_be_visible()
    page.get_by_role("button", name="Clear filters").click()
    expect(page.locator(".frow")).to_have_count(22)


def test_p4_keyboard_navigation(page, base_url):
    open_findings(page, base_url)
    page.keyboard.press("j")
    first = page.locator(".frow").first
    expect(first).to_be_focused()
    page.keyboard.press("j")
    expect(page.locator(".frow").nth(1)).to_be_focused()
    page.keyboard.press("k")
    expect(first).to_be_focused()
    page.keyboard.press("Enter")
    expect(page.get_by_role("dialog", name="Finding detail")).to_be_visible()


def test_p4_priority_order_puts_prod_before_dev_critical(page, base_url):
    open_findings(page, base_url)
    names = page.locator(".frow__name").all_inner_texts()
    assert names.index("qs@6.7.0") < names.index("minimist@0.0.8")


def test_p4_clean_demo_honesty_copy(page, base_url):
    start_demo(page, base_url, "clean-demo")
    page.locator(".card--ready").get_by_role("link", name="View result").click()
    expect(page.get_by_text(re.compile(
        r"OSV reported no known advisories for these packages at .+\. "
        r"This is not proof the project is secure\."))).to_be_visible()


def test_p4_nav_rail_enables_findings(page, base_url):
    start_demo(page, base_url)
    link = page.locator('[data-nav="findings"]')
    expect(link).not_to_have_attribute("aria-disabled", "true")
    link.click()
    expect(page.locator(".frow").first).to_be_visible()
    expect(link).to_have_attribute("aria-current", "page")


@pytest.mark.parametrize("width", [1440, 1024, 390])
def test_p4_findings_fit_viewport(page, base_url, width):
    page.set_viewport_size({"width": width, "height": 900})
    open_findings(page, base_url)
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    page.locator(".frow").first.click()
    expect(page.get_by_role("dialog", name="Finding detail")).to_be_visible()
