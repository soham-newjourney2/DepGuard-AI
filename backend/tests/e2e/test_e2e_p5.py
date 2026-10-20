import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e

QS = '.gnode[data-label="qs@6.7.0"]'


def open_graph(page, base_url):
    page.goto(base_url + "/")
    page.get_by_role("button", name="Try the demo project").click()
    expect(page.locator(".card--ready")).to_be_visible()
    page.locator('[data-nav="graph"]').click()
    expect(page).to_have_url(re.compile(r"#/jobs/[0-9a-f]{32}/graph$"))
    expect(page.locator(".gsvg")).to_have_attribute("data-settled", "true", timeout=10_000)


def test_p5_graph_renders(page, base_url, console_errors):
    open_graph(page, base_url)
    nodes = page.locator(".gnode")
    assert nodes.count() > 20
    expect(page.locator('.gnode[data-sev="root"]')).to_have_count(1)
    expect(page.locator(QS)).to_have_count(1)
    expect(page.locator(".fhead__meta")).to_contain_text("of 96 packages")
    assert page.locator(".glink").count() > 20
    assert console_errors == []


def test_p5_click_qs_highlights_path_and_opens_drawer(page, base_url):
    open_graph(page, base_url)
    page.locator(QS).dispatch_event("click")
    expect(page.locator(QS)).to_have_class(re.compile(r"\bis-sel\b"))
    for label in ("express@4.17.1", "body-parser@1.19.0"):
        expect(page.locator(f'.gnode[data-label="{label}"]')).to_have_class(re.compile(r"\bis-path\b"))
    expect(page.locator('.gnode[data-sev="root"]')).to_have_class(re.compile(r"\bis-path\b"))
    expect(page.locator('.gnode[data-label="minimist@0.0.8"]')).to_have_class(re.compile(r"\bis-dim\b"))
    assert page.locator(".glink.is-hot").count() >= 3
    drawer = page.get_by_role("dialog", name="Finding detail")
    expect(drawer).to_be_visible()
    expect(drawer.locator(".detail__pkg")).to_contain_text("qs@6.7.0")
    page.keyboard.press("Escape")
    expect(drawer).to_be_hidden()
    page.keyboard.press("Escape")
    expect(page.locator(".gnode.is-dim")).to_have_count(0)


def test_p5_full_mode_and_search(page, base_url):
    open_graph(page, base_url)
    page.get_by_role("button", name="Full graph").click()
    expect(page.locator(".gnode")).to_have_count(96, timeout=10_000)
    page.keyboard.press("/")
    page.keyboard.type("minimist")
    page.keyboard.press("Enter")
    expect(page.locator(".gsvg")).to_have_attribute("data-focus", "node_modules/minimist")


def test_p5_show_in_graph_from_findings(page, base_url):
    open_graph(page, base_url)
    page.keyboard.press("f")
    page.locator(".frow").filter(has_text="minimist@0.0.8").first.click()
    page.get_by_role("link", name="Show in graph →").click()
    expect(page).to_have_url(re.compile(r"/graph\?focus=f_[0-9a-f]{12}$"))
    expect(page.locator(".gsvg")).to_have_attribute("data-focus", "node_modules/minimist",
                                                    timeout=10_000)


def test_p5_reduced_motion_static_layout(browser, base_url):
    ctx = browser.new_context(reduced_motion="reduce")
    page = ctx.new_page()
    open_graph(page, base_url)
    first = page.locator(QS).get_attribute("transform")
    page.wait_for_timeout(400)
    assert page.locator(QS).get_attribute("transform") == first
    ctx.close()


def test_p5_graph_fits_mobile(page, base_url):
    page.set_viewport_size({"width": 390, "height": 844})
    open_graph(page, base_url)
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
