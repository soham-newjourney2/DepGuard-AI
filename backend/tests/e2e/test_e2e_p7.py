import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def open_fix(page, base_url, row_text, advisory=None):
    page.goto(base_url + "/")
    page.get_by_role("button", name="Try the demo project").click()
    expect(page.locator(".card--ready")).to_be_visible()
    page.locator('[data-nav="findings"]').click()
    name = page.locator(".frow__name", has_text=re.compile(f"^{re.escape(row_text)}$"))
    row = page.locator(".frow").filter(has=name)
    if advisory:
        row = row.filter(has_text=advisory)
    row.first.click()
    page.get_by_role("link", name="Propose a fix").click()
    expect(page).to_have_url(re.compile(r"#/jobs/[0-9a-f]{32}/fix/f_[0-9a-f]{12}$"))
    expect(page.locator(".scard").first).to_be_visible()


def test_p7_parent_bump_diff_for_qs(page, base_url, console_errors):
    open_fix(page, base_url, "qs@6.7.0", "GHSA-hrpp-h998-j3pp")
    expect(page.get_by_role("heading", level=1)).to_have_text("Fix qs@6.7.0")
    cards = page.get_by_role("radio")
    expect(cards).to_have_count(2)
    expect(cards.first).to_have_attribute("aria-checked", "true")
    expect(cards.first).to_contain_text("Upgrade the parent")
    added = page.locator(".diff__row--add")
    expect(added).to_have_count(1)
    expect(added).to_contain_text('"express": "4.22.3"')
    expect(added.locator("mark")).to_have_text("22.3")
    expect(page.locator(".warnbox")).to_contain_text("predicted from the registry")
    href = page.get_by_role("link", name="Download .patch").get_attribute("href")
    assert re.fullmatch(r"/api/jobs/[0-9a-f]{32}/patch\?pid=p_[0-9a-f]{12}", href)
    assert console_errors == []


def test_p7_switch_to_override(page, base_url):
    open_fix(page, base_url, "qs@6.7.0", "GHSA-hrpp-h998-j3pp")
    override = page.get_by_role("radio").filter(has_text="npm override")
    override.click()
    expect(override).to_have_attribute("aria-checked", "true")
    expect(page.locator(".diff")).to_contain_text('"overrides"')
    expect(page.locator(".warnbox")).to_contain_text("outside express@4.17.1's declared range")
    expect(override.locator(".conf")).to_have_text("low confidence")


def test_p7_confirm_modal_lists_what_runs(page, base_url):
    open_fix(page, base_url, "express@4.17.1")
    approve = page.get_by_role("button", name="Approve & verify")
    approve.click()
    modal = page.get_by_role("dialog")
    expect(modal).to_be_visible()
    expect(modal).to_contain_text("npm install --package-lock-only --ignore-scripts")
    expect(modal).to_contain_text("npm test --if-present")
    expect(page.get_by_role("button", name="Cancel")).to_be_focused()
    page.keyboard.press("Escape")
    expect(modal).to_have_count(0)
    expect(approve).to_be_focused()


def test_p7_request_has_no_fix(page, base_url):
    open_fix(page, base_url, "request@2.88.2")
    expect(page.get_by_role("radio")).to_have_count(1)
    expect(page.get_by_role("radio")).to_contain_text("No safe upgrade")
    expect(page.get_by_role("button", name="Approve & verify")).to_be_disabled()
    expect(page.locator(".warnbox")).to_contain_text("No published version of request")
    expect(page.locator(".diff")).to_have_count(0)
    expect(page.locator(".fixdetail")).not_to_contain_text("null")


def test_p7_fix_view_fits_mobile(page, base_url):
    page.set_viewport_size({"width": 390, "height": 844})
    open_fix(page, base_url, "qs@6.7.0", "GHSA-hrpp-h998-j3pp")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
