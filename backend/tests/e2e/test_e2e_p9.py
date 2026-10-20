import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def demo(page, base_url):
    page.goto(base_url + "/")
    page.get_by_role("button", name="Try the demo project").click()
    expect(page.locator(".card--ready")).to_be_visible()


def test_p9_full_flow_demo_fix_verify_report(page, base_url, console_errors):
    demo(page, base_url)
    page.locator('[data-nav="findings"]').click()
    page.locator(".frow").filter(has_text="GHSA-hrpp-h998-j3pp").filter(
        has=page.locator(".frow__name", has_text="qs@6.7.0")).click()
    page.get_by_role("link", name="Propose a fix").click()
    page.get_by_role("button", name="Approve & verify").click()
    page.get_by_role("button", name="Approve & run verification").click()
    expect(page.locator(".vresult")).to_be_visible(timeout=20_000)
    page.get_by_role("link", name="Open report").click()
    expect(page).to_have_url(re.compile(r"#/jobs/[0-9a-f]{32}/report\?pid=p_[0-9a-f]{12}$"))
    expect(page.locator(".seal .seal__label")).to_have_text("VERIFIED")
    resolved = page.locator(".rsec--resolved")
    expect(resolved.locator(".rsec__n")).not_to_have_text("0")
    expect(resolved).to_contain_text("GHSA-hrpp-h998-j3pp")
    residual = page.locator(".rsec--still_present .rlist__item")
    assert residual.count() >= 1
    expect(page.locator(".rtests")).to_contain_text("Tests exited 0.")
    expect(page.locator(".rsec").filter(has_text="Audit trail")).to_contain_text(
        "npm test --if-present")
    for label in ("JSON", "Markdown", "HTML", ".patch"):
        expect(page.locator(".downloads").get_by_role("link", name=label)).to_be_visible()
    href = page.locator(".downloads").get_by_role("link", name="HTML").get_attribute("href")
    resp = page.request.get(base_url + href)
    assert resp.ok and "VERIFIED" in resp.text()
    assert "attachment" in resp.headers["content-disposition"]
    assert console_errors == []


def test_p9_report_before_any_fix_is_scan_only(page, base_url):
    demo(page, base_url)
    page.locator('[data-nav="report"]').click()
    expect(page.locator(".seal .seal__label")).to_have_text("Scan only")
    expect(page.locator(".split__na")).to_have_text("No verified rescan yet")
    expect(page.locator(".rtests")).to_contain_text("No verification has run")


def test_p9_report_fits_mobile(page, base_url):
    page.set_viewport_size({"width": 390, "height": 844})
    demo(page, base_url)
    page.locator('[data-nav="report"]').click()
    expect(page.locator(".seal")).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
