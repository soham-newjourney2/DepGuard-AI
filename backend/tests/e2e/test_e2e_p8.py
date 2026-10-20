import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def approve_qs(page, base_url):
    page.goto(base_url + "/")
    page.get_by_role("button", name="Try the demo project").click()
    expect(page.locator(".card--ready")).to_be_visible()
    page.locator('[data-nav="findings"]').click()
    page.locator(".frow").filter(has_text="GHSA-hrpp-h998-j3pp").filter(
        has=page.locator(".frow__name", has_text="qs@6.7.0")).click()
    page.get_by_role("link", name="Propose a fix").click()
    page.get_by_role("button", name="Approve & verify").click()
    page.get_by_role("button", name="Approve & run verification").click()
    expect(page).to_have_url(re.compile(r"#/jobs/[0-9a-f]{32}/verify/p_[0-9a-f]{12}$"))


def test_p8_mock_verification_streams_and_verifies(page, base_url, console_errors):
    approve_qs(page, base_url)
    result = page.locator(".vresult")
    expect(result).to_be_visible(timeout=20_000)
    expect(result.locator(".chip").first).to_have_text("VERIFIED")
    expect(result).to_contain_text("Simulated verification (test mode)")
    for stage in ("approved", "resolve", "test", "rescan", "result"):
        step = page.locator(f'.vstep[data-stage="{stage}"]')
        expect(step).to_have_attribute("data-state", "done")
    terminal = page.get_by_role("log")
    expect(terminal).to_contain_text("npm install --package-lock-only --ignore-scripts")
    expect(terminal).to_contain_text("npm test --if-present")
    expect(terminal.locator(".ansi-green").first).to_be_visible()
    expect(page.locator('.xchip[data-stage="test"]')).to_have_text("test · exit 0")
    assert terminal.get_by_text("npm test --if-present").count() == 1, "no duplicated log"
    expect(result.locator(".kpi").filter(has_text="Target resolved")).to_contain_text("Yes")
    result.locator("summary", has_text="package-lock.json diff").click()
    expect(result.locator(".diff__row--add").first).to_be_visible()
    assert console_errors == []


def test_p8_reload_shows_stored_result(page, base_url):
    approve_qs(page, base_url)
    expect(page.locator(".vresult")).to_be_visible(timeout=20_000)
    page.reload()
    expect(page.locator(".vresult .chip").first).to_have_text("VERIFIED")
    expect(page.get_by_role("log")).to_contain_text("npm ci --ignore-scripts")


def test_p8_fix_view_links_to_existing_verification(page, base_url):
    approve_qs(page, base_url)
    expect(page.locator(".vresult")).to_be_visible(timeout=20_000)
    page.go_back()
    expect(page.get_by_role("link", name="View verification")).to_be_visible()
