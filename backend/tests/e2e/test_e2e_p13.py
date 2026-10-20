import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def scan_site(page, base_url, site_url):
    page.goto(base_url + "/")
    box = page.get_by_label("GitHub repository or website URL")
    box.fill(site_url)
    expect(page.locator(".gh__kind")).to_have_text("Website")
    page.get_by_role("button", name="Scan", exact=True).click()
    expect(page).to_have_url(re.compile(r"#/jobs/[0-9a-f]{32}$"))
    expect(page.locator('.step[data-step="extracting"] .step__label')).to_have_text("Fetch")
    expect(page.locator(".card--ready")).to_be_visible(timeout=20_000)


def test_p13_site_scan_finds_jquery_with_evidence(page, base_url, site_url, console_errors):
    scan_site(page, base_url, site_url)
    expect(page.locator(".card--ready .eco-badge")).to_have_text("Website")
    expect(page.locator(".card--ready")).to_contain_text("W_NOT_SCANNABLE")
    page.locator('[data-nav="findings"]').click()
    row = page.locator(".frow").filter(has=page.locator(".frow__name", has_text="jquery@3.4.1"))
    row.first.click()
    expect(page.locator("#ev-E5")).to_contain_text("The page loads jquery 3.4.1 at "
                                                   "https://code.jquery.com/jquery-3.4.1.min.js")
    assert console_errors == []


def test_p13_site_fix_is_an_include_diff(page, base_url, site_url):
    scan_site(page, base_url, site_url)
    page.locator('[data-nav="findings"]').click()
    page.locator(".frow").filter(has=page.locator(".frow__name", has_text="jquery@3.4.1")) \
        .first.click()
    page.get_by_role("link", name="Propose a fix").click()
    expect(page.locator(".diff")).to_contain_text("jquery-3.5.0.min.js")
    expect(page.locator(".cmdbox")).to_contain_text("Update the page's jquery include")
    expect(page.get_by_role("button", name="Approve & verify")).to_have_count(0)


def test_p13_private_site_blocked_by_default_message(page, base_url):
    page.goto(base_url + "/")
    box = page.get_by_label("GitHub repository or website URL")
    box.fill("not a url")
    expect(page.locator(".gh__kind")).to_have_text("Not recognised")
