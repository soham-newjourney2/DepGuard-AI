import pytest
from conftest import ZIPS
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def demo(page, base_url):
    page.goto(base_url + "/")
    page.get_by_role("button", name="Try the demo project").click()
    expect(page.locator(".card--ready")).to_be_visible()


def test_ptask0b_demo_compares_with_answer_key(page, base_url, console_errors):
    demo(page, base_url)
    page.get_by_role("link", name="Compare with answer key").click()
    expect(page.locator(".fhead__meta")).to_contain_text("Answer key built with npm audit")
    expect(page.locator(".fhead__meta")).to_contain_text("new since answer key")
    for label in ("Matched", "Missed", "Extra", "Found"):
        expect(page.locator(".akstrip .kpistrip__k", has_text=label)).to_be_visible()
    expect(page.locator(".akgrid__head")).to_contain_text("DepGuard · live scan")
    row = page.locator('.akrow[data-status="matched"]').filter(has_text="GHSA-hrpp-h998-j3pp")
    expect(row).to_contain_text("qs@6.7.0")
    expect(row.locator(".chip")).to_have_text("Matched")
    assert page.locator(".akrow").count() >= page.locator('.akrow[data-status="matched"]').count()
    assert console_errors == []


def test_ptask0b_report_has_answer_key_section_for_demo(page, base_url, console_errors):
    demo(page, base_url)
    job = page.url.rsplit("/", 1)[-1]
    page.goto(f"{base_url}/#/jobs/{job}/report")
    section = page.locator(".rsec--answers")
    expect(section.locator(".akstrip")).to_be_visible()
    expect(section.get_by_role("link", name="Open side by side")).to_be_visible()
    assert console_errors == []


def test_ptask0b_upload_has_no_compare(page, base_url, console_errors):
    page.goto(base_url + "/")
    page.locator(".drop input[type=file]").set_input_files(str(ZIPS / "ok_root.zip"))
    expect(page.locator(".card--ready")).to_be_visible()
    expect(page.get_by_role("link", name="Compare with answer key")).to_have_count(0)
    job = page.url.rsplit("/", 1)[-1]
    page.goto(f"{base_url}/#/jobs/{job}/report")
    expect(page.locator(".rsec__title").first).to_be_visible()
    expect(page.locator(".rsec--answers")).to_have_count(0)
    assert console_errors == []
