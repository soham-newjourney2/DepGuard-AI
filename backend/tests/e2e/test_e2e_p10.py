import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def demo(page, base_url):
    page.goto(base_url + "/")
    page.get_by_role("button", name="Try the demo project").click()
    expect(page.locator(".card--ready")).to_be_visible()


def test_p10_policy_chip_and_reachability_evidence(page, base_url, console_errors):
    demo(page, base_url)
    page.locator('[data-nav="findings"]').click()
    chip = page.locator(".policychip")
    expect(chip).to_have_text("Policy FAIL · 2 violations")
    expect(chip).to_have_attribute("title", "default: fails on critical or worse")
    page.locator(".frow").filter(has_text="GHSA-hrpp-h998-j3pp").filter(
        has=page.locator(".frow__name", has_text="qs@6.7.0")).click()
    expect(page.locator("#ev-E5")).to_contain_text("express, which pulls in qs, is imported at "
                                                   "index.js:1")
    expect(page.locator(".signal").filter(has_text="Reachability")).to_contain_text("+6")
    assert console_errors == []


def test_p10_batch_plan_view(page, base_url):
    demo(page, base_url)
    page.locator('[data-nav="findings"]').click()
    page.get_by_role("link", name="Plan all fixes").click()
    expect(page).to_have_url(re.compile(r"#/jobs/[0-9a-f]{32}/plan$"))
    expect(page.locator('.pgroup[data-status="conflict"]')).to_contain_text("path-to-regexp@0.1.7")
    expect(page.locator('.pgroup[data-status="no_fix"]')).to_contain_text("request@2.88.2")
    expect(page.locator(".diff")).to_contain_text('"overrides"')
    page.get_by_role("button", name="Approve & verify all").click()
    page.get_by_role("button", name="Approve & run verification").click()
    expect(page.locator(".vresult .chip").first).to_have_text("VERIFIED", timeout=20_000)


def test_p10_report_has_sbom_and_policy(page, base_url):
    demo(page, base_url)
    page.locator('[data-nav="report"]').click()
    expect(page.locator(".rpolicy")).to_contain_text("Before FAIL · 2")
    link = page.get_by_role("link", name="SBOM (CycloneDX)")
    resp = page.request.get(base_url + link.get_attribute("href"))
    assert resp.ok and resp.json()["specVersion"] == "1.5"


def test_p10_github_form_validates_client_side(page, base_url):
    page.goto(base_url + "/")
    form = page.get_by_role("form", name="Scan a GitHub repository or a live website")
    form.get_by_role("textbox").fill("not a repo")
    form.get_by_role("button", name="Scan").click()
    expect(page.locator(".toast")).to_contain_text("owner/repo")
    assert "#/jobs/" not in page.url
