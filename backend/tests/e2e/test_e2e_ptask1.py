import json
import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e

KEV = {"cve": "CVE-2022-24999", "dateAdded": "2026-01-15", "dueDate": "2026-02-05",
       "requiredAction": "Apply updates per vendor instructions.",
       "knownRansomwareCampaignUse": "Unknown", "vulnerabilityName": "qs prototype pollution"}


def findings(page, base_url):
    page.goto(base_url + "/")
    page.get_by_role("button", name="Try the demo project").click()
    expect(page.locator(".card--ready")).to_be_visible()
    page.locator('[data-nav="findings"]').click()
    expect(page.locator(".frow").first).to_be_visible()


def qs_row(page):
    return page.locator(".frow").filter(has_text="GHSA-hrpp-h998-j3pp").filter(
        has=page.locator(".frow__name", has_text="qs@6.7.0"))


def test_ptask1_epss_chip_kpis_filter_and_drawer(page, base_url, console_errors):
    findings(page, base_url)
    expect(qs_row(page).locator(".epss")).to_have_text("EPSS 96th")
    expect(page.locator('.kpistrip__cell[data-sev="kev"] .kpistrip__k')).to_have_text("In CISA KEV")
    expect(page.locator('.kpistrip__cell[data-sev="kev"] .kpistrip__v')).to_have_text("0")
    total = page.locator(".frow").count()
    page.get_by_role("group", name="Exploited").get_by_role("button", name="EPSS ≥80th").click()
    expect(page.locator(".fcount")).not_to_have_text(f"{total} of {total} shown")
    tiers = page.locator(".frow .epss").evaluate_all("els => els.map(e => e.dataset.tier)")
    assert tiers and set(tiers) <= {"warm", "hot"}
    assert page.locator(".frow").count() == len(tiers)
    qs_row(page).click()
    card = page.locator(".xcard")
    expect(card).to_contain_text("Not in CISA KEV · EPSS scored")
    expect(card).to_contain_text("Not in CISA KEV as of")
    expect(card.locator(".xmeter__v")).to_have_text("96th")
    expect(card).to_contain_text("not an observation")
    expect(page.locator(".signal").filter(has_text="Exploitation")).to_contain_text("+8")
    expect(page.locator("#ev-E7")).to_contain_text("EPSS")
    assert console_errors == []


def test_ptask1_kev_badge_and_card(page, base_url, console_errors):
    def listed(route):
        resp = route.fetch()
        body = resp.json()
        items = body.get("items", [body])
        for f in items:
            if f["advisory"]["id"] == "GHSA-hrpp-h998-j3pp" and f.get("exploit"):
                f["exploit"].update(status="listed", kev=KEV)
        route.fulfill(response=resp, body=json.dumps(body))

    page.route(re.compile(r".*/api/jobs/[0-9a-f]+/findings(/f_\w+)?(\?.*)?$"), listed)
    findings(page, base_url)
    expect(qs_row(page).locator(".xbadge")).to_have_text("Known exploited")
    expect(page.locator('.kpistrip__cell[data-sev="kev"] .kpistrip__v')).not_to_have_text("0")
    qs_row(page).click()
    card = page.locator(".xcard")
    expect(card).to_have_attribute("data-status", "listed")
    expect(card).to_contain_text("Known exploited (CISA KEV)")
    expect(card.locator(".xkev")).to_contain_text("2026-01-15")
    expect(card.locator(".xkev")).to_contain_text("Ransomware use")
    assert console_errors == []
