"""Planted risks are built at run time so no secret-looking string is committed."""
import json
import re
import zipfile

import pytest
from helpers import real
from playwright.sync_api import expect

from app.config import ROOT

pytestmark = pytest.mark.e2e

AWS = "AKIA" + "Q" * 4 + "7RTZ3XWVN2BM"
ENVVAL = "Zk29xTq81LmPw7"


def planted_zip(tmp_path):
    src = real(ROOT / "samples" / "clean-demo")
    manifest = json.loads((src / "package.json").read_text("utf-8"))
    manifest["dependencies"]["expresss"] = "1.0.0"
    lock = json.loads((src / "package-lock.json").read_text("utf-8"))
    lock["packages"][""]["dependencies"]["expresss"] = "1.0.0"
    lock["packages"]["node_modules/expresss"] = {
        "version": "1.0.0", "resolved": "git+https://github.com/someone/expresss.git#0123abc"}
    path = tmp_path / "planted.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("package.json", json.dumps(manifest, indent=2))
        zf.writestr("package-lock.json", json.dumps(lock, indent=2))
        zf.writestr("index.js", "module.exports = require('ms');\n")
        zf.writestr(".env", f"API_TOKEN={ENVVAL}\n")
        zf.writestr("src/config.js", f"module.exports = {{ key: '{AWS}' }};\n")
    return path


def test_ptask2_supply_chain_view_groups_and_masks(page, base_url, console_errors, tmp_path):
    page.goto(base_url + "/")
    page.locator(".drop input[type=file]").set_input_files(str(planted_zip(tmp_path)))
    expect(page.locator(".card--ready")).to_be_visible()
    page.get_by_role("link", name=re.compile(r"^Supply chain · \d+ signals$")).click()
    expect(page.locator(".fhead__meta")).to_contain_text("signals, not verdicts")
    for kind, n in (("integrity", "1"), ("typosquat", "1"), ("secret", "2"), ("malware", "0")):
        expect(page.locator(f'.rkstrip .kpistrip__cell[data-kind="{kind}"] .kpistrip__v')
               ).to_have_text(n)
    expect(page.locator('.rkgroup[data-kind="typosquat"]')).to_contain_text(
        "expresss@1.0.0 looks like a typosquat of express")
    expect(page.locator('.rkgroup[data-kind="integrity"]')).to_contain_text(
        "expresss@1.0.0 is resolved from a git URL")
    expect(page.locator('.rkgroup[data-kind="malware"]')).to_have_count(0)
    page.locator(".rkrow").filter(has_text="AWS access key id").click()
    drawer = page.get_by_role("dialog", name="Risk detail")
    expect(drawer).to_contain_text("src/config.js:1")
    expect(drawer).to_contain_text("value not shown")
    assert AWS not in page.content() and ENVVAL not in page.content()
    page.keyboard.press("Escape")
    expect(drawer).to_be_hidden()
    job = re.search(r"#/jobs/([0-9a-f]+)/", page.url).group(1)
    page.goto(f"{base_url}/#/jobs/{job}/report")
    expect(page.locator(".rsec--risks .rsec__n")).to_have_text("4")
    expect(page.locator(".rsec--risks")).to_contain_text("2 secrets in the code")
    assert AWS not in page.content()
    assert console_errors == []


def test_ptask2_demo_without_signals_shows_empty_state(page, base_url, console_errors):
    page.goto(base_url + "/")
    page.get_by_role("button", name="Try the demo project").click()
    expect(page.locator(".card--ready")).to_be_visible()
    expect(page.get_by_role("link", name=re.compile("^Supply chain ·"))).to_have_count(0)
    page.locator('[data-nav="risks"]').click()
    expect(page.locator(".card--ready.clean")).to_contain_text("cannot prove the dependencies "
                                                               "are safe")
    assert console_errors == []


def test_ptask2_malware_row_treatment(page, base_url, console_errors):
    def malicious(route):
        resp = route.fetch()
        body = resp.json()
        items = body.get("items", [body])
        for f in items:
            if f["advisory"]["id"] == "GHSA-hrpp-h998-j3pp":
                f["malicious"] = True
        route.fulfill(response=resp, body=json.dumps(body))

    page.route(re.compile(r".*/api/jobs/[0-9a-f]+/findings(/f_\w+)?(\?.*)?$"), malicious)
    page.goto(base_url + "/")
    page.get_by_role("button", name="Try the demo project").click()
    expect(page.locator(".card--ready")).to_be_visible()
    page.locator('[data-nav="findings"]').click()
    row = page.locator(".frow--mal").first
    expect(row.locator(".xbadge--mal")).to_have_text("Malware")
    row.click()
    expect(page.locator(".malnote")).to_contain_text("Upgrading is not a fix")
    assert console_errors == []


def test_ptask2_supplychain_demo_end_to_end(page, base_url, console_errors):
    page.goto(base_url + "/")
    page.get_by_role("button", name="Supply-chain demo").click()
    expect(page.locator(".card--ready")).to_be_visible()
    page.get_by_role("link", name="Compare with answer key").click()
    section = page.locator(".akrisks")
    expect(section.locator(".rsec__n")).to_have_text("5/5 planted found")
    expect(section.locator('.akrow[data-status="matched"]')).to_have_count(5)
    page.locator('[data-nav="risks"]').click()
    expect(page.locator('.rkstrip .kpistrip__cell[data-kind="malware"] .kpistrip__v')
           ).to_have_text("1")
    expect(page.locator('.rkgroup[data-kind="malware"]')).to_contain_text(
        "loadyaml@1.0.2 is a known malicious package (MAL-2025-25475)")
    page.locator('[data-nav="findings"]').click()
    expect(page.locator(".frow--mal")).to_have_count(2)
    page.locator(".frow--mal").first.click()
    expect(page.locator(".malnote")).to_be_visible()
    assert console_errors == []
