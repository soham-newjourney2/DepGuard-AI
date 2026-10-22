import zipfile

import pytest
from helpers import real
from playwright.sync_api import expect

from app.config import ROOT

pytestmark = pytest.mark.e2e

QS = "GHSA-hrpp-h998-j3pp"


def vuln_zip(tmp_path):
    src = real(ROOT / "samples" / "vuln-demo")
    path = tmp_path / "vuln-demo.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for f in src.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(src).as_posix())
    return path


def open_fix(page):
    page.locator('[data-nav="findings"]').click()
    page.locator(".frow").filter(has_text="qs@6.7.0").filter(has_text=QS).click()
    page.get_by_role("link", name="Propose a fix").click()
    expect(page.locator(".scard").first).to_be_visible()


def test_ptask4_upload_never_offers_approve_and_verify(page, base_url, console_errors, tmp_path):
    page.goto(base_url + "/")
    page.locator(".drop input[type=file]").set_input_files(str(vuln_zip(tmp_path)))
    expect(page.locator(".card--ready")).to_be_visible()
    open_fix(page)
    expect(page.locator(".fixactions")).to_contain_text("Verification covers the bundled npm demos")
    expect(page.get_by_role("button", name="Approve & verify")).to_have_count(0)
    expect(page.locator(".warnbox")).to_contain_text("bundled npm demos only")
    assert console_errors == []


def test_ptask4_demo_still_offers_approve_and_verify(page, base_url, console_errors):
    page.goto(base_url + "/")
    page.get_by_role("button", name="Try the demo project").click()
    expect(page.locator(".card--ready")).to_be_visible()
    open_fix(page)
    expect(page.get_by_role("button", name="Approve & verify")).to_be_enabled()
    assert console_errors == []
