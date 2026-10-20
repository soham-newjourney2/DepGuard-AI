import re

import pytest
from conftest import ZIPS
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e

JOB_URL = re.compile(r"#/jobs/[0-9a-f]{32}$")
STEPS = ["queued", "extracting", "parsing", "scanning", "analyzing", "ready"]


def pick(page, name):
    page.locator(".drop input[type=file]").set_input_files(str(ZIPS / name))


def expect_ready(page):
    for step in STEPS:
        expect(page.locator(f'.step[data-step="{step}"]')).to_have_attribute("data-state", "done")
    expect(page.locator(".card--ready")).to_be_visible()


def test_p1_upload_reaches_ready(page, base_url, console_errors):
    page.goto(base_url + "/")
    pick(page, "ok_root.zip")
    expect(page).to_have_url(JOB_URL)
    expect(page.get_by_role("heading", level=1)).to_have_text("ok_root.zip")
    expect_ready(page)
    kpis = page.locator(".kpi")
    expect(kpis.filter(has_text="Packages").locator(".kpi__v")).to_have_text("1")
    expect(kpis.filter(has_text="Findings").locator(".kpi__v")).to_have_text("0")
    expect(page.locator('.step[data-step="extracting"] .step__time')).to_have_text(
        re.compile(r"\d\d:\d\d:\d\d\.\d{3}"))
    expect(page.locator(".log__line").filter(has_text="Extracted 3 files")).to_be_visible()
    expect(page.locator(".crumbs [aria-current]")).to_have_text(re.compile(r"Job [0-9a-f]{8}"))
    assert console_errors == []


def test_p1_hostile_zip_shows_error_card_and_retry(page, base_url):
    page.goto(base_url + "/")
    pick(page, "traversal.zip")
    card = page.get_by_role("alert")
    expect(card.locator(".chip--err")).to_have_text("E_PATH_TRAVERSAL")
    expect(card.locator(".card__hint")).not_to_be_empty()
    expect(page.locator('.step[data-step="extracting"]')).to_have_attribute("data-state", "failed")
    expect(page.locator('.step[data-step="parsing"]')).to_have_attribute("data-state", "pending")
    first = page.url
    card.get_by_role("button", name="Retry").click()
    expect(page).not_to_have_url(first)
    expect(page.get_by_role("alert").locator(".chip--err")).to_have_text("E_PATH_TRAVERSAL")
    page.get_by_role("link", name="Choose another file").click()
    expect(page.locator(".drop")).to_be_visible()


def test_p1_demo_button(page, base_url):
    page.goto(base_url + "/")
    page.get_by_role("button", name="Try the demo project").click()
    expect(page).to_have_url(JOB_URL)
    expect(page.get_by_role("heading", level=1)).to_have_text("vuln-demo.zip")
    expect_ready(page)


def test_p1_client_size_check_blocks_upload(page, base_url):
    page.goto(base_url + "/")
    page.locator(".drop input[type=file]").set_input_files(
        {"name": "huge.zip", "mimeType": "application/zip", "buffer": b"\0" * (16 * 1024 * 1024)})
    expect(page.locator(".toast")).to_contain_text("the limit is 15 MB")
    assert "#/jobs/" not in page.url


def test_p1_drop_file_uploads(page, base_url):
    page.goto(base_url + "/")
    data = list((ZIPS / "ok_root.zip").read_bytes())
    page.evaluate("""(bytes) => {
        const dt = new DataTransfer();
        dt.items.add(new File([new Uint8Array(bytes)], 'dropped.zip', { type: 'application/zip' }));
        const zone = document.querySelector('.drop');
        zone.dispatchEvent(new DragEvent('dragenter', { dataTransfer: dt, bubbles: true }));
        zone.dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true }));
    }""", data)
    expect(page).to_have_url(JOB_URL)
    expect(page.get_by_role("heading", level=1)).to_have_text("dropped.zip")
    expect_ready(page)


def test_p1_reload_finished_job_replays_state(page, base_url):
    page.goto(base_url + "/")
    pick(page, "ok_root.zip")
    expect_ready(page)
    page.reload()
    expect_ready(page)
    expect(page.locator('.step[data-step="parsing"] .step__dur')).not_to_be_empty()


def test_p1_unknown_job(page, base_url):
    page.goto(base_url + "/#/jobs/" + "0" * 32)
    expect(page.get_by_text("This job does not exist.")).to_be_visible()


def test_p1_job_page_fits_mobile(page, base_url):
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(base_url + "/")
    pick(page, "ok_root.zip")
    expect_ready(page)
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
