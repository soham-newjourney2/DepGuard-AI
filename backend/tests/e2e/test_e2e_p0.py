import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e

CANVAS = "canvas.hero__fx"


def snapshot(page) -> str:
    return page.locator(CANVAS).evaluate("c => c.toDataURL()")


def test_p0_landing_loads_without_console_errors(page, base_url, console_errors):
    page.goto(base_url + "/")
    expect(page.get_by_role("heading", level=1)).to_have_text(
        "Know which dependency actually puts you at risk.")
    expect(page.locator('.pill[data-state="ok"]')).to_have_count(2)
    expect(page.locator(".pill").filter(has_text="template")).to_be_visible()
    page.wait_for_load_state("networkidle")
    assert console_errors == []


def test_p0_hero_canvas_animates(page, base_url):
    page.goto(base_url + "/")
    expect(page.locator(CANVAS)).to_be_visible()
    page.wait_for_timeout(300)
    first = snapshot(page)
    page.wait_for_timeout(700)
    assert snapshot(page) != first


def test_p0_reduced_motion_is_static(browser, base_url):
    ctx = browser.new_context(reduced_motion="reduce")
    page = ctx.new_page()
    page.goto(base_url + "/")
    page.wait_for_timeout(300)
    first = snapshot(page)
    page.wait_for_timeout(700)
    assert snapshot(page) == first
    blank = page.locator(CANVAS).evaluate(
        "c => { const b = document.createElement('canvas'); b.width = c.width;"
        " b.height = c.height; return b.toDataURL(); }")
    assert first != blank
    ctx.close()


def test_p0_dom_h_never_parses_html(page, base_url):
    page.goto(base_url + "/")
    html, kids, threw = page.evaluate("""async () => {
        const { h } = await import('/js/dom.js');
        const el = h('div', { title: '"><img src=x>' }, '<img src=x onerror=alert(1)>');
        let threw = false;
        try { h('div', { innerHTML: '<b>x</b>' }); } catch { threw = true; }
        return [el.innerHTML, el.children.length, threw];
    }""")
    assert kids == 0 and "&lt;img" in html and threw


def test_p0_drop_zone_types_filename_and_toasts(page, base_url):
    page.goto(base_url + "/")
    page.locator(".drop input[type=file]").set_input_files(
        {"name": "my-app.zip", "mimeType": "application/zip", "buffer": b"PK\x05\x06" + b"\0" * 18})
    expect(page.locator(".drop__file")).to_have_text("my-app.zip")
    expect(page.locator(".toast")).to_be_visible()


def test_p0_unknown_route_shows_not_found(page, base_url):
    page.goto(base_url + "/#/nowhere")
    expect(page.get_by_text("Nothing at this address.")).to_be_visible()
    page.get_by_role("link", name="Start a new scan").click()
    expect(page.get_by_role("heading", level=1)).to_be_visible()


def test_p0_keyboard_focus_visible(page, base_url):
    page.goto(base_url + "/")
    page.keyboard.press("Tab")
    outline = page.evaluate("getComputedStyle(document.activeElement).outlineStyle")
    assert outline == "solid"


@pytest.mark.parametrize("width", [1440, 1024, 390])
def test_p0_no_horizontal_scroll(page, base_url, width):
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(base_url + "/")
    expect(page.get_by_role("heading", level=1)).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
