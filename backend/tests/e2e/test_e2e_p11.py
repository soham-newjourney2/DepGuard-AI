import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def demo(page, base_url):
    page.goto(base_url + "/")
    page.get_by_role("button", name="Try the demo project").click()
    expect(page.locator(".card--ready")).to_be_visible()


def test_p11_palette_navigates(page, base_url, console_errors):
    demo(page, base_url)
    page.keyboard.press("Control+k")
    palette = page.get_by_role("dialog", name="Command palette")
    expect(palette).to_be_visible()
    expect(palette.get_by_role("combobox")).to_be_focused()
    page.keyboard.type("graph")
    expect(palette.get_by_role("option")).to_have_count(1)
    page.keyboard.press("Enter")
    expect(page).to_have_url(re.compile(r"/graph$"))
    expect(palette).to_have_count(0)
    assert console_errors == []


def test_p11_palette_keyboard_and_escape(page, base_url):
    demo(page, base_url)
    page.keyboard.press("Control+k")
    palette = page.get_by_role("dialog", name="Command palette")
    page.keyboard.press("ArrowDown")
    expect(palette.locator(".palette__item.is-sel")).to_have_count(1)
    page.keyboard.type("zzzz")
    expect(palette).to_contain_text("No matching command")
    page.keyboard.press("Escape")
    expect(palette).to_have_count(0)


def test_p11_shortcut_sheet(page, base_url):
    page.goto(base_url + "/")
    page.locator("body").press("?")
    sheet = page.get_by_role("dialog", name="Keyboard shortcuts")
    expect(sheet).to_contain_text("Command palette")
    expect(sheet).to_contain_text("Next / previous finding")
    page.keyboard.press("Escape")
    expect(sheet).to_have_count(0)


def test_p11_light_theme_persists(page, base_url):
    page.goto(base_url + "/")
    page.keyboard.press("Control+k")
    page.keyboard.type("light theme")
    page.keyboard.press("Enter")
    expect(page.locator("html")).to_have_attribute("data-theme", "light")
    bg = page.evaluate("getComputedStyle(document.body).backgroundColor")
    assert bg == "rgb(245, 246, 248)"
    page.reload()
    expect(page.locator("html")).to_have_attribute("data-theme", "light")
    page.keyboard.press("Control+k")
    page.keyboard.type("dark theme")
    page.keyboard.press("Enter")
    expect(page.locator("html")).to_have_attribute("data-theme", "dark")
