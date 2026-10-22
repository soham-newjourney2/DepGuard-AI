import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize("value,kind", [
    ("https://github.com/expressjs/express/tree/master/examples", "GitHub repo"),
    ("git@github.com:vercel/ms.git", "GitHub repo"),
    ("expressjs/express@4.17.1", "GitHub repo"),
    ("https://example.com/shop?x=1", "Not recognised"),
    ("example.org", "Not recognised"),
    ("not a url", "Not recognised"),
])
def test_p14_unified_input_classifies(page, base_url, value, kind):
    page.goto(base_url + "/")
    page.get_by_label("GitHub repository link").fill(value)
    expect(page.locator(".gh__kind")).to_have_text(kind)


def test_p14_invalid_input_explains_and_stays(page, base_url):
    page.goto(base_url + "/")
    page.get_by_label("GitHub repository link").fill("just words")
    page.get_by_role("button", name="Scan", exact=True).click()
    expect(page.locator(".toast")).to_contain_text("github.com/owner/repo")
    assert "#/jobs/" not in page.url


def test_p14_server_rejects_unsupported_github_page(page, base_url):
    page.goto(base_url + "/")
    page.get_by_label("GitHub repository link").fill(
        "https://github.com/vercel/ms/pull/12")
    page.get_by_role("button", name="Scan", exact=True).click()
    expect(page.locator(".toast")).to_contain_text("pull pages cannot be scanned")
    assert "#/jobs/" not in page.url
