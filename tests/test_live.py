"""Quick check of the live site. Read-only: it never signs up, posts or changes anything."""
import os, re
import requests
from playwright.sync_api import sync_playwright

SITE = os.environ.get("LIVE_URL", "https://trailconstruct.com").rstrip("/")


def test_health():
    r = requests.get(SITE + "/api/health", timeout=30)
    assert r.status_code == 200 and r.json().get("ok") is True, f"health check failed: {r.status_code} {r.text[:300]}"


def test_homepage_and_guide_render():
    errors = []
    with sync_playwright() as p:
        b = p.chromium.launch()
        for path, text in [("/", "TrailConstruct"), ("/#guide", "TrailConstruct")]:
            page = b.new_page()  # a fresh page each time: a change after "#" alone isn't a new page load
            page.on("pageerror", lambda e: errors.append(f"JS error: {e}"))
            r = page.goto(SITE + path)
            assert r and r.status == 200, f"{path} returned {r and r.status}"
            page.wait_for_load_state("load")
            page.wait_for_timeout(2000)  # the app keeps polling, so the network never goes idle
            assert text in page.inner_text("body"), f"{path} didn't render"
        b.close()
    assert not errors, "\n".join(errors)
