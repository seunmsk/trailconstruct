"""End-to-end check: clicks through the developer, site engineer and investor sides of TrailConstruct.

Runs against a local copy of the app (BASE_URL, default http://localhost:8788) with a fresh database.
It creates its own test accounts, so never point it at the live site.
"""
import os, re, time, datetime
import requests
from playwright.sync_api import sync_playwright, expect

BASE = os.environ.get("BASE_URL", "http://localhost:8788").rstrip("/")
OUT = os.environ.get("E2E_OUT", "e2e-output")
T = str(int(time.time()))
TODAY = datetime.date.today().isoformat()
# Messages from the browser that aren't app bugs (blocked fonts, maps, favicon and so on in CI).
IGNORE = re.compile(r"fonts\.(googleapis|gstatic)|maps\.googleapis|favicon|ERR_NAME_NOT_RESOLVED|ERR_INTERNET_DISCONNECTED|net::ERR_|status of 401", re.I)


def api(method, path, body=None, cookie=None):
    r = requests.request(method, BASE + path, json=body, headers={"cookie": cookie} if cookie else {}, timeout=30)
    assert r.status_code < 400, f"{method} {path} -> {r.status_code} {r.text[:200]}"
    return r


def signup(name, email):
    r = api("POST", "/api/auth/signup", {"name": name, "email": email, "password": "password123"})
    return r.headers["set-cookie"].split(";")[0]


def setup_project():
    dev = signup("Test Developer", f"dev{T}@example.com")
    pid = "e2e" + T
    api("PUT", f"/api/docs/projects/{pid}", {"name": "E2E Palm Court", "location": "Lekki", "checks": {}}, dev)
    people = {}
    for role, name in [("engineer", "Test Engineer"), ("investor", "Test Investor")]:
        code = api("POST", "/api/invites", {"pid": pid, "role": role, "name": name}, dev).json()["code"]
        c = signup(name, f"{role[:3]}{T}@example.com")
        api("POST", "/api/invites/accept", {"code": code}, c)
        people[role] = c
    return pid, dev, people["engineer"], people["investor"]


class Watch:
    """Collects JavaScript errors and failed app requests while a page is used."""

    def __init__(self, page, who):
        self.errors = []
        page.on("pageerror", lambda e: self.errors.append(f"[{who}] JS error: {e}"))
        page.on("console", lambda m: m.type == "error" and not IGNORE.search(m.text) and self.errors.append(f"[{who}] console: {m.text[:200]}"))
        page.on("response", lambda r: "/api/" in r.url and r.status >= 500 and self.errors.append(f"[{who}] server error {r.status} {r.url}"))


def open_as(browser, cookie, role, watches):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    if cookie:
        name, value = cookie.split("=", 1)
        ctx.add_cookies([{"name": name, "value": value, "url": BASE}])
    page = ctx.new_page()
    watches.append(Watch(page, role))
    page.goto(f"{BASE}/#{role}" if cookie else BASE + "/")
    settle(page)
    return page


def settle(page):
    # The app keeps checking for new data, so the network never goes fully quiet. Wait for the page instead.
    page.wait_for_load_state("load")
    page.wait_for_timeout(1500)


def every_tab(page, who):
    """Opens each tab on this side of the app and checks it shows something."""
    tabs = page.locator("nav.tabs [role=tab]")
    names = [tabs.nth(i).inner_text().split("\n")[0].strip() for i in range(tabs.count())]
    assert names, f"{who}: no tabs found"
    for i, name in enumerate(names):
        page.locator("nav.tabs [role=tab]").nth(i).click()
        page.wait_for_timeout(400)
        assert page.locator("main, #app").first.inner_text().strip(), f"{who}: '{name}' tab is empty"
        page.screenshot(path=f"{OUT}/{who}-{i}-{re.sub(r'[^a-z]+', '-', name.lower())}.png")
    return names


def tab(page, name):
    page.locator("nav.tabs [role=tab]", has_text=name).first.click()
    page.wait_for_timeout(400)


def test_all_three_sides():
    os.makedirs(OUT, exist_ok=True)
    pid, dev, eng, inv = setup_project()
    watches = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            # Public homepage
            home = open_as(browser, None, "public", watches)
            expect(home.locator("body")).to_contain_text("TrailConstruct")
            home.screenshot(path=f"{OUT}/public-home.png", full_page=False)

            # Developer: every tab
            d = open_as(browser, dev, "developer", watches)
            expect(d.locator("body")).to_contain_text("E2E Palm Court")
            print("developer tabs:", every_tab(d, "developer"))

            # Engineer: every tab, post today's update, request materials
            e = open_as(browser, eng, "engineer", watches)
            expect(e.locator("body")).to_contain_text("E2E Palm Court")
            print("engineer tabs:", every_tab(e, "engineer"))
            tab(e, "Today")
            e.fill("#lg-work", "E2E: blockwork on ground floor")
            e.fill("#lg-workers", "12")
            if e.locator("#lg-by").count():
                e.fill("#lg-by", "Test Engineer")
            e.locator("#log-form button[type=submit]").click()
            expect(e.locator("body")).to_contain_text("Update posted", timeout=15000)
            tab(e, "Materials")
            e.fill("#rq-item", "Cement (E2E)")
            e.fill("#rq-qty", "100")
            e.fill("#rq-need", TODAY)
            e.locator("#req-form button[type=submit]").click()
            expect(e.locator("body")).to_contain_text("Request sent", timeout=15000)

            # Developer: sees the update, approves part of the request, marks it sent
            d.reload(); settle(d)
            tab(d, "Site reports")
            expect(d.locator("body")).to_contain_text("blockwork on ground floor", timeout=15000)
            tab(d, "Materials")
            d.locator("form[data-form=mat-approve] input[id^=aq-]").first.fill("60")
            d.locator("form[data-form=mat-approve] button[type=submit]").first.click()
            expect(d.locator("body")).to_contain_text("To buy", timeout=15000)
            d.locator("details.send summary").first.click()
            d.locator("form[data-form=mat-sent] input[id^=ss-]").first.fill("E2E Supplier")
            d.locator("form[data-form=mat-sent] button[type=submit]").first.click()
            expect(d.locator("body")).to_contain_text("On the way", timeout=15000)

            # Engineer: confirms 55 arrived with 5 damaged, so it should be 10 short
            e.reload(); settle(e)
            tab(e, "Materials")
            e.locator("form[data-form=mat-recv] input[id^=rv-]").first.fill("55")
            e.locator("form[data-form=mat-recv] input[id^=rd-]").first.fill("5")
            e.locator("form[data-form=mat-recv] button[type=submit]").first.click()
            expect(e.locator("body")).to_contain_text("short", timeout=15000)

            # Investor: every tab
            i = open_as(browser, inv, "investor", watches)
            expect(i.locator("body")).to_contain_text("E2E Palm Court")
            print("investor tabs:", every_tab(i, "investor"))
        except Exception:
            for n, pg in enumerate(pg for ctx in browser.contexts for pg in ctx.pages):
                pg.screenshot(path=f"{OUT}/failure-{n}.png", full_page=True)
            raise
        finally:
            browser.close()

    # The server's own record agrees with what the screens showed.
    docs = api("GET", "/api/data?since=0", cookie=dev).json()["docs"]
    logs = [x["data"] for x in docs["logs"] if x["data"]["pid"] == pid]
    req = [x["data"] for x in docs["matreqs"] if x["data"]["pid"] == pid]
    stock = [x["data"] for x in docs["stock"] if x["data"]["pid"] == pid]
    assert logs and logs[0]["workers"] == 12, "daily update wasn't saved"
    assert req and req[0]["status"] == "short" and req[0]["shortBy"] == 10, f"material request ended as {req and req[0].get('status')}"
    assert stock and stock[0]["qty"] == 50, "received materials weren't added to the store log"

    errors = [x for w in watches for x in w.errors]
    assert not errors, "Problems seen in the browser:\n" + "\n".join(errors)
