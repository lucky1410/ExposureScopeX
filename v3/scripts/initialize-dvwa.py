import time

from playwright.sync_api import Error, sync_playwright


BASE_URL = "http://dvwa.lab.internal"
READY_ATTEMPTS = 30


def wait_until_ready(page) -> None:
    last_error = None
    for _ in range(READY_ATTEMPTS):
        try:
            response = page.goto(f"{BASE_URL}/setup.php", wait_until="domcontentloaded", timeout=5_000)
            if response and response.status < 500:
                return
        except Error as exc:
            last_error = exc
        time.sleep(2)
    raise RuntimeError(f"DVWA did not become reachable after {READY_ATTEMPTS * 2} seconds: {last_error}")


def main() -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            wait_until_ready(page)
            create_database = page.locator('input[name="create_db"]')
            if create_database.count() and create_database.first.is_visible():
                create_database.first.click()
                page.wait_for_load_state("domcontentloaded")

            page.goto(f"{BASE_URL}/login.php", wait_until="domcontentloaded")
            page.locator('input[name="username"]').fill("admin")
            page.locator('input[name="password"]').fill("password")
            page.locator('input[name="Login"], input[type="submit"]').first.click()
            page.wait_for_load_state("domcontentloaded")

            password = page.locator('input[name="password"]')
            if page.url.rstrip("/").endswith("login.php") and password.count() and password.first.is_visible():
                raise RuntimeError("DVWA database initialization or default login verification failed")
            print(f"DVWA ready: authenticated at {page.url}")
        finally:
            browser.close()


if __name__ == "__main__":
    main()
