#!/usr/bin/env python3
"""Establish an operator-approved browser session without persisting credentials."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright


LOGIN_STEP_TIMEOUT_MS = 15_000
LOGIN_RESULT_TIMEOUT_SECONDS = 10


def _log(message: str) -> None:
    print(message, flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    os.chmod(output, 0o700)
    config = json.loads(os.environ["EXPOSURESCOPEX_WEB_AUTH_JSON"])
    login_url = str(config["login_url"])
    hostname = urlsplit(login_url).hostname or ""
    launch_args: list[str] = []
    resolved_ip = None
    if hostname.endswith(".localhost"):
        resolved_ip = socket.gethostbyname(hostname)
        launch_args.append(f"--host-resolver-rules=MAP {hostname} {resolved_ip}")

    state_path = output / "web-auth-storage-state.json"
    cookie_path = output / "web-auth-cookie.txt"
    screenshot_path = output / "web-authenticated-session.png"
    with sync_playwright() as playwright:
        _log(f"Resolving authenticated login page for {hostname}")
        browser = playwright.chromium.launch(headless=True, args=launch_args)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.set_default_timeout(LOGIN_STEP_TIMEOUT_MS)
        page.set_default_navigation_timeout(LOGIN_STEP_TIMEOUT_MS)
        page.goto(login_url, wait_until="domcontentloaded", timeout=LOGIN_STEP_TIMEOUT_MS)
        username_selector = f'[name="{config.get("username_field", "username")}"]'
        password_selector = f'[name="{config.get("password_field", "password")}"]'
        page.locator(username_selector).fill(str(config["username"]))
        page.locator(password_selector).fill(str(config["password"]))
        _log("Submitting the configured login form")
        page.locator('button[type="submit"], input[type="submit"]').first.click(
            no_wait_after=True,
            timeout=LOGIN_STEP_TIMEOUT_MS,
        )

        # Do not wait twice for a navigation event that may have already fired.
        # Instead, observe the post-submit URL/form state with a short bounded poll.
        deadline = time.monotonic() + LOGIN_RESULT_TIMEOUT_SECONDS
        expected = config.get("success_url_pattern")
        while time.monotonic() < deadline:
            current_url = page.url
            if expected and re.search(str(expected), current_url):
                break
            if not expected and current_url.rstrip("/") != login_url.rstrip("/"):
                break
            page.wait_for_timeout(200)
        final_url = page.url
        if expected and not re.search(str(expected), final_url):
            raise RuntimeError("Authenticated URL did not match the configured success pattern")
        if not expected and final_url.rstrip("/") == login_url.rstrip("/"):
            login_form_visible = page.locator(username_selector).is_visible() and page.locator(password_selector).is_visible()
            if login_form_visible:
                raise RuntimeError("Login remained on the configured login form")
        context.storage_state(path=str(state_path))
        os.chmod(state_path, 0o600)
        cookies = context.cookies()
        cookie_header = "; ".join(f'{item["name"]}={item["value"]}' for item in cookies)
        if not cookie_header:
            raise RuntimeError("Login produced no browser session cookies")
        cookie_path.write_text(cookie_header, encoding="utf-8")
        os.chmod(cookie_path, 0o600)
        page.screenshot(path=str(screenshot_path), full_page=True)
        browser.close()
        _log(f"Authenticated session reached {final_url}")

    metadata = {
        "schema_version": 1,
        "capture_type": "authenticated_session_establishment",
        "login_url": login_url,
        "final_url": final_url,
        "resolved_ip": resolved_ip,
        "cookie_names": sorted(item["name"] for item in cookies),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "storage_state_sha256": hashlib.sha256(state_path.read_bytes()).hexdigest(),
        "screenshot_sha256": hashlib.sha256(screenshot_path.read_bytes()).hexdigest(),
    }
    (output / "web-auth-session.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"Authenticated browser session established for {hostname}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
