"""Optional local Playwright runner for approved loopback browser journeys."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any
from urllib.parse import urljoin, urlparse

from .runner import RunnerError, _is_loopback_host, sha256


def validate_browser_adapter(adapter: dict[str, Any]) -> None:
    url = adapter.get("base_url")
    parsed = urlparse(url) if isinstance(url, str) else None
    if not parsed or parsed.scheme not in {"http", "https"} or not parsed.hostname or not _is_loopback_host(parsed.hostname):
        raise RunnerError("browser_journey.base_url must be a loopback HTTP(S) URL; remote browser testing is not supported")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RunnerError("browser_journey.base_url must not contain credentials, query strings, or fragments")


def invoke_browser_journeys(adapter: dict[str, Any], cases: list[dict[str, Any]], _evaluation: dict[str, Any]) -> tuple[dict[str, Any], int, str, str]:
    """Run declarative UI actions locally. Assertions yield pass/fail labels."""
    validate_browser_adapter(adapter)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RunnerError("Browser journeys require `pip install exposurescopex-eval-runner[browser]` and `playwright install chromium`") from exc
    started = time.monotonic()
    output: list[dict[str, object]] = []
    response_hash = hashlib.sha256()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=not bool(adapter.get("headed", False)))
        try:
            for case in cases:
                actions = case.get("input", {}).get("journey") if isinstance(case.get("input"), dict) else None
                if not isinstance(actions, list) or not actions:
                    raise RunnerError("Every browser journey case needs a non-empty input.journey action list")
                page = browser.new_page()
                passed = True
                try:
                    for action in actions:
                        _perform(page, adapter["base_url"], action)
                except Exception:  # Assertions are an observed failing test, not a runner crash.
                    passed = False
                finally:
                    page.close()
                result = {"case_id": case["case_id"], "predicted_label": adapter.get("pass_label", "pass") if passed else adapter.get("fail_label", "fail"), "confidence": 1.0}
                output.append(result)
                response_hash.update(json.dumps(result, sort_keys=True).encode("utf-8"))
        finally:
            browser.close()
    response = {"schema_version": "esx-client-adapter-response-2.0", "results": output, "measurements": {}}
    return response, round((time.monotonic() - started) * 1000), sha256([{ "case_id": case["case_id"], "journey_sha256": sha256(case["input"]) } for case in cases]), response_hash.hexdigest()


def _perform(page: Any, base_url: str, action: object) -> None:
    if not isinstance(action, dict) or not isinstance(action.get("type"), str):
        raise RunnerError("Browser journey actions need a type")
    kind, selector = action["type"], action.get("selector")
    if kind == "goto":
        path = action.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            raise RunnerError("Browser goto actions require a same-origin path starting with /")
        page.goto(urljoin(base_url, path), wait_until="networkidle")
    elif kind == "fill" and isinstance(selector, str) and isinstance(action.get("value"), str):
        page.locator(selector).fill(action["value"])
    elif kind == "click" and isinstance(selector, str):
        page.locator(selector).click()
    elif kind == "press" and isinstance(selector, str) and isinstance(action.get("key"), str):
        page.locator(selector).press(action["key"])
    elif kind == "expect_text" and isinstance(action.get("value"), str):
        if action["value"] not in page.locator(selector or "body").inner_text():
            raise AssertionError("Expected browser text was not present")
    elif kind == "expect_visible" and isinstance(selector, str):
        if not page.locator(selector).is_visible():
            raise AssertionError("Expected browser element was not visible")
    else:
        raise RunnerError("Unsupported browser journey action")
