"""Approved local Playwright journeys with explicit authentication and safe diagnostics."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

from .runner import RunnerError, _is_loopback_host, sha256


_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")
_SAFE_ENV = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_SAFE_LOCAL_FILE = re.compile(r"^[A-Za-z0-9._/-]{1,240}$")
_SAFE_IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
_WAIT_UNTIL = {"commit", "domcontentloaded", "load", "networkidle"}
_SELECTOR_STATES = {"attached", "detached", "visible", "hidden"}
_PERSONA_ROLES = {"admin", "analyst", "read_only", "service"}
_RETRYABLE_ACTIONS = {"goto", "wait_for_selector", "expect_visible", "wait_for_text", "expect_text", "wait_for_url", "wait_for_navigation", "wait_for_stable", "assert_path", "assert_title"}


def validate_browser_adapter(adapter: dict[str, Any]) -> None:
    """Validate a local-only browser adapter without retaining credentials."""
    url = adapter.get("base_url")
    parsed = urlparse(url) if isinstance(url, str) else None
    if not parsed or parsed.scheme not in {"http", "https"} or not parsed.hostname or not _is_loopback_host(parsed.hostname):
        raise RunnerError("browser_journey.base_url must be a loopback HTTP(S) URL; remote browser testing is not supported")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RunnerError("browser_journey.base_url must not contain credentials, query strings, or fragments")
    timeout = adapter.get("action_timeout_ms", 15_000)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 100 or timeout > 120_000:
        raise RunnerError("browser_journey.action_timeout_ms must be an integer between 100 and 120000")
    _validate_local_file(adapter.get("session_state_path"), "browser_journey.session_state_path")
    _validate_local_file(adapter.get("evidence_dir", ".esx/browser-evidence"), "browser_journey.evidence_dir")
    screenshots = adapter.get("capture_failure_screenshots", False)
    if not isinstance(screenshots, bool):
        raise RunnerError("browser_journey.capture_failure_screenshots must be true or false")
    auth = adapter.get("auth")
    if auth is not None:
        _validate_auth(auth)
    session_bootstrap = adapter.get("session_bootstrap")
    if session_bootstrap is not None:
        if auth is not None:
            raise RunnerError("browser_journey can use either form auth or session_bootstrap, not both")
        if adapter.get("session_state_path") is None:
            raise RunnerError("browser_journey.session_bootstrap requires a relative session_state_path")
        _validate_session_bootstrap(session_bootstrap)
    _validate_personas(adapter.get("personas"))


def validate_browser_case(case: dict[str, Any], adapter: dict[str, Any] | None = None) -> None:
    """Reject an incomplete workflow before the browser starts."""
    if "requires_auth" in case and not isinstance(case["requires_auth"], bool):
        raise RunnerError("browser journey requires_auth must be true or false")
    actions = case.get("input", {}).get("journey") if isinstance(case.get("input"), dict) else None
    if not isinstance(actions, list) or not actions:
        raise RunnerError("Every browser journey case needs a non-empty input.journey action list")
    for action in actions:
        _validate_action(action)
    persona = case.get("persona", "default")
    if not isinstance(persona, str) or not _SAFE_IDENTIFIER.fullmatch(persona):
        raise RunnerError("browser journey persona must use lowercase letters, digits, and hyphens")
    if adapter is not None and persona not in {"default", "anonymous"}:
        personas = adapter.get("personas", {})
        if not isinstance(personas, dict) or persona not in personas:
            raise RunnerError(f"browser journey persona '{persona}' is not configured")
    for field in ("capability_area", "workflow_pack"):
        if field in case and (not isinstance(case[field], str) or not _SAFE_IDENTIFIER.fullmatch(case[field])):
            raise RunnerError(f"browser journey {field} must use lowercase letters, digits, and hyphens")


def invoke_browser_journeys(adapter: dict[str, Any], cases: list[dict[str, Any]], _evaluation: dict[str, Any]) -> tuple[dict[str, Any], int, str, str]:
    """Run declared UI actions and retain only local, content-free diagnostics."""
    validate_browser_adapter(adapter)
    for case in cases:
        validate_browser_case(case)
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RunnerError("Browser journeys require `pip install exposurescopex-eval-runner[browser]` and `playwright install chromium`") from exc

    started = time.monotonic()
    results: list[dict[str, object]] = []
    diagnostics: list[dict[str, object]] = []
    sessions: dict[str, tuple[dict[str, Any] | None, str, str | None]] = {}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=not bool(adapter.get("headed", False)))
        try:
            sessions = _prepare_persona_sessions(browser, adapter)
            for case in cases:
                persona = str(case.get("persona", "default"))
                state, session_status, session_error = sessions[persona]
                result, diagnostic = _run_case(
                    browser, adapter, case, state, session_status, session_error,
                    timeout_error=PlaywrightTimeoutError, playwright_error=PlaywrightError,
                )
                results.append(result)
                diagnostics.append(diagnostic)
        finally:
            browser.close()
    response = {
        "schema_version": "esx-client-adapter-response-2.0",
        "results": results,
        "measurements": {},
        "browser_diagnostics": diagnostics,
        "browser_session_status": _overall_session_status(sessions),
    }
    request_summary = {
        "cases": [{"case_id": case["case_id"], "journey_sha256": sha256(case["input"]), "requires_auth": bool(case.get("requires_auth", False))} for case in cases],
        "auth_configured": isinstance(adapter.get("auth"), dict),
        "session_state_configured": isinstance(adapter.get("session_state_path"), str),
    }
    return response, round((time.monotonic() - started) * 1000), sha256(request_summary), hashlib.sha256(json.dumps(response, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def bootstrap_browser_session(adapter: dict[str, Any]) -> dict[str, str]:
    """Let a tester complete approved SSO locally and save local-app state only."""
    validate_browser_adapter(adapter)
    bootstrap = adapter.get("session_bootstrap")
    if not isinstance(bootstrap, dict):
        raise RunnerError("This browser plan has no session_bootstrap configuration")
    state_path = _local_path(adapter.get("session_state_path"))
    if state_path is None:
        raise RunnerError("This browser plan needs a relative session_state_path")
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RunnerError("Browser journeys require `pip install exposurescopex-eval-runner[browser]` and `playwright install chromium`") from exc

    timeout_ms = int(adapter.get("action_timeout_ms", 15_000))
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=False)
            context = browser.new_context()
            page = context.new_page()
            try:
                page.goto(urljoin(adapter["base_url"], bootstrap["login_path"]), wait_until="domcontentloaded", timeout=timeout_ms)
                print("Complete the approved sign-in in the opened browser. Return to the local application, then press Enter here to save its local session state.")
                input()
                _assert_same_origin(page, adapter["base_url"])
                _perform(page, adapter["base_url"], bootstrap["success"], timeout_ms)
                _write_local_session_state(state_path, context.storage_state(), adapter["base_url"])
                return {"session_state_path": str(state_path), "session_status": "authenticated_interactively"}
            finally:
                context.close()
                browser.close()
    except RunnerError:
        raise
    except PlaywrightError as exc:
        raise RunnerError("Could not save the approved local browser session: browser_action_failed") from exc
    except OSError as exc:
        raise RunnerError("Could not save the approved local browser session: local_storage_failed") from exc


def browser_adapter_for_persona(adapter: dict[str, Any], persona: str | None) -> dict[str, Any]:
    """Resolve an isolated persona profile without inheriting another persona's session."""
    selected = persona or "default"
    if not isinstance(selected, str) or not _SAFE_IDENTIFIER.fullmatch(selected):
        raise RunnerError("Persona must use lowercase letters, digits, and hyphens")
    profiles = adapter.get("personas", {})
    if selected == "default" and (not isinstance(profiles, dict) or selected not in profiles):
        return {key: value for key, value in adapter.items() if key != "personas"}
    if not isinstance(profiles, dict) or not isinstance(profiles.get(selected), dict):
        raise RunnerError(f"Persona '{selected}' is not configured")
    result = {
        key: value for key, value in adapter.items()
        if key not in {"personas", "auth", "session_bootstrap", "session_state_path"}
    }
    result.update(profiles[selected])
    return result


def _prepare_persona_sessions(browser: Any, adapter: dict[str, Any]) -> dict[str, tuple[dict[str, Any] | None, str, str | None]]:
    sessions = {"default": _prepare_session(browser, browser_adapter_for_persona(adapter, "default"))}
    profiles = adapter.get("personas", {})
    if isinstance(profiles, dict):
        for persona in profiles:
            if persona == "default":
                sessions[persona] = _prepare_session(browser, browser_adapter_for_persona(adapter, persona))
            else:
                sessions[persona] = _prepare_session(browser, browser_adapter_for_persona(adapter, persona))
    sessions["anonymous"] = (None, "not_required", None)
    return sessions


def _overall_session_status(sessions: dict[str, tuple[dict[str, Any] | None, str, str | None]]) -> str:
    statuses = {item[1] for persona, item in sessions.items() if persona != "anonymous"}
    if len(statuses) == 1:
        return next(iter(statuses))
    return "multiple_personas"


def _prepare_session(browser: Any, adapter: dict[str, Any]) -> tuple[dict[str, Any] | None, str, str | None]:
    state_path = _local_path(adapter.get("session_state_path"))
    if state_path and state_path.is_file():
        try:
            raw_state = json.loads(state_path.read_text(encoding="utf-8"))
            state = _local_only_session_state(raw_state, adapter["base_url"])
            return state, "reused_local_session", None
        except (OSError, json.JSONDecodeError):
            return None, "session_unavailable", "saved_session_unreadable"
    auth = adapter.get("auth")
    if not isinstance(auth, dict):
        if isinstance(adapter.get("session_bootstrap"), dict):
            return None, "interactive_auth_required", "session_bootstrap_required"
        return None, "not_requested", None
    context = browser.new_context()
    page = context.new_page()
    try:
        _run_login(page, adapter["base_url"], auth, int(adapter.get("action_timeout_ms", 15_000)))
        state = _local_only_session_state(context.storage_state(), adapter["base_url"])
        if state_path:
            _write_local_session_state(state_path, state, adapter["base_url"])
        return state, "authenticated_this_run", None
    except Exception as exc:  # Page errors can include application content, so retain only a category.
        return None, "authentication_failed", _failure_kind(exc)
    finally:
        context.close()


def _run_login(page: Any, base_url: str, auth: dict[str, Any], timeout_ms: int) -> None:
    username = os.environ.get(auth["username_env"])
    password = os.environ.get(auth["password_env"])
    if not username or not password:
        raise RunnerError("approved browser credential environment variables are not set")
    page.goto(urljoin(base_url, auth["login_path"]), wait_until="domcontentloaded", timeout=timeout_ms)
    page.locator(auth["username_selector"]).fill(username, timeout=timeout_ms)
    page.locator(auth["password_selector"]).fill(password, timeout=timeout_ms)
    page.locator(auth["submit_selector"]).click(timeout=timeout_ms)
    _perform(page, base_url, auth["success"], timeout_ms)


def _run_case(
    browser: Any,
    adapter: dict[str, Any],
    case: dict[str, Any],
    state: dict[str, Any] | None,
    session_status: str,
    session_error: str | None,
    *,
    timeout_error: type[Exception],
    playwright_error: type[Exception],
) -> tuple[dict[str, object], dict[str, object]]:
    requires_auth = bool(case.get("requires_auth", False))
    diagnostic: dict[str, object] = {
        "case_id": case["case_id"],
        "coverage_scope": "authenticated" if requires_auth else "pre_auth",
        "persona": str(case.get("persona", "default")),
        "capability_area": str(case.get("capability_area", "general")),
        "workflow_pack": str(case.get("workflow_pack", "starter")),
        "session_status": session_status,
        "steps": [],
        "outcome": "passed",
    }
    if requires_auth and state is None:
        diagnostic.update({"outcome": "failed", "failure_kind": session_error or "authenticated_session_unavailable"})
        return _result(adapter, case, False), diagnostic
    context = browser.new_context(storage_state=state) if state is not None else browser.new_context()
    page = context.new_page()
    observations = {"console_error_count": 0, "page_error_count": 0, "request_failure_count": 0}
    page.on("console", lambda message: _count_console_error(message, observations))
    page.on("pageerror", lambda _error: _increment(observations, "page_error_count"))
    page.on("requestfailed", lambda _request: _increment(observations, "request_failure_count"))
    try:
        for index, action in enumerate(case["input"]["journey"], start=1):
            step = {"step": index, "action": str(action.get("type", "unknown")), "status": "passed", **_action_reference(action)}
            started = time.monotonic()
            try:
                attempts = _perform_with_retries(page, adapter["base_url"], action, int(adapter.get("action_timeout_ms", 15_000)))
            except Exception as exc:
                step.update({"status": "failed", "attempt_count": int(action.get("retry_count", 0)) + 1, "duration_ms": round((time.monotonic() - started) * 1000), "failure_kind": _failure_kind(exc, timeout_error, playwright_error), **_page_observation(page, adapter["base_url"])})
                diagnostic["steps"].append(step)
                diagnostic.update({"outcome": "failed", "failure_kind": step["failure_kind"], "browser_health": observations})
                screenshot = _capture_failure_screenshot(page, adapter, str(case["case_id"]))
                if screenshot:
                    diagnostic["failure_screenshot"] = screenshot
                return _result(adapter, case, False), diagnostic
            step.update({"attempt_count": attempts, "duration_ms": round((time.monotonic() - started) * 1000), **_page_observation(page, adapter["base_url"])})
            diagnostic["steps"].append(step)
        diagnostic["browser_health"] = observations
        return _result(adapter, case, True), diagnostic
    finally:
        context.close()


def _result(adapter: dict[str, Any], case: dict[str, Any], passed: bool) -> dict[str, object]:
    return {
        "case_id": case["case_id"],
        "predicted_label": adapter.get("pass_label", "pass") if passed else adapter.get("fail_label", "fail"),
        "confidence": 1.0,
    }


def _perform_with_retries(page: Any, base_url: str, action: dict[str, Any], timeout_ms: int) -> int:
    """Retry only navigation, waits, and assertions; never replay a mutating click."""
    attempts = int(action.get("retry_count", 0)) + 1
    for attempt in range(1, attempts + 1):
        try:
            _perform(page, base_url, action, timeout_ms)
            return attempt
        except RunnerError:
            raise
        except Exception:
            if attempt == attempts:
                raise
            page.wait_for_timeout(int(action.get("retry_delay_ms", 250)))
    raise AssertionError("unreachable retry state")


def _page_observation(page: Any, base_url: str) -> dict[str, object]:
    """Report browser health without retaining page content, titles, or dynamic paths."""
    parsed = urlparse(page.url)
    expected = urlparse(base_url)
    expected_port = expected.port or (443 if expected.scheme == "https" else 80)
    actual_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        ready_state = page.evaluate("document.readyState")
    except Exception:
        ready_state = "unavailable"
    return {
        "observed_origin": "approved_local_origin" if (parsed.scheme, parsed.hostname, actual_port) == (expected.scheme, expected.hostname, expected_port) else "outside_approved_origin",
        "document_ready_state": ready_state if ready_state in {"loading", "interactive", "complete"} else "unavailable",
    }


def _increment(values: dict[str, int], key: str) -> None:
    values[key] += 1


def _count_console_error(message: Any, values: dict[str, int]) -> None:
    if getattr(message, "type", None) == "error":
        _increment(values, "console_error_count")


def _perform(page: Any, base_url: str, action: dict[str, Any], timeout_ms: int) -> None:
    kind, selector = action["type"], action.get("selector")
    if kind == "goto":
        page.goto(urljoin(base_url, action["path"]), wait_until=action.get("wait_until", "domcontentloaded"), timeout=timeout_ms)
    elif kind == "fill":
        page.locator(selector).fill(action["value"], timeout=timeout_ms)
    elif kind == "click":
        page.locator(selector).click(timeout=timeout_ms)
    elif kind == "press":
        page.locator(selector).press(action["key"], timeout=timeout_ms)
    elif kind in {"wait_for_selector", "expect_visible"}:
        page.locator(selector).wait_for(state=action.get("state", "visible"), timeout=timeout_ms)
    elif kind in {"wait_for_text", "expect_text"}:
        locator = page.locator(selector or "body")
        locator.get_by_text(action["value"], exact=bool(action.get("exact", False))).wait_for(state="visible", timeout=timeout_ms)
    elif kind == "wait_for_url":
        page.wait_for_url(urljoin(base_url, action["path"]), timeout=timeout_ms, wait_until=action.get("wait_until", "domcontentloaded"))
    elif kind == "wait_for_navigation":
        page.wait_for_load_state(action.get("wait_until", "domcontentloaded"), timeout=timeout_ms)
    elif kind == "wait_for_stable":
        # SPAs often keep telemetry or websocket traffic open, so network-idle is
        # not a trustworthy generic completion signal. Pair a bounded settle with
        # an explicit wait/assert action for the state that matters.
        page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
        page.wait_for_timeout(action.get("settle_ms", 250))
    elif kind == "assert_path":
        if urlparse(page.url).path != action["path"]:
            raise AssertionError("path assertion failed")
    elif kind == "assert_title":
        actual = page.title()
        expected = action["value"]
        matches = actual == expected if action.get("exact", True) else expected in actual
        if not matches:
            raise AssertionError("title assertion failed")
    else:
        raise RunnerError("Unsupported browser journey action")
    _assert_same_origin(page, base_url)


def _assert_same_origin(page: Any, base_url: str) -> None:
    """Prevent a login redirect or action from broadening local browser scope."""
    expected = urlparse(base_url)
    actual = urlparse(page.url)
    expected_port = expected.port or (443 if expected.scheme == "https" else 80)
    actual_port = actual.port or (443 if actual.scheme == "https" else 80)
    if (actual.scheme, actual.hostname, actual_port) != (expected.scheme, expected.hostname, expected_port):
        raise RunnerError("browser journey left the approved local origin")


def _validate_auth(value: object) -> None:
    if not isinstance(value, dict):
        raise RunnerError("browser_journey.auth must be an object")
    allowed = {"login_path", "username_env", "password_env", "username_selector", "password_selector", "submit_selector", "success"}
    if set(value) - allowed or set(value) != allowed:
        raise RunnerError("browser_journey.auth must contain login_path, username_env, password_env, username_selector, password_selector, submit_selector, and success only")
    _validate_path(value["login_path"], "browser_journey.auth.login_path")
    for key in ("username_env", "password_env"):
        if not isinstance(value[key], str) or not _SAFE_ENV.fullmatch(value[key]):
            raise RunnerError(f"browser_journey.auth.{key} must be an environment-variable name, not a credential")
    for key in ("username_selector", "password_selector", "submit_selector"):
        _validate_selector(value[key], f"browser_journey.auth.{key}")
    _validate_action(value["success"])
    if value["success"]["type"] not in {"wait_for_url", "wait_for_text", "wait_for_selector", "wait_for_navigation", "wait_for_stable", "expect_text", "expect_visible", "assert_path", "assert_title"}:
        raise RunnerError("browser_journey.auth.success must be a wait or assertion action")


def _validate_session_bootstrap(value: object) -> None:
    if not isinstance(value, dict):
        raise RunnerError("browser_journey.session_bootstrap must be an object")
    if set(value) != {"login_path", "success"}:
        raise RunnerError("browser_journey.session_bootstrap must contain login_path and success only")
    _validate_path(value["login_path"], "browser_journey.session_bootstrap.login_path")
    _validate_action(value["success"])
    if value["success"]["type"] not in {"wait_for_url", "wait_for_text", "wait_for_selector", "wait_for_navigation", "wait_for_stable", "expect_text", "expect_visible", "assert_path", "assert_title"}:
        raise RunnerError("browser_journey.session_bootstrap.success must be a wait or assertion action")


def _validate_personas(value: object) -> None:
    if value is None:
        return
    if not isinstance(value, dict) or len(value) > 32:
        raise RunnerError("browser_journey.personas must be an object with at most 32 profiles")
    for persona, profile in value.items():
        if not isinstance(persona, str) or not _SAFE_IDENTIFIER.fullmatch(persona):
            raise RunnerError("browser persona IDs must use lowercase letters, digits, and hyphens")
        if not isinstance(profile, dict) or set(profile) != {"label", "role", "session_state_path", "session_bootstrap"}:
            raise RunnerError("Each browser persona needs label, role, session_state_path, and session_bootstrap only")
        if not isinstance(profile["label"], str) or not profile["label"].strip() or len(profile["label"]) > 120:
            raise RunnerError("browser persona label must be non-empty text up to 120 characters")
        if profile["role"] not in _PERSONA_ROLES:
            raise RunnerError("browser persona role must be admin, analyst, read_only, or service")
        _validate_local_file(profile["session_state_path"], f"browser persona {persona}.session_state_path")
        _validate_session_bootstrap(profile["session_bootstrap"])


def _validate_action(action: object) -> None:
    if not isinstance(action, dict) or not isinstance(action.get("type"), str):
        raise RunnerError("Browser journey actions need a type")
    kind = action["type"]
    allowed: dict[str, set[str]] = {
        "goto": {"type", "path", "wait_until"}, "fill": {"type", "selector", "value"},
        "click": {"type", "selector"}, "press": {"type", "selector", "key"},
        "wait_for_selector": {"type", "selector", "state"}, "expect_visible": {"type", "selector", "state"},
        "wait_for_text": {"type", "selector", "value", "exact"}, "expect_text": {"type", "selector", "value", "exact"},
        "wait_for_url": {"type", "path", "wait_until"}, "wait_for_navigation": {"type", "wait_until"},
        "wait_for_stable": {"type", "settle_ms"}, "assert_path": {"type", "path"},
        "assert_title": {"type", "value", "exact"},
    }
    for fields in allowed.values():
        fields.update({"retry_count", "retry_delay_ms"})
    if kind not in allowed or set(action) - allowed[kind]:
        raise RunnerError("Unsupported browser journey action")
    if kind in {"goto", "wait_for_url", "assert_path"}:
        _validate_path(action.get("path"), f"browser action {kind}.path")
    if kind in {"fill", "click", "press", "wait_for_selector", "expect_visible"}:
        _validate_selector(action.get("selector"), f"browser action {kind}.selector")
    if kind == "fill" and (not isinstance(action.get("value"), str) or len(action["value"]) > 20_000):
        raise RunnerError("browser action fill.value must be text up to 20000 characters")
    if kind == "press" and (not isinstance(action.get("key"), str) or not action["key"]):
        raise RunnerError("browser action press.key must be non-empty text")
    if kind in {"wait_for_text", "expect_text", "assert_title"} and (not isinstance(action.get("value"), str) or not action["value"]):
        raise RunnerError(f"browser action {kind}.value must be non-empty text")
    if "exact" in action and not isinstance(action["exact"], bool):
        raise RunnerError("browser action exact must be true or false")
    if "wait_until" in action and action["wait_until"] not in _WAIT_UNTIL:
        raise RunnerError("browser action wait_until must be commit, domcontentloaded, load, or networkidle")
    if "state" in action and action["state"] not in _SELECTOR_STATES:
        raise RunnerError("browser action state must be attached, detached, visible, or hidden")
    if "settle_ms" in action and (not isinstance(action["settle_ms"], int) or isinstance(action["settle_ms"], bool) or not 0 <= action["settle_ms"] <= 30_000):
        raise RunnerError("browser action settle_ms must be an integer between 0 and 30000")
    retry_count = action.get("retry_count", 0)
    retry_delay_ms = action.get("retry_delay_ms", 250)
    if not isinstance(retry_count, int) or isinstance(retry_count, bool) or not 0 <= retry_count <= 5:
        raise RunnerError("browser action retry_count must be an integer between 0 and 5")
    if not isinstance(retry_delay_ms, int) or isinstance(retry_delay_ms, bool) or not 0 <= retry_delay_ms <= 5_000:
        raise RunnerError("browser action retry_delay_ms must be an integer between 0 and 5000")
    if retry_count and kind not in _RETRYABLE_ACTIONS:
        raise RunnerError("browser action retries are allowed only for navigation, waits, and assertions")


def _validate_path(value: object, field: str) -> None:
    if not isinstance(value, str) or not _SAFE_PATH.fullmatch(value) or "?" in value or "#" in value:
        raise RunnerError(f"{field} must be a same-origin path starting with / without a query or fragment")


def _validate_selector(value: object, field: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 500 or "\n" in value or "\r" in value:
        raise RunnerError(f"{field} must be a one-line selector up to 500 characters")


def _validate_local_file(value: object, field: str) -> None:
    if value is None:
        return
    if not isinstance(value, str) or not _SAFE_LOCAL_FILE.fullmatch(value) or value.startswith("/") or ".." in Path(value).parts:
        raise RunnerError(f"{field} must be a relative local path without parent directories")


def _local_path(value: object) -> Path | None:
    if value is None:
        return None
    _validate_local_file(value, "browser local path")
    return Path.cwd() / str(value)


def _action_reference(action: dict[str, Any]) -> dict[str, str]:
    """Keep diagnostic structure but never preserve filled values or pressed keys."""
    if isinstance(action.get("path"), str):
        return {"target": action["path"]}
    if isinstance(action.get("selector"), str):
        return {"target": action["selector"]}
    return {}


def _failure_kind(error: Exception, timeout_error: type[Exception] | None = None, playwright_error: type[Exception] | None = None) -> str:
    if timeout_error and isinstance(error, timeout_error):
        return "timeout"
    if playwright_error and isinstance(error, playwright_error):
        return "browser_action_failed"
    if isinstance(error, AssertionError):
        return "assertion_failed"
    if isinstance(error, RunnerError):
        return "configuration_error"
    return "browser_action_failed"


def _capture_failure_screenshot(page: Any, adapter: dict[str, Any], case_id: str) -> str | None:
    if not adapter.get("capture_failure_screenshots", False):
        return None
    try:
        directory = _local_path(adapter.get("evidence_dir", ".esx/browser-evidence"))
        assert directory is not None
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / f"{case_id}-failure.png"
        page.screenshot(path=str(target), full_page=True)
        return str(target)
    except Exception:
        return None


def _write_local_session_state(state_path: Path, state: object, base_url: str) -> None:
    """Persist only the approved application's state, never an identity-provider session."""
    local_state = _local_only_session_state(state, base_url)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(local_state), encoding="utf-8")
    try:
        state_path.chmod(0o600)
    except OSError:
        pass


def _local_only_session_state(state: object, base_url: str) -> dict[str, object]:
    if not isinstance(state, dict):
        raise RunnerError("saved local browser session is invalid")
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    origin = f"{parsed.scheme}://{parsed.netloc}"
    cookies = state.get("cookies", [])
    origins = state.get("origins", [])
    if not isinstance(cookies, list) or not isinstance(origins, list):
        raise RunnerError("saved local browser session is invalid")
    return {
        "cookies": [cookie for cookie in cookies if isinstance(cookie, dict) and _cookie_is_for_host(cookie, host)],
        "origins": [item for item in origins if isinstance(item, dict) and item.get("origin") == origin],
    }


def _cookie_is_for_host(cookie: dict[str, object], host: str) -> bool:
    domain = cookie.get("domain")
    if not isinstance(domain, str):
        return False
    return domain.lstrip(".").lower() == host.lower()
