from __future__ import annotations

import asyncio
import hashlib
import os
import re
import shlex
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

from playwright.async_api import BrowserContext, async_playwright


BLOCKED_ROUTE_TERMS = ("logout", "signout", "reset", "setup", "install", "delete", "remove")


async def authenticated_context(auth: dict | None):
    playwright = await async_playwright().start()
    browser = await playwright.chromium.launch(headless=True)
    context = await browser.new_context(
        viewport={"width": 1440, "height": 1000},
        accept_downloads=False,
        service_workers="block",
        ignore_https_errors=True,
    )
    authentication = {"configured": bool(auth), "verified": False, "login_url": auth.get("login_url") if auth else None}
    if auth:
        page = await context.new_page()
        try:
            await page.goto(auth["login_url"], wait_until="domcontentloaded", timeout=30_000)
            await page.locator(auth["username_selector"]).first.fill(auth["username"])
            await page.locator(auth["password_selector"]).first.fill(auth["password"])
            await page.locator(auth["submit_selector"]).first.click()
            await page.wait_for_load_state("domcontentloaded", timeout=30_000)
            await page.wait_for_timeout(750)
            password_visible = await page.locator(auth["password_selector"]).count() and await page.locator(auth["password_selector"]).first.is_visible()
            if page.url.rstrip("/") == auth["login_url"].rstrip("/") and password_visible:
                raise RuntimeError("Authentication remained at the login boundary")
            authentication.update({"verified": True, "final_url": page.url})
        except Exception:
            await context.close()
            await browser.close()
            await playwright.stop()
            raise
        finally:
            if not page.is_closed():
                await page.close()
    return playwright, browser, context, authentication


async def close_context(playwright, browser, context: BrowserContext) -> None:
    await context.close()
    await browser.close()
    await playwright.stop()


async def enforce_browser_scope(context: BrowserContext, target: str) -> None:
    """Prevent the browser from requesting redirect targets or embedded assets outside scope."""
    async def guard(route) -> None:
        if same_origin(target, route.request.url):
            await route.continue_()
        else:
            await route.abort("blockedbyclient")

    await context.route("**/*", guard)


async def capture_page(context: BrowserContext, url: str, target: str) -> tuple[bytes, dict]:
    page = await context.new_page()
    try:
        response = await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_timeout(500)
        if not same_origin(target, page.url):
            raise RuntimeError(f"Browser capture redirected outside authorized origin: {page.url}")
        content = await page.screenshot(full_page=True)
        return content, {
            "capture_type": "playwright_browser",
            "capture_tool": "playwright",
            "requested_url": url,
            "final_url": page.url,
            "http_status": response.status if response else None,
            "browser_engine": "chromium",
        }
    finally:
        await page.close()


def capture_terminal_png(transcript: Path, output: Path, scan_id: str, stage_name: str) -> str:
    output.parent.mkdir(parents=True, exist_ok=True)
    display = f":{100 + (os.getpid() % 500)}"
    environment = {**os.environ, "DISPLAY": display}
    xvfb = subprocess.Popen(["Xvfb", display, "-screen", "0", "1440x900x24", "-nolisten", "tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    terminal = None
    try:
        time.sleep(0.5)
        heading = f"ExposureScopeX scan {scan_id} | stage {stage_name}"
        retained_lines = transcript.read_text(encoding="utf-8", errors="replace").splitlines()
        # Keep the exact recorded command and final output visible at a readable
        # terminal width. The complete transcript remains the canonical artifact.
        rows = min(48, max(14, min(len(retained_lines), 34) + 8))
        command = (
            f"printf '%s\\n\\n' {shlex.quote(heading)}; "
            f"head -n 1 -- {shlex.quote(str(transcript))}; "
            f"printf '\\n[final retained output]\\n'; "
            f"tail -n +2 -- {shlex.quote(str(transcript))} | tail -n 34; sleep 6"
        )
        terminal = subprocess.Popen(["xterm", "-title", heading, "-geometry", f"112x{rows}", "-fa", "DejaVu Sans Mono", "-fs", "11", "-e", "/bin/sh", "-c", command], env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.2)
        # Xvfb has no window manager, so a focused-window capture is unreliable.
        # Resolve xterm's geometry and capture precisely that original window.
        try:
            window_id = subprocess.check_output(
                ["xdotool", "search", "--onlyvisible", "--name", re.escape(heading)],
                env=environment,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=10,
            ).splitlines()[0]
            geometry = subprocess.check_output(
                ["xdotool", "getwindowgeometry", "--shell", window_id],
                env=environment,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=10,
            )
            values = dict(line.split("=", 1) for line in geometry.splitlines() if "=" in line)
            area = f"{values['X']},{values['Y']},{values['WIDTH']},{values['HEIGHT']}"
            subprocess.run(["scrot", "-a", area, "-o", str(output)], env=environment, check=True, timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return "xterm_window_geometry"
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired, IndexError, KeyError):
            subprocess.run(["scrot", "-o", str(output)], env=environment, check=True, timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return "xvfb_display_fallback"
    finally:
        if terminal and terminal.poll() is None:
            terminal.terminate()
            try:
                terminal.wait(timeout=2)
            except subprocess.TimeoutExpired:
                terminal.kill()
        xvfb.terminate()
        try:
            xvfb.wait(timeout=2)
        except subprocess.TimeoutExpired:
            xvfb.kill()


async def terminal_evidence(transcript: Path, output: Path, scan_id: str, stage_name: str) -> dict:
    try:
        framing = await asyncio.to_thread(capture_terminal_png, transcript, output, scan_id, stage_name)
    except Exception as exc:
        return {"capture_type": "terminal_capture_unavailable", "capture_error": f"{type(exc).__name__}: {exc}", "source_transcript_sha256": hashlib.sha256(transcript.read_bytes()).hexdigest(), "stage": stage_name}
    source_digest = hashlib.sha256(transcript.read_bytes()).hexdigest()
    return {"capture_type": "xvfb_xterm_transcript_capture", "capture_timing": "post_execution", "capture_tool": "xvfb-xterm-scrot", "capture_framing": framing, "displayed_content": "recorded command plus final 34 transcript lines", "source_transcript_sha256": source_digest, "stage": stage_name}


def same_origin(base: str, candidate: str) -> bool:
    left, right = urlsplit(base), urlsplit(candidate)
    return (
        right.scheme in {"http", "https"}
        and left.scheme == right.scheme
        and left.hostname == right.hostname
        and (right.port or (443 if right.scheme == "https" else 80))
        == (left.port or (443 if left.scheme == "https" else 80))
    )


def safe_route(url: str) -> bool:
    lowered = url.lower()
    return not any(term in lowered for term in BLOCKED_ROUTE_TERMS)
