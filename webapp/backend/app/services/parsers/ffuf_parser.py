"""Parse ffuf JSON output into normalized content-discovery hits."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("exposurescopex.parsers")


def parse_ffuf_results(filepath: Path) -> list[dict[str, Any]]:
    filepath = Path(filepath)
    if not filepath.exists() or filepath.stat().st_size == 0:
        return []

    try:
        payload = json.loads(filepath.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.debug("Failed to parse ffuf output %s: %s", filepath, exc)
        return []

    results = payload.get("results", []) if isinstance(payload, dict) else payload if isinstance(payload, list) else []
    findings: list[dict[str, Any]] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        input_payload = item.get("input") if isinstance(item.get("input"), dict) else {}
        fuzz_value = str(
            input_payload.get("FUZZ")
            or input_payload.get("WORD")
            or input_payload.get("PATH")
            or ""
        ).strip("/")
        findings.append({
            "url": str(item.get("url") or ""),
            "status": int(item.get("status") or 0),
            "length": int(item.get("length") or 0),
            "words": int(item.get("words") or 0),
            "lines": int(item.get("lines") or 0),
            "content_type": str(item.get("content-type") or item.get("content_type") or ""),
            "redirect": str(item.get("redirectlocation") or item.get("redirect") or ""),
            "input": fuzz_value,
        })
    return findings
