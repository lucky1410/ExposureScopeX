"""Parse Arjun parameter-discovery output."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("exposurescopex.parsers")


def parse_arjun_results(filepath: Path) -> list[dict[str, Any]]:
    filepath = Path(filepath)
    if not filepath.exists() or filepath.stat().st_size == 0:
        return []

    try:
        payload = json.loads(filepath.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.debug("Failed to parse Arjun output %s: %s", filepath, exc)
        return []

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def add_item(url: str, method: str, parameter: str) -> None:
        key = (url, method.upper(), parameter)
        if not url or not parameter or key in seen:
            return
        seen.add(key)
        findings.append({
            "url": url,
            "method": method.upper(),
            "parameter": parameter,
        })

    if isinstance(payload, dict):
        if isinstance(payload.get("parameters"), list):
            url = str(payload.get("url") or "")
            method = str(payload.get("method") or "GET")
            for parameter in payload.get("parameters", []):
                add_item(url, method, str(parameter))
        else:
            for url, value in payload.items():
                if isinstance(value, list):
                    for parameter in value:
                        add_item(str(url), "GET", str(parameter))
                elif isinstance(value, dict):
                    method = str(value.get("method") or "GET")
                    parameters = value.get("params") or value.get("parameters") or []
                    if isinstance(parameters, dict):
                        parameters = list(parameters.keys())
                    for parameter in parameters if isinstance(parameters, list) else []:
                        add_item(str(url), method, str(parameter))
    elif isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or item.get("endpoint") or "")
            method = str(item.get("method") or "GET")
            parameters = item.get("parameters") or item.get("params") or []
            if isinstance(parameters, dict):
                parameters = list(parameters.keys())
            for parameter in parameters if isinstance(parameters, list) else []:
                add_item(url, method, str(parameter))

    return findings
