"""Parse sqlmap CSV summary output."""

from __future__ import annotations

import csv
import logging
from pathlib import Path

logger = logging.getLogger("exposurescopex.parsers")


def parse_sqlmap_results(filepath: Path) -> list[dict[str, str]]:
    filepath = Path(filepath)
    if not filepath.exists() or filepath.stat().st_size == 0:
        return []

    findings: list[dict[str, str]] = []
    try:
        with filepath.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                url = (row.get("Target URL") or "").strip()
                parameter = (row.get("Parameter") or "").strip()
                place = (row.get("Place") or "").strip()
                techniques = (row.get("Technique(s)") or "").strip()
                notes = (row.get("Note(s)") or "").strip()
                if not url or not parameter:
                    continue
                findings.append({
                    "url": url,
                    "parameter": parameter,
                    "place": place or "unknown",
                    "techniques": techniques or "unspecified",
                    "notes": notes,
                })
    except OSError as exc:
        logger.debug("Failed to read sqlmap results %s: %s", filepath, exc)
        return []
    return findings
