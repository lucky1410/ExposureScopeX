"""Scan intent normalization shared by assessment orchestration."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from app.services.scan_profiles import merge_scan_inputs

SCAN_INTENT_PRESETS: dict[str, dict[str, Any]] = {
    "passive": {
        "phases": {"enum": True, "scan": False, "cloud": False, "exploit": False, "report": True},
        "flags": {"passive_only": True, "crawl": False, "screenshots": False, "cve": False, "no_osint": False},
        "utilities": ["crtsh", "wayback", "assetfinder"],
        "nuclei_tags": [],
    },
    "nuclei": {
        "phases": {"enum": True, "scan": True, "cloud": False, "exploit": False, "report": True},
        "flags": {"passive_only": False, "crawl": True, "screenshots": False, "cve": True},
        "utilities": ["httpx", "katana", "naabu", "arjun", "nikto", "nuclei"],
        "nuclei_tags": ["cves", "misconfig", "exposures", "tech", "takeovers"],
    },
    "web": {
        "phases": {"enum": True, "scan": True, "cloud": False, "exploit": False, "report": True},
        "flags": {"crawl": True, "screenshots": True, "cve": True},
        "utilities": ["httpx", "katana", "arjun", "nikto", "ffuf", "nuclei"],
        "nuclei_tags": ["misconfig", "exposures", "tech", "panel", "workflow"],
    },
    "cloud": {
        "phases": {"enum": False, "scan": False, "cloud": True, "exploit": False, "report": True},
        "flags": {"passive_only": False},
        "utilities": ["cloud", "prowler"],
        "nuclei_tags": [],
    },
    "api": {
        "phases": {"enum": True, "scan": True, "cloud": False, "exploit": False, "report": True},
        "flags": {"crawl": True, "screenshots": False, "cve": True},
        "utilities": ["httpx", "katana", "arjun", "nuclei"],
        "nuclei_tags": ["api", "misconfig", "cves"],
    },
}


def build_scan_plan(
    *,
    scan_mode: str,
    target_type: str,
    phases: dict[str, Any] | None,
    flags: dict[str, Any] | None,
    requested_scans: list[str] | None,
    requested_utilities: list[str] | None,
    nuclei_tags: list[str] | None,
) -> dict[str, Any]:
    """Merge platform profile defaults with operator-requested scan intent."""
    plan = merge_scan_inputs(scan_mode, target_type, phases, flags)

    requested_scans = [item.strip().lower() for item in (requested_scans or []) if item.strip()]
    combined_utilities = list(plan["utilities"])
    combined_tags = list(plan["nuclei_tags"])

    for scan_name in requested_scans:
        preset = deepcopy(SCAN_INTENT_PRESETS.get(scan_name))
        if not preset:
            continue
        plan["phases"] = {**plan["phases"], **preset["phases"]}
        plan["flags"] = {**plan["flags"], **preset["flags"]}
        combined_utilities.extend(preset["utilities"])
        combined_tags.extend(preset["nuclei_tags"])

    if requested_utilities:
        combined_utilities.extend([utility.strip() for utility in requested_utilities if utility.strip()])
    if nuclei_tags:
        combined_tags.extend([tag.strip() for tag in nuclei_tags if tag.strip()])

    if target_type == "url":
        plan["phases"]["enum"] = False
        plan["phases"]["cloud"] = False
        plan["flags"]["crawl"] = True
    elif target_type in {"ip", "cidr"}:
        plan["flags"]["crawl"] = False
        plan["flags"]["screenshots"] = False

    plan["utilities"] = sorted(set(combined_utilities))
    plan["nuclei_tags"] = sorted(set(combined_tags))
    plan["requested_scans"] = requested_scans
    return plan
