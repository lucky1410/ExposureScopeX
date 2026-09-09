"""Shared scan profile definitions used across assessments, ASM, and recon."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


SCAN_PROFILES: dict[str, dict[str, Any]] = {
    "light": {
        "mode": "light",
        "label": "Light",
        "description": "Fast surface snapshot with passive enumeration and light validation.",
        "phases": {"enum": True, "scan": True, "cloud": False, "exploit": False, "report": True},
        "flags": {
            "passive_only": False,
            "stealth": True,
            "screenshots": False,
            "cve": False,
            "crawl": False,
            "agent": False,
            "no_osint": False,
            "diff": False,
            "baseline": False,
        },
        "utilities": ["crtsh", "wayback", "headers", "dns", "subfinder", "assetfinder", "httpx"],
        "nuclei_tags": ["exposures", "misconfig", "tech"],
        "business_logic": "discovery_only",
    },
    "medium": {
        "mode": "medium",
        "label": "Medium",
        "description": "Balanced recon with active probing, crawling, and curated nuclei coverage.",
        "phases": {"enum": True, "scan": True, "cloud": True, "exploit": False, "report": True},
        "flags": {
            "passive_only": False,
            "stealth": False,
            "screenshots": True,
            "cve": True,
            "crawl": True,
            "agent": False,
            "no_osint": False,
            "diff": False,
            "baseline": False,
        },
        "utilities": ["subfinder", "assetfinder", "amass", "dnsx", "httpx", "gau", "waybackurls", "katana", "arjun", "nikto", "naabu", "nuclei"],
        "nuclei_tags": ["cves", "default-login", "exposures", "files", "misconfig", "tech", "takeovers"],
        "business_logic": "workflow_mapping",
    },
    "aggressive": {
        "mode": "aggressive",
        "label": "Aggressive",
        "description": "Expanded attack-surface enumeration, deep crawling, and broader nuclei execution.",
        "phases": {"enum": True, "scan": True, "cloud": True, "exploit": True, "report": True},
        "flags": {
            "passive_only": False,
            "stealth": False,
            "screenshots": True,
            "cve": True,
            "crawl": True,
            "agent": True,
            "no_osint": False,
            "diff": True,
            "baseline": False,
        },
        "utilities": ["subfinder", "assetfinder", "amass", "dnsx", "httpx", "gau", "waybackurls", "katana", "ffuf", "arjun", "nikto", "naabu", "nmap", "nuclei"],
        "nuclei_tags": ["cves", "default-login", "dns", "exposures", "files", "misconfig", "panel", "takeovers", "tech", "workflow"],
        "business_logic": "authenticated_and_stateful",
    },
}

TARGET_PIPELINES: dict[str, list[str]] = {
    "domain": [
        "normalize", "ct", "passive_dns", "active_dns", "wildcard_filter", "provider_analysis",
        "ip_correlation", "asn_correlation", "certificate_graph", "service_discovery",
        "http_probe", "virtual_hosts", "fingerprint", "crawl", "api_inventory",
        "vulnerability_scan", "cloud_correlation", "ownership", "attack_path", "historical_diff",
    ],
    "url": [
        "normalize", "http_probe", "fingerprint", "crawl", "api_inventory",
        "vulnerability_scan", "authentication_checks", "attack_path",
    ],
    "api": ["normalize", "http_probe", "schema_discovery", "endpoint_inventory", "authentication_checks", "vulnerability_scan", "drift"],
    "kubernetes": ["normalize", "manifest_inventory", "misconfiguration_scan", "secret_scan", "rbac_analysis", "reporting"],
    "android": ["normalize", "artifact_inventory", "manifest_analysis", "secret_scan", "dependency_scan", "endpoint_inventory", "reporting"],
    "ios": ["normalize", "artifact_inventory", "plist_analysis", "secret_scan", "dependency_scan", "endpoint_inventory", "reporting"],
    "ip": [
        "normalize", "reverse_dns", "rdap", "asn_correlation", "certificate_graph",
        "port_discovery", "service_identification", "http_probe", "vulnerability_scan", "historical_diff",
    ],
    "cidr": [
        "normalize", "range_expansion", "reverse_dns", "rdap", "asn_correlation",
        "port_discovery", "service_identification", "http_probe", "historical_diff",
    ],
    "mcp": [
        "normalize", "discover", "protocol_validation", "oauth_metadata", "tool_inventory",
        "resource_inventory", "prompt_inventory", "task_state", "cache_isolation", "semantic_analysis", "drift",
    ],
    "repository": [
        "normalize", "repo_inventory", "secrets", "sbom", "dependency_correlation", "provenance",
    ],
    "image": [
        "normalize", "image_inventory", "registry_fingerprint", "vulnerability_correlation",
        "sbom", "supply_chain", "attack_path",
    ],
    "cloud_account": [
        "normalize", "cloud_inventory", "public_resource_correlation", "iam_analysis", "shadow_it", "attack_path",
    ],
    "organization": [
        "normalize", "brand_seeds", "domain_discovery", "repo_discovery", "saas_discovery",
        "certificate_graph", "ownership", "shadow_it", "historical_diff",
    ],
    "asn": [
        "normalize", "prefix_inventory", "routing_correlation", "reverse_dns", "service_discovery", "ownership",
    ],
    "file": [
        "normalize", "seed_extraction", "dedupe", "cross_seed_correlation", "dispatch_by_type",
    ],
}


def get_scan_profile(scan_mode: str, target_type: str | None = None) -> dict[str, Any]:
    """Return a normalized scan profile for the requested mode and target type."""
    base = deepcopy(SCAN_PROFILES.get(scan_mode, SCAN_PROFILES["medium"]))
    target_type = (target_type or "domain").lower()

    if target_type in {"ip", "cidr"}:
        base["utilities"] = [tool for tool in base["utilities"] if tool not in {"katana", "hakrawler"}]
        base["business_logic"] = "limited_for_non_http_targets"
    elif target_type in {"url", "api"}:
        base["phases"]["cloud"] = False
        if "httpx" not in base["utilities"]:
            base["utilities"].append("httpx")
        if target_type == "api":
            base["utilities"] = ["httpx", "katana", "arjun", "nuclei"]
            base["business_logic"] = "api_schema_auth_and_object_access"
    elif target_type in {"kubernetes", "android", "ios"}:
        base["phases"] = {"enum": True, "scan": True, "cloud": False, "exploit": False, "report": True}
        base["flags"]["crawl"] = False
        base["flags"]["screenshots"] = False
        base["utilities"] = ["trivy"]
        base["nuclei_tags"] = []
        base["business_logic"] = "static_artifact_security"
    elif target_type == "mcp":
        base["phases"]["cloud"] = False
        base["utilities"] = ["httpx", "nuclei", "mcp-audit"]
        base["nuclei_tags"] = ["ai", "exposures", "misconfig", "tech"]
        base["business_logic"] = "mcp_protocol_and_isolation"
    elif target_type == "repository":
        base["phases"] = {"enum": True, "scan": True, "cloud": False, "exploit": False, "report": True}
        base["flags"]["crawl"] = False
        base["flags"]["screenshots"] = False
        base["utilities"] = ["git", "secrets", "sbom", "deps"]
        base["nuclei_tags"] = []
        base["business_logic"] = "supply_chain_and_secrets"
    elif target_type == "image":
        base["phases"] = {"enum": False, "scan": True, "cloud": False, "exploit": False, "report": True}
        base["flags"]["crawl"] = False
        base["flags"]["screenshots"] = False
        base["utilities"] = ["trivy", "syft", "grype", "sbom", "deps"]
        base["nuclei_tags"] = []
        base["business_logic"] = "container_supply_chain"
    elif target_type == "cloud_account":
        base["phases"] = {"enum": True, "scan": False, "cloud": True, "exploit": False, "report": True}
        base["flags"]["crawl"] = False
        base["flags"]["screenshots"] = False
        base["utilities"] = ["cloud", "iam", "graph", "prowler", "scoutsuite"]
        base["nuclei_tags"] = []
        base["business_logic"] = "cloud_inventory_and_access"
    elif target_type in {"organization", "asn"}:
        base["phases"] = {"enum": True, "scan": False, "cloud": False, "exploit": False, "report": True}
        base["flags"]["crawl"] = False
        base["flags"]["screenshots"] = False
        base["utilities"] = ["search", "ct", "rdap", "bgp"]
        base["nuclei_tags"] = []
        base["business_logic"] = "seed_expansion_and_attribution"

    base["target_type"] = target_type
    base["pipeline"] = TARGET_PIPELINES.get(target_type, TARGET_PIPELINES["domain"])
    base["scan_strategy"] = "active" if base["phases"].get("scan") or base["phases"].get("exploit") else "inventory"
    base["readiness"] = {
        "recon": "ready",
        "enumeration": "ready" if scan_mode in {"medium", "aggressive"} else "partial",
        "nuclei": "ready" if base["phases"].get("scan") and scan_mode in {"medium", "aggressive"} else "partial" if base["phases"].get("scan") else "not_applicable",
        "cspm": "ready" if target_type == "cloud_account" else "not_applicable",
        "software_inventory": "ready" if target_type in {"repository", "image", "kubernetes", "android", "ios"} else "not_applicable",
        "business_logic": "partial",
        "attack_graph": "partial",
        "ownership": "partial" if target_type in {"domain", "ip", "cidr", "organization", "cloud_account", "asn"} else "not_applicable",
    }
    return base


def merge_scan_inputs(
    scan_mode: str,
    target_type: str | None,
    phases: dict[str, Any] | None,
    flags: dict[str, Any] | None,
) -> dict[str, Any]:
    """Merge user-provided phases/flags with the normalized profile defaults."""
    profile = get_scan_profile(scan_mode, target_type)
    profile["phases"] = {**profile["phases"], **(phases or {})}
    profile["flags"] = {**profile["flags"], **(flags or {})}
    return profile
