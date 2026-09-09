"""Open-source scanner catalog and adapter planning for platform scans."""

from __future__ import annotations

from typing import Any


def _tool(
    tool_id: str,
    name: str,
    *,
    category: str,
    license_name: str,
    status: str,
    install_mode: str,
    target_types: list[str],
    outputs: list[str],
    execution: str,
    notes: str,
    bundled: bool = False,
) -> dict[str, Any]:
    return {
        "id": tool_id,
        "name": name,
        "category": category,
        "license": license_name,
        "status": status,
        "install_mode": install_mode,
        "target_types": target_types,
        "outputs": outputs,
        "execution": execution,
        "notes": notes,
        "bundled": bundled,
    }


OPEN_SOURCE_SCANNERS: list[dict[str, Any]] = [
    _tool(
        "subfinder",
        "Subfinder",
        category="passive_discovery",
        license_name="MIT",
        status="bundled",
        install_mode="container",
        target_types=["domain", "organization"],
        outputs=["subdomains", "passive_inventory"],
        execution="direct",
        notes="Primary passive subdomain collector.",
        bundled=True,
    ),
    _tool(
        "assetfinder",
        "Assetfinder",
        category="passive_discovery",
        license_name="MIT",
        status="bundled",
        install_mode="container",
        target_types=["domain", "organization"],
        outputs=["subdomains"],
        execution="direct",
        notes="Secondary passive source for lightweight enumeration.",
        bundled=True,
    ),
    _tool(
        "amass",
        "OWASP Amass",
        category="graph_discovery",
        license_name="Apache-2.0",
        status="bundled",
        install_mode="container",
        target_types=["domain", "organization", "asn"],
        outputs=["subdomains", "relationships", "intel"],
        execution="direct",
        notes="Deeper recursive attack-surface mapping.",
        bundled=True,
    ),
    _tool(
        "httpx",
        "httpx",
        category="http_fingerprinting",
        license_name="MIT",
        status="bundled",
        install_mode="container",
        target_types=["domain", "url", "ip", "cidr", "mcp"],
        outputs=["http_services", "fingerprints"],
        execution="direct",
        notes="HTTP probing, title/tech fingerprinting, and liveness checks.",
        bundled=True,
    ),
    _tool(
        "dnsx",
        "dnsx",
        category="dns",
        license_name="MIT",
        status="bundled",
        install_mode="container",
        target_types=["domain", "ip", "cidr"],
        outputs=["dns_records", "resolution"],
        execution="direct",
        notes="Active DNS resolution and enrichment.",
        bundled=True,
    ),
    _tool(
        "naabu",
        "Naabu",
        category="network",
        license_name="MIT",
        status="bundled",
        install_mode="container",
        target_types=["domain", "ip", "cidr"],
        outputs=["ports", "services"],
        execution="direct",
        notes="Fast port discovery before deeper service enumeration.",
        bundled=True,
    ),
    _tool(
        "nmap",
        "Nmap",
        category="network",
        license_name="NPSL",
        status="bundled",
        install_mode="container",
        target_types=["domain", "ip", "cidr"],
        outputs=["service_versions", "banners"],
        execution="direct",
        notes="Deeper service identification after reachability is established.",
        bundled=True,
    ),
    _tool(
        "katana",
        "Katana",
        category="web_crawling",
        license_name="MIT",
        status="bundled",
        install_mode="container",
        target_types=["domain", "url"],
        outputs=["routes", "parameters", "api_candidates"],
        execution="direct",
        notes="Primary crawler for routes, JS references, and surface discovery.",
        bundled=True,
    ),
    _tool(
        "ffuf",
        "ffuf",
        category="content_discovery",
        license_name="MIT",
        status="bundled",
        install_mode="container",
        target_types=["domain", "url"],
        outputs=["paths", "status_codes", "response_fingerprints"],
        execution="direct",
        notes="Fast content discovery for targeted follow-up surface expansion.",
        bundled=True,
    ),
    _tool(
        "arjun",
        "Arjun",
        category="parameter_discovery",
        license_name="MIT",
        status="bundled",
        install_mode="container",
        target_types=["domain", "url"],
        outputs=["parameters", "methods", "endpoint_candidates"],
        execution="direct",
        notes="Parameter discovery for URLs and API-like endpoints.",
        bundled=True,
    ),
    _tool(
        "nikto",
        "Nikto",
        category="web_baseline",
        license_name="GPL-3.0",
        status="bundled",
        install_mode="container",
        target_types=["domain", "url"],
        outputs=["web_findings", "headers", "server_misconfigurations"],
        execution="direct",
        notes="Baseline web-server and framework misconfiguration coverage.",
        bundled=True,
    ),
    _tool(
        "nuclei",
        "Nuclei",
        category="vulnerability_validation",
        license_name="MIT",
        status="bundled",
        install_mode="container",
        target_types=["domain", "url", "ip", "cidr", "mcp"],
        outputs=["findings", "evidence", "template_hits"],
        execution="direct",
        notes="Official/community template execution with curated tags by profile.",
        bundled=True,
    ),
    _tool(
        "sqlmap",
        "sqlmap",
        category="active_validation",
        license_name="GPL-2.0",
        status="bundled",
        install_mode="container",
        target_types=["domain", "url"],
        outputs=["sql_injection_findings", "db_fingerprints"],
        execution="guarded",
        notes="Guard-railed SQL injection validation requiring explicit operator approval.",
        bundled=True,
    ),
    _tool(
        "nuclei_templates",
        "Nuclei Templates",
        category="content_pack",
        license_name="MIT",
        status="bundled",
        install_mode="runtime_volume",
        target_types=["domain", "url", "ip", "cidr", "mcp"],
        outputs=["template_inventory", "versioned_coverage"],
        execution="direct",
        notes="Community-maintained detection corpus used by Nuclei.",
        bundled=True,
    ),
    _tool(
        "gitleaks",
        "Gitleaks",
        category="repository",
        license_name="MIT",
        status="bundled",
        install_mode="container",
        target_types=["repository"],
        outputs=["secret_findings"],
        execution="direct",
        notes="Repository secret detection with redacted evidence.",
        bundled=True,
    ),
    _tool(
        "trivy",
        "Trivy",
        category="repository",
        license_name="Apache-2.0",
        status="bundled",
        install_mode="container",
        target_types=["repository", "image", "kubernetes", "android", "ios"],
        outputs=["vulnerabilities", "misconfigurations", "sbom"],
        execution="direct",
        notes="Repository and container-image scanning for CVEs, secrets, misconfigurations, and SBOM output.",
        bundled=True,
    ),
    _tool(
        "mcp_audit",
        "ExposureScopeX MCP Audit",
        category="ai_agent_security",
        license_name="Internal platform module",
        status="bundled",
        install_mode="application",
        target_types=["mcp"],
        outputs=["protocol_findings", "inventory", "redacted_exchanges", "drift"],
        execution="adapter",
        notes="Built-in non-destructive MCP security and capability-chain assessment.",
        bundled=True,
    ),
    _tool(
        "prowler",
        "Prowler",
        category="cspm",
        license_name="Apache-2.0",
        status="bundled",
        install_mode="container",
        target_types=["cloud_account"],
        outputs=["json_ocsf", "csv", "html", "compliance"],
        execution="adapter",
        notes="Primary open-source CSPM engine for provider posture and compliance coverage.",
        bundled=True,
    ),
    _tool(
        "scoutsuite",
        "ScoutSuite",
        category="cspm",
        license_name="GPL-2.0",
        status="optional",
        install_mode="external_adapter",
        target_types=["cloud_account"],
        outputs=["html", "json_like_report", "resource_inventory"],
        execution="adapter",
        notes="Optional secondary comparator. Disabled by default because its current release pins legacy cloud SDKs.",
        bundled=False,
    ),
    _tool(
        "syft",
        "Syft",
        category="software_inventory",
        license_name="Apache-2.0",
        status="bundled",
        install_mode="container",
        target_types=["repository", "image"],
        outputs=["sbom"],
        execution="adapter",
        notes="Secondary SBOM adapter for deeper package and layer inventory.",
        bundled=True,
    ),
    _tool(
        "grype",
        "Grype",
        category="software_inventory",
        license_name="Apache-2.0",
        status="bundled",
        install_mode="container",
        target_types=["repository", "image"],
        outputs=["vulnerability_correlation"],
        execution="adapter",
        notes="Secondary vulnerability correlation engine for SBOM-centric workflows.",
        bundled=True,
    ),
]


UTILITY_TO_TOOL_ID = {
    "amass": "amass",
    "assetfinder": "assetfinder",
    "cloud": "prowler",
    "dnsx": "dnsx",
    "git": "gitleaks",
    "gitleaks": "gitleaks",
    "ffuf": "ffuf",
    "arjun": "arjun",
    "httpx": "httpx",
    "iam": "prowler",
    "katana": "katana",
    "mcp-audit": "mcp_audit",
    "naabu": "naabu",
    "nmap": "nmap",
    "nikto": "nikto",
    "nuclei": "nuclei",
    "scoutsuite": "scoutsuite",
    "search": "amass",
    "secrets": "gitleaks",
    "sbom": "trivy",
    "sqlmap": "sqlmap",
    "syft": "syft",
    "grype": "grype",
    "subfinder": "subfinder",
    "trivy": "trivy",
}


def _tool_by_id(tool_id: str) -> dict[str, Any]:
    return next(item for item in OPEN_SOURCE_SCANNERS if item["id"] == tool_id)


def build_tool_plan(
    *,
    target_type: str,
    scan_mode: str,
    utilities: list[str] | None = None,
    requested_scans: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Return a normalized execution plan of platform tools for the requested scan."""
    target_type = (target_type or "domain").lower()
    scan_mode = (scan_mode or "medium").lower()
    requested_scans = [item.lower() for item in (requested_scans or []) if item]
    utilities = [item.lower() for item in (utilities or []) if item]

    tool_ids: list[tuple[str, str, bool]] = []
    if target_type == "repository":
        tool_ids.extend([
            ("git_clone", "inventory", True),
            ("gitleaks", "secret_detection", True),
            ("trivy", "vulnerability_and_sbom", True),
            ("syft", "sbom_secondary", scan_mode in {"medium", "aggressive"}),
            ("grype", "sbom_vulnerability_correlation", scan_mode == "aggressive"),
        ])
    elif target_type == "image":
        tool_ids.extend([
            ("trivy", "image_vulnerability_and_sbom", True),
            ("syft", "image_sbom_secondary", scan_mode in {"medium", "aggressive"}),
            ("grype", "image_vulnerability_correlation", scan_mode == "aggressive"),
        ])
    elif target_type in {"kubernetes", "android", "ios"}:
        tool_ids.append(("trivy", "artifact_static_analysis", True))
    elif target_type == "mcp":
        tool_ids.extend([
            ("httpx", "transport_probe", True),
            ("mcp_audit", "protocol_and_semantic_security", True),
            ("nuclei", "supporting_surface_validation", scan_mode != "light"),
        ])
    elif target_type == "cloud_account":
        tool_ids.extend([
            ("prowler", "cspm_primary", True),
            ("scoutsuite", "cspm_secondary_optional", False),
        ])
    elif target_type == "asn":
        tool_ids.extend([
            ("amass", "relationship_expansion", False),
        ])
    else:
        tool_ids.extend([
            ("subfinder", "passive_enumeration", target_type in {"domain", "organization"}),
            ("assetfinder", "passive_enumeration", target_type in {"domain", "organization"}),
            ("amass", "recursive_enumeration", scan_mode != "light" and target_type in {"domain", "organization"}),
            ("dnsx", "dns_resolution", target_type in {"domain", "ip", "cidr"}),
            ("httpx", "http_probe", target_type in {"domain", "url", "ip", "cidr"}),
            ("naabu", "port_scan", target_type in {"domain", "ip", "cidr"} and scan_mode != "light"),
            ("nmap", "service_identification", target_type in {"domain", "ip", "cidr"} and scan_mode == "aggressive"),
            ("katana", "crawler", target_type in {"domain", "url"} and scan_mode != "light"),
            ("ffuf", "content_discovery", target_type in {"domain", "url"} and scan_mode == "aggressive"),
            ("arjun", "parameter_discovery", target_type in {"domain", "url"} and scan_mode != "light"),
            ("nikto", "baseline_web_validation", target_type in {"domain", "url"} and scan_mode != "light"),
            ("nuclei", "template_validation", target_type in {"domain", "url", "ip", "cidr"}),
        ])

    for utility in utilities:
        mapped = UTILITY_TO_TOOL_ID.get(utility)
        if mapped:
            tool_ids.append((mapped, "operator_requested", True))
    if "cloud" in requested_scans and target_type == "cloud_account":
        tool_ids.append(("scoutsuite", "operator_requested", True))

    plan: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for tool_id, role, required in tool_ids:
        if not any(item["id"] == tool_id for item in OPEN_SOURCE_SCANNERS):
            continue
        key = (tool_id, role)
        if key in seen:
            continue
        seen.add(key)
        scanner = _tool_by_id(tool_id)
        plan.append({
            "tool_id": scanner["id"],
            "name": scanner["name"],
            "role": role,
            "required": required,
            "status": scanner["status"],
            "bundled": scanner["bundled"],
            "install_mode": scanner["install_mode"],
            "outputs": scanner["outputs"],
            "execution": scanner["execution"],
            "safety_tier": (
                "explicit_approval" if scanner["execution"] == "guarded"
                else "conditional_adapter" if scanner["execution"] == "adapter"
                else "passive" if scanner["category"] in {"passive_discovery", "graph_discovery", "dns"}
                else "safe_active"
            ),
            "prerequisites": (
                ["external adapter configuration"] if scanner["install_mode"] == "external_adapter"
                else ["target authorization"] if scanner["execution"] in {"direct", "guarded"}
                else ["tenant configuration"] if scanner["execution"] == "adapter"
                else []
            ),
            "confidence": "high" if scanner["bundled"] and required else "medium" if scanner["bundled"] else "conditional",
        })
    return plan


def get_open_source_tool_catalog() -> dict[str, Any]:
    """Return the platform's curated open-source tool inventory."""
    by_category: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for scanner in OPEN_SOURCE_SCANNERS:
        by_category[scanner["category"]] = by_category.get(scanner["category"], 0) + 1
        by_status[scanner["status"]] = by_status.get(scanner["status"], 0) + 1
    return {
        "version": "2026.09",
        "counts": {
            "total": len(OPEN_SOURCE_SCANNERS),
            "by_category": by_category,
            "by_status": by_status,
        },
        "scanners": OPEN_SOURCE_SCANNERS,
    }
