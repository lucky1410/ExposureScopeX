"""Canonical, truthful platform capability registry derived from the 2026 blueprint."""

from __future__ import annotations

from typing import Any


def _capability(
    capability_id: str,
    name: str,
    sections: list[str],
    status: str,
    execution: str,
    safety_tier: str,
    outputs: list[str],
    prerequisites: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": capability_id,
        "name": name,
        "blueprint_sections": sections,
        "status": status,
        "execution": execution,
        "safety_tier": safety_tier,
        "outputs": outputs,
        "prerequisites": prerequisites or [],
    }


CAPABILITY_CATALOG = [
    _capability("seed_normalization", "Seed normalization and recursive expansion", ["3", "4", "76"], "operational", "inventory", "passive", ["canonical_assets", "deduplication", "relations", "scope_decisions"]),
    _capability("domain_dns", "Domain and DNS surface", ["5", "53", "75"], "operational", "assessment", "safe_active", ["assets", "relations", "findings", "drift"]),
    _capability("certificate_tls", "Certificate and TLS surface", ["6"], "operational", "assessment", "safe_active", ["certificates", "findings", "drift"]),
    _capability("routing", "IP, ASN, prefix, and routing", ["7", "76"], "operational", "assessment", "passive", ["prefixes", "assets", "ownership", "relations"]),
    _capability("ports_services", "Port and service enumeration", ["8"], "operational", "assessment", "safe_active", ["services", "technologies", "findings"]),
    _capability("web", "Web application enumeration and testing", ["9", "57"], "operational", "assessment", "safe_active", ["urls", "technologies", "findings", "evidence"]),
    _capability("api", "API discovery, inventory, and testing", ["10"], "operational", "assessment", "safe_active", ["endpoints", "schemas", "findings", "drift"]),
    _capability("cloud", "Cloud attack surface", ["11"], "conditional", "cloud_source", "authenticated", ["cloud_assets", "relationships", "findings"], ["configured AWS, Azure, or GCP source"]),
    _capability("container_kubernetes", "Container and Kubernetes surface", ["12"], "operational", "artifact", "authenticated", ["misconfigurations", "vulnerabilities", "sbom"], ["container image or public authorized manifest artifact"]),
    _capability("supply_chain", "Software supply chain", ["13", "58"], "operational", "artifact", "safe_active", ["dependencies", "sbom", "findings", "evidence"]),
    _capability("secrets", "Secrets and credential exposure", ["14"], "operational", "repository", "safe_active", ["redacted_findings", "attack_paths"], ["authorized repository"]),
    _capability("identity_saas", "Identity and SaaS surface", ["15"], "integration_required", "connector", "authenticated", ["identities", "applications", "relationships", "drift"], ["authorized IdP or SaaS connector"]),
    _capability("email_messaging", "Email and messaging surface", ["16"], "partial", "assessment", "safe_active", ["dns_posture", "findings"]),
    _capability("mobile", "Mobile application static artifact surface", ["17"], "operational", "artifact", "safe_active", ["packages", "endpoints", "findings"], ["authorized public APK/IPA artifact URL; dynamic device testing is separate"]),
    _capability("mobile_dynamic", "Mobile dynamic device analysis", ["17"], "conditional", "external_runtime_adapter", "authenticated", ["runtime_findings", "device_checks", "evidence"], ["authorized device controller and MOBILE_DYNAMIC_ADAPTER_URL"]),
    _capability("kubernetes_runtime", "Kubernetes runtime posture", ["12"], "conditional", "external_runtime_adapter", "authenticated", ["runtime_findings", "cluster_checks", "evidence"], ["authorized cluster analyzer and KUBERNETES_RUNTIME_ADAPTER_URL"]),
    _capability("iot_ot", "IoT and OT surface", ["18"], "integration_required", "connector", "authenticated", ["devices", "services", "findings"], ["explicitly authorized network and safe device profile"]),
    _capability("remote_access", "Remote access and management", ["19"], "partial", "assessment", "safe_active", ["services", "risk_signals", "findings"]),
    _capability("webhooks", "Webhooks and event-driven surface", ["20"], "partial", "assessment", "safe_active", ["endpoints", "findings", "evidence"], ["known endpoint or discovered API schema"]),
    _capability("browser_client", "Browser and client-side surface", ["21"], "partial", "assessment", "safe_active", ["scripts", "routes", "findings"]),
    _capability("ai_agent", "AI and agentic attack surface", ["22", "45", "74"], "research", "review", "deep_pentest", ["hypotheses", "candidate_paths"], ["explicit model/application authorization"]),
    _capability("mcp", "MCP protocol and semantic security", ["23", "24", "25", "26", "27"], "operational", "assessment", "safe_active", ["inventory", "test_coverage", "findings", "redacted_exchanges", "drift"]),
    _capability("attack_graph", "Asset and semantic attack graph", ["46", "59", "60"], "operational", "ingestion", "passive", ["nodes", "edges", "attack_paths"]),
    _capability("risk_confidence", "Contextual risk and confidence", ["47", "48"], "operational", "ingestion", "passive", ["risk_scores", "confidence_scores"]),
    _capability("continuous_drift", "Continuous monitoring and drift", ["49", "50", "54", "62"], "operational", "scheduler", "passive", ["snapshots", "events", "drift"]),
    _capability("shadow_it", "Shadow IT detection", ["51", "52"], "partial", "assessment", "passive", ["candidate_assets", "ownership_state"]),
    _capability("ownership", "Asset ownership and attribution", ["61"], "operational", "inventory", "passive", ["owner", "ownership_status", "relations"]),
    _capability("evidence", "Evidence-first findings", ["66", "67", "77"], "operational", "ingestion", "passive", ["fingerprints", "evidence", "dispositions", "expiry"]),
    _capability("soc_feedback", "SIEM/SOC feedback loop", ["78", "79"], "conditional", "integration", "passive", ["exposure_events", "notifications"], ["configured destination integration"]),
    _capability("autonomous_red_team", "Autonomous red-team loop", ["68", "69", "71", "72", "73"], "research", "review", "deep_pentest", ["hypotheses", "review_queue"], ["human approval and isolated authorized target"]),
    _capability("scan_orchestration", "Scan profiles, scheduling, and execution safety", ["28", "53", "54", "55", "56", "75"], "operational", "scheduler", "safe_active", ["execution_manifests", "heartbeats", "progress", "tool_runs", "cancellation"]),
    _capability("scan_job_isolation", "Per-scan Kubernetes Job isolation", ["64", "75", "80"], "conditional", "kubernetes_job", "safe_active", ["job_identity", "resource_limits", "cancellation", "audit_metadata"], ["SCAN_EXECUTOR=kubernetes, scanner RBAC, runtime secret, and results PVC"]),
    _capability("platform_architecture", "Platform architecture and data services", ["64", "65", "80", "85"], "operational", "platform", "passive", ["relational_records", "graph_relations", "task_state", "database_or_s3_evidence_artifacts"]),
    _capability("operating_model", "Metrics, roadmap, and operating controls", ["63", "70", "81", "82", "83"], "operational", "platform", "passive", ["coverage_metrics", "risk_metrics", "queue_metrics", "alerts", "readiness"]),
]


ACTIONABLE_BLUEPRINT_SECTIONS = {
    str(section) for section in list(range(3, 29)) + list(range(45, 84))
}
REFERENCE_ONLY_BLUEPRINT_SECTIONS = ["1", "2", "84"]


def get_capability_catalog() -> dict[str, Any]:
    counts: dict[str, int] = {}
    for item in CAPABILITY_CATALOG:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    mapped_sections = {
        section
        for capability in CAPABILITY_CATALOG
        for section in capability["blueprint_sections"]
    }
    return {
        "source": "ASM_Red_Team_Attack_Surface_Research_2026.md",
        "version": "2026.08",
        "status_definitions": {
            "operational": "Executes and produces normalized persisted output.",
            "conditional": "Executes when its named integration is configured.",
            "partial": "A production path exists, but not every blueprint test is automated.",
            "integration_required": "Modeled, but requires a dedicated authorized connector or artifact pipeline.",
            "research": "Tracked as safe hypotheses; not advertised as an executed test.",
        },
        "counts": counts,
        "document_coverage": {
            "actionable_sections": len(ACTIONABLE_BLUEPRINT_SECTIONS),
            "mapped_sections": len(ACTIONABLE_BLUEPRINT_SECTIONS & mapped_sections),
            "unmapped_sections": sorted(
                ACTIONABLE_BLUEPRINT_SECTIONS - mapped_sections,
                key=int,
            ),
            "reference_only_sections": REFERENCE_ONLY_BLUEPRINT_SECTIONS,
        },
        "capabilities": CAPABILITY_CATALOG,
    }
