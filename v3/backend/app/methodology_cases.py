from __future__ import annotations

from dataclasses import dataclass

from .methodology import METHODOLOGY_VERSION


@dataclass(frozen=True)
class MethodologyCase:
    case_id: str
    family: str
    adapter: str
    profiles: frozenset[str]
    title: str


CASES = (
    MethodologyCase("ESX-SCOPE-001", "scope_authorization", "scope_preflight", frozenset({"light", "medium", "aggressive"}), "Authorization and target scope preflight"),
    MethodologyCase("ESX-SUBDOMAIN-001", "attack_surface", "subdomain_enumeration", frozenset({"light"}), "Passive certificate-transparency subdomain inventory"),
    MethodologyCase("ESX-HTTP-001", "attack_surface", "http_profile", frozenset({"light", "medium", "aggressive"}), "HTTP reachability and response profile"),
    MethodologyCase("ESX-SERVICE-001", "service_tls_http_configuration", "tls_service_discovery", frozenset({"light", "medium", "aggressive"}), "Service and TLS discovery"),
    MethodologyCase("ESX-CRAWL-001", "attack_surface", "authenticated_crawl", frozenset({"light", "medium", "aggressive"}), "Same-origin route and authenticated-state inventory"),
    MethodologyCase("ESX-STANDARDS-001", "attack_surface", "standards_discovery", frozenset({"medium", "aggressive"}), "Published security and API metadata discovery"),
    MethodologyCase("ESX-SURFACE-002", "attack_surface", "application_surface_inventory", frozenset({"medium", "aggressive"}), "Safe application route, form, parameter, and client-resource inventory"),
    MethodologyCase("ESX-SESSION-002", "session_management", "authenticated_session_review", frozenset({"medium", "aggressive"}), "Authenticated session cookie control review"),
    MethodologyCase("ESX-API-002", "api_security", "api_contract_review", frozenset({"medium", "aggressive"}), "Published API contract and authentication-scheme review"),
    MethodologyCase("ESX-CONFIG-002", "service_tls_http_configuration", "route_security_policy_review", frozenset({"aggressive"}), "Route-level HTTP security policy consistency review"),
    MethodologyCase("ESX-HEADERS-001", "service_tls_http_configuration", "security_headers", frozenset({"light", "medium", "aggressive"}), "HTTP security policy header assessment"),
    MethodologyCase("ESX-NUCLEI-BASELINE-001", "attack_surface", "nuclei_baseline", frozenset({"light", "medium", "aggressive"}), "Approved signed non-intrusive template baseline"),
    MethodologyCase("ESX-EVIDENCE-001", "evidence_validation", "evidence_validation", frozenset({"light", "medium", "aggressive"}), "Evidence integrity validation"),
)

CASES_BY_ADAPTER = {case.adapter: case for case in CASES}


def coverage_records(plan: dict) -> list[dict]:
    profile = str(plan["mode"])
    records = []
    for stage in plan["stages"]:
        case = CASES_BY_ADAPTER.get(stage["adapter"])
        if case is None:
            raise ValueError(f"adapter {stage['adapter']!r} has no methodology case")
        if profile not in case.profiles:
            raise ValueError(f"methodology case {case.case_id!r} is not applicable to profile {profile!r}")
        records.append({
            "case_id": case.case_id,
            "methodology_version": METHODOLOGY_VERSION,
            "profile": profile,
            "family": case.family,
            "adapter": case.adapter,
            "title": case.title,
            "required": bool(stage["required"]),
        })
    return records


def canonical_observation_key(evidence: dict) -> str | None:
    if evidence.get("evidence_type") == "http_response_header_absence":
        header = str(evidence.get("header_name") or "").strip().lower()
        return f"http.header.absent:{header}" if header else None
    template_id = str(evidence.get("template_id") or "").strip().lower()
    return f"nuclei.template:{template_id}" if template_id else None


def evaluate_evidence_oracle(evidence: dict, source_payload: object | None) -> tuple[str, str]:
    if evidence.get("evidence_type") != "http_response_header_absence":
        return "not_evaluated", "No independent deterministic oracle is registered for this observation type."
    if not isinstance(source_payload, dict):
        return "failed", "The header oracle requires a structured original HTTP response artifact."
    headers = source_payload.get("headers")
    header = str(evidence.get("header_name") or "").lower()
    if not isinstance(headers, dict) or not header:
        return "failed", "The original response does not contain the fields required by the header oracle."
    normalized = {str(name).lower() for name in headers}
    if header in normalized:
        return "failed", f"The original response contains {header}; the absence claim is contradicted."
    return "passed", f"The original response independently confirms that {header} is absent."


def observation_evidence_kinds(evidence: dict) -> frozenset[str]:
    kinds = set()
    if evidence.get("evidence_type") == "http_response_header_absence":
        kinds.add("response")
    if evidence.get("request"):
        kinds.add("request")
    if evidence.get("response"):
        kinds.add("response")
    if evidence.get("screenshot_artifact_id"):
        kinds.add("browser_capture")
    return frozenset(kinds)
