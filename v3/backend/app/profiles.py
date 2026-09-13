from typing import Final

PLAN_VERSION: Final = "2026.09.11.5"

PROFILES: Final = {
    "light": [
        {"adapter": "scope_preflight", "timeout_seconds": 30, "required": True},
        {"adapter": "http_profile", "timeout_seconds": 60, "required": True},
        {"adapter": "tls_service_discovery", "timeout_seconds": 150, "required": True},
        {"adapter": "authenticated_crawl", "timeout_seconds": 300, "required": True},
        {"adapter": "security_headers", "timeout_seconds": 60, "required": True},
        {"adapter": "nuclei_baseline", "timeout_seconds": 1800, "required": True},
        {"adapter": "evidence_validation", "timeout_seconds": 60, "required": True},
    ],
    "medium": [
        {"adapter": "scope_preflight", "timeout_seconds": 30, "required": True},
        {"adapter": "http_profile", "timeout_seconds": 90, "required": True},
        {"adapter": "tls_service_discovery", "timeout_seconds": 300, "required": True},
        {"adapter": "authenticated_crawl", "timeout_seconds": 900, "required": True},
        {"adapter": "standards_discovery", "timeout_seconds": 120, "required": False},
        {"adapter": "application_surface_inventory", "timeout_seconds": 180, "required": True},
        {"adapter": "authenticated_session_review", "timeout_seconds": 120, "required": True},
        {"adapter": "api_contract_review", "timeout_seconds": 120, "required": False},
        {"adapter": "security_headers", "timeout_seconds": 90, "required": True},
        {"adapter": "nuclei_baseline", "timeout_seconds": 3600, "required": True},
        {"adapter": "evidence_validation", "timeout_seconds": 120, "required": True},
    ],
    "aggressive": [
        {"adapter": "scope_preflight", "timeout_seconds": 30, "required": True},
        {"adapter": "http_profile", "timeout_seconds": 120, "required": True},
        {"adapter": "tls_service_discovery", "timeout_seconds": 900, "required": True},
        {"adapter": "authenticated_crawl", "timeout_seconds": 1800, "required": True},
        {"adapter": "standards_discovery", "timeout_seconds": 240, "required": False},
        {"adapter": "application_surface_inventory", "timeout_seconds": 480, "required": True},
        {"adapter": "authenticated_session_review", "timeout_seconds": 180, "required": True},
        {"adapter": "api_contract_review", "timeout_seconds": 240, "required": False},
        {"adapter": "security_headers", "timeout_seconds": 120, "required": True},
        {"adapter": "route_security_policy_review", "timeout_seconds": 360, "required": True},
        {"adapter": "nuclei_baseline", "timeout_seconds": 7200, "required": True},
        {"adapter": "evidence_validation", "timeout_seconds": 180, "required": True},
    ],
}


def compile_plan(mode: str, target: str) -> dict:
    stages = [dict(position=index, **stage) for index, stage in enumerate(PROFILES[mode])]
    return {
        "version": PLAN_VERSION,
        "mode": mode,
        "target": target,
        "safety_class": "non_exploitative",
        "stages": stages,
    }
