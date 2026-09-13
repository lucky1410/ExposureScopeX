from __future__ import annotations

from enum import IntEnum


METHODOLOGY_VERSION = "1.0.0-draft"


class AssuranceDepth(IntEnum):
    NOT_TESTED = 0
    OBSERVED = 1
    SAFE_VALIDATED = 2
    COMPREHENSIVE_SAFE_VALIDATION = 3


PROFILE_ORDER = ("light", "medium", "aggressive")

PROFILE_COVERAGE = {
    "light": {
        "scope_authorization": AssuranceDepth.OBSERVED,
        "attack_surface": AssuranceDepth.OBSERVED,
        "service_tls_http_configuration": AssuranceDepth.OBSERVED,
        "authentication": AssuranceDepth.OBSERVED,
        "session_management": AssuranceDepth.OBSERVED,
        "authorization": AssuranceDepth.NOT_TESTED,
        "input_validation": AssuranceDepth.NOT_TESTED,
        "client_side": AssuranceDepth.OBSERVED,
        "api_security": AssuranceDepth.OBSERVED,
        "business_logic": AssuranceDepth.NOT_TESTED,
        "evidence_validation": AssuranceDepth.SAFE_VALIDATED,
    },
    "medium": {
        "scope_authorization": AssuranceDepth.OBSERVED,
        "attack_surface": AssuranceDepth.SAFE_VALIDATED,
        "service_tls_http_configuration": AssuranceDepth.OBSERVED,
        "authentication": AssuranceDepth.OBSERVED,
        "session_management": AssuranceDepth.OBSERVED,
        "authorization": AssuranceDepth.NOT_TESTED,
        "input_validation": AssuranceDepth.NOT_TESTED,
        "client_side": AssuranceDepth.OBSERVED,
        "api_security": AssuranceDepth.OBSERVED,
        "business_logic": AssuranceDepth.OBSERVED,
        "evidence_validation": AssuranceDepth.SAFE_VALIDATED,
    },
    "aggressive": {
        "scope_authorization": AssuranceDepth.OBSERVED,
        "attack_surface": AssuranceDepth.SAFE_VALIDATED,
        "service_tls_http_configuration": AssuranceDepth.SAFE_VALIDATED,
        "authentication": AssuranceDepth.OBSERVED,
        "session_management": AssuranceDepth.OBSERVED,
        "authorization": AssuranceDepth.NOT_TESTED,
        "input_validation": AssuranceDepth.NOT_TESTED,
        "client_side": AssuranceDepth.OBSERVED,
        "api_security": AssuranceDepth.OBSERVED,
        "business_logic": AssuranceDepth.OBSERVED,
        "evidence_validation": AssuranceDepth.SAFE_VALIDATED,
    },
}


def validate_profile_monotonicity() -> None:
    families = set(PROFILE_COVERAGE[PROFILE_ORDER[0]])
    for profile in PROFILE_ORDER:
        if set(PROFILE_COVERAGE[profile]) != families:
            raise ValueError(f"profile {profile!r} does not define the complete test-family set")
    for lower, higher in zip(PROFILE_ORDER, PROFILE_ORDER[1:]):
        regressions = [
            family
            for family in sorted(families)
            if PROFILE_COVERAGE[higher][family] < PROFILE_COVERAGE[lower][family]
        ]
        if regressions:
            raise ValueError(f"profile {higher!r} regresses below {lower!r}: {', '.join(regressions)}")


def profile_contract(profile: str) -> dict:
    validate_profile_monotonicity()
    if profile not in PROFILE_COVERAGE:
        raise ValueError(f"unsupported assessment profile: {profile}")
    return {
        "methodology_version": METHODOLOGY_VERSION,
        "profile": profile,
        "coverage": {
            family: {"depth": depth.name.lower(), "level": int(depth)}
            for family, depth in PROFILE_COVERAGE[profile].items()
        },
    }
