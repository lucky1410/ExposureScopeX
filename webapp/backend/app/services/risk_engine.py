"""Consistent evidence confidence and contextual risk scoring."""

from __future__ import annotations

from decimal import Decimal


SEVERITY_BASE = {"CRITICAL": 95, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 5}
SOURCE_CONFIDENCE = {
    "nuclei": 88,
    "nmap": 92,
    "api": 82,
    "api_security": 82,
    "ssl_check": 90,
    "http_headers": 90,
    "cloud": 80,
    "ffuf": 72,
    "arjun": 78,
    "nikto": 70,
    "email_security": 85,
    "mcp": 85,
    "trivy": 86,
    "trivy-misconfiguration": 84,
    "trivy-secret": 88,
    "gitleaks": 90,
    "prowler": 87,
    "scoutsuite": 80,
    "sqlmap": 93,
    "grype": 84,
    "safe-web-validator": 80,
}


def confidence_score(source: str | None, evidence: str | None, *, corroboration_count: int = 1) -> Decimal:
    score = SOURCE_CONFIDENCE.get((source or "").lower(), 65)
    if evidence and len(evidence.strip()) >= 20:
        score += 5
    if corroboration_count > 1:
        score += min(10, (corroboration_count - 1) * 3)
    return Decimal(min(100, score))


def contextual_risk_score(
    severity: str,
    confidence: Decimal | int | float,
    *,
    reachable: bool = True,
    exploitable: bool | None = None,
    business_criticality: int = 50,
) -> Decimal:
    base = SEVERITY_BASE.get(severity.upper(), 5)
    reachability_factor = 1.0 if reachable else 0.55
    exploit_factor = 1.15 if exploitable is True else 0.85 if exploitable is False else 1.0
    criticality_factor = 0.75 + (max(0, min(100, business_criticality)) / 200)
    value = base * (float(confidence) / 100) * reachability_factor * exploit_factor * criticality_factor
    return Decimal(str(round(min(100, value), 2)))
