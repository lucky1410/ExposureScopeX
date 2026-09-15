from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from .subdomain_scope import normalized_hostname


DISCOVERY_SOURCE_CLIENT_DECLARED = "client_declared_seed"
DISCOVERY_SOURCE_CERTIFICATE_TRANSPARENCY = "certificate_transparency:crt.sh"


def target_for_discovered_hostname(parent_target: str, hostname: str) -> str:
    """Keep the parent scheme and explicit port while removing paths and credentials."""
    parent = urlsplit(parent_target)
    if parent.scheme not in {"http", "https"}:
        raise ValueError("Parent target must be an absolute HTTP or HTTPS URL")
    host = normalized_hostname(hostname)
    port = f":{parent.port}" if parent.port else ""
    return urlunsplit((parent.scheme, f"{host}{port}", "", "", ""))


def display_asset_status(ownership_status: str, assessment_status: str) -> str:
    """Return the client-facing state without suggesting that a candidate is owned."""
    if ownership_status == "excluded":
        return "excluded"
    if ownership_status == "candidate":
        return "needs ownership review"
    if ownership_status == "client_declared" and assessment_status == "not_assessed":
        return "authorization required"
    if assessment_status == "queued":
        return "assessment queued"
    if assessment_status == "assessed":
        return "assessed"
    if assessment_status == "blocked":
        return "assessment blocked"
    return "approved for assessment"
