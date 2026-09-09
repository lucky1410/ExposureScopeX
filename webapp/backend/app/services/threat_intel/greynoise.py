"""Standalone GreyNoise IP enrichment service.

Not coupled to OrgIntegration — call directly with an optional API key.

Community API (no key):
    GET https://api.greynoise.io/v3/community/{ip}

Enterprise API (with key):
    GET https://api.greynoise.io/v2/noise/quick/{ip}

Usage::

    from app.services.threat_intel.greynoise import enrich_ip

    result = await enrich_ip("198.51.100.42")
    result = await enrich_ip("198.51.100.42", api_key="gn-xxxxxxxx")
"""

import logging

import httpx

logger = logging.getLogger("exposurescopex.threat_intel.greynoise")

_COMMUNITY_URL = "https://api.greynoise.io/v3/community"
_ENTERPRISE_URL = "https://api.greynoise.io/v2/noise/quick"


async def enrich_ip(ip: str, api_key: str | None = None) -> dict:
    """Query GreyNoise for context about a single IP address.

    Uses the community API when *api_key* is ``None`` or empty; falls back to
    the enterprise endpoint when a key is provided.

    Args:
        ip:      IPv4 or IPv6 address to look up.
        api_key: Optional GreyNoise API key for the enterprise endpoint.

    Returns:
        A dict with the following keys (all present, some may be ``None``)::

            {
                "ip":             str,
                "noise":          bool,   # known scanner/crawler?
                "riot":           bool,   # known benign service?
                "classification": str | None,  # "benign" | "malicious" | "unknown"
                "name":           str | None,  # actor name if known
                "last_seen":      str | None,
                "tags":           list[str],
                "message":        str,
                "source":         "greynoise",
            }
    """
    use_enterprise = bool(api_key)
    url = f"{_ENTERPRISE_URL}/{ip}" if use_enterprise else f"{_COMMUNITY_URL}/{ip}"
    headers: dict[str, str] = {}
    if use_enterprise and api_key:
        headers["key"] = api_key

    _default = {
        "ip": ip,
        "noise": False,
        "riot": False,
        "classification": None,
        "name": None,
        "last_seen": None,
        "tags": [],
        "message": "",
        "source": "greynoise",
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers=headers)
    except httpx.RequestError as exc:
        logger.warning("GreyNoise request error for %s: %s", ip, exc)
        return {**_default, "message": f"Request error: {exc}"}

    if resp.status_code == 404:
        return {**_default, "message": "Not seen by GreyNoise"}

    if resp.status_code == 429:
        logger.warning("GreyNoise rate limit hit for %s", ip)
        return {**_default, "message": "Rate limited — retry later"}

    if resp.status_code != 200:
        logger.warning("GreyNoise %s: HTTP %d", ip, resp.status_code)
        return {**_default, "message": f"GreyNoise error: HTTP {resp.status_code}"}

    try:
        data = resp.json()
    except Exception as exc:
        return {**_default, "message": f"JSON parse error: {exc}"}

    if use_enterprise:
        # Enterprise /v2/noise/quick response shape
        return {
            "ip": ip,
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "classification": data.get("classification"),
            "name": data.get("name"),
            "last_seen": data.get("last_seen"),
            "tags": data.get("tags") or [],
            "message": data.get("message", ""),
            "source": "greynoise",
        }
    else:
        # Community /v3/community response shape
        return {
            "ip": ip,
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "classification": data.get("classification"),
            "name": data.get("name"),
            "last_seen": data.get("last_seen"),
            "tags": [],  # not available in community tier
            "message": data.get("message", ""),
            "source": "greynoise",
        }
