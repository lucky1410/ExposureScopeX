"""Azure asset synchronization for ExposureScopeX ASM.

Uses pure httpx with the OAuth2 client credentials flow.
No Azure SDK dependency required.
"""

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_ARM_BASE = "https://management.azure.com"
_ARM_SCOPE = "https://management.azure.com/.default"


# ── Auth helper ───────────────────────────────────────────────────────────────

def _get_access_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Obtain an Azure ARM access token via the client credentials flow.

    Args:
        tenant_id:     Azure AD tenant ID.
        client_id:     Service principal (app) client ID.
        client_secret: Service principal client secret.

    Returns:
        Bearer access token string.

    Raises:
        RuntimeError on auth failure.
    """
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    try:
        resp = httpx.post(
            url,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": _ARM_SCOPE,
                "grant_type": "client_credentials",
            },
            timeout=30,
        )
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise RuntimeError(
            f"Azure token request failed ({exc.response.status_code}): {exc.response.text}"
        ) from exc
    return resp.json()["access_token"]


def _arm_get(url: str, headers: dict, params: dict | None = None) -> dict:
    """GET from the Azure ARM API and return the parsed JSON body."""
    resp = httpx.get(url, headers=headers, params=params, timeout=60)
    resp.raise_for_status()
    return resp.json()


# ── Main sync function ────────────────────────────────────────────────────────

def sync_azure_assets(source_id: str, org_id: str, config: dict) -> dict:
    """Enumerate public-facing Azure assets and return a normalized asset list.

    Args:
        source_id:      AsmCloudSource UUID (used for logging only).
        org_id:         Organisation UUID (used for logging only).
        config:         Decrypted credential dict from AsmCloudSource.config.
                        Expected keys: tenant_id, client_id, client_secret,
                        subscription_id.

    Returns:
        {"assets": [...], "count": N}

    Each asset dict contains:
        name, target_value, target_type, tags (list[str]),
        cloud_region, cloud_account_id (subscription_id)
    """
    tenant_id = config.get("tenant_id")
    client_id = config.get("client_id")
    client_secret = config.get("client_secret")
    subscription_id = config.get("subscription_id")

    missing = [k for k, v in {
        "tenant_id": tenant_id,
        "client_id": client_id,
        "client_secret": client_secret,
        "subscription_id": subscription_id,
    }.items() if not v]
    if missing:
        raise RuntimeError(f"Azure config missing required keys: {', '.join(missing)}")

    try:
        access_token = _get_access_token(tenant_id, client_id, client_secret)
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(f"Failed to obtain Azure access token: {exc}") from exc

    auth_headers = {"Authorization": f"Bearer {access_token}"}
    sub_base = f"{_ARM_BASE}/subscriptions/{subscription_id}"
    assets: list[dict[str, Any]] = []

    # ── 1. Public IP addresses ────────────────────────────────────────────────
    # Fetching all public IPs is more reliable than walking VMs → NICs → PIPs
    try:
        url = f"{sub_base}/providers/Microsoft.Network/publicIPAddresses"
        data = _arm_get(url, auth_headers, params={"api-version": "2024-03-01"})
        for pip in data.get("value", []):
            props = pip.get("properties", {})
            ip_addr = props.get("ipAddress")
            if not ip_addr:
                # Unallocated / deallocated PIPs have no ipAddress yet
                continue
            location = pip.get("location", "unknown")
            name = pip.get("name", ip_addr)
            assets.append({
                "name": name,
                "target_value": ip_addr,
                "target_type": "ip",
                "tags": [f"{k}={v}" for k, v in pip.get("tags", {}).items()],
                "cloud_region": location,
                "cloud_account_id": subscription_id,
            })
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "source=%s Azure publicIPAddresses failed (%s): %s",
            source_id, exc.response.status_code, exc.response.text[:200],
        )

    # ── 2. App Services (Web Apps) ────────────────────────────────────────────
    try:
        url = f"{sub_base}/providers/Microsoft.Web/sites"
        data = _arm_get(url, auth_headers, params={"api-version": "2023-12-01"})
        for site in data.get("value", []):
            hostname = site.get("properties", {}).get("defaultHostName")
            if not hostname:
                continue
            location = site.get("location", "unknown")
            assets.append({
                "name": site.get("name", hostname),
                "target_value": hostname,
                "target_type": "domain",
                "tags": [f"{k}={v}" for k, v in site.get("tags", {}).items()],
                "cloud_region": location,
                "cloud_account_id": subscription_id,
            })
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "source=%s Azure App Services failed (%s): %s",
            source_id, exc.response.status_code, exc.response.text[:200],
        )

    # ── 3. Azure DNS zones → A / CNAME record sets ───────────────────────────
    try:
        url = f"{sub_base}/providers/Microsoft.Network/dnsZones"
        data = _arm_get(url, auth_headers, params={"api-version": "2018-05-01"})
        for zone in data.get("value", []):
            zone_name = zone.get("name")
            zone_id = zone.get("id")
            if not zone_name or not zone_id:
                continue
            zone_location = zone.get("location", "global")
            try:
                rs_url = f"{_ARM_BASE}{zone_id}/recordSets"
                rs_data = _arm_get(rs_url, auth_headers, params={"api-version": "2018-05-01"})
                for rs in rs_data.get("value", []):
                    # type is like "Microsoft.Network/dnszones/A"
                    rs_type = rs.get("type", "").split("/")[-1].upper()
                    props = rs.get("properties", {})
                    rs_name = rs.get("name", "@")
                    fqdn = zone_name if rs_name == "@" else f"{rs_name}.{zone_name}"

                    if rs_type == "A":
                        for a_rec in props.get("ARecords", []):
                            ip = a_rec.get("ipv4Address")
                            if not ip:
                                continue
                            assets.append({
                                "name": fqdn,
                                "target_value": ip,
                                "target_type": "ip",
                                "tags": [f"dns_zone={zone_name}"],
                                "cloud_region": zone_location,
                                "cloud_account_id": subscription_id,
                            })
                    elif rs_type == "CNAME":
                        cname = props.get("CNAMERecord", {}).get("cname")
                        if cname:
                            assets.append({
                                "name": fqdn,
                                "target_value": cname.rstrip("."),
                                "target_type": "domain",
                                "tags": [f"dns_zone={zone_name}"],
                                "cloud_region": zone_location,
                                "cloud_account_id": subscription_id,
                            })
            except httpx.HTTPStatusError as exc:
                logger.warning(
                    "source=%s Azure DNS record sets for zone %s failed (%s)",
                    source_id, zone_name, exc.response.status_code,
                )
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "source=%s Azure DNS zones failed (%s): %s",
            source_id, exc.response.status_code, exc.response.text[:200],
        )

    # ── 4. Storage accounts (blob endpoints) ──────────────────────────────────
    try:
        url = f"{sub_base}/providers/Microsoft.Storage/storageAccounts"
        data = _arm_get(url, auth_headers, params={"api-version": "2023-05-01"})
        for sa in data.get("value", []):
            sa_name = sa.get("name")
            if not sa_name:
                continue
            location = sa.get("location", "unknown")
            assets.append({
                "name": sa_name,
                "target_value": f"{sa_name}.blob.core.windows.net",
                "target_type": "domain",
                "tags": [f"{k}={v}" for k, v in sa.get("tags", {}).items()],
                "cloud_region": location,
                "cloud_account_id": subscription_id,
            })
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "source=%s Azure storage accounts failed (%s): %s",
            source_id, exc.response.status_code, exc.response.text[:200],
        )

    logger.info("source=%s Azure sync complete: %d assets", source_id, len(assets))
    return {"assets": assets, "count": len(assets)}
