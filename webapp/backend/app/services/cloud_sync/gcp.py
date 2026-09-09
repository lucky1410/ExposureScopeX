"""GCP asset synchronization for ExposureScopeX ASM.

Uses pure httpx + cryptography library for RS256 JWT signing.
No google-cloud SDK dependency required.
"""

import base64
import json
import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GCP_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


# ── JWT helpers ───────────────────────────────────────────────────────────────

def _b64url(data: bytes) -> str:
    """Base64-URL encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _get_access_token(sa_info: dict) -> str:
    """Exchange a service account JSON for a Google OAuth2 access token.

    Args:
        sa_info: Parsed service account JSON dict (must contain
                 'client_email' and 'private_key').

    Returns:
        Bearer access token string.

    Raises:
        RuntimeError on auth failure.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iss": sa_info["client_email"],
        "scope": _GCP_SCOPE,
        "aud": _TOKEN_URL,
        "exp": now + 3600,
        "iat": now,
    }

    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    try:
        private_key = serialization.load_pem_private_key(
            sa_info["private_key"].encode(),
            password=None,
        )
    except Exception as exc:
        raise RuntimeError(f"Failed to load GCP private key: {exc}") from exc

    signature = private_key.sign(signing_input, asym_padding.PKCS1v15(), hashes.SHA256())
    jwt_token = f"{header_b64}.{payload_b64}.{_b64url(signature)}"

    try:
        resp = httpx.post(
            _TOKEN_URL,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jwt_token,
            },
            timeout=30,
        )
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise RuntimeError(
            f"GCP token exchange failed ({exc.response.status_code}): {exc.response.text}"
        ) from exc

    return resp.json()["access_token"]


# ── Main sync function ────────────────────────────────────────────────────────

def sync_gcp_assets(source_id: str, org_id: str, config: dict) -> dict:
    """Enumerate public-facing GCP assets and return a normalized asset list.

    Args:
        source_id: AsmCloudSource UUID (used for logging only).
        org_id:    Organisation UUID (used for logging only).
        config:    Decrypted credential dict from AsmCloudSource.config.
                   Expected keys: service_account_json (JSON string),
                   project_id.

    Returns:
        {"assets": [...], "count": N}

    Each asset dict contains:
        name, target_value, target_type, tags (list[str]),
        cloud_region, cloud_account_id (project_id)
    """
    sa_json_str = config.get("service_account_json")
    project_id = config.get("project_id")
    if not sa_json_str:
        raise RuntimeError("GCP config missing required key 'service_account_json'")
    if not project_id:
        raise RuntimeError("GCP config missing required key 'project_id'")

    try:
        sa_info = json.loads(sa_json_str)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid service_account_json (not valid JSON): {exc}") from exc

    try:
        access_token = _get_access_token(sa_info)
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(f"Failed to obtain GCP access token: {exc}") from exc

    auth_headers = {"Authorization": f"Bearer {access_token}"}
    assets: list[dict[str, Any]] = []

    # ── 1. Compute Engine instances with external IPs ─────────────────────────
    try:
        url = (
            f"https://compute.googleapis.com/compute/v1"
            f"/projects/{project_id}/aggregated/instances"
        )
        resp = httpx.get(url, headers=auth_headers, timeout=60)
        resp.raise_for_status()
        for zone_key, zone_data in resp.json().get("items", {}).items():
            if zone_key == "unreachable":
                continue
            # zone_key is like "zones/us-central1-a"; strip to region
            zone_label = zone_key.split("/")[-1] if "/" in zone_key else zone_key
            # "us-central1-a" → "us-central1"
            inst_region = zone_label.rsplit("-", 1)[0]
            for inst in zone_data.get("instances", []):
                # Walk network interfaces looking for a natIP
                nat_ip: str | None = None
                for iface in inst.get("networkInterfaces", []):
                    for ac in iface.get("accessConfigs", []):
                        if ac.get("natIP"):
                            nat_ip = ac["natIP"]
                            break
                    if nat_ip:
                        break
                if not nat_ip:
                    continue
                assets.append({
                    "name": inst.get("name", nat_ip),
                    "target_value": nat_ip,
                    "target_type": "ip",
                    "tags": [f"{k}={v}" for k, v in inst.get("labels", {}).items()],
                    "cloud_region": inst_region,
                    "cloud_account_id": project_id,
                })
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "source=%s GCP Compute aggregated instances failed (%s): %s",
            source_id, exc.response.status_code, exc.response.text[:200],
        )

    # ── 2. Cloud DNS managed zones → A / CNAME record sets ───────────────────
    try:
        url = (
            f"https://dns.googleapis.com/dns/v1"
            f"/projects/{project_id}/managedZones"
        )
        resp = httpx.get(url, headers=auth_headers, timeout=30)
        resp.raise_for_status()
        for zone in resp.json().get("managedZones", []):
            zone_name = zone.get("name")
            if not zone_name:
                continue
            try:
                rrs_url = (
                    f"https://dns.googleapis.com/dns/v1"
                    f"/projects/{project_id}/managedZones/{zone_name}/rrsets"
                )
                rrs_resp = httpx.get(rrs_url, headers=auth_headers, timeout=30)
                rrs_resp.raise_for_status()
                for rrset in rrs_resp.json().get("rrsets", []):
                    rr_type = rrset.get("type")
                    if rr_type not in ("A", "CNAME"):
                        continue
                    record_name = rrset.get("name", "").rstrip(".")
                    target_type = "ip" if rr_type == "A" else "domain"
                    for rdata in rrset.get("rrdatas", []):
                        assets.append({
                            "name": record_name,
                            "target_value": rdata.rstrip("."),
                            "target_type": target_type,
                            "tags": [f"dns_zone={zone_name}"],
                            "cloud_region": "global",
                            "cloud_account_id": project_id,
                        })
            except httpx.HTTPStatusError as exc:
                logger.warning(
                    "source=%s GCP DNS rrsets for zone %s failed (%s)",
                    source_id, zone_name, exc.response.status_code,
                )
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "source=%s GCP DNS managedZones failed (%s): %s",
            source_id, exc.response.status_code, exc.response.text[:200],
        )

    # ── 3. External forwarding rules (Load Balancers) ─────────────────────────
    try:
        url = (
            f"https://compute.googleapis.com/compute/v1"
            f"/projects/{project_id}/aggregated/forwardingRules"
        )
        resp = httpx.get(url, headers=auth_headers, timeout=60)
        resp.raise_for_status()
        for zone_key, zone_data in resp.json().get("items", {}).items():
            if zone_key == "unreachable":
                continue
            zone_label = zone_key.split("/")[-1] if "/" in zone_key else zone_key
            for rule in zone_data.get("forwardingRules", []):
                if rule.get("loadBalancingScheme") != "EXTERNAL":
                    continue
                ip_address = rule.get("IPAddress")
                if not ip_address:
                    continue
                assets.append({
                    "name": rule.get("name", ip_address),
                    "target_value": ip_address,
                    "target_type": "ip",
                    "tags": [f"{k}={v}" for k, v in rule.get("labels", {}).items()],
                    "cloud_region": zone_label,
                    "cloud_account_id": project_id,
                })
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "source=%s GCP forwardingRules failed (%s): %s",
            source_id, exc.response.status_code, exc.response.text[:200],
        )

    # ── 4. GCS buckets ────────────────────────────────────────────────────────
    try:
        url = f"https://storage.googleapis.com/storage/v1/b"
        resp = httpx.get(
            url,
            headers=auth_headers,
            params={"project": project_id},
            timeout=30,
        )
        resp.raise_for_status()
        for bucket in resp.json().get("items", []):
            bucket_name = bucket.get("name")
            if not bucket_name:
                continue
            assets.append({
                "name": bucket_name,
                "target_value": f"{bucket_name}.storage.googleapis.com",
                "target_type": "domain",
                "tags": [f"{k}={v}" for k, v in bucket.get("labels", {}).items()],
                "cloud_region": bucket.get("location", "global").lower(),
                "cloud_account_id": project_id,
            })
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "source=%s GCS list buckets failed (%s): %s",
            source_id, exc.response.status_code, exc.response.text[:200],
        )

    logger.info("source=%s GCP sync complete: %d assets", source_id, len(assets))
    return {"assets": assets, "count": len(assets)}
