"""NVD 2.0 daily CVE feed ingestion.

Fetches CVEs published or modified in the last N days from the NVD 2.0 REST
API and optionally matches them against asset technologies tracked in the
database.

NVD API reference: https://nvd.nist.gov/developers/vulnerabilities
Rate limits (2024):
  - No API key : 5 requests / 30 s  → sleep 6 s between requests
  - With API key: 50 requests / 30 s → sleep 0.6 s between requests

Usage (standalone)::

    import asyncio
    from app.services.threat_intel.nvd_feed import run_nvd_feed_sync

    result = asyncio.run(run_nvd_feed_sync())
    print(result)

Usage (Celery task, defined in app.services.celery_app)::

    from app.services.celery_app import nvd_feed_sync_task
    nvd_feed_sync_task.delay()
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

logger = logging.getLogger("exposurescopex.threat_intel.nvd_feed")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_RESULTS_PER_PAGE = 2000  # NVD maximum per request


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso(dt: datetime) -> str:
    """Format a datetime as NVD-compatible ISO 8601 (UTC, no microseconds)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def _parse_cvss_v3(metrics: dict) -> tuple[float | None, str]:
    """Extract CVSS v3.1 (preferred) or v3.0 base score and severity."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity", "UNKNOWN")
            return score, severity
    return None, "UNKNOWN"


def _extract_affected_products(configurations: dict) -> list[str]:
    """Pull CPE match strings from CVE configuration nodes (best-effort)."""
    products: list[str] = []
    nodes = configurations.get("nodes", [])
    for node in nodes:
        for match in node.get("cpeMatch", []):
            cpe = match.get("criteria", "")
            # cpe:2.3:a:<vendor>:<product>:<version>:...
            parts = cpe.split(":")
            if len(parts) >= 5:
                vendor = parts[3]
                product = parts[4]
                version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""
                label = f"{vendor}:{product}"
                if version:
                    label += f":{version}"
                products.append(label)
    return list(set(products))  # deduplicate


def _parse_cve_item(item: dict) -> dict:
    """Normalise a raw NVD CVE item into a flat dict."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    published = cve.get("published", "")
    modified = cve.get("lastModified", "")

    # English description (preferred)
    description = ""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    metrics = cve.get("metrics", {})
    cvss_score, severity = _parse_cvss_v3(metrics)

    # Fall back to v2
    if cvss_score is None:
        for entry in metrics.get("cvssMetricV2", []):
            cvss_score = entry.get("cvssData", {}).get("baseScore")
            severity = entry.get("baseSeverity", "UNKNOWN")
            break

    configurations = cve.get("configurations", {})
    affected_products = _extract_affected_products(configurations)

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_v3_score": cvss_score,
        "severity": severity,
        "published": published,
        "last_modified": modified,
        "affected_products": affected_products,
    }


# ---------------------------------------------------------------------------
# Core fetch
# ---------------------------------------------------------------------------

async def fetch_recent_cves(
    days_back: int = 1,
    api_key: str | None = None,
) -> list[dict]:
    """Fetch CVEs published in the last *days_back* days from NVD API 2.0.

    Paginates automatically.  Respects rate limits: 6 s between requests
    without an API key, 0.6 s with one.

    Args:
        days_back: How many calendar days back to query (default 1 = yesterday).
        api_key:   Optional NVD API key for higher rate limits.

    Returns:
        List of normalised CVE dicts (see :func:`_parse_cve_item`).
    """
    now_utc = datetime.now(timezone.utc)
    pub_end = now_utc
    pub_start = now_utc - timedelta(days=days_back)

    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    sleep_between = 0.6 if api_key else 6.0

    cves: list[dict] = []
    start_index = 0

    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        while True:
            params: dict[str, str | int] = {
                "pubStartDate": _iso(pub_start),
                "pubEndDate": _iso(pub_end),
                "resultsPerPage": _RESULTS_PER_PAGE,
                "startIndex": start_index,
            }

            try:
                resp = await client.get(NVD_API_URL, params=params)
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                logger.error("NVD API HTTP error: %s", exc)
                break
            except httpx.RequestError as exc:
                logger.error("NVD API request error: %s", exc)
                break

            data = resp.json()
            total = data.get("totalResults", 0)
            results_per_page = data.get("resultsPerPage", 0)
            vulnerabilities = data.get("vulnerabilities", [])

            for item in vulnerabilities:
                cves.append(_parse_cve_item(item))

            logger.info(
                "NVD feed: fetched %d/%d CVEs (startIndex=%d)",
                start_index + len(vulnerabilities),
                total,
                start_index,
            )

            start_index += results_per_page
            if start_index >= total or not vulnerabilities:
                break

            await asyncio.sleep(sleep_between)

    return cves


# ---------------------------------------------------------------------------
# Asset matching
# ---------------------------------------------------------------------------

async def match_cves_to_assets(cves: list[dict], db) -> list[dict]:
    """Check if any fetched CVEs affect technologies tracked in the DB.

    Queries the ``assets`` table for JSONB ``technologies`` columns.
    Each technology is expected to be ``{"name": str, "version": str | None}``.

    Matching strategy: case-insensitive substring match of the CPE product
    token against the asset technology name.

    Args:
        cves: Output of :func:`fetch_recent_cves`.
        db:   An async SQLAlchemy ``AsyncSession``.

    Returns:
        List of match dicts::

            {
                "cve_id": str,
                "asset_id": str,
                "asset_name": str,
                "product": str,
                "version": str | None,
                "cvss_score": float | None,
            }
    """
    if not cves:
        return []

    from sqlalchemy import select, text

    try:
        # Pull all assets with their technology arrays
        result = await db.execute(
            text(
                "SELECT id::text, name, technologies "
                "FROM assets "
                "WHERE technologies IS NOT NULL AND jsonb_array_length(technologies) > 0"
            )
        )
        rows = result.fetchall()
    except Exception as exc:
        logger.warning("match_cves_to_assets: DB query failed: %s", exc)
        return []

    matches: list[dict] = []

    for cve in cves:
        cve_id = cve["cve_id"]
        cvss_score = cve.get("cvss_v3_score")

        # Build set of product tokens from CPE strings
        product_tokens: set[str] = set()
        for prod_str in cve.get("affected_products", []):
            # "vendor:product" or "vendor:product:version"
            parts = prod_str.split(":")
            if len(parts) >= 2:
                product_tokens.add(parts[1].lower())

        if not product_tokens:
            continue

        for asset_id, asset_name, technologies in rows:
            if not technologies:
                continue
            for tech in technologies:
                tech_name = (tech.get("name") or "").lower()
                tech_version = tech.get("version")
                # Match any product token as substring of the tech name
                for token in product_tokens:
                    if token and token in tech_name:
                        matches.append(
                            {
                                "cve_id": cve_id,
                                "asset_id": asset_id,
                                "asset_name": asset_name,
                                "product": tech_name,
                                "version": tech_version,
                                "cvss_score": cvss_score,
                            }
                        )
                        break  # one match per tech per CVE is enough

    return matches


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

async def run_nvd_feed_sync(
    org_id: str | None = None,
    days_back: int = 1,
    api_key: str | None = None,
    db=None,
) -> dict:
    """Fetch yesterday's CVEs and optionally match against tracked assets.

    This is the main entry point called by the Celery task wrapper.

    Args:
        org_id:   Organisation UUID (used for asset filtering — reserved for
                  future use; currently all assets are queried).
        days_back: Number of days to look back in NVD (default 1).
        api_key:  NVD API key (optional).
        db:       Async DB session for asset matching (optional; skipped when
                  not provided).

    Returns:
        Summary dict::

            {
                "cves_fetched": int,
                "asset_matches": int,
                "status": "ok" | "error",
                "message": str,
            }
    """
    logger.info("NVD feed sync starting: days_back=%d org=%s", days_back, org_id)

    try:
        cves = await fetch_recent_cves(days_back=days_back, api_key=api_key)
    except Exception as exc:
        logger.error("NVD feed fetch failed: %s", exc)
        return {
            "cves_fetched": 0,
            "asset_matches": 0,
            "status": "error",
            "message": str(exc),
        }

    asset_matches: list[dict] = []
    if db is not None and cves:
        try:
            asset_matches = await match_cves_to_assets(cves, db)
        except Exception as exc:
            logger.warning("NVD asset matching failed: %s", exc)

    logger.info(
        "NVD feed sync complete: cves=%d matches=%d",
        len(cves),
        len(asset_matches),
    )

    return {
        "cves_fetched": len(cves),
        "asset_matches": len(asset_matches),
        "status": "ok",
        "message": f"Fetched {len(cves)} CVEs, {len(asset_matches)} asset matches",
    }
