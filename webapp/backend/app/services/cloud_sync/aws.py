"""AWS asset synchronization for ExposureScopeX ASM.

Uses boto3 (imported inside the function to avoid worker startup errors if
boto3 is not installed in the current environment).
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _tags_to_list(aws_tags: list[dict]) -> list[str]:
    """Convert AWS Tags list ({Key, Value} dicts) to 'key=value' strings."""
    return [f"{t['Key']}={t['Value']}" for t in (aws_tags or [])]


def _name_from_tags(tags: list[dict], fallback: str) -> str:
    """Return the value of the 'Name' tag, or *fallback* if absent."""
    for t in (tags or []):
        if t.get("Key") == "Name":
            return t["Value"]
    return fallback


# ── Main sync function ────────────────────────────────────────────────────────

def sync_aws_assets(source_id: str, org_id: str, config: dict) -> dict:
    """Enumerate public-facing AWS assets and return a normalized asset list.

    Args:
        source_id: AsmCloudSource UUID (used for logging only).
        org_id:    Organisation UUID (used for logging only).
        config:    Decrypted credential dict from AsmCloudSource.config.
                   Expected keys: aws_access_key_id, aws_secret_access_key,
                   optionally aws_region (default "us-east-1") and
                   aws_session_token.

    Returns:
        {"assets": [...], "count": N}

    Each asset dict contains:
        name, target_value, target_type, tags (list[str]),
        cloud_region, cloud_account_id
    """
    try:
        import boto3
        import botocore.exceptions
    except ImportError as exc:
        raise RuntimeError(
            "boto3 is not installed; add 'boto3' to requirements.txt"
        ) from exc

    region = config.get("aws_region", "us-east-1")

    try:
        session = boto3.Session(
            aws_access_key_id=config["aws_access_key_id"],
            aws_secret_access_key=config["aws_secret_access_key"],
            aws_session_token=config.get("aws_session_token"),
            region_name=region,
        )
    except KeyError as exc:
        raise RuntimeError(
            f"AWS config missing required key: {exc}"
        ) from exc
    except botocore.exceptions.NoCredentialsError as exc:
        raise RuntimeError(f"AWS credentials invalid: {exc}") from exc

    # Attempt to resolve account ID (informational; non-fatal if it fails)
    account_id: str | None = None
    try:
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
    except Exception as exc:
        logger.warning("source=%s Could not retrieve AWS account ID: %s", source_id, exc)

    assets: list[dict[str, Any]] = []

    # ── 1. EC2 instances ──────────────────────────────────────────────────────
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    public_ip = inst.get("PublicIpAddress")
                    if not public_ip:
                        continue
                    instance_id = inst.get("InstanceId", "unknown")
                    inst_tags = inst.get("Tags", [])
                    assets.append({
                        "name": _name_from_tags(inst_tags, instance_id),
                        "target_value": public_ip,
                        "target_type": "ip",
                        "tags": _tags_to_list(inst_tags),
                        "cloud_region": region,
                        "cloud_account_id": account_id,
                    })
    except botocore.exceptions.ClientError as exc:
        logger.warning("source=%s EC2 describe_instances failed: %s", source_id, exc)

    # ── 2. Application / Network Load Balancers (ELBv2) ──────────────────────
    try:
        elbv2 = session.client("elbv2", region_name=region)
        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                dns_name = lb.get("DNSName")
                if not dns_name:
                    continue
                # Derive a region label from the first AZ name if available
                azs = lb.get("AvailabilityZones", [])
                lb_region = azs[0].get("ZoneName", region).rsplit("-", 1)[0] if azs else region
                assets.append({
                    "name": lb.get("LoadBalancerName", dns_name),
                    "target_value": dns_name,
                    "target_type": "domain",
                    "tags": [],
                    "cloud_region": lb_region,
                    "cloud_account_id": account_id,
                })
    except botocore.exceptions.ClientError as exc:
        logger.warning("source=%s ELBv2 describe_load_balancers failed: %s", source_id, exc)

    # ── 3. Classic ELBs ───────────────────────────────────────────────────────
    try:
        elb = session.client("elb", region_name=region)
        paginator = elb.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancerDescriptions", []):
                dns_name = lb.get("DNSName")
                if not dns_name:
                    continue
                azs = lb.get("AvailabilityZones", [])
                lb_region = azs[0] if azs else region
                assets.append({
                    "name": lb.get("LoadBalancerName", dns_name),
                    "target_value": dns_name,
                    "target_type": "domain",
                    "tags": [],
                    "cloud_region": lb_region,
                    "cloud_account_id": account_id,
                })
    except botocore.exceptions.ClientError as exc:
        logger.warning("source=%s Classic ELB describe_load_balancers failed: %s", source_id, exc)

    # ── 4. CloudFront distributions ───────────────────────────────────────────
    try:
        cf = session.client("cloudfront")
        paginator = cf.get_paginator("list_distributions")
        for page in paginator.paginate():
            dist_list = page.get("DistributionList", {})
            for dist in dist_list.get("Items", []):
                domain_name = dist.get("DomainName")
                if not domain_name:
                    continue
                assets.append({
                    "name": dist.get("Id", domain_name),
                    "target_value": domain_name,
                    "target_type": "domain",
                    "tags": [],
                    "cloud_region": "global",
                    "cloud_account_id": account_id,
                })
    except botocore.exceptions.ClientError as exc:
        logger.warning("source=%s CloudFront list_distributions failed: %s", source_id, exc)

    # ── 5. Route53 records ────────────────────────────────────────────────────
    _INTERNAL_SUFFIXES = (".internal", ".local", ".compute.internal", ".amazonaws.com")
    try:
        r53 = session.client("route53")
        zones_paginator = r53.get_paginator("list_hosted_zones")
        for zones_page in zones_paginator.paginate():
            for zone in zones_page.get("HostedZones", []):
                zone_id = zone["Id"]
                zone_dns = zone.get("Name", "").rstrip(".")
                try:
                    rrs_paginator = r53.get_paginator("list_resource_record_sets")
                    for rrs_page in rrs_paginator.paginate(HostedZoneId=zone_id):
                        for rr_set in rrs_page.get("ResourceRecordSets", []):
                            rr_type = rr_set.get("Type")
                            if rr_type not in ("A", "CNAME"):
                                continue
                            record_name = rr_set.get("Name", "").rstrip(".")
                            # Skip internal / AWS-managed names
                            if any(record_name.endswith(s) for s in _INTERNAL_SUFFIXES):
                                continue
                            # Alias records (ALIAS → AWS service endpoint)
                            alias_target = rr_set.get("AliasTarget", {})
                            if alias_target.get("DNSName"):
                                target_val = alias_target["DNSName"].rstrip(".")
                                target_type = "domain"
                            else:
                                rr_values = [
                                    r["Value"]
                                    for r in rr_set.get("ResourceRecords", [])
                                ]
                                if not rr_values:
                                    continue
                                target_val = rr_values[0].rstrip(".")
                                target_type = "ip" if rr_type == "A" else "domain"
                            assets.append({
                                "name": record_name,
                                "target_value": target_val,
                                "target_type": target_type,
                                "tags": [f"zone={zone_dns}"],
                                "cloud_region": "global",
                                "cloud_account_id": account_id,
                            })
                except botocore.exceptions.ClientError as exc:
                    logger.warning(
                        "source=%s Route53 list_resource_record_sets for zone %s failed: %s",
                        source_id, zone_id, exc,
                    )
    except botocore.exceptions.ClientError as exc:
        logger.warning("source=%s Route53 list_hosted_zones failed: %s", source_id, exc)

    # ── 6. S3 buckets ─────────────────────────────────────────────────────────
    try:
        s3 = session.client("s3")
        response = s3.list_buckets()
        for bucket in response.get("Buckets", []):
            bucket_name = bucket.get("Name")
            if not bucket_name:
                continue
            assets.append({
                "name": bucket_name,
                "target_value": f"{bucket_name}.s3.amazonaws.com",
                "target_type": "domain",
                "tags": [],
                "cloud_region": region,
                "cloud_account_id": account_id,
            })
    except botocore.exceptions.ClientError as exc:
        logger.warning("source=%s S3 list_buckets failed: %s", source_id, exc)

    logger.info("source=%s AWS sync complete: %d assets", source_id, len(assets))
    return {"assets": assets, "count": len(assets)}
