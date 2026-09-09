"""Parse cloud security scan results from cloud_buckets.txt and cloud_results.txt."""
import logging
import re
from pathlib import Path

logger = logging.getLogger("exposurescopex.parsers")

# Bucket line pattern:
# [HIGH] S3 EXISTS (private): https://cricut.s3.amazonaws.com
# [CRITICAL] GCS EXISTS (public): https://storage.googleapis.com/cricut
_BUCKET_RE = re.compile(
    r"^\[(\w+)\]"               # [severity]
    r"\s+(S3|GCS|Azure|AZURE)"  # bucket type
    r"\s+EXISTS"                # EXISTS marker
    r"\s+\((\w+)\)"             # (access)
    r":\s+(\S+)"               # URL
    , re.IGNORECASE
)

# Nuclei-style line for cloud_results.txt
# Reuse the same pattern as nuclei_parser
_NUCLEI_LINE_RE = re.compile(
    r"\[([^\]]+)\]"     # [template_id]
    r"\s+\[([^\]]+)\]"  # [protocol]
    r"\s+\[([^\]]+)\]"  # [severity]
    r"\s+(\S+)"         # target URL/host
    r"(.*)"             # optional extra data
)


def parse_cloud_buckets(filepath: Path) -> list[dict]:
    """Parse cloud_buckets.txt and return discovered bucket information.

    Args:
        filepath: Path to cloud_buckets.txt.

    Returns:
        List of bucket dicts::

            [{"severity": "HIGH",
              "bucket_type": "S3",
              "access": "private",
              "url": "https://cricut.s3.amazonaws.com"}]
    """
    filepath = Path(filepath)
    if not filepath.exists():
        logger.debug("Cloud buckets file not found: %s", filepath)
        return []

    if filepath.stat().st_size == 0:
        logger.debug("Cloud buckets file is empty: %s", filepath)
        return []

    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("Failed to read cloud buckets file %s: %s", filepath, exc)
        return []

    buckets: list[dict] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        m = _BUCKET_RE.match(line)
        if not m:
            logger.debug("Skipping non-matching cloud bucket line: %.120s", line)
            continue

        buckets.append({
            "severity": m.group(1).strip().upper(),
            "bucket_type": m.group(2).strip().upper(),
            "access": m.group(3).strip().lower(),
            "url": m.group(4).strip(),
        })

    logger.debug("Parsed %d cloud buckets from %s", len(buckets), filepath)
    return buckets


def parse_cloud_results(filepath: Path) -> list[dict]:
    """Parse cloud_results.txt containing nuclei-style cloud findings.

    Args:
        filepath: Path to cloud_results.txt.

    Returns:
        List of finding dicts (same structure as nuclei_parser)::

            [{"template_id": "azure-domain-tenant",
              "protocol": "http",
              "severity": "INFO",
              "url": "https://login.microsoftonline.com:443/...",
              "extra": "",
              "title": "Azure Domain Tenant"}]
    """
    filepath = Path(filepath)
    if not filepath.exists():
        logger.debug("Cloud results file not found: %s", filepath)
        return []

    if filepath.stat().st_size == 0:
        logger.debug("Cloud results file is empty: %s", filepath)
        return []

    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("Failed to read cloud results file %s: %s", filepath, exc)
        return []

    findings: list[dict] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        m = _NUCLEI_LINE_RE.match(line)
        if not m:
            logger.debug("Skipping non-matching cloud result line: %.120s", line)
            continue

        template_id = m.group(1).strip()
        title = template_id.replace("-", " ").replace("_", " ").title()

        findings.append({
            "template_id": template_id,
            "protocol": m.group(2).strip(),
            "severity": m.group(3).strip().upper(),
            "url": m.group(4).strip(),
            "extra": m.group(5).strip(),
            "title": title,
        })

    logger.debug("Parsed %d cloud findings from %s", len(findings), filepath)
    return findings
