"""Parse API security scan results from api_security.txt."""
import logging
import re
from pathlib import Path

logger = logging.getLogger("exposurescopex.parsers")

# Section headers: "--- OpenAPI / Swagger Discovery ---"
_SECTION_RE = re.compile(r"^---\s+(.+?)\s+---$")

# Status-tagged lines: [NOT FOUND] ..., [OK] ..., [CRITICAL] ..., [INFO] ...
_TAGGED_RE = re.compile(r"^\[([^\]]+)\]\s+(.+)$")

# URL extraction from finding content
_URL_RE = re.compile(r"(https?://\S+)")

# Tags that indicate "nothing found" or "all clear" -- skip these
_SKIP_TAGS = {"NOT FOUND", "OK", "SAFE", "CLEAN", "NONE"}

# Valid severity tags
_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def parse_api_security(filepath: Path) -> list[dict]:
    """Parse api_security.txt and return findings for non-OK / non-NOT-FOUND items.

    Only returns actionable findings -- lines tagged [OK] or [NOT FOUND] are
    silently skipped since they indicate no issue was detected.

    Args:
        filepath: Path to api_security.txt.

    Returns:
        List of finding dicts::

            [{"severity": "CRITICAL",
              "title": "GraphQL introspection ENABLED",
              "url": "https://cricut.com/graphql",
              "category": "api",
              "section": "GraphQL Introspection"}]

        Returns empty list if no actionable findings exist.
    """
    filepath = Path(filepath)
    if not filepath.exists():
        logger.debug("API security file not found: %s", filepath)
        return []

    if filepath.stat().st_size == 0:
        logger.debug("API security file is empty: %s", filepath)
        return []

    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("Failed to read API security file %s: %s", filepath, exc)
        return []

    findings: list[dict] = []
    current_section: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()

        # Skip blank lines and top-level header
        if not line or line.startswith("==="):
            continue

        # Check for section header
        section_match = _SECTION_RE.match(line)
        if section_match:
            current_section = section_match.group(1).strip()
            continue

        # Tagged lines
        tagged_match = _TAGGED_RE.match(line)
        if not tagged_match:
            continue

        tag = tagged_match.group(1).strip().upper()
        content = tagged_match.group(2).strip()

        # Skip non-finding status tags
        if tag in _SKIP_TAGS:
            continue

        # Determine severity
        if tag in _VALID_SEVERITIES:
            severity = tag
        elif tag == "WARNING":
            severity = "MEDIUM"
        elif tag == "WEAK":
            severity = "MEDIUM"
        elif tag == "FOUND":
            # [FOUND] usually indicates something was discovered -- treat as INFO
            # unless the content suggests otherwise
            severity = "INFO"
        elif tag == "EXPOSED":
            severity = "HIGH"
        elif tag == "ENABLED":
            severity = "MEDIUM"
        elif tag == "PRESENT":
            # [PRESENT] in API context could indicate exposed endpoints
            severity = "INFO"
        else:
            logger.debug("Unknown API security tag [%s], treating as INFO: %s",
                         tag, line)
            severity = "INFO"

        # Try to extract a URL from the content
        url = None
        url_match = _URL_RE.search(content)
        if url_match:
            url = url_match.group(1).rstrip(".,;)\"'")

        findings.append({
            "severity": severity,
            "title": content,
            "url": url,
            "category": "api",
            "section": current_section if current_section else "Unknown",
        })

    logger.debug("Parsed %d API security findings from %s",
                 len(findings), filepath)
    return findings
