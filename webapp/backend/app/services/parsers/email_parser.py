"""Parse email security analysis from email_security.txt."""
import logging
import re
from pathlib import Path

logger = logging.getLogger("exposurescopex.parsers")

# Section headers: "--- SPF ---", "--- DMARC ---", etc.
_SECTION_RE = re.compile(r"^---\s+(.+?)\s+---$")

# Severity-tagged lines: [CRITICAL] No SPF record -- domain can be spoofed freely
_TAGGED_RE = re.compile(r"^\[(\w+)\]\s+(.+)$")

# MX priority lines:  "  Priority 10: us-smtp-inbound-1.mimecast.com."
_MX_RE = re.compile(r"^\s*Priority\s+(\d+):\s+(.+)$", re.IGNORECASE)

# Valid severity tags
_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

# Section-to-category mapping
_SECTION_CATEGORY: dict[str, str] = {
    "spf": "email",
    "dmarc": "email",
    "dkim": "email",
    "dkim (common selectors)": "email",
    "mx records": "email",
    "mta-sts": "email",
    "dane/tlsa": "email",
    "bimi": "email",
}


def parse_email_security(filepath: Path) -> dict:
    """Parse email_security.txt and return findings and MX records.

    Args:
        filepath: Path to email_security.txt.

    Returns:
        Dict with findings list and MX records::

            {"findings": [
                 {"severity": "CRITICAL",
                  "title": "No SPF record -- domain can be spoofed freely",
                  "category": "email",
                  "section": "SPF"}
             ],
             "mx_records": [
                 {"priority": 10,
                  "server": "us-smtp-inbound-1.mimecast.com."}
             ]}
    """
    filepath = Path(filepath)
    result: dict = {
        "findings": [],
        "mx_records": [],
    }

    if not filepath.exists():
        logger.debug("Email security file not found: %s", filepath)
        return result

    if filepath.stat().st_size == 0:
        logger.debug("Email security file is empty: %s", filepath)
        return result

    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("Failed to read email security file %s: %s", filepath, exc)
        return result

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

        # MX record lines (inside "MX Records" section)
        if current_section and current_section.lower().startswith("mx"):
            mx_match = _MX_RE.match(raw_line)  # use raw_line to preserve leading spaces
            if mx_match:
                try:
                    priority = int(mx_match.group(1))
                except (ValueError, TypeError):
                    priority = 0
                result["mx_records"].append({
                    "priority": priority,
                    "server": mx_match.group(2).strip(),
                })
                continue

        # Severity-tagged lines
        tagged_match = _TAGGED_RE.match(line)
        if tagged_match:
            tag = tagged_match.group(1).upper()
            content = tagged_match.group(2).strip()

            # Skip informational/status tags that are not findings
            if tag == "PRESENT":
                # [PRESENT] is just confirming existence, not a finding
                continue
            if tag == "OK":
                continue
            if tag == "NOT" or tag == "NONE":
                # Malformed tag, skip
                continue

            # Map the tag to a proper severity
            if tag in _VALID_SEVERITIES:
                severity = tag
            elif tag == "WARNING":
                severity = "MEDIUM"
            elif tag == "WEAK":
                severity = "MEDIUM"
            else:
                # Unknown tag, skip
                logger.debug("Unknown email security tag [%s], skipping: %s", tag, line)
                continue

            category = "email"
            if current_section:
                category = _SECTION_CATEGORY.get(current_section.lower(), "email")

            result["findings"].append({
                "severity": severity,
                "title": content,
                "category": category,
                "section": current_section if current_section else "Unknown",
            })

    logger.debug("Parsed %d email security findings and %d MX records from %s",
                 len(result["findings"]), len(result["mx_records"]), filepath)
    return result
