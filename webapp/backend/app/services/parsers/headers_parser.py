"""Parse HTTP security headers analysis from http_headers.txt."""
import logging
import re
from pathlib import Path

logger = logging.getLogger("exposurescopex.parsers")

# Block header: "=== Security Headers: https://cricut.com ==="
_BLOCK_RE = re.compile(r"^===\s+Security Headers:\s+(\S+)\s+===")

# Status lines inside a block
# [MISSING] Strict-Transport-Security -- Recommended: ...
# [OK]      Content-Security-Policy: frame-ancestors self
# [DISCLOSURE] server: cloudflare
_STATUS_RE = re.compile(
    r"^\[(\w+)\]\s+(.+)$"
)

# Header value pattern for [OK] lines:  "Header-Name: value"
_HEADER_VALUE_RE = re.compile(r"^([\w-]+):\s*(.*)$")

# CORS result pattern
_CORS_RE = re.compile(r"^\[(\w+)\]\s+(.+)$")

# Missing count line: "Missing security headers: 5 / 7"
_MISSING_COUNT_RE = re.compile(r"^Missing security headers:\s+(\d+)\s*/\s*(\d+)")

# Severity mapping for missing headers
_HEADER_SEVERITY: dict[str, str] = {
    "Strict-Transport-Security": "HIGH",
    "Content-Security-Policy": "MEDIUM",
    "X-Frame-Options": "MEDIUM",
    "X-Content-Type-Options": "LOW",
    "Referrer-Policy": "LOW",
    "Permissions-Policy": "LOW",
    "X-XSS-Protection": "INFO",
}


def parse_http_headers(filepath: Path) -> list[dict]:
    """Parse http_headers.txt and return one dict per URL block.

    Args:
        filepath: Path to http_headers.txt.

    Returns:
        List of dicts, one per analysed URL::

            [{"url": "https://cricut.com",
              "missing_headers": ["Strict-Transport-Security", ...],
              "present_headers": {"Content-Security-Policy": "frame-ancestors self"},
              "server_header": "cloudflare",
              "cors_policy": "No wildcard CORS",
              "findings": [
                  {"severity": "MEDIUM",
                   "title": "Missing Strict-Transport-Security"}
              ]}]
    """
    filepath = Path(filepath)
    if not filepath.exists():
        logger.debug("HTTP headers file not found: %s", filepath)
        return []

    if filepath.stat().st_size == 0:
        logger.debug("HTTP headers file is empty: %s", filepath)
        return []

    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("Failed to read HTTP headers file %s: %s", filepath, exc)
        return []

    blocks: list[dict] = []
    current: dict | None = None
    section: str | None = None  # "headers", "disclosure", "cors"

    for raw_line in text.splitlines():
        line = raw_line.strip()

        # New URL block
        block_match = _BLOCK_RE.match(line)
        if block_match:
            if current is not None:
                blocks.append(current)
            current = {
                "url": block_match.group(1).strip(),
                "missing_headers": [],
                "present_headers": {},
                "server_header": None,
                "cors_policy": None,
                "findings": [],
            }
            section = None
            continue

        if current is None:
            continue

        # Detect sub-sections
        if line.startswith("Security Header Analysis"):
            section = "headers"
            continue
        if line.startswith("Information Disclosure"):
            section = "disclosure"
            continue
        if line.upper().startswith("CORS"):
            section = "cors"
            continue
        if _MISSING_COUNT_RE.match(line):
            # Informational summary line, skip
            continue

        if not line:
            continue

        # Parse status lines
        status_match = _STATUS_RE.match(line)
        if not status_match:
            continue

        tag = status_match.group(1).upper()
        content = status_match.group(2).strip()

        if section == "headers":
            if tag == "MISSING":
                # Extract header name: everything before " -- " or " — "
                header_name = re.split(r"\s+[—\-]{1,2}\s+", content, maxsplit=1)[0].strip()
                current["missing_headers"].append(header_name)
                severity = _HEADER_SEVERITY.get(header_name, "MEDIUM")
                current["findings"].append({
                    "severity": severity,
                    "title": f"Missing {header_name}",
                })
            elif tag == "OK":
                hv_match = _HEADER_VALUE_RE.match(content)
                if hv_match:
                    current["present_headers"][hv_match.group(1).strip()] = hv_match.group(2).strip()
                else:
                    # OK line without colon — just note it
                    current["present_headers"][content] = ""

        elif section == "disclosure":
            if tag == "DISCLOSURE":
                # "server: cloudflare" or "x-powered-by: Express"
                hv_match = _HEADER_VALUE_RE.match(content)
                if hv_match:
                    header_lower = hv_match.group(1).strip().lower()
                    value = hv_match.group(2).strip()
                    if header_lower == "server":
                        current["server_header"] = value
                    current["findings"].append({
                        "severity": "INFO",
                        "title": f"Information disclosure: {hv_match.group(1)}: {value}",
                    })
                else:
                    current["findings"].append({
                        "severity": "INFO",
                        "title": f"Information disclosure: {content}",
                    })

        elif section == "cors":
            if tag == "OK":
                current["cors_policy"] = content
            elif tag in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "WARNING"):
                current["cors_policy"] = content
                current["findings"].append({
                    "severity": tag if tag != "WARNING" else "MEDIUM",
                    "title": f"CORS: {content}",
                })

    # Don't forget the last block
    if current is not None:
        blocks.append(current)

    logger.debug("Parsed %d URL blocks from HTTP headers file: %s",
                 len(blocks), filepath)
    return blocks
