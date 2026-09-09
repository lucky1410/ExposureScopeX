"""Parse Nikto web vulnerability scanner output from nikto_*.txt files."""
import logging
import re
from pathlib import Path

logger = logging.getLogger("exposurescopex.parsers")

# Target info lines
# + Target Host: cricut.com
_TARGET_HOST_RE = re.compile(r"^\+\s+Target\s+Host:\s+(.+)$", re.IGNORECASE)
# + Target Port: 443
_TARGET_PORT_RE = re.compile(r"^\+\s+Target\s+Port:\s+(\d+)", re.IGNORECASE)

# Finding lines starting with +
# + GET /: The anti-clickjacking X-Frame-Options header is not present.
# + GET /: Cookie dwanonymous_... created without the httponly flag.
# + GET Server is using a wildcard certificate: *.cricut.com.
# Also handles lines with "See: https://..." references
_FINDING_RE = re.compile(
    r"^\+\s+"
    r"(?:(\w+)\s+)?"       # optional HTTP method (GET, POST, etc.)
    r"(?:(/\S*)\s*:\s+)?"  # optional path followed by colon
    r"(.+)$"               # description
)

# Reference URL in the description: "See: https://..."
_REFERENCE_RE = re.compile(r"See:\s+(https?://\S+)", re.IGNORECASE)


def parse_nikto(filepath: Path) -> dict:
    """Parse a nikto output file and return target info with findings.

    Args:
        filepath: Path to a nikto_*.txt file.

    Returns:
        Dict with target metadata and findings list::

            {"target": "cricut.com",
             "port": 443,
             "findings": [
                 {"method": "GET",
                  "path": "/",
                  "description": "The anti-clickjacking X-Frame-Options header is not present.",
                  "reference": None}
             ]}
    """
    filepath = Path(filepath)
    result: dict = {
        "target": None,
        "port": None,
        "findings": [],
    }

    if not filepath.exists():
        logger.debug("Nikto file not found: %s", filepath)
        return result

    if filepath.stat().st_size == 0:
        logger.debug("Nikto file is empty: %s", filepath)
        return result

    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("Failed to read nikto file %s: %s", filepath, exc)
        return result

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Skip banner/version lines (start with - )
        if line.startswith("- "):
            continue

        # Target host
        m = _TARGET_HOST_RE.match(line)
        if m:
            result["target"] = m.group(1).strip()
            continue

        # Target port
        m = _TARGET_PORT_RE.match(line)
        if m:
            try:
                result["port"] = int(m.group(1))
            except (ValueError, TypeError):
                pass
            continue

        # Finding lines
        if not line.startswith("+"):
            continue

        m = _FINDING_RE.match(line)
        if not m:
            continue

        method = m.group(1)
        path = m.group(2)
        description = m.group(3).strip() if m.group(3) else ""

        # Skip meta-info lines that are not actual findings
        if not description:
            continue
        # Lines like "+ Target IP:" or "+ Start Time:" are not findings
        lower_desc = description.lower()
        if any(lower_desc.startswith(prefix) for prefix in
               ("target ip:", "start time:", "end time:", "ssl info:",
                "hostname:", "server:", "retrieved")):
            # These are informational lines, not findings
            # But "Server is using a wildcard certificate" IS a finding
            if "server" in lower_desc and "certificate" not in lower_desc:
                continue
            if lower_desc.startswith(("target ip:", "start time:", "end time:",
                                      "ssl info:", "hostname:")):
                continue

        # Extract reference URL if present
        reference = None
        ref_match = _REFERENCE_RE.search(description)
        if ref_match:
            reference = ref_match.group(1).rstrip(".")
            # Remove "See: URL" from the description
            description = _REFERENCE_RE.sub("", description).strip().rstrip(".")

        result["findings"].append({
            "method": method if method else None,
            "path": path if path else None,
            "description": description,
            "reference": reference,
        })

    logger.debug("Parsed %d nikto findings for %s:%s from %s",
                 len(result["findings"]), result["target"],
                 result["port"], filepath)
    return result
