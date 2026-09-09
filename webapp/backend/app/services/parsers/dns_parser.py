"""Parse DNS reconnaissance output from dns_recon.txt."""
import logging
import re
from pathlib import Path

logger = logging.getLogger("exposurescopex.parsers")

# Record types we know how to parse
KNOWN_RECORD_TYPES = {"A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME", "CAA"}

# Pattern matching section headers like "--- A Records ---"
_SECTION_RE = re.compile(r"^---\s+(\S+)\s+Records?\s+---", re.IGNORECASE)

# MX lines start with a numeric priority, e.g. "10 us-smtp-inbound-1.mimecast.com."
_MX_RE = re.compile(r"^\s*(\d+)\s+(.+)$")


def parse_dns_recon(filepath: Path) -> list[dict]:
    """Parse dns_recon.txt and return DNS records.

    Args:
        filepath: Path to dns_recon.txt.

    Returns:
        List of record dicts.  Example::

            [{"record_type": "A", "value": "99.86.182.72",
              "priority": None, "ttl": None},
             {"record_type": "MX", "value": "us-smtp-inbound-1.mimecast.com.",
              "priority": 10, "ttl": None}]
    """
    filepath = Path(filepath)
    if not filepath.exists():
        logger.debug("DNS recon file not found: %s", filepath)
        return []

    if filepath.stat().st_size == 0:
        logger.debug("DNS recon file is empty: %s", filepath)
        return []

    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("Failed to read DNS recon file %s: %s", filepath, exc)
        return []

    records: list[dict] = []
    current_type: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()

        # Skip blank lines, comments, and the top-level "=== DNS Reconnaissance" header
        if not line or line.startswith("===") or line.startswith("#"):
            continue

        # Check for a section header (--- Something ---)
        if line.startswith("---"):
            section_match = _SECTION_RE.match(line)
            if section_match:
                rtype = section_match.group(1).upper()
                current_type = rtype if rtype in KNOWN_RECORD_TYPES else None
            else:
                # Non-record section (WHOIS, DNSSEC, Wildcard, IP & ASN, etc.)
                current_type = None
            continue

        # Skip if we haven't entered a known section yet
        if current_type is None:
            continue

        # Skip lines that start with [ (status tags like [MISSING], [OK], [PRESENT])
        if line.startswith("["):
            continue

        # Skip lines with connection errors
        if "connection timed out" in line.lower() or "no servers could be reached" in line.lower():
            continue

        # Skip placeholder / error lines
        if line.lower() in ("(none)", "none", "(empty)", "n/a"):
            continue
        if line.startswith("[") and ("ERROR" in line.upper() or "FAIL" in line.upper()):
            logger.debug("Skipping error line in DNS section %s: %s", current_type, line)
            continue

        # Parse according to record type
        try:
            record = _parse_record_line(current_type, line)
            if record is not None:
                records.append(record)
        except Exception:
            logger.debug("Malformed DNS line in section %s, skipping: %s",
                         current_type, line)

    logger.debug("Parsed %d DNS records from %s", len(records), filepath)
    return records


def _parse_record_line(record_type: str, line: str) -> dict | None:
    """Parse a single value line within a known DNS record section."""
    if record_type == "MX":
        mx_match = _MX_RE.match(line)
        if mx_match:
            return {
                "record_type": "MX",
                "value": mx_match.group(2).strip(),
                "priority": int(mx_match.group(1)),
                "ttl": None,
            }
        # Fallback: MX line without priority
        return {
            "record_type": "MX",
            "value": line.strip(),
            "priority": None,
            "ttl": None,
        }

    if record_type == "CAA":
        # CAA lines: "0 issue "amazonaws.com""
        parts = line.split(None, 2)
        if len(parts) >= 3:
            value = f"{parts[0]} {parts[1]} {parts[2]}"
        else:
            value = line
        return {
            "record_type": "CAA",
            "value": value.strip(),
            "priority": None,
            "ttl": None,
        }

    if record_type == "SOA":
        # SOA is usually a single multi-field line; keep it whole
        return {
            "record_type": "SOA",
            "value": line.strip(),
            "priority": None,
            "ttl": None,
        }

    # Generic: A, AAAA, NS, TXT, CNAME
    value = line.strip()
    if not value:
        return None

    return {
        "record_type": record_type,
        "value": value,
        "priority": None,
        "ttl": None,
    }
