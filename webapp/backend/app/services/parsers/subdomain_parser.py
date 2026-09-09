"""Parse subdomain enumeration output from subdomains.txt."""
import logging
from pathlib import Path

logger = logging.getLogger("exposurescopex.parsers")


def parse_subdomains(filepath: Path) -> list[str]:
    """Parse subdomains.txt and return a deduplicated sorted list of subdomains.

    Args:
        filepath: Path to subdomains.txt (one subdomain per line).

    Returns:
        Sorted deduplicated list of subdomain strings::

            ["access.cricut.com", "account.cricut.com", "api.cricut.com", "cricut.com"]
    """
    filepath = Path(filepath)
    if not filepath.exists():
        logger.debug("Subdomains file not found: %s", filepath)
        return []

    if filepath.stat().st_size == 0:
        logger.debug("Subdomains file is empty: %s", filepath)
        return []

    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("Failed to read subdomains file %s: %s", filepath, exc)
        return []

    seen: set[str] = set()
    subdomains: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip().lower()

        # Skip blank lines, comments, and lines that don't look like hostnames
        if not line or line.startswith("#"):
            continue

        # Basic validation: must contain at least one dot and no spaces
        if " " in line or "\t" in line:
            logger.debug("Skipping line with whitespace: %s", line)
            continue

        if line not in seen:
            seen.add(line)
            subdomains.append(line)

    subdomains.sort()

    logger.debug("Parsed %d unique subdomains from %s", len(subdomains), filepath)
    return subdomains
