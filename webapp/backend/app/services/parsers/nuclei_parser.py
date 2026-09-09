"""Parse Nuclei vulnerability scan results from nuclei_results.txt."""
import logging
import re
from pathlib import Path

logger = logging.getLogger("exposurescopex.parsers")

# Nuclei output format:
# [template_id] [protocol] [severity] target [extra_data]
# Examples:
#   [external-service-interaction] [http] [info] https://208.81.100.14
#   [apache-mod-negotiation-listing:exposed_files] [http] [low] https://.../ ["index.html"]
#   [weak-cipher-suites:tls-1.0] [ssl] [low] 208.81.100.215:443 ["[tls10 ...]"]
_NUCLEI_LINE_RE = re.compile(
    r"\[([^\]]+)\]"     # [template_id]
    r"\s+\[([^\]]+)\]"  # [protocol]
    r"\s+\[([^\]]+)\]"  # [severity]
    r"\s+(\S+)"         # target URL/host
    r"(.*)"             # optional extra data
)


def _template_id_to_title(template_id: str) -> str:
    """Convert a nuclei template_id to a human-readable title.

    "apache-mod-negotiation-listing:exposed_files" -> "Apache Mod Negotiation Listing: Exposed Files"
    "weak-cipher-suites:tls-1.0" -> "Weak Cipher Suites: Tls 1.0"
    """
    # Split on colon to separate template from sub-check
    parts = template_id.split(":", 1)
    titles = []
    for part in parts:
        # Replace hyphens and underscores with spaces, then title-case
        readable = part.replace("-", " ").replace("_", " ")
        titles.append(readable.title())
    return ": ".join(titles)


def parse_nuclei_results(filepath: Path) -> list[dict]:
    """Parse nuclei_results.txt and return structured findings.

    Args:
        filepath: Path to nuclei_results.txt.

    Returns:
        List of finding dicts::

            [{"template_id": "external-service-interaction",
              "protocol": "http",
              "severity": "INFO",
              "url": "https://208.81.100.14",
              "extra": "",
              "title": "External Service Interaction"}]
    """
    filepath = Path(filepath)
    if not filepath.exists():
        logger.debug("Nuclei results file not found: %s", filepath)
        return []

    if filepath.stat().st_size == 0:
        logger.debug("Nuclei results file is empty: %s", filepath)
        return []

    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("Failed to read nuclei results %s: %s", filepath, exc)
        return []

    findings: list[dict] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        m = _NUCLEI_LINE_RE.match(line)
        if not m:
            logger.debug("Skipping non-matching nuclei line: %.120s", line)
            continue

        template_id = m.group(1).strip()
        protocol = m.group(2).strip()
        severity = m.group(3).strip().upper()
        url = m.group(4).strip()
        extra = m.group(5).strip()

        findings.append({
            "template_id": template_id,
            "protocol": protocol,
            "severity": severity,
            "url": url,
            "extra": extra,
            "title": _template_id_to_title(template_id),
        })

    logger.debug("Parsed %d nuclei findings from %s", len(findings), filepath)
    return findings
