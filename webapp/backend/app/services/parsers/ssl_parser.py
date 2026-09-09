"""Parse SSL/TLS scan results from ssl_results.txt."""
import logging
import re
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("exposurescopex.parsers")

# Patterns for certificate fields
_SUBJECT_RE = re.compile(r"^subject\s*=\s*(.+)$", re.IGNORECASE)
_ISSUER_RE = re.compile(r"^issuer\s*=\s*(.+)$", re.IGNORECASE)
_NOT_BEFORE_RE = re.compile(r"^notBefore\s*=\s*(.+)$", re.IGNORECASE)
_NOT_AFTER_RE = re.compile(r"^notAfter\s*=\s*(.+)$", re.IGNORECASE)
_SHA1_RE = re.compile(r"^SHA1\s+Fingerprint\s*=\s*(.+)$", re.IGNORECASE)
_SHA256_RE = re.compile(r"^SHA256\s+Fingerprint\s*=\s*(.+)$", re.IGNORECASE)

# Severity-tagged finding lines: [MEDIUM] ..., [WEAK] ..., [CRITICAL] ...
_FINDING_RE = re.compile(r"^\[(\w+)\]\s+(.+)$")

# Protocol support lines: e.g. "tls1 is supported" or "[WEAK] tls1 is supported"
_PROTOCOL_RE = re.compile(r"(tls\S*|ssl\S*)\s+is\s+supported", re.IGNORECASE)

# CN extraction from subject
_CN_RE = re.compile(r"CN\s*=\s*([^,/]+)")

# Date formats openssl may produce
_DATE_FORMATS = [
    "%b %d %H:%M:%S %Y %Z",     # "Jul  8 00:00:00 2025 GMT"
    "%b  %d %H:%M:%S %Y %Z",    # double-space day
    "%Y-%m-%dT%H:%M:%S",        # ISO
    "%Y-%m-%d %H:%M:%S",        # ISO without T
]


def _parse_date(raw: str) -> datetime | None:
    """Try multiple date formats and return a datetime or None."""
    raw = raw.strip()
    # Collapse multiple spaces to single space for consistent parsing
    normalized = re.sub(r"\s+", " ", raw)
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(normalized, fmt)
        except ValueError:
            continue
    logger.debug("Could not parse SSL date: %s", raw)
    return None


def parse_ssl_results(filepath: Path) -> dict:
    """Parse ssl_results.txt and return certificate + protocol information.

    Args:
        filepath: Path to ssl_results.txt.

    Returns:
        Dict with certificate metadata, protocol info, and findings::

            {"subject_cn": "*.cricut.com",
             "issuer": "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
             "not_before": datetime(...),
             "not_after": datetime(...),
             "fingerprint_sha1": "6A:50:...",
             "fingerprint_sha256": None,
             "protocols": ["tls1", "tls1_2", "tls1_3"],
             "weak_protocols": ["tls1"],
             "findings": [
                 {"severity": "MEDIUM",
                  "title": "Certificate expires in 79 days"}
             ]}
    """
    filepath = Path(filepath)
    result: dict = {
        "subject_cn": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "fingerprint_sha1": None,
        "fingerprint_sha256": None,
        "protocols": [],
        "weak_protocols": [],
        "findings": [],
    }

    if not filepath.exists():
        logger.debug("SSL results file not found: %s", filepath)
        return result

    if filepath.stat().st_size == 0:
        logger.debug("SSL results file is empty: %s", filepath)
        return result

    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("Failed to read SSL results %s: %s", filepath, exc)
        return result

    protocols_seen: set[str] = set()
    weak_seen: set[str] = set()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Subject
        m = _SUBJECT_RE.match(line)
        if m and result["subject_cn"] is None:
            cn_match = _CN_RE.search(m.group(1))
            if cn_match:
                result["subject_cn"] = cn_match.group(1).strip()
            continue

        # Issuer
        m = _ISSUER_RE.match(line)
        if m and result["issuer"] is None:
            # Try to extract CN from issuer, otherwise use full string
            cn_match = _CN_RE.search(m.group(1))
            result["issuer"] = cn_match.group(1).strip() if cn_match else m.group(1).strip()
            continue

        # notBefore
        m = _NOT_BEFORE_RE.match(line)
        if m and result["not_before"] is None:
            result["not_before"] = _parse_date(m.group(1))
            continue

        # notAfter
        m = _NOT_AFTER_RE.match(line)
        if m and result["not_after"] is None:
            result["not_after"] = _parse_date(m.group(1))
            continue

        # SHA1 Fingerprint
        m = _SHA1_RE.match(line)
        if m:
            result["fingerprint_sha1"] = m.group(1).strip()
            continue

        # SHA256 Fingerprint
        m = _SHA256_RE.match(line)
        if m:
            result["fingerprint_sha256"] = m.group(1).strip()
            continue

        # Protocol support detection (can appear with or without severity tag)
        proto_match = _PROTOCOL_RE.search(line)
        if proto_match:
            proto = proto_match.group(1).strip().lower()
            protocols_seen.add(proto)

        # Severity-tagged finding lines
        finding_match = _FINDING_RE.match(line)
        if finding_match:
            severity_raw = finding_match.group(1).upper()
            title = finding_match.group(2).strip()

            # Map WEAK to a proper severity for findings list
            severity = severity_raw
            if severity == "WEAK":
                severity = "MEDIUM"

            # Check if this is a weak protocol line
            if severity_raw == "WEAK" and proto_match:
                proto = proto_match.group(1).strip().lower()
                weak_seen.add(proto)

            # Remove trailing details like " — should be disabled"
            # but keep the full text as the title
            result["findings"].append({
                "severity": severity,
                "title": title,
            })

    result["protocols"] = sorted(protocols_seen)
    result["weak_protocols"] = sorted(weak_seen)

    logger.debug("Parsed SSL results from %s: CN=%s, %d protocols, %d findings",
                 filepath, result["subject_cn"], len(result["protocols"]),
                 len(result["findings"]))
    return result
