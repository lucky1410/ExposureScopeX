"""MITRE ATT&CK technique tagging for ExposureScopeX findings.

Usage::

    from app.services.threat_intel.mitre_attack import tag_finding, tag_findings_batch

    tags = tag_finding("Exposed SSH port 22 on external host")
    # [{"tactic": "Initial Access", "technique_id": "T1133", ...}]

    findings = tag_findings_batch(findings_list)
    # Each finding dict gains a 'mitre_attack' key
"""

import re
from typing import Any

# ---------------------------------------------------------------------------
# Static mapping — pattern → ATT&CK technique
# ---------------------------------------------------------------------------

ATTACK_MAPPINGS: list[dict[str, str]] = [
    # Initial Access
    {
        "pattern": r"exposed.*port.*22|ssh.*open|ssh.*exposed",
        "tactic": "Initial Access",
        "technique_id": "T1133",
        "technique_name": "External Remote Services",
    },
    {
        "pattern": r"exposed.*rdp|port.*3389|rdp.*open",
        "tactic": "Initial Access",
        "technique_id": "T1133",
        "technique_name": "External Remote Services",
    },
    {
        "pattern": r"exploit.*public|sql.?injection|xss|rce|injection",
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
    },
    {
        "pattern": r"vpn|citrix|pulse|anyconnect",
        "tactic": "Initial Access",
        "technique_id": "T1133",
        "technique_name": "External Remote Services",
    },
    {
        "pattern": r"phish|spf|dmarc|dkim|email.*spoof",
        "tactic": "Initial Access",
        "technique_id": "T1566",
        "technique_name": "Phishing",
    },
    {
        "pattern": r"supply.?chain|package|dependency",
        "tactic": "Initial Access",
        "technique_id": "T1195",
        "technique_name": "Supply Chain Compromise",
    },
    {
        "pattern": r"default.?credential|default.*password|default.*login",
        "tactic": "Initial Access",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
    },
    # Collection / Cloud storage
    {
        "pattern": r"s3.*public|bucket.*public|storage.*exposed|open.*bucket",
        "tactic": "Collection",
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage Object",
    },
    # Discovery
    {
        "pattern": r"directory.*listing|open.*directory|dir.*listing",
        "tactic": "Discovery",
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
    },
    {
        "pattern": r"port.*scan|nmap|masscan|open.*port",
        "tactic": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
    },
    {
        "pattern": r"subdomain|dns.*enum|zone.*transfer|axfr",
        "tactic": "Reconnaissance",
        "technique_id": "T1590",
        "technique_name": "Gather Victim Network Information",
    },
    # Adversary-in-the-Middle
    {
        "pattern": r"weak.*tls|ssl.*weak|weak.*cipher|tls.*1\.0|tls.*1\.1",
        "tactic": "Collection",
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle",
    },
    {
        "pattern": r"missing.*hsts|no.*hsts|hsts.*missing",
        "tactic": "Collection",
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle",
    },
    # Credential Access
    {
        "pattern": r"secret|api.?key|token.*leak|credential.*leak",
        "tactic": "Credential Access",
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
    },
    {
        "pattern": r"aws.*metadata|169\.254\.169\.254|imds|ssrf",
        "tactic": "Credential Access",
        "technique_id": "T1552.005",
        "technique_name": "Cloud Instance Metadata API",
    },
    # Execution
    {
        "pattern": r"rce|remote.*code.*execution|command.*injection",
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
    },
    {
        "pattern": r"kubernetes|k8s.*api|kubectl.*exposed|etcd",
        "tactic": "Execution",
        "technique_id": "T1609",
        "technique_name": "Container Administration Command",
    },
    {
        "pattern": r"docker.*exposed|docker.*api|container.*escape",
        "tactic": "Execution",
        "technique_id": "T1610",
        "technique_name": "Deploy Container",
    },
    # Persistence
    {
        "pattern": r"webshell|web.*shell|backdoor",
        "tactic": "Persistence",
        "technique_id": "T1505",
        "technique_name": "Server Software Component",
    },
    # Browser session hijacking
    {
        "pattern": r"cors.*misconfigur|cors.*any.*origin|cors.*wildcard",
        "tactic": "Collection",
        "technique_id": "T1185",
        "technique_name": "Browser Session Hijacking",
    },
    {
        "pattern": r"clickjack|x-frame|frame.*option",
        "tactic": "Collection",
        "technique_id": "T1185",
        "technique_name": "Browser Session Hijacking",
    },
]

ATTACK_BASE_URL = "https://attack.mitre.org/techniques/"

# Pre-compile patterns once at import time for performance
_COMPILED: list[dict[str, Any]] = [
    {**m, "_re": re.compile(m["pattern"], re.IGNORECASE)}
    for m in ATTACK_MAPPINGS
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def tag_finding(title: str, description: str = "") -> list[dict[str, str]]:
    """Return ATT&CK technique matches for a finding title + description.

    Searches ATTACK_MAPPINGS patterns against the lowercased concatenation of
    *title* and *description*.

    Returns a deduplicated list (by ``technique_id``) of::

        [
            {
                "tactic": str,
                "technique_id": str,
                "technique_name": str,
                "url": str,
            },
            ...
        ]
    """
    haystack = f"{title} {description}".lower()
    seen: set[str] = set()
    matches: list[dict[str, str]] = []

    for mapping in _COMPILED:
        if mapping["_re"].search(haystack):
            tid = mapping["technique_id"]
            if tid not in seen:
                seen.add(tid)
                # Normalise sub-technique URL (T1552.005 → T1552/005)
                url_path = tid.replace(".", "/")
                matches.append(
                    {
                        "tactic": mapping["tactic"],
                        "technique_id": tid,
                        "technique_name": mapping["technique_name"],
                        "url": f"{ATTACK_BASE_URL}{url_path}/",
                    }
                )

    return matches


def tag_findings_batch(findings: list[dict]) -> list[dict]:
    """Tag a list of finding dicts in place.

    Each dict is expected to have at minimum a ``title`` key; ``description``
    is used if present.  A ``mitre_attack`` key is added (or overwritten) on
    every dict with the result of :func:`tag_finding`.

    Returns the same list (mutated) for convenience.
    """
    for finding in findings:
        title = finding.get("title", "")
        description = finding.get("description", "") or ""
        finding["mitre_attack"] = tag_finding(title, description)
    return findings
