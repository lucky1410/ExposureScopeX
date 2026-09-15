from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit


_HOSTNAME = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z", re.IGNORECASE)


def normalized_hostname(value: str) -> str:
    hostname = value.strip().rstrip(".").lower()
    if not _HOSTNAME.fullmatch(hostname):
        raise ValueError(f"Invalid DNS hostname: {value}")
    return hostname


def approved_discovered_subdomains(
    inventory: Mapping[str, object],
    parent_target: str,
    selected: Iterable[str],
) -> list[str]:
    """Validate operator selections against the hash-verified passive inventory."""
    if inventory.get("status") != "completed":
        raise ValueError("The passive subdomain inventory did not complete successfully")
    parent_hostname = normalized_hostname(str(urlsplit(parent_target).hostname or ""))
    discovered = {
        normalized_hostname(item)
        for item in inventory.get("subdomains", [])
        if isinstance(item, str)
    }
    approved: list[str] = []
    for value in selected:
        hostname = normalized_hostname(value)
        if not hostname.endswith("." + parent_hostname):
            raise ValueError(f"{hostname} is not a descendant of {parent_hostname}")
        if hostname not in discovered:
            raise ValueError(f"{hostname} was not present in the passive inventory")
        if hostname not in approved:
            approved.append(hostname)
    if not approved:
        raise ValueError("Select at least one discovered subdomain")
    return approved


def target_for_subdomain(parent_target: str, hostname: str) -> str:
    """Build a credential-free exact-origin target for a confirmed hostname."""
    parent = urlsplit(parent_target)
    if parent.scheme not in {"http", "https"}:
        raise ValueError("Parent target must be an absolute HTTP or HTTPS URL")
    host = normalized_hostname(hostname)
    port = f":{parent.port}" if parent.port else ""
    return urlunsplit((parent.scheme, f"{host}{port}", "", "", ""))
