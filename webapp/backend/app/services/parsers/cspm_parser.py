"""Parse CSPM scanner outputs into normalized findings and cloud resources."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("exposurescopex.parsers.cspm")
_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
}


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _normalize_severity(value: str | None, *, default: str = "INFO") -> str:
    if not value:
        return default
    return _SEVERITY_MAP.get(value.strip().lower(), value.strip().upper())


def parse_prowler_ocsf(filepath: Path) -> dict[str, Any]:
    """Parse a Prowler JSON-OCSF report into findings and resource identities."""
    filepath = Path(filepath)
    payload = _read_json(filepath)
    if payload is None:
        return {"findings": [], "resources": [], "summary": {}}

    entries = payload if isinstance(payload, list) else [payload]
    findings: list[dict[str, Any]] = []
    resources: dict[str, dict[str, Any]] = {}
    statuses: dict[str, int] = {}
    provider = None

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        provider = provider or ((entry.get("cloud") or {}).get("provider"))
        status_code = str(entry.get("status_code") or entry.get("status") or "").upper()
        if status_code:
            statuses[status_code] = statuses.get(status_code, 0) + 1
        finding_resources = entry.get("resources") or []
        for resource in finding_resources:
            if not isinstance(resource, dict):
                continue
            resource_uid = str(resource.get("uid") or resource.get("name") or resource.get("type") or "").strip()
            if not resource_uid:
                continue
            key = f"{provider or 'cloud'}:{resource.get('type') or 'resource'}:{resource_uid}"
            resources[key] = {
                "value": key,
                "provider": provider,
                "resource_uid": resource_uid,
                "resource_type": str(resource.get("type") or "resource"),
                "name": str(resource.get("name") or resource_uid),
                "raw": resource,
            }

        if status_code in {"PASS", "SUCCESS", "OK"}:
            continue

        finding_info = entry.get("finding_info") or {}
        metadata = entry.get("metadata") or {}
        title = (
            str(finding_info.get("title") or "")
            or str(entry.get("message") or "")
            or str(metadata.get("event_code") or "Prowler finding")
        ).strip()
        if not title:
            continue
        evidence_parts = [
            f"status={status_code}" if status_code else "",
            f"provider={provider}" if provider else "",
            f"event={metadata.get('event_code')}" if metadata.get("event_code") else "",
            f"resource={next(iter(resources.values()))['resource_uid']}" if finding_resources and resources else "",
            str(entry.get("status_detail") or "")[:2000],
        ]
        findings.append({
            "severity": _normalize_severity(str(entry.get("severity") or ""), default="MEDIUM"),
            "title": title[:500],
            "description": str(
                finding_info.get("desc")
                or entry.get("message")
                or entry.get("status_detail")
                or ""
            )[:10000],
            "source": "prowler",
            "template_id": str(metadata.get("event_code") or metadata.get("product", {}).get("name") or "prowler"),
            "url": "",
            "evidence": " | ".join(part for part in evidence_parts if part)[:4000],
        })

    return {
        "findings": findings,
        "resources": list(resources.values()),
        "summary": {
            "provider": provider,
            "entries": len(entries),
            "findings": len(findings),
            "statuses": statuses,
        },
    }


def parse_scoutsuite_report(filepath: Path) -> dict[str, Any]:
    """Parse a ScoutSuite JSON or JS-backed report into best-effort findings and resources."""
    filepath = Path(filepath)
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"findings": [], "resources": [], "summary": {}}

    payload_text = text.strip()
    if payload_text.endswith(";") and "\n" in payload_text:
        payload_text = payload_text.split("\n", 1)[1].strip()
    elif "=" in payload_text and payload_text.lstrip().startswith("scoutsuite_results"):
        payload_text = payload_text.split("=", 1)[1].strip()
    payload_text = payload_text.removeprefix("scoutsuite_results =").strip().rstrip(";")
    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError:
        logger.debug("Could not parse ScoutSuite report %s", filepath)
        return {"findings": [], "resources": [], "summary": {}}

    findings: list[dict[str, Any]] = []
    resources: list[dict[str, Any]] = []
    seen_findings: set[str] = set()
    seen_resources: set[str] = set()
    cloud_provider = str(payload.get("provider") or payload.get("cloud_provider") or "").lower() or None
    services = payload.get("services") if isinstance(payload, dict) else None

    if isinstance(services, dict):
        for service_name, service_payload in services.items():
            service_key = f"{cloud_provider or 'cloud'}:service:{service_name}"
            if service_key not in seen_resources:
                seen_resources.add(service_key)
                resources.append({
                    "value": service_key,
                    "provider": cloud_provider,
                    "resource_uid": service_name,
                    "resource_type": "service",
                    "name": service_name,
                    "raw": service_payload if isinstance(service_payload, dict) else {"value": service_payload},
                })

    def walk(node: Any, path: tuple[str, ...] = ()) -> None:
        if isinstance(node, dict):
            lowered_keys = {str(key).lower() for key in node}
            if {"description", "level"} <= lowered_keys or {"rationale", "level"} <= lowered_keys:
                severity = _normalize_severity(str(node.get("level") or node.get("severity") or ""), default="MEDIUM")
                title = str(node.get("description") or node.get("rationale") or ".".join(path[-3:]) or "ScoutSuite finding").strip()
                evidence = str(node.get("resource") or node.get("id") or ".".join(path))[:4000]
                key = f"{severity}|{title}|{evidence}"
                if key not in seen_findings:
                    seen_findings.add(key)
                    findings.append({
                        "severity": severity,
                        "title": title[:500],
                        "description": str(node.get("rationale") or node.get("message") or "")[:10000],
                        "source": "scoutsuite",
                        "template_id": ".".join(path[-4:]) or "scoutsuite",
                        "url": "",
                        "evidence": evidence,
                    })
            for key, value in node.items():
                walk(value, (*path, str(key)))
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, (*path, str(index)))

    walk(payload)
    return {
        "findings": findings,
        "resources": resources,
        "summary": {
            "provider": cloud_provider,
            "services": len(services) if isinstance(services, dict) else 0,
            "findings": len(findings),
        },
    }
