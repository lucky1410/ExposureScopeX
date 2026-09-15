"""Reviewable browser workflow-pack suggestions and local pack operations."""

from __future__ import annotations

import copy
import re
from typing import Any

from .runner import RunnerError


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
_AREAS: dict[str, dict[str, str]] = {
    "authentication": {"title": "Authentication", "persona": "anonymous", "requires_auth": "false"},
    "case_management": {"title": "Case management", "persona": "analyst", "requires_auth": "true"},
    "threat_hunt": {"title": "Threat hunt", "persona": "analyst", "requires_auth": "true"},
    "audit": {"title": "Audit and traceability", "persona": "analyst", "requires_auth": "true"},
    "administration": {"title": "Administration", "persona": "admin", "requires_auth": "true"},
    "integrations": {"title": "Integrations", "persona": "admin", "requires_auth": "true"},
    "general": {"title": "General application workflow", "persona": "analyst", "requires_auth": "true"},
}


def classify_workflow_route(route: str) -> str:
    """Classify a literal route for review; classification is never proof of behavior."""
    value = route.lower()
    if any(token in value for token in ("login", "logout", "signin", "sign-in", "auth", "session", "sso")):
        return "authentication"
    if any(token in value for token in ("case", "investigation", "incident", "alert", "evidence")):
        return "case_management"
    if any(token in value for token in ("hunt", "threat", "detection", "intel")):
        return "threat_hunt"
    if any(token in value for token in ("audit", "activity", "trace", "history", "compliance")):
        return "audit"
    if any(token in value for token in ("setting", "admin", "user", "role", "permission", "tenant")):
        return "administration"
    if any(token in value for token in ("integration", "connector", "webhook", "api-key")):
        return "integrations"
    return "general"


def suggested_workflow(route: str, method: str, component_id: str, evidence_path: str) -> dict[str, str]:
    """Create an honest candidate journey from static route evidence."""
    area = classify_workflow_route(route)
    definition = _AREAS[area]
    return {
        "pack_id": component_id,
        "component_id": component_id,
        "label": f"{definition['title']}: {method} {route}",
        "route": route,
        "method": method,
        "capability_area": area,
        "recommended_persona": definition["persona"],
        "recommended_requires_auth": definition["requires_auth"],
        "evidence_path": evidence_path,
        "status": "review_required",
        "notice": "This is a source-derived candidate. Add it only after confirming the route is user-facing and providing a stable expected signal.",
    }


def build_workflow_pack_catalog(discovery: dict[str, Any], scope: dict[str, Any]) -> dict[str, Any]:
    """Keep source-derived workflow candidates separate from executable cases."""
    approved_ids = {
        item.get("id") for item in scope.get("components", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    candidates: list[dict[str, str]] = []
    for item in discovery.get("workflow_suggestions", []):
        if not isinstance(item, dict) or item.get("component_id") not in approved_ids:
            continue
        candidate = {key: value for key, value in item.items() if isinstance(key, str) and isinstance(value, str)}
        candidate["status"] = "review_required"
        candidates.append(candidate)
    return {
        "schema_version": "esx-browser-workflow-catalog-1.0",
        "status": "review_required",
        "candidates": sorted(candidates, key=lambda item: (item.get("capability_area", "general"), item.get("route", ""))),
        "notice": "Candidates are not test cases. An operator must add an expected signal, choose a persona, and explicitly include each workflow before it can execute.",
    }


def add_candidate_to_config(
    config: dict[str, Any], catalog: dict[str, Any], *, pack_id: str,
    expected_text: str, persona: str | None, authenticated: bool | None,
) -> dict[str, Any]:
    """Materialize one reviewed candidate into an explicit browser test case."""
    if not isinstance(config.get("adapter"), dict) or config["adapter"].get("type") != "browser_journey":
        raise RunnerError("Workflow packs can be added only to a browser_journey plan")
    candidate = next((item for item in catalog.get("candidates", []) if isinstance(item, dict) and item.get("pack_id") == pack_id), None)
    if not isinstance(candidate, dict):
        raise RunnerError("Workflow pack was not found in this plan's approved catalog")
    route = candidate.get("route")
    area = candidate.get("capability_area", "general")
    if not isinstance(route, str) or not route.startswith("/") or not isinstance(area, str):
        raise RunnerError("Workflow pack has invalid route data")
    if not isinstance(expected_text, str) or not expected_text.strip() or len(expected_text.strip()) > 500:
        raise RunnerError("Workflow pack expected text must be non-empty text up to 500 characters")
    recommended_auth = candidate.get("recommended_requires_auth") == "true"
    requires_auth = recommended_auth if authenticated is None else authenticated
    recommended_persona = candidate.get("recommended_persona", "default")
    chosen_persona = persona or (recommended_persona if requires_auth else "anonymous")
    if not isinstance(chosen_persona, str) or not _IDENTIFIER.fullmatch(chosen_persona):
        raise RunnerError("Workflow pack persona must use lowercase letters, digits, and hyphens")
    if not requires_auth:
        chosen_persona = "anonymous"
    elif chosen_persona != "default" and chosen_persona not in config["adapter"].get("personas", {}):
        raise RunnerError(f"Persona '{chosen_persona}' is not configured. Add its approved local session first.")
    cases = config.get("dataset", {}).get("cases")
    if not isinstance(cases, list):
        raise RunnerError("Config dataset.cases is invalid")
    base_id = f"{pack_id}-{chosen_persona}"
    case_id = _available_case_id({str(case.get("case_id")) for case in cases if isinstance(case, dict)}, base_id)
    case = {
        "case_id": case_id,
        "input": {"journey": [
            {"type": "goto", "path": route},
            {"type": "wait_for_stable", "settle_ms": 250, "retry_count": 2, "retry_delay_ms": 250},
            {"type": "wait_for_text", "value": expected_text.strip(), "retry_count": 2, "retry_delay_ms": 250},
            {"type": "assert_path", "path": route, "retry_count": 1, "retry_delay_ms": 100},
        ]},
        "expected_label": "pass",
        "requires_auth": requires_auth,
        "persona": chosen_persona,
        "capability_area": area,
        "workflow_pack": pack_id,
    }
    updated = copy.deepcopy(config)
    updated["dataset"]["cases"].append(case)
    packs = updated.setdefault("workflow_packs", [])
    if not isinstance(packs, list):
        raise RunnerError("Config workflow_packs must be a list when supplied")
    packs.append({
        "pack_id": pack_id,
        "capability_area": area,
        "persona": chosen_persona,
        "status": "approved_and_added",
        "case_id": case_id,
    })
    return updated


def export_reusable_pack(config: dict[str, Any], *, name: str) -> dict[str, Any]:
    """Export metadata-only browser cases for reuse on another local plan."""
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 120:
        raise RunnerError("Workflow pack name must be non-empty text up to 120 characters")
    if not isinstance(config.get("adapter"), dict) or config["adapter"].get("type") != "browser_journey":
        raise RunnerError("Only browser_journey cases can be exported as a workflow pack")
    cases = config.get("dataset", {}).get("cases", [])
    if not isinstance(cases, list):
        raise RunnerError("Config dataset.cases is invalid")
    exported: list[dict[str, Any]] = []
    for case in cases:
        if not isinstance(case, dict) or not case.get("workflow_pack"):
            continue
        copy_case = copy.deepcopy(case)
        copy_case.pop("case_id", None)
        exported.append(copy_case)
    if not exported:
        raise RunnerError("There are no reviewed workflow-pack cases to export")
    return {
        "schema_version": "esx-browser-workflow-pack-1.0",
        "name": name.strip(),
        "notice": "This pack is reusable only after the recipient reviews its paths, expected signals, personas, and authorization.",
        "cases": exported,
    }


def apply_reusable_pack(config: dict[str, Any], reusable: dict[str, Any]) -> dict[str, Any]:
    """Copy reviewed cases into another browser plan with collision-safe IDs."""
    if reusable.get("schema_version") != "esx-browser-workflow-pack-1.0" or not isinstance(reusable.get("cases"), list):
        raise RunnerError("Workflow pack file is invalid")
    if not isinstance(config.get("adapter"), dict) or config["adapter"].get("type") != "browser_journey":
        raise RunnerError("Workflow packs can be applied only to a browser_journey plan")
    updated = copy.deepcopy(config)
    existing = {str(case.get("case_id")) for case in updated.get("dataset", {}).get("cases", []) if isinstance(case, dict)}
    for source in reusable["cases"]:
        if not isinstance(source, dict):
            raise RunnerError("Workflow pack contains an invalid case")
        case = copy.deepcopy(source)
        pack_id = case.get("workflow_pack", "workflow")
        if not isinstance(pack_id, str) or not _IDENTIFIER.fullmatch(pack_id):
            raise RunnerError("Workflow pack case has an invalid workflow_pack ID")
        persona = case.get("persona", "default")
        if not isinstance(persona, str) or not _IDENTIFIER.fullmatch(persona):
            raise RunnerError("Workflow pack case has an invalid persona")
        case["case_id"] = _available_case_id(existing, f"{pack_id}-{persona}")
        existing.add(case["case_id"])
        updated["dataset"]["cases"].append(case)
    return updated


def _available_case_id(existing: set[str], base: str) -> str:
    normalized = "-".join(re.findall(r"[a-z0-9]+", base.lower()))[:58] or "workflow"
    candidate = normalized
    number = 2
    while candidate in existing:
        candidate = f"{normalized}-{number}"
        number += 1
    return candidate
