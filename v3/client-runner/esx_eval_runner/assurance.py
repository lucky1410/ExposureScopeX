"""Build reviewable local assurance scope, risk plans, and coverage graphs."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_CAPABILITY_ALIASES = {
    "authentication": "authentication",
    "case_management": "case_management",
    "case_management_and_evidence": "case_management",
    "threat_hunt": "threat_hunt",
    "audit": "audit",
    "audit_and_traceability": "audit",
    "administration": "administration",
    "integrations": "integrations",
    "general": "general",
}


def _id(value: str) -> str:
    return "-".join("".join(char if char.isalnum() else " " for char in value.lower()).split())[:72]


def _capability_area(value: object, *, allow_custom: bool = False) -> str | None:
    """Use workflow capability names, not raw framework/discovery categories."""
    if not isinstance(value, str):
        return None
    normalized = "_".join("".join(char.lower() if char.isalnum() else " " for char in value).split())
    if not normalized:
        return None
    return _CAPABILITY_ALIASES.get(normalized, normalized if allow_custom else None)


def create_scope(discovery: dict[str, Any], selected_ids: list[str]) -> dict[str, Any]:
    """Create an explicit customer-authorized scope from local discovery output."""
    components = discovery.get("components", [])
    if not isinstance(components, list):
        raise ValueError("Discovery document does not contain components")
    candidates = {item.get("id"): item for item in components if isinstance(item, dict) and isinstance(item.get("id"), str)}
    unknown = sorted(set(selected_ids) - set(candidates))
    if unknown:
        raise ValueError("Unknown discovered component ID: " + ", ".join(unknown))
    selected = []
    for component_id in selected_ids:
        component = candidates[component_id]
        selected.append({
            "id": component_id,
            "name": component.get("name", component_id),
            "kind": component.get("kind", "unknown"),
            "category": component.get("category", "general"),
            "source": "customer_confirmed_discovery",
            "verification_status": component.get("verification_status", "customer_declared"),
            "evidence_path": component.get("evidence_path", "not_recorded"),
        })
    return {
        "schema_version": "esx-assurance-scope-1.0",
        "status": "confirmed",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "repository": discovery.get("repository"),
        "components": selected,
        "notice": "Only customer-confirmed components are in scope. Discovery did not execute application code.",
    }


def build_risk_plan(scope: dict[str, Any], profile: str) -> dict[str, Any]:
    """Produce a deterministic, reviewable test plan without hidden model calls."""
    components = scope.get("components", [])
    if scope.get("status") != "confirmed" or not isinstance(components, list) or not components:
        raise ValueError("A confirmed scope with at least one component is required")
    kinds = {item.get("kind") for item in components if isinstance(item, dict)}
    dimensions = {"classification", "confidence"}
    test_areas = [
        {"id": "workflow-contract", "title": "Workflow contract", "why": "Each approved entry point needs labelled expected behavior."},
        {"id": "policy-boundaries", "title": "Policy boundaries", "why": "Authorized adversarial and negative-control cases verify refuse/block behavior."},
    ]
    if {"agent_framework", "tool"} & kinds:
        dimensions.update({"trajectory", "tool_use", "security", "robustness", "reproducibility"})
        test_areas.append({"id": "agent-tool-behavior", "title": "Agent and tool behavior", "why": "Trace milestones, tool authorization, repeated runs, and permitted action boundaries."})
    if {"rag_framework", "retrieval_store"} & kinds:
        dimensions.update({"groundedness", "rag"})
        test_areas.append({"id": "retrieval-grounding", "title": "Retrieval and grounding", "why": "Measure retrieval coverage, citation validity, and evidence-backed claims."})
    if "model_provider" in kinds:
        dimensions.update({"cost_efficiency", "judge_agreement"})
        test_areas.append({"id": "quality-cost", "title": "Quality, agreement, cost", "why": "Measure provider usage, latency, repeatability, and approved judge agreement."})
    capability_areas = sorted({
        area for item in components if isinstance(item, dict)
        if (area := _capability_area(item.get("category"))) is not None
    })
    for area in capability_areas:
        title = area.replace("_", " ").title()
        test_areas.append({"id": "capability-" + _id(area), "title": title, "why": "Use an approved workflow pack with an explicit persona and observable success signal; discovery alone is not coverage."})
    return {
        "schema_version": "esx-risk-plan-1.0",
        "status": "review_required",
        "profile": profile,
        "planner": {"mode": "deterministic", "external_ai_called": False},
        "scope_component_ids": [item["id"] for item in components if isinstance(item, dict) and isinstance(item.get("id"), str)],
        "required_dimensions": sorted(dimensions),
        "test_areas": test_areas,
        "capability_areas": capability_areas,
        "notice": "Review and approve this plan before use. It is rules-based; no AI model generated or judged this plan.",
    }


def build_assurance_graph(
    package: dict[str, Any], metrics: dict[str, dict[str, Any]], *,
    discovery: dict[str, Any] | None = None, scope: dict[str, Any] | None = None,
    plan: dict[str, Any] | None = None, telemetry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Link scope, evidence, metrics, and local decision inputs without raw data."""
    nodes: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []
    evaluation = package["evaluation"]
    subject_id = "subject:" + _id(str(evaluation["agent_id"]))
    nodes.append({"id": subject_id, "kind": "subject", "label": str(evaluation["agent_id"]), "status": "evaluated"})
    for component in (scope or {}).get("components", []):
        if not isinstance(component, dict):
            continue
        component_id = "component:" + str(component.get("id", "unknown"))
        evidence = str(component.get("verification_status", "customer_declared")).replace("_", " ")
        nodes.append({"id": component_id, "kind": str(component.get("kind", "unknown")), "label": f"{component.get('name', component_id)} [{evidence}]", "status": "in_scope"})
        edges.append({"from": subject_id, "to": component_id, "kind": "contains"})
    required_dimensions = list(evaluation["required_dimensions"])
    for dimension in (plan or {}).get("required_dimensions", []):
        if isinstance(dimension, str) and dimension not in required_dimensions:
            required_dimensions.append(dimension)
    for dimension in required_dimensions:
        metric = metrics.get(dimension, {"measurement_status": "not_measurable"})
        status = str(metric.get("measurement_status", "not_measurable"))
        node_id = "metric:" + dimension
        nodes.append({"id": node_id, "kind": "metric", "label": dimension.replace("_", " "), "status": status})
        edges.append({"from": subject_id, "to": node_id, "kind": "measured_by"})
    if telemetry:
        node_id = "evidence:telemetry"
        status = "captured" if telemetry.get("span_count", 0) else "not_measurable"
        nodes.append({"id": node_id, "kind": "telemetry", "label": f"{telemetry.get('span_count', 0)} redacted spans", "status": status})
        edges.append({"from": subject_id, "to": node_id, "kind": "evidence"})
    diagnostics = package.get("execution", {}).get("browser_case_diagnostics", [])
    diagnostics = diagnostics if isinstance(diagnostics, list) else []
    for item in diagnostics:
        if not isinstance(item, dict) or not isinstance(item.get("case_id"), str):
            continue
        outcome = item.get("outcome", "unknown")
        stage = item.get("failure_stage")
        status = "blocked_at_session_setup" if outcome == "blocked" and stage == "session_setup" else str(outcome)
        node_id = "workflow:" + item["case_id"]
        label = f"{item.get('capability_area', 'general')} / {item.get('persona', 'default')}"
        nodes.append({"id": node_id, "kind": "workflow_case", "label": label, "status": status})
        edges.append({"from": subject_id, "to": node_id, "kind": "executed_by"})
    measured = sum(1 for dimension in required_dimensions if metrics.get(dimension, {}).get("measurement_status") == "measured")
    required = len(required_dimensions)
    blocked_cases = sum(1 for item in diagnostics if isinstance(item, dict) and item.get("outcome") == "blocked")
    failed_cases = sum(1 for item in diagnostics if isinstance(item, dict) and item.get("outcome") == "failed")
    if blocked_cases:
        release_reason = (
            f"{blocked_cases} browser case(s) were blocked during approved session setup and did not reach an application workflow. "
            "They are coverage limitations, not application findings."
        )
    elif failed_cases:
        release_reason = (
            f"{failed_cases} browser workflow assertion(s) did not match their approved signal. "
            "Review local evidence before treating an assertion as an application finding."
        )
    else:
        release_reason = "Local results are evidence, not a governed release decision. Review executed cases and unmeasurable dimensions."
    return {
        "schema_version": "esx-assurance-graph-1.0",
        "summary": {
            "scope_status": (scope or {}).get("status", "not_confirmed"),
            "discovered_component_count": len((discovery or {}).get("components", [])),
            "confirmed_component_count": len((scope or {}).get("components", [])),
            "required_metric_count": required,
            "measured_metric_count": measured,
            "unmeasurable_metric_count": required - measured,
            "release_reason": release_reason,
        },
        "nodes": nodes,
        "edges": edges,
        "plan": {"profile": (plan or {}).get("profile"), "planner": (plan or {}).get("planner")},
    }


def build_coverage_model(
    package: dict[str, Any], metrics: dict[str, dict[str, Any]], *,
    discovery: dict[str, Any] | None = None, scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Separate what was found from what was actually run and measured."""
    execution = package.get("execution", {})
    evaluation = package.get("evaluation", {})
    browser_cases = execution.get("browser_case_diagnostics", []) if isinstance(execution, dict) else []
    browser_cases = browser_cases if isinstance(browser_cases, list) else []
    discovered = (discovery or {}).get("components", [])
    approved = (scope or {}).get("components", [])
    required_dimensions = evaluation.get("required_dimensions", []) if isinstance(evaluation, dict) else []
    measured_dimensions = [
        dimension for dimension in required_dimensions
        if isinstance(dimension, str) and metrics.get(dimension, {}).get("measurement_status") == "measured"
    ]
    is_browser_run = bool(browser_cases)
    completed_cases = [
        case for case in browser_cases
        if isinstance(case, dict) and case.get("outcome") in {"passed", "failed"}
    ]
    blocked_cases = [
        case for case in browser_cases
        if isinstance(case, dict) and case.get("outcome") == "blocked"
    ]
    requested = int(execution.get("case_count", 0)) if isinstance(execution, dict) else 0
    executed = len(completed_cases) if is_browser_run else requested
    capability_areas = _capability_coverage(discovery, scope, browser_cases)
    return {
        "discovered": {
            "component_count": len(discovered) if isinstance(discovered, list) else 0,
            "meaning": "Repository evidence and candidate entry points. Discovery is not execution.",
        },
        "approved": {
            "component_count": len(approved) if isinstance(approved, list) else 0,
            "meaning": "Customer-confirmed scope only. Unapproved discoveries are excluded from evaluation.",
        },
        "executed": {
            "requested_case_count": requested,
            "case_count": executed,
            "pre_auth_case_count": sum(1 for case in completed_cases if case.get("coverage_scope") == "pre_auth"),
            "authenticated_case_count": sum(1 for case in completed_cases if case.get("coverage_scope") == "authenticated"),
            "passed_case_count": sum(1 for case in completed_cases if case.get("outcome") == "passed"),
            "failed_case_count": sum(1 for case in completed_cases if case.get("outcome") == "failed"),
            "blocked_case_count": len(blocked_cases),
            "meaning": "Only completed test cases count as executed coverage.",
        },
        "measured": {
            "dimension_count": len(measured_dimensions),
            "required_dimension_count": len(required_dimensions) if isinstance(required_dimensions, list) else 0,
            "dimensions": measured_dimensions,
            "meaning": "A metric is measured only when required local evidence was supplied and validated.",
        },
        "capability_areas": capability_areas,
    }


def _capability_coverage(
    discovery: dict[str, Any] | None, scope: dict[str, Any] | None,
    browser_cases: list[object],
) -> list[dict[str, object]]:
    """Group evidence by product capability without treating candidates as tests."""
    areas: dict[str, dict[str, object]] = {}

    def add(area: object, field: str) -> None:
        if not isinstance(area, str) or not area:
            area = "general"
        item = areas.setdefault(area, {"capability_area": area, "discovered": 0, "approved": 0, "executed": 0, "passed": 0, "failed": 0, "blocked": 0})
        item[field] = int(item[field]) + 1

    suggested_areas = {
        item.get("component_id"): _capability_area(item.get("capability_area"))
        for item in (discovery or {}).get("workflow_suggestions", [])
        if isinstance(item, dict) and isinstance(item.get("component_id"), str)
    }
    for component in (discovery or {}).get("components", []):
        if isinstance(component, dict):
            area = suggested_areas.get(component.get("id")) or _capability_area(component.get("category"))
            if area:
                add(area, "discovered")
    for component in (scope or {}).get("components", []):
        if isinstance(component, dict):
            area = suggested_areas.get(component.get("id")) or _capability_area(component.get("category"))
            if area:
                add(area, "approved")
    for case in browser_cases:
        if not isinstance(case, dict):
            continue
        area = _capability_area(case.get("capability_area"), allow_custom=True) or "general"
        if case.get("outcome") in {"passed", "failed"}:
            add(area, "executed")
        if case.get("outcome") == "passed":
            add(area, "passed")
        elif case.get("outcome") == "failed":
            add(area, "failed")
        elif case.get("outcome") == "blocked":
            add(area, "blocked")
    return [areas[key] for key in sorted(areas)]
