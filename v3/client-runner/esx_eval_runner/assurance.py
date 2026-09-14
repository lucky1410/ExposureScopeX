"""Build reviewable local assurance scope, risk plans, and coverage graphs."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _id(value: str) -> str:
    return "-".join("".join(char if char.isalnum() else " " for char in value.lower()).split())[:72]


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
        dimensions.update({"trajectory", "security", "robustness", "reproducibility"})
        test_areas.append({"id": "agent-tool-behavior", "title": "Agent and tool behavior", "why": "Trace milestones, tool authorization, repeated runs, and permitted action boundaries."})
    if {"rag_framework", "retrieval_store"} & kinds:
        dimensions.update({"groundedness", "rag"})
        test_areas.append({"id": "retrieval-grounding", "title": "Retrieval and grounding", "why": "Measure retrieval coverage, citation validity, and evidence-backed claims."})
    if "model_provider" in kinds:
        dimensions.update({"cost_efficiency", "judge_agreement"})
        test_areas.append({"id": "quality-cost", "title": "Quality, agreement, cost", "why": "Measure provider usage, latency, repeatability, and approved judge agreement."})
    return {
        "schema_version": "esx-risk-plan-1.0",
        "status": "review_required",
        "profile": profile,
        "planner": {"mode": "deterministic", "external_ai_called": False},
        "scope_component_ids": [item["id"] for item in components if isinstance(item, dict) and isinstance(item.get("id"), str)],
        "required_dimensions": sorted(dimensions),
        "test_areas": test_areas,
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
    measured = sum(1 for dimension in required_dimensions if metrics.get(dimension, {}).get("measurement_status") == "measured")
    required = len(required_dimensions)
    return {
        "schema_version": "esx-assurance-graph-1.0",
        "summary": {
            "scope_status": (scope or {}).get("status", "not_confirmed"),
            "discovered_component_count": len((discovery or {}).get("components", [])),
            "confirmed_component_count": len((scope or {}).get("components", [])),
            "required_metric_count": required,
            "measured_metric_count": measured,
            "unmeasurable_metric_count": required - measured,
            "release_reason": "Local results are evidence, not a governed release decision. Review any failed cases and unmeasurable dimensions.",
        },
        "nodes": nodes,
        "edges": edges,
        "plan": {"profile": (plan or {}).get("profile"), "planner": (plan or {}).get("planner")},
    }
