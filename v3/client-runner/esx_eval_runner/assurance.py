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
_CAPABILITY_TITLES = {
    "authentication": "Authentication",
    "case_management": "Case management",
    "threat_hunt": "Threat hunt",
    "audit": "Audit and traceability",
    "administration": "Administration",
    "integrations": "Integrations",
    "general": "General application workflow",
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
        dimensions.update({"groundedness", "hallucination", "rag"})
        test_areas.append({"id": "retrieval-grounding", "title": "Retrieval, grounding, and hallucination", "why": "Measure retrieval coverage, citation validity, evidence-backed claims, unsupported output, and required abstention."})
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
    # The graph reflects scores collected by this run. A risk plan may suggest
    # future dimensions, but it must not be shown as an evidence gap today.
    required_dimensions = list(evaluation["required_dimensions"])
    trust_counts = {"verified": 0, "declared": 0, "missing": 0}
    for dimension in required_dimensions:
        metric = metrics.get(dimension, {"measurement_status": "not_measurable"})
        status = (
            str(metric.get("trust_status", "declared"))
            if metric.get("measurement_status") == "measured" else "missing"
        )
        status = status if status in trust_counts else "missing"
        trust_counts[status] += 1
        node_id = "metric:" + dimension
        nodes.append({"id": node_id, "kind": "metric", "label": dimension.replace("_", " "), "status": status})
        edges.append({
            "from": subject_id, "to": node_id,
            "kind": {"verified": "verified_by", "declared": "declared_by", "missing": "missing_evidence_for"}[status],
        })
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
        "schema_version": "esx-assurance-graph-1.1",
        "summary": {
            "scope_status": (scope or {}).get("status", "not_confirmed"),
            "discovered_component_count": len((discovery or {}).get("components", [])),
            "confirmed_component_count": len((scope or {}).get("components", [])),
            "required_metric_count": required,
            "verified_metric_count": trust_counts["verified"],
            "declared_metric_count": trust_counts["declared"],
            "missing_metric_count": trust_counts["missing"],
            "release_reason": release_reason,
        },
        "nodes": nodes,
        "edges": edges,
        "plan": {"profile": (plan or {}).get("profile"), "planner": (plan or {}).get("planner")},
    }


def build_coverage_model(
    package: dict[str, Any], metrics: dict[str, dict[str, Any]], *,
    discovery: dict[str, Any] | None = None, scope: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Separate what was found from what was actually run and measured."""
    execution = package.get("execution", {})
    evaluation = package.get("evaluation", {})
    browser_cases = execution.get("browser_case_diagnostics", []) if isinstance(execution, dict) else []
    browser_cases = browser_cases if isinstance(browser_cases, list) else []
    discovered = (discovery or {}).get("components", [])
    approved = (scope or {}).get("components", [])
    required_dimensions = evaluation.get("required_dimensions", []) if isinstance(evaluation, dict) else []
    trust_dimensions: dict[str, list[str]] = {"verified": [], "declared": [], "missing": []}
    for dimension in required_dimensions:
        if not isinstance(dimension, str):
            continue
        metric = metrics.get(dimension, {})
        trust = (
            str(metric.get("trust_status", "declared"))
            if metric.get("measurement_status") == "measured" else "missing"
        )
        trust_dimensions[trust if trust in trust_dimensions else "missing"].append(dimension)
    is_browser_run = execution.get("adapter_type") == "browser_journey" or bool(browser_cases)
    completed_cases = [
        case for case in browser_cases
        if isinstance(case, dict) and case.get("outcome") in {"passed", "failed"}
    ]
    blocked_cases = [
        case for case in browser_cases
        if isinstance(case, dict) and case.get("outcome") == "blocked"
    ]
    requested = int(execution.get("case_count", 0)) if isinstance(execution, dict) else 0
    executed = len(completed_cases) if is_browser_run else int(execution.get("scored_case_count", requested))
    capability_areas = _capability_coverage(discovery, scope, browser_cases)
    module_coverage = _module_coverage(discovery, scope, config, browser_cases)
    workflow_packs = _workflow_pack_summary(discovery, scope, config)
    personas = _persona_coverage(config, browser_cases)
    execution_summary: dict[str, Any] = {
        "kind": "browser_workflow" if is_browser_run else "decision_evaluation",
        "requested_case_count": requested,
        "case_count": executed,
        "blocked_case_count": len(blocked_cases) if is_browser_run else int(execution.get("blocked_case_count", 0)),
    }
    if is_browser_run:
        execution_summary.update({
            "pre_auth_case_count": sum(1 for case in completed_cases if case.get("coverage_scope") == "pre_auth"),
            "authenticated_case_count": sum(1 for case in completed_cases if case.get("coverage_scope") == "authenticated"),
            "passed_case_count": sum(1 for case in completed_cases if case.get("outcome") == "passed"),
            "failed_case_count": sum(1 for case in completed_cases if case.get("outcome") == "failed"),
            "meaning": "Browser cases are passed, assertion-review, or blocked workflow observations.",
        })
    else:
        classification = metrics.get("classification", {})
        case_results = classification.get("case_results", []) if isinstance(classification, dict) else []
        if classification.get("measurement_status") != "measured":
            correct = 0
        elif isinstance(case_results, list) and case_results:
            correct = sum(
                1 for item in case_results
                if isinstance(item, dict) and item.get("correct") is True
            )
        else:
            sample_size = int(classification.get("sample_size", executed))
            correct = round(float(classification.get("accuracy", 0)) * sample_size)
        execution_summary.update({
            "correct_case_count": correct,
            "incorrect_case_count": max(0, executed - correct),
            "meaning": "Decision cases are executed and compared with their labelled expected outcomes.",
        })
    return {
        "schema_version": "esx-coverage-model-1.2",
        "discovered": {
            "component_count": len(discovered) if isinstance(discovered, list) else 0,
            "meaning": "Repository evidence and candidate entry points. Discovery is not execution.",
        },
        "approved": {
            "component_count": len(approved) if isinstance(approved, list) else 0,
            "meaning": "Customer-confirmed scope only. Unapproved discoveries are excluded from evaluation.",
        },
        "executed": execution_summary,
        "metric_trust": {
            "required_dimension_count": len(required_dimensions) if isinstance(required_dimensions, list) else 0,
            "verified_count": len(trust_dimensions["verified"]),
            "declared_count": len(trust_dimensions["declared"]),
            "missing_count": len(trust_dimensions["missing"]),
            "verified_dimensions": trust_dimensions["verified"],
            "declared_dimensions": trust_dimensions["declared"],
            "missing_dimensions": trust_dimensions["missing"],
            "meaning": "Every required metric belongs to exactly one provenance state; declared is not verified.",
        },
        "capability_areas": capability_areas,
        "module_coverage": module_coverage,
        "workflow_packs": workflow_packs,
        "personas": personas,
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


def _module_coverage(
    discovery: dict[str, Any] | None, scope: dict[str, Any] | None, config: dict[str, Any] | None,
    browser_cases: list[object],
) -> list[dict[str, object]]:
    """Summarize how broad browser module coverage is becoming area by area."""
    rows: dict[str, dict[str, object]] = {}
    approved_ids = {
        item.get("id")
        for item in (scope or {}).get("components", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }

    def row_for(area: str) -> dict[str, object]:
        normalized = _capability_area(area, allow_custom=True) or "general"
        return rows.setdefault(normalized, {
            "capability_area": normalized,
            "title": _CAPABILITY_TITLES.get(normalized, normalized.replace("_", " ").title()),
            "discovered_component_count": 0,
            "approved_component_count": 0,
            "candidate_workflow_count": 0,
            "planned_case_count": 0,
            "executed_case_count": 0,
            "passed_case_count": 0,
            "failed_case_count": 0,
            "blocked_case_count": 0,
            "personas": set(),
            "next_step": "Review scope and add explicit workflow coverage.",
        })

    component_areas = {
        item.get("component_id"): _capability_area(item.get("capability_area"), allow_custom=True) or "general"
        for item in (discovery or {}).get("workflow_suggestions", [])
        if isinstance(item, dict) and isinstance(item.get("component_id"), str)
    }
    for component in (discovery or {}).get("components", []):
        if not isinstance(component, dict):
            continue
        area = component_areas.get(component.get("id")) or _capability_area(component.get("category")) or "general"
        row_for(area)["discovered_component_count"] = int(row_for(area)["discovered_component_count"]) + 1
    for component in (scope or {}).get("components", []):
        if not isinstance(component, dict):
            continue
        area = component_areas.get(component.get("id")) or _capability_area(component.get("category")) or "general"
        row_for(area)["approved_component_count"] = int(row_for(area)["approved_component_count"]) + 1
    for candidate in (discovery or {}).get("workflow_suggestions", []):
        if not isinstance(candidate, dict):
            continue
        component_id = candidate.get("component_id")
        if isinstance(component_id, str) and component_id not in approved_ids:
            continue
        area = _capability_area(candidate.get("capability_area"), allow_custom=True) or "general"
        row_for(area)["candidate_workflow_count"] = int(row_for(area)["candidate_workflow_count"]) + 1
        persona = candidate.get("recommended_persona")
        if isinstance(persona, str) and persona:
            row_for(area)["personas"].add(persona)
    cases = (config or {}).get("dataset", {}).get("cases", [])
    cases = cases if isinstance(cases, list) else []
    for case in cases:
        if not isinstance(case, dict):
            continue
        area = _capability_area(case.get("capability_area"), allow_custom=True)
        if area is None:
            continue
        row = row_for(area)
        row["planned_case_count"] = int(row["planned_case_count"]) + 1
        persona = case.get("persona")
        if isinstance(persona, str) and persona:
            row["personas"].add(persona)
    for case in browser_cases:
        if not isinstance(case, dict):
            continue
        area = _capability_area(case.get("capability_area"), allow_custom=True) or "general"
        row = row_for(area)
        outcome = case.get("outcome")
        if outcome in {"passed", "failed"}:
            row["executed_case_count"] = int(row["executed_case_count"]) + 1
        if outcome == "passed":
            row["passed_case_count"] = int(row["passed_case_count"]) + 1
        elif outcome == "failed":
            row["failed_case_count"] = int(row["failed_case_count"]) + 1
        elif outcome == "blocked":
            row["blocked_case_count"] = int(row["blocked_case_count"]) + 1
        persona = case.get("persona")
        if isinstance(persona, str) and persona:
            row["personas"].add(persona)
    output: list[dict[str, object]] = []
    for area in sorted(rows):
        row = rows[area]
        candidate_count = int(row["candidate_workflow_count"])
        planned_count = int(row["planned_case_count"])
        executed_count = int(row["executed_case_count"])
        failed_count = int(row["failed_case_count"])
        blocked_count = int(row["blocked_case_count"])
        approved_count = int(row["approved_component_count"])
        if approved_count == 0:
            next_step = "Approve the owned surface for this area before treating it as test scope."
        elif candidate_count > planned_count:
            next_step = "Convert more approved workflow candidates into reviewed cases for this area."
        elif planned_count == 0:
            next_step = "Add at least one reviewed workflow case with a stable expected signal."
        elif blocked_count:
            next_step = "Refresh the approved session or persona for this area, then rerun."
        elif failed_count:
            next_step = "Review the failed workflow signal or fix the product behavior, then rerun."
        elif executed_count == 0:
            next_step = "Run the reviewed cases for this area."
        else:
            next_step = "Coverage exists here; add alternate personas or negative-path cases next."
        output.append({
            **row,
            "personas": sorted(str(item) for item in row["personas"]),
            "next_step": next_step,
        })
    return output


def _workflow_pack_summary(
    discovery: dict[str, Any] | None, scope: dict[str, Any] | None, config: dict[str, Any] | None,
) -> dict[str, object]:
    approved_ids = {
        item.get("id")
        for item in (scope or {}).get("components", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    approved_cases = [
        case for case in (config or {}).get("dataset", {}).get("cases", [])
        if isinstance(case, dict) and isinstance(case.get("workflow_pack"), str)
    ]
    reviewed_entries = (config or {}).get("workflow_packs", [])
    reviewed_entries = reviewed_entries if isinstance(reviewed_entries, list) else []
    candidate_count = sum(
        1 for item in (discovery or {}).get("workflow_suggestions", [])
        if isinstance(item, dict)
        and isinstance(item.get("pack_id"), str)
        and (not approved_ids or item.get("component_id") in approved_ids)
    )
    reviewed_ids = {
        str(item.get("pack_id"))
        for item in reviewed_entries
        if isinstance(item, dict) and isinstance(item.get("pack_id"), str)
    } | {
        str(case.get("workflow_pack"))
        for case in approved_cases
        if isinstance(case.get("workflow_pack"), str)
    }
    reviewed_count = len(reviewed_ids)
    return {
        "candidate_count": candidate_count,
        "reviewed_count": reviewed_count,
        "planned_case_count": len(approved_cases),
        "remaining_candidate_count": max(0, candidate_count - reviewed_count),
        "meaning": "Workflow candidates come from discovery and scope. They broaden coverage only after review, expected-signal approval, and persona assignment.",
    }


def _persona_coverage(
    config: dict[str, Any] | None, browser_cases: list[object],
) -> list[dict[str, object]]:
    adapter = (config or {}).get("adapter", {})
    adapter = adapter if isinstance(adapter, dict) else {}
    configured = adapter.get("personas", {})
    configured = configured if isinstance(configured, dict) else {}
    rows: dict[str, dict[str, object]] = {}

    def row_for(persona: str) -> dict[str, object]:
        profile = configured.get(persona, {})
        profile = profile if isinstance(profile, dict) else {}
        configured_here = persona in configured or persona in {"default", "anonymous"}
        return rows.setdefault(persona, {
            "persona": persona,
            "label": profile.get("label", persona.replace("-", " ").title()),
            "role": profile.get("role", "implicit"),
            "configured": configured_here,
            "planned_case_count": 0,
            "executed_case_count": 0,
            "blocked_case_count": 0,
            "capability_areas": set(),
        })

    for persona in configured:
        if isinstance(persona, str) and persona:
            row_for(persona)

    cases = (config or {}).get("dataset", {}).get("cases", [])
    cases = cases if isinstance(cases, list) else []
    for case in cases:
        if not isinstance(case, dict):
            continue
        persona = case.get("persona")
        if not isinstance(persona, str) or not persona:
            continue
        row = row_for(persona)
        row["planned_case_count"] = int(row["planned_case_count"]) + 1
        area = _capability_area(case.get("capability_area"), allow_custom=True)
        if area:
            row["capability_areas"].add(area)
    for case in browser_cases:
        if not isinstance(case, dict):
            continue
        persona = case.get("persona")
        if not isinstance(persona, str) or not persona:
            continue
        row = row_for(persona)
        outcome = case.get("outcome")
        if outcome in {"passed", "failed"}:
            row["executed_case_count"] = int(row["executed_case_count"]) + 1
        elif outcome == "blocked":
            row["blocked_case_count"] = int(row["blocked_case_count"]) + 1
        area = _capability_area(case.get("capability_area"), allow_custom=True)
        if area:
            row["capability_areas"].add(area)
    output = []
    for persona in sorted(rows):
        row = rows[persona]
        output.append({
            **row,
            "capability_areas": sorted(str(item) for item in row["capability_areas"]),
        })
    return output
