"""Pre-run coverage readiness, workflow validation, and evidence-gap reports."""

from __future__ import annotations

from collections import Counter
from contextlib import chdir
import os
from pathlib import Path
import re
from typing import Any

from .release import BASELINE_TIER_DIMENSIONS, GATE_FIELDS, RECOMMENDATIONS
from .runner import RunnerError, _validate_config, sha256
from .system_inventory import document
from .workflow_signals import workflow_signal_advisories, workflow_signal_strength


_SAFE_ID = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
_AI_BASELINE = {"classification", "confidence", "decision_evidence"}
_GROUNDING_BASELINE = {"groundedness", "hallucination", "rag"}
_SECURITY_BASELINE = {"security", "tool_use"}
_RELIABILITY_BASELINE = {"robustness", "reproducibility", "cost_efficiency"}
_WORKFLOW_BASELINE = {"workflow_coverage"}


def validate_workflow_packs(plan: dict, root: Path, *, include_disabled: bool = False) -> dict:
    """Validate browser workflow packs before dispatch, without target calls."""
    checks = []
    summary = Counter()
    bound_cases = _scope_case_bindings(plan)
    for check in plan.get("checks", []):
        if check.get("type") != "evaluation":
            continue
        if not include_disabled and not check.get("enabled"):
            continue
        row = _workflow_check_readiness(check, root, bound_cases.get(check.get("id"), set()))
        if row is None:
            continue
        checks.append(row)
        summary["browser_checks"] += 1
        summary["planned_case_count"] += row["planned_case_count"]
        summary["content_signal_case_count"] += row["content_signal_case_count"]
        summary["weak_signal_case_count"] += row["weak_signal_case_count"]
        summary["auth_case_count"] += row["auth_case_count"]
        summary["missing_session_case_count"] += row["missing_session_case_count"]
        summary["unbound_case_count"] += row["unbound_case_count"]
        for issue in row["issues"]:
            summary[issue["severity"] + "_count"] += 1
    blocker_count = summary["blocker_count"]
    warning_count = summary["warning_count"]
    return {
        "schema_version": "pre-d-workflow-pack-readiness-1.0",
        "ready": blocker_count == 0,
        "strong_enough_for_coverage": blocker_count == 0 and warning_count == 0,
        "summary": {
            "browser_check_count": summary["browser_checks"],
            "planned_case_count": summary["planned_case_count"],
            "content_signal_case_count": summary["content_signal_case_count"],
            "weak_signal_case_count": summary["weak_signal_case_count"],
            "auth_case_count": summary["auth_case_count"],
            "missing_session_case_count": summary["missing_session_case_count"],
            "unbound_case_count": summary["unbound_case_count"],
            "blocker_count": blocker_count,
            "warning_count": warning_count,
        },
        "checks": checks,
        "target_calls_made": False,
        "notice": (
            "Workflow readiness is a static PRE-D validation. It proves that planned journeys, personas, "
            "sessions, and stable signals are configured; it does not prove the target UI will pass."
        ),
    }


def coverage_readiness(plan: dict, root: Path) -> dict:
    """Explain whether discovered modules are ready for meaningful evidence collection."""
    workflow = validate_workflow_packs(plan, root)
    components = []
    metric_gaps = []
    checks_by_component = _checks_by_component(plan)
    for component in plan.get("components", []):
        checks = checks_by_component.get(component["id"], [])
        enabled_checks = [check for check in checks if check.get("enabled")]
        missing_layers = [
            layer for layer in component.get("required_layers", [])
            if not any(check.get("layer") == layer and check.get("enabled") for check in checks)
        ]
        requested_dimensions = {
            dimension for check in checks if check.get("type") == "evaluation"
            for dimension in _check_dimensions(check)
        }
        expected_dimensions = _expected_dimensions(component)
        missing_dimensions = sorted(expected_dimensions - requested_dimensions)
        if missing_dimensions:
            metric_gaps.append({
                "component_id": component["id"],
                "module": component["module"],
                "component": component["name"],
                "missing_dimensions": missing_dimensions,
                "action": _metric_gap_action(missing_dimensions),
            })
        if missing_layers:
            status = "missing_required_layers"
        elif not enabled_checks:
            status = "configured_not_enabled"
        else:
            status = "ready_to_attempt"
        components.append({
            "component_id": component["id"],
            "module": component["module"],
            "component": component["name"],
            "kind": component["kind"],
            "status": status,
            "required_layers": component.get("required_layers", []),
            "enabled_check_count": len(enabled_checks),
            "missing_layers": missing_layers,
            "expected_metric_dimensions": sorted(expected_dimensions),
            "requested_metric_dimensions": sorted(requested_dimensions),
            "missing_metric_dimensions": missing_dimensions,
        })
    blockers = []
    blockers.extend(
        issue["message"] for row in workflow["checks"] for issue in row["issues"]
        if issue["severity"] == "blocker"
    )
    blockers.extend(
        f'{row["module"]}/{row["component"]}: missing layer coverage for {", ".join(row["missing_layers"])}'
        for row in components if row["missing_layers"]
    )
    return {
        "schema_version": "pre-d-coverage-readiness-1.0",
        "ready_to_dispatch": not blockers,
        "ready_for_whole_system_claim": not blockers and workflow["strong_enough_for_coverage"],
        "summary": {
            "component_count": len(components),
            "ready_component_count": sum(row["status"] == "ready_to_attempt" for row in components),
            "component_gap_count": sum(row["status"] != "ready_to_attempt" for row in components),
            "metric_gap_count": len(metric_gaps),
            "workflow_blocker_count": workflow["summary"]["blocker_count"],
            "workflow_warning_count": workflow["summary"]["warning_count"],
        },
        "blockers": blockers,
        "components": components,
        "metric_gaps": metric_gaps,
        "workflow_readiness": workflow,
        "target_calls_made": False,
    }


def draft_coverage_packs(plan: dict, root: Path) -> dict:
    """Draft review-only packs for uncovered modules; never enable or approve them."""
    existing_ids = {check["id"] for check in plan.get("checks", [])}
    workflow_cases = []
    api_checks = []
    decision_packs = []
    security_checks = []
    reliability_checks = []
    for component in plan.get("components", []):
        identifier = _slug(component["module"] + "-" + component["name"])
        path = component.get("path", "/")
        if component.get("kind") == "page" or "workflow" in component.get("required_layers", []):
            workflow_cases.append({
                "pack_id": "workflow-" + identifier,
                "component_id": component["id"],
                "module": component["module"],
                "path": path if isinstance(path, str) and path.startswith("/") else "/",
                "persona": _first_non_anonymous_role(plan),
                "requires_auth": _first_non_anonymous_role(plan) != "anonymous",
                "expected_text": "REVIEW_VISIBLE_TEXT",
                "status": "review_required",
                "case_template": {
                    "case_id": "workflow-" + identifier,
                    "input": {"journey": [
                        {"type": "goto", "path": path if isinstance(path, str) and path.startswith("/") else "/"},
                        {"type": "wait_for_stable", "settle_ms": 250, "retry_count": 2, "retry_delay_ms": 250},
                        {"type": "wait_for_text", "value": "REVIEW_VISIBLE_TEXT", "retry_count": 2, "retry_delay_ms": 250},
                    ]},
                    "expected_label": "pass",
                    "requires_auth": _first_non_anonymous_role(plan) != "anonymous",
                    "persona": _first_non_anonymous_role(plan),
                    "capability_area": _slug(component["module"])[:62] or "general",
                    "workflow_pack": "workflow-" + identifier,
                },
            })
        if component.get("kind") == "api":
            check_id = _available_check_id(existing_ids, "api-" + identifier)
            api_checks.append({
                "id": check_id,
                "component_id": component["id"],
                "module": component["module"],
                "type": "http",
                "layer": "functional",
                "method": component.get("method") or "GET",
                "path": path,
                "expected_status": [200],
                "json_assertions": [{"path": "REVIEW_JSON_FIELD", "equals": "REVIEW_EXPECTED_VALUE"}],
                "enabled": False,
                "reviewed": False,
                "status": "review_required",
            })
            if len(plan.get("roles", [])) > 1:
                security_checks.append({
                    "id": _available_check_id(existing_ids, "authz-" + identifier),
                    "component_id": component["id"],
                    "module": component["module"],
                    "type": "http",
                    "layer": "authorization",
                    "method": component.get("method") or "GET",
                    "path": path,
                    "roles_to_review": plan.get("roles", []),
                    "status": "review_required",
                    "note": "Fill expected 200/403 outcomes and identity environment variables per role before enabling.",
                })
        expected = _expected_dimensions(component)
        if expected & (_AI_BASELINE | _GROUNDING_BASELINE):
            decision_packs.append({
                "pack_id": "decision-" + identifier,
                "component_id": component["id"],
                "module": component["module"],
                "required_dimensions": sorted(expected & (_AI_BASELINE | _GROUNDING_BASELINE)),
                "status": "review_required",
                "dataset_requirements": [
                    "labelled cases with expected labels for classification metrics",
                    "returned labels and confidence values from a local endpoint or adapter",
                    "response text plus source chunks for groundedness and hallucination",
                    "expected evidence IDs and abstention expectations where applicable",
                ],
            })
        if "reliability" in component.get("required_layers", []) or component.get("kind") == "service":
            reliability_checks.append({
                "id": _available_check_id(existing_ids, "load-" + identifier),
                "component_id": component["id"],
                "module": component["module"],
                "type": "load",
                "layer": "reliability",
                "method": "GET",
                "path": path if isinstance(path, str) and path.startswith("/") else "/health",
                "requests": 10,
                "concurrency": 2,
                "max_p95_ms": 1000,
                "status": "review_required",
            })
    return {
        "schema_version": "pre-d-coverage-pack-draft-1.0",
        "plan_sha256": sha256(plan),
        "target_calls_made": False,
        "notice": (
            "Drafts are authoring aids only. PRE-D did not call the target and did not approve, enable, "
            "or execute these checks. Replace every REVIEW_* placeholder before use."
        ),
        "summary": {
            "workflow_case_templates": len(workflow_cases),
            "api_check_templates": len(api_checks),
            "decision_pack_templates": len(decision_packs),
            "security_check_templates": len(security_checks),
            "reliability_check_templates": len(reliability_checks),
        },
        "workflow_cases": workflow_cases,
        "api_checks": api_checks,
        "decision_packs": decision_packs,
        "security_checks": security_checks,
        "reliability_checks": reliability_checks,
    }


def evidence_gap_report(
    plan: dict, root: Path, *, results: list[dict] | None = None,
    coverage: list[dict] | None = None, module_summary: dict | None = None,
) -> dict:
    """Create a human-actionable evidence gap report from plan and optional run results."""
    readiness = coverage_readiness(plan, root)
    setup_plan = full_platform_setup_plan(plan, root, readiness=readiness)
    run_results = results or []
    result_by_id = {result["id"]: result for result in run_results}
    not_executed = [
        {"check_id": check["id"], "component_ids": check.get("component_ids", []), "reason": "enabled_check_not_executed"}
        for check in plan.get("checks", []) if check.get("enabled") and check["id"] not in result_by_id
    ]
    blocked = [
        {"check_id": result["id"], "reason": result.get("reason", "blocked"), "action": result.get("action", "Inspect blocked evidence.")}
        for result in run_results if result.get("status") == "blocked"
    ]
    weak_workflows = [
        {"check_id": row["check_id"], "case_ids": issue["case_ids"], "message": issue["message"], "action": issue["action"]}
        for row in readiness["workflow_readiness"]["checks"]
        for issue in row["issues"] if issue["category"] in {"weak_signal", "unbound_case"}
    ]
    module_gaps = [
        {
            "component_id": row["component_id"],
            "module": row["module"],
            "component": row["component"],
            "missing_layers": row["missing_layers"],
            "missing_metric_dimensions": row["missing_metric_dimensions"],
            "action": _component_gap_action(row),
        }
        for row in readiness["components"]
        if row["missing_layers"] or row["missing_metric_dimensions"]
    ]
    action_items = []
    action_items.extend({
        "priority": "high", "category": "workflow_config", "message": issue["message"], "action": issue["action"],
    } for row in readiness["workflow_readiness"]["checks"] for issue in row["issues"] if issue["severity"] == "blocker")
    action_items.extend({
        "priority": "high", "category": "blocked_execution", "message": item["check_id"] + ": " + item["reason"], "action": item["action"],
    } for item in blocked)
    action_items.extend({
        "priority": "medium", "category": "coverage_gap", "message": item["module"] + "/" + item["component"], "action": item["action"],
    } for item in module_gaps[:100])
    summary = {
        "component_gap_count": len(module_gaps),
        "workflow_gap_count": len(weak_workflows) + readiness["workflow_readiness"]["summary"]["blocker_count"],
        "blocked_check_count": len(blocked),
        "not_executed_check_count": len(not_executed),
        "action_item_count": len(action_items),
    }
    if module_summary:
        summary["areas_with_executed_evidence"] = module_summary.get("summary", {}).get("areas_with_executed_evidence", 0)
        summary["area_count"] = module_summary.get("summary", {}).get("area_count", 0)
    report = {
        "schema_version": "pre-d-evidence-gap-report-1.0",
        "plan_sha256": sha256(plan),
        "target_calls_made": False,
        "summary": summary,
        "readiness": readiness,
        "module_evaluation_summary": module_summary,
        "coverage_snapshot": coverage or [],
        "not_executed_checks": not_executed,
        "blocked_checks": blocked,
        "weak_workflows": weak_workflows,
        "module_gaps": module_gaps,
        "action_items": action_items,
        "setup_plan": setup_plan,
        "notice": "This report separates missing evidence from failed evidence. It does not infer behavior for modules that were discovered but not executed.",
    }
    from .system_findings import evidence_gap_findings, harness_recommendations
    report["finding_register"] = evidence_gap_findings(plan, report)
    report["harness_recommendations"] = harness_recommendations(report["finding_register"])
    return report


def full_platform_setup_plan(plan: dict, root: Path, *, readiness: dict | None = None) -> dict:
    """Turn coverage gaps into ordered setup work, without target calls."""
    readiness = readiness or coverage_readiness(plan, root)
    steps = []
    if not plan.get("inventory_confirmed"):
        steps.append(_setup_step(
            "confirm-inventory",
            "high",
            "Confirm the application inventory and module grouping",
            "PRE-D can discover candidates, but the operator must confirm what belongs in the product scope.",
            ["Review discovered components", "Add missing modules/components", "Mark disabled or feature-flagged capabilities explicitly"],
            ["Open system setup and check inventory_confirmed only after module scope is reviewed."],
        ))
    if "scope_contract" not in plan:
        steps.append(_setup_step(
            "draft-behavior-contract",
            "high",
            "Draft whole-system behavior objectives",
            "A module is not covered until its required behaviors are bound to executable evidence.",
            ["Define critical behaviors per component/layer/role", "Bind case IDs or assertion paths", "Keep exclusions visible as gaps"],
            ['esx-eval system scope --plan "<system-plan.json>" --init'],
        ))
    if readiness["summary"]["component_gap_count"] or readiness["summary"]["metric_gap_count"]:
        steps.append(_setup_step(
            "agent-authoring-handoff",
            "medium",
            "Use agent-assisted drafting for uncovered modules",
            "Claude/Codex can help draft missing checks and objectives, but PRE-D imports only source-anchored disabled drafts.",
            ["Export the task pack", "Ask the coding agent to return pre-d-agent-pack-1.0 JSON", "Import, review, and enable only approved drafts"],
            [
                'esx-eval system agent-tasks --plan "<system-plan.json>" --out "./agent-tasks.json"',
                'esx-eval system import-agent-pack --plan "<system-plan.json>" --pack "./agent-pack.json"',
            ],
        ))
    component_steps = []
    for row in readiness["components"]:
        if not row["missing_layers"] and not row["missing_metric_dimensions"]:
            continue
        component_steps.append(_component_setup_action(row))
    workflow = readiness.get("workflow_readiness", {})
    if workflow.get("summary", {}).get("blocker_count") or workflow.get("summary", {}).get("warning_count"):
        steps.append(_setup_step(
            "repair-browser-workflows",
            "high" if workflow["summary"].get("blocker_count") else "medium",
            "Repair browser workflow packs before rerun",
            "Browser coverage needs approved sessions/personas and stable visible content assertions, not path-only checks.",
            ["Refresh stale sessions", "Add persona configs", "Replace path-only checks with visible text/selector assertions", "Bind workflow cases to behavior objectives"],
            ['esx-eval system validate-workflows --plan "<system-plan.json>" --out "./workflow-readiness.json"'],
        ))
    if component_steps:
        steps.append(_setup_step(
            "bind-missing-module-evidence",
            "high",
            "Bind missing module and metric evidence",
            "Each missing layer or dimension needs the right kind of evidence pack; discovery alone does not count.",
            [f'{item["module"]}/{item["component"]}: {item["summary"]}' for item in component_steps[:25]],
            ['esx-eval system draft-packs --plan "<system-plan.json>" --out "./coverage-drafts.json"'],
            component_actions=component_steps[:500],
        ))
    steps.append(_setup_step(
        "approve-and-run-reviewed-plan",
        "medium",
        "Approve only after reviewed evidence is bound",
        "Execution should happen after inventory, behavior objectives, checks, sessions, identities, and gates are reviewed.",
        ["Run preflight", "Resolve blockers", "Run into a new output directory", "Use history for regression context"],
        [
            'esx-eval system approve --plan "<system-plan.json>"',
            'esx-eval system preflight --plan "<system-plan.json>" --require-whole-system',
            'esx-eval system run --plan "<system-plan.json>" --out "./runs/candidate-001" --history "./pred-history.sqlite" --require-whole-system',
        ],
    ))
    return {
        "schema_version": "pre-d-full-platform-setup-plan-1.0",
        "target_calls_made": False,
        "application_code_modified": False,
        "summary": {
            "step_count": len(steps),
            "component_action_count": len(component_steps),
            "high_priority_step_count": sum(step["priority"] == "high" for step in steps),
            "ready_for_whole_system_claim": readiness["ready_for_whole_system_claim"],
        },
        "steps": steps,
        "notice": (
            "This setup plan is an authoring guide. It does not execute the target, modify application code, "
            "approve checks, or turn missing evidence into results."
        ),
    }


def _setup_step(identifier: str, priority: str, title: str, why: str, actions: list[str],
                commands: list[str], *, component_actions: list[dict] | None = None) -> dict:
    return {
        "id": identifier,
        "priority": priority,
        "title": title,
        "why": why,
        "actions": actions,
        "commands": commands,
        "component_actions": component_actions or [],
    }


def _component_setup_action(row: dict) -> dict:
    missing_layers = row["missing_layers"]
    missing_dimensions = row["missing_metric_dimensions"]
    requirements, templates = [], []
    for layer in missing_layers:
        req, template = _layer_requirement(layer)
        requirements.append(req)
        templates.append(template)
    for dimension in missing_dimensions:
        req, template = _dimension_requirement(dimension)
        requirements.append(req)
        templates.append(template)
    summary = "; ".join(dict.fromkeys(requirements)) or "Review and bind executable evidence."
    return {
        "component_id": row["component_id"],
        "module": row["module"],
        "component": row["component"],
        "kind": row["kind"],
        "missing_layers": missing_layers,
        "missing_metric_dimensions": missing_dimensions,
        "summary": summary,
        "recommended_templates": sorted(set(templates)),
        "required_inputs": sorted(set(requirements)),
        "next_action": _component_gap_action(row),
    }


def _layer_requirement(layer: str) -> tuple[str, str]:
    return {
        "functional": ("Add HTTP/API checks with reviewed status and JSON business assertions.", "api_check"),
        "workflow": ("Add browser workflow cases with approved auth/session and stable visible assertions.", "browser_workflow"),
        "ai": ("Bind a decision or semantic evaluation config with labelled cases and real adapter outputs.", "decision_eval"),
        "integration": ("Add cross-component or dependency checks with content assertions, not status alone.", "integration_check"),
        "code": ("Attach a reviewed JUnit-producing unit/integration/security test command.", "junit_command"),
        "authorization": ("Add role allow/deny checks using declared test identities and expected 200/403 outcomes.", "role_matrix"),
        "security": ("Attach adversarial, tenant-isolation, unsafe-action, or prompt-injection checks with expected outcomes.", "security_pack"),
        "reliability": ("Add health/budget/load/recovery evidence in an isolated local or staging environment.", "reliability_pack"),
    }.get(layer, ("Bind reviewed executable evidence for this layer.", "custom_check"))


def _dimension_requirement(dimension: str) -> tuple[str, str]:
    return {
        "classification": ("Provide labelled cases plus real predicted labels from an endpoint or adapter.", "decision_eval"),
        "confidence": ("Provide genuine 0..1 confidence values with clear provenance for returned labels.", "decision_eval"),
        "decision_evidence": ("Provide expected/observed evidence IDs and abstention fields.", "decision_eval"),
        "groundedness": ("Provide response text, source chunks, and independent local claim-support judgments.", "semantic_eval"),
        "hallucination": ("Provide response text, source chunks or expected abstention, and unsupported-claim verdicts.", "semantic_eval"),
        "rag": ("Provide retrieval results, expected relevant sources, evidence coverage, and response grounding material.", "rag_eval"),
        "security": ("Provide adversarial/security cases with expected blocked/allowed outcomes.", "security_pack"),
        "tool_use": ("Provide expected/observed tool calls, authorization, parameters, and results.", "tool_eval"),
        "robustness": ("Provide perturbation or failure cases with expected stable behavior.", "reliability_pack"),
        "judge_agreement": ("Provide repeated or alternate judge verdicts for the same cases.", "agreement_pack"),
        "reproducibility": ("Provide repeated runs over the same cases with comparable outputs.", "history_or_repeat_pack"),
        "cost_efficiency": ("Provide per-case token, runtime, cost, timeout, or bounded load observations.", "cost_latency_pack"),
    }.get(dimension, ("Provide the required evidence contract for this metric.", "custom_metric_pack"))


def _workflow_check_readiness(check: dict, root: Path, scope_bindings: set[str]) -> dict | None:
    issues = []
    config_path = (root / check.get("config", "")).resolve()
    try:
        config = document(config_path)
    except (OSError, RunnerError, ValueError, KeyError, TypeError) as exc:
        if check.get("layer") != "workflow" and "workflow_coverage" not in _check_dimensions(check):
            return None
        return _invalid_workflow_check(check, exc)
    if config.get("adapter", {}).get("type") != "browser_journey":
        return None
    try:
        with chdir(config_path.parent):
            _validate_config(config)
    except (OSError, RunnerError, ValueError, KeyError, TypeError) as exc:
        return _invalid_workflow_check(check, exc)
    adapter = config["adapter"]
    cases = config.get("dataset", {}).get("cases", [])
    signal = workflow_signal_strength(cases)
    weak = [row["case_id"] for row in signal["cases"] if row["signal_strength"] != "content_signal"]
    for advisory in workflow_signal_advisories(signal):
        issues.append(_issue("warning", "weak_signal", advisory["summary"], advisory["action"], case_ids=advisory["case_ids"]))
    all_case_ids = {case.get("case_id") for case in cases}
    unbound = sorted(case_id for case_id in all_case_ids if isinstance(case_id, str) and case_id not in scope_bindings)
    if scope_bindings and unbound:
        issues.append(_issue(
            "warning", "unbound_case",
            f"{len(unbound)} planned workflow case(s) are not bound to a reviewed behavior objective.",
            "Bind each meaningful case to a scope objective, or explicitly mark it as exploratory smoke coverage.",
            case_ids=unbound,
        ))
    auth_cases = []
    missing_session_cases = []
    for case in cases:
        if not case.get("requires_auth"):
            continue
        auth_cases.append(case.get("case_id"))
        persona = case.get("persona", "default")
        missing = _auth_gap(adapter, config_path.parent, persona)
        if missing:
            missing_session_cases.append(case.get("case_id"))
            issues.append(_issue(
                "blocker", "session_binding",
                f"{case.get('case_id')}: {missing}",
                "Refresh the approved local session or configure an approved persona/auth bootstrap before execution.",
                case_ids=[case.get("case_id")],
            ))
    status = "blocked" if any(issue["severity"] == "blocker" for issue in issues) else "needs_review" if issues else "ready"
    return {
        "check_id": check["id"],
        "status": status,
        "config": check.get("config"),
        "planned_case_count": len(cases),
        "content_signal_case_count": signal["content_signal_count"],
        "weak_signal_case_count": len(weak),
        "auth_case_count": len(auth_cases),
        "missing_session_case_count": len(missing_session_cases),
        "unbound_case_count": len(unbound),
        "issues": issues,
        "advisories": workflow_signal_advisories(signal),
        "cases": [
            {**row, "requires_auth": bool(next((case for case in cases if case.get("case_id") == row["case_id"]), {}).get("requires_auth")),
             "persona": next((case for case in cases if case.get("case_id") == row["case_id"]), {}).get("persona", "default")}
            for row in signal["cases"]
        ],
    }


def _invalid_workflow_check(check: dict, exc: Exception) -> dict:
    return {
        "check_id": check.get("id", "unknown"),
        "status": "blocked",
        "config": check.get("config"),
        "planned_case_count": 0,
        "content_signal_case_count": 0,
        "weak_signal_case_count": 0,
        "auth_case_count": 0,
        "missing_session_case_count": 0,
        "unbound_case_count": 0,
        "issues": [_issue("blocker", "invalid_config", str(exc), "Repair the browser workflow config and rebind it before execution.")],
        "cases": [],
    }


def _scope_case_bindings(plan: dict) -> dict[str, set[str]]:
    bindings: dict[str, set[str]] = {}
    for objective in plan.get("scope_contract", {}).get("objectives", []):
        check_id = objective.get("check_id")
        if not check_id:
            continue
        bindings.setdefault(check_id, set()).update(
            case_id for case_id in objective.get("case_ids", [])
            if isinstance(case_id, str) and case_id
        )
    return bindings


def _auth_gap(adapter: dict, base: Path, persona: str) -> str | None:
    selected = _persona_adapter(adapter, persona)
    if selected is None:
        return f"persona '{persona}' is not configured"
    state = selected.get("session_state_path")
    if isinstance(state, str) and (base / state).is_file():
        return None
    auth = selected.get("auth")
    if isinstance(auth, dict):
        missing = [auth[key] for key in ("username_env", "password_env") if not os.environ.get(auth[key])]
        return "browser auth environment values are missing: " + ", ".join(missing) if missing else None
    if isinstance(selected.get("session_bootstrap"), dict) or isinstance(state, str):
        return "approved browser session file is missing or stale"
    return "no approved auth, session_state_path or session_bootstrap is configured"


def _persona_adapter(adapter: dict, persona: str) -> dict | None:
    if persona == "anonymous":
        return {}
    if persona in {"default", ""}:
        return adapter
    profiles = adapter.get("personas", {})
    if not isinstance(profiles, dict) or persona not in profiles:
        return None
    return {
        **{key: value for key, value in adapter.items() if key not in {"personas", "auth", "session_state_path", "session_bootstrap"}},
        **profiles[persona],
    }


def _issue(severity: str, category: str, message: str, action: str, *, case_ids: list[str] | None = None) -> dict:
    return {"severity": severity, "category": category, "message": message, "action": action, "case_ids": case_ids or []}


def _checks_by_component(plan: dict) -> dict[str, list[dict]]:
    rows: dict[str, list[dict]] = {}
    for check in plan.get("checks", []):
        for component_id in check.get("component_ids", []):
            rows.setdefault(component_id, []).append(check)
    return rows


def _check_dimensions(check: dict) -> set[str]:
    dimensions = set(check.get("requested_dimensions", []))
    for gate in check.get("gates", []):
        signal = str(gate.get("signal", ""))
        if "." in signal:
            dimensions.add(signal.split(".", 1)[0])
    return dimensions


def _expected_dimensions(component: dict) -> set[str]:
    layers = set(component.get("required_layers", []))
    text = " ".join(str(component.get(key, "")) for key in ("name", "module", "kind", "path")).lower()
    dimensions = set(component.get("suggested_dimensions", [])) & set(GATE_FIELDS)
    if "workflow" in layers or component.get("kind") == "page":
        dimensions |= _WORKFLOW_BASELINE
    if "ai" in layers or component.get("kind") == "ai_candidate":
        dimensions |= _AI_BASELINE
    if any(token in text for token in ("rag", "knowledge", "retrieval", "citation", "ground", "summary")):
        dimensions |= _GROUNDING_BASELINE
    if "security" in layers or "authorization" in layers or any(token in text for token in ("auth", "tenant", "policy", "permission", "tool")):
        dimensions |= _SECURITY_BASELINE
    if "reliability" in layers or any(token in text for token in ("queue", "job", "worker", "latency", "cost", "token", "retry", "dead")):
        dimensions |= _RELIABILITY_BASELINE
    return dimensions & set(BASELINE_TIER_DIMENSIONS)


def _metric_gap_action(dimensions: list[str]) -> str:
    if not dimensions:
        return "No metric gap."
    first = dimensions[0]
    return RECOMMENDATIONS.get(first, ("coverage", "Bind an explicit evidence pack for the missing metric."))[1]


def _component_gap_action(row: dict) -> str:
    if row["missing_layers"]:
        return "Add reviewed checks for missing layers: " + ", ".join(row["missing_layers"]) + "."
    return _metric_gap_action(row["missing_metric_dimensions"])


def _first_non_anonymous_role(plan: dict) -> str:
    return next((role for role in plan.get("roles", []) if role != "anonymous"), "anonymous")


def _available_check_id(existing: set[str], base: str) -> str:
    identifier = _slug(base)
    candidate = identifier
    suffix = 2
    while candidate in existing:
        candidate = f"{identifier}-{suffix}"
        suffix += 1
    existing.add(candidate)
    return candidate


def _slug(value: str) -> str:
    slug = "-".join(re.findall(r"[a-z0-9]+", value.lower()))[:58] or "draft"
    if not _SAFE_ID.fullmatch(slug):
        slug = "draft-" + slug[:50]
    return slug
