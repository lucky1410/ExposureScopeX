"""Whole-inventory planning and execution accounting, without target calls."""

from __future__ import annotations

from contextlib import chdir
from pathlib import Path
from typing import Any

from .runner import RunnerError, _validate_config, read_json, sha256
from .release_coverage import plan_requirement_issues
from .workflow_signals import has_explicit_signal, workflow_signal_advisories, workflow_signal_strength


def plan_metadata(evaluation: dict[str, Any], cases: list[dict[str, Any]], *, kind: str) -> dict[str, Any]:
    required = list(evaluation.get("required_dimensions", ["classification", "confidence"]))
    result: dict[str, Any] = {"required_dimensions": required}
    if kind == "workflow":
        result["workflow_signal_strength"] = workflow_signal_strength(cases)
    return result


def load_plan(path: Path, application: dict, suite: dict | None = None) -> tuple[dict, list, dict, str]:
    config = read_json(path)
    with chdir(path.parent):
        evaluation, cases, adapter = _validate_config(config)
    if (evaluation["project_key"] != application["id"]
            or evaluation["subject_version"] != application["version"]):
        raise RunnerError("Plan project_key and subject_version must match the release application")
    kind = "workflow" if adapter["type"] == "browser_journey" else "decision"
    if kind == "workflow":
        if any(not has_explicit_signal(case["input"]["journey"]) for case in cases):
            raise RunnerError("Release workflows require an explicit expect_text, wait_for_text, expect_visible, wait_for_selector, assert_path, or assert_title assertion in every case; navigation alone is not a success signal")
    if suite and (evaluation["agent_id"] != suite["subject_id"] or kind != suite["kind"]):
        raise RunnerError("Plan subject or evaluation kind does not match its release suite")
    return evaluation, cases, adapter, sha256(config)


def preflight_all_modules(
    manifest: dict, manifest_path: Path,
) -> tuple[dict, dict[str, tuple[Path, str]], dict[str, dict[str, Any]]]:
    """Check all plans before any adapter runs; never infer a missing test oracle."""
    issues: list[dict[str, Any]] = []
    advisories: list[dict[str, Any]] = []
    modules = []
    prepared = {}
    metadata: dict[str, dict[str, Any]] = {}
    seen_paths: set[Path] = set()
    seen_configs: set[str] = set()

    def issue(code: str, action: str, module_id: str | None = None, suite_id: str | None = None) -> None:
        issues.append({"code": code, "module_id": module_id, "suite_id": suite_id, "action": action})

    def advisory(code: str, summary: str, action: str, module_id: str, suite_id: str, **extra: Any) -> None:
        advisories.append({
            "code": code,
            "module_id": module_id,
            "suite_id": suite_id,
            "summary": summary,
            "action": action,
            **extra,
        })

    if not manifest["application"]["inventory_complete"]:
        issue("inventory_unconfirmed", "Review the full module inventory and confirm application.inventory_complete. Discovery is not execution.")
    for module in manifest["modules"]:
        start = len(issues)
        module_id = module["id"]
        suites = []
        plans = {}
        if not module["required"]:
            issue("module_excluded", "An all-module run cannot skip this module. Prepare an approved test environment and plans, or use release check for an explicitly partial review.", module_id)
        elif not module["suites"]:
            issue("module_has_no_plans", "Create a workflow or decision plan, then attach it with release attach. No test is invented for this module.", module_id)
        if module["required"] and not module.get("test_requirements"):
            issue("test_objectives_unconfirmed", "Use release scope to draft the module's test objectives, review them, and bind actual cases with release bind. Attached test kinds alone do not confirm sufficient test depth.", module_id)
        for dependency in module["depends_on"]:
            if not any(r.get("dependency") == dependency for r in module.get("test_requirements", [])):
                issue("dependency_objective_missing", "Declare and bind an integration objective for dependency " + dependency + "; independent module runs do not exercise a cross-module path.", module_id)
        kinds = module.get("required_kinds", [])
        if module["required"] and not kinds:
            issue("test_kinds_unconfirmed", "Declare required_kinds as workflow, decision, or both. Use release attach --require-kind for each needed kind.", module_id)
        for kind in sorted(set(kinds) - {s["kind"] for s in module["suites"]}):
            issue("required_kind_missing", f"Attach a {kind} plan; another evaluation kind cannot cover it.", module_id)
        if module.get("test_requirements"):
            for kind in sorted(set(kinds) - {r["kind"] for r in module["test_requirements"]}):
                issue("required_kind_objective_missing", f"Review and bind at least one {kind} objective; objectives from another evaluation kind cannot cover it.", module_id)
        for suite in module["suites"]:
            suite_id = suite["id"]
            suite_start = len(issues)
            row = {"id": suite_id, "kind": suite["kind"], "planned_cases": 0, "status": "blocked"}
            suites.append(row)
            if "config" not in suite:
                issue("report_reuse_not_execution", "Attach the original runnable config. Existing reports cannot replace fresh execution in an all-module run.", module_id, suite_id)
                continue
            path = (manifest_path.parent / suite["config"]).resolve()
            repeated_path = path in seen_paths
            if repeated_path:
                issue("duplicate_plan", "Use a distinct plan for each suite; binding one file twice is not additional module coverage.", module_id, suite_id)
            seen_paths.add(path)
            try:
                evaluation, cases, _, digest = load_plan(path, manifest["application"], suite)
            except (RunnerError, OSError, ValueError):
                issue("invalid_plan", "Validate this plan with esx-eval evidence-check. Check its path, dataset, adapter, application/version and subject. No target was called.", module_id, suite_id)
                continue
            metadata[suite_id] = plan_metadata(evaluation, cases, kind=suite["kind"])
            row["planned_cases"] = len(cases)
            plans[suite_id] = cases
            row["required_dimensions"] = list(metadata[suite_id]["required_dimensions"])
            if "workflow_signal_strength" in metadata[suite_id]:
                row["workflow_signal_strength"] = metadata[suite_id]["workflow_signal_strength"]
            if digest in seen_configs and not repeated_path:
                issue("duplicate_plan", "This config duplicates another suite's plan content. Supply distinct module-specific cases and bindings, not a copied plan.", module_id, suite_id)
            seen_configs.add(digest)
            approval = suite.get("execution_policy", {})
            row["execution_mode"] = approval.get("mode")
            row["config_sha256"] = digest
            if approval.get("config_sha256") != digest:
                issue("execution_not_approved", "Review the current plan and reattach it with --read-only or --isolated-writes plus an isolation note. Approval must match this exact config.", module_id, suite_id)
            if suite["kind"] == "decision":
                required = set(metadata[suite_id]["required_dimensions"])
                if "decision_evidence" not in required:
                    advisory(
                        "baseline_dimension_unexercised",
                        "Baseline decision evidence is not requested in this plan.",
                        "Add decision_evidence to evaluation.required_dimensions and gate at least one abstention or evidence-reference signal before relying on this suite as a fuller decision-quality release input.",
                        module_id,
                        suite_id,
                        dimensions=["decision_evidence"],
                    )
                if "population" not in suite:
                    advisory(
                        "population_context_missing",
                        "This decision suite has no declared labelled population context.",
                        "Optionally declare suite.population.available_case_count and class_counts so PRE-D can show how much of the available labelled universe this pack actually covers.",
                        module_id,
                        suite_id,
                    )
            if suite["kind"] == "workflow":
                strength = metadata[suite_id]["workflow_signal_strength"]
                for caution in workflow_signal_advisories(strength):
                    advisory(module_id=module_id, suite_id=suite_id, **caution)
            if len(issues) == suite_start:
                row["status"] = "ready"
                prepared[suite_id] = (path, digest)
        issues.extend(plan_requirement_issues(module, plans))
        modules.append({"id": module_id, "required": module["required"],
                        "test_requirement_count": len(module.get("test_requirements", [])),
                        "advisory_count": sum(item.get("module_id") == module_id for item in advisories),
                        "status": "ready" if len(issues) == start else "blocked", "suites": suites})
    result = {
        "schema_version": "pre-d-release-preflight-1.0", "manifest_sha256": sha256(manifest),
        "status": "blocked" if issues else "ready", "module_count": len(modules),
        "ready_module_count": sum(m["status"] == "ready" for m in modules),
        "planned_suite_count": sum(len(m["suites"]) for m in modules),
        "planned_case_count": sum(s["planned_cases"] for m in modules for s in m["suites"]),
        "modules": modules, "issues": issues, "advisories": advisories,
        "target_calls_made": False,
        "notice": "Readiness validates the supplied plans, not connectivity, business correctness, or complete test design. Execution approval is an operator declaration, not an external-write sandbox.",
    }
    return result, {} if issues else prepared, metadata


def execution_summary(report: dict, *, mode: str, attempted: list[str], reused: list[str],
                      preflight: dict | None = None) -> dict:
    modules = []
    for module in report["modules"]:
        suites = module["suites"]
        full = bool(suites) and module["required"] and all(
            s["id"] in attempted and s["requested_cases"] > 0
            and s["executed_cases"] == s["requested_cases"] for s in suites
        )
        kinds = {c["kind"] for c in module["coverage"] if c["required"]}
        full = full and kinds <= {s["kind"] for s in suites}
        full = full and all(r["status"] in ("passed", "failed") for r in module.get("test_requirements", []))
        modules.append({"id": module["id"], "fully_executed_here": full,
                        "suites_attempted_here": sum(s["id"] in attempted for s in suites),
                        "has_execution_evidence": any(s["executed_cases"] > 0 for s in suites)})
    inventory_confirmed = report["application"]["inventory_complete"] is True
    kinds_confirmed = all(m["coverage_basis"] == "declared_requirements" for m in report["modules"])
    requirements_confirmed = all(bool(m.get("test_requirements")) for m in report["modules"])
    all_executed = bool(modules) and inventory_confirmed and kinds_confirmed and all(m["fully_executed_here"] for m in modules)
    return {
        "mode": mode, "module_count": len(modules), "modules": modules,
        "suite_attempt_count": len(attempted), "attempted_suite_ids": attempted,
        "reused_report_count": len(reused), "reused_report_suite_ids": reused,
        "modules_with_execution_evidence": sum(m["has_execution_evidence"] for m in modules),
        "modules_fully_executed_here": sum(m["fully_executed_here"] for m in modules),
        "not_fully_executed_module_ids": [m["id"] for m in modules if not m["fully_executed_here"]],
        "all_modules_executed": all_executed,
        "test_requirement_coverage": report.get("test_coverage"),
        "inventory_confirmed": inventory_confirmed, "test_requirements_confirmed": requirements_confirmed,
        "test_kinds_confirmed": kinds_confirmed,
        "all_test_objectives_passed": bool(requirements_confirmed and all(r["status"] == "passed" for m in report["modules"] for r in m["test_requirements"])),
        "baseline_comparison_performed": report.get("comparison") is not None,
        "preflight": preflight,
        "notice": "Execution completeness covers the declared suites and cases, not every possible behavior. Executed does not mean passed; existing reports are not new runs.",
    }
