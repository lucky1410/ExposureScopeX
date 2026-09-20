"""Explicit behavior coverage, separate from attached checks and passing scores."""

from collections import Counter
from pathlib import Path

from .runner import RunnerError
from .system_inventory import LAYERS, document
from .workflow_signals import workflow_signal_strength


def draft_scope(plan: dict) -> dict:
    """Draft obligations without approving policy or claiming inventory completeness."""
    return {
        "mode": "whole_system", "policy_reviewed": False,
        "inventory_totals_reviewed": False,
        "inventory_totals": dict(Counter(c["kind"] for c in plan["components"])),
        "build": {},
        "objectives": [
            {"id": f"objective-{index}-{layer}-{role or 'all'}", "component_id": c["id"],
             "title": f"Review {c['name']}: {layer}" + (f" / {role}" if role else ""),
             "layer": layer, "role": role, "reviewed": False, "check_id": "",
             "case_ids": [], "assertion_paths": []}
            for index, c in enumerate(plan["components"])
            for layer in c["required_layers"]
            for role in (plan["roles"] if layer == "authorization" else [None])
        ],
    }


def validate_scope(plan: dict) -> None:
    scope = plan.get("scope_contract")
    if scope is None:
        return
    if not isinstance(scope, dict) or scope.get("mode") != "whole_system":
        raise RunnerError("scope_contract must declare mode whole_system")
    for key in ("policy_reviewed", "inventory_totals_reviewed"):
        if type(scope.get(key)) is not bool:
            raise RunnerError(f"scope_contract.{key} must be boolean")
    totals = scope.get("inventory_totals")
    if not isinstance(totals, dict) or len(totals) > 100 or any(
        not isinstance(k, str) or not k.strip() or type(v) is not int or not 0 <= v <= 10000
        for k, v in totals.items()
    ):
        raise RunnerError("inventory_totals must contain bounded counts by component kind")
    components = {c["id"]: c for c in plan["components"]}
    checks = {c["id"]: c for c in plan["checks"]}
    objectives = scope.get("objectives")
    if not isinstance(objectives, list) or len(objectives) > 10000:
        raise RunnerError("Scope objectives must be a list of at most 10000 entries")
    seen = set()
    for objective in objectives:
        if not isinstance(objective, dict):
            raise RunnerError("Every scope objective must be an object")
        key = objective.get("id")
        if not isinstance(key, str) or not key or len(key) > 200 or key in seen:
            raise RunnerError("Scope objectives require distinct bounded IDs")
        seen.add(key)
        if not isinstance(objective.get("component_id"), str) or objective["component_id"] not in components or objective.get("layer") not in LAYERS:
            raise RunnerError("Objectives must reference a declared component and layer")
        if not isinstance(objective.get("title"), str) or not objective["title"].strip():
            raise RunnerError("Objectives need an independently reviewed behavior description")
        if type(objective.get("reviewed")) is not bool:
            raise RunnerError("Objective reviewed must be boolean")
        role = objective.get("role")
        if role is not None and (not isinstance(role, str) or role not in plan["roles"]):
            raise RunnerError("Objective role must be declared")
        if objective["layer"] == "authorization" and role is None:
            raise RunnerError("Authorization objectives need an explicit role")
        check_id = objective.get("check_id", "")
        if not isinstance(check_id, str) or (check_id and check_id not in checks):
            raise RunnerError("Objective check_id must reference a check or be empty while drafting")
        if check_id:
            check = checks[check_id]
            if objective["component_id"] not in check["component_ids"] or objective["layer"] != check["layer"]:
                raise RunnerError(
                    "Objective binding mismatch for "
                    + objective["id"]
                    + " -> "
                    + check_id
                    + ": expected component "
                    + objective["component_id"]
                    + " within "
                    + ", ".join(check["component_ids"])
                    + " and layer "
                    + objective["layer"]
                    + " == "
                    + check["layer"]
                )
            if role is not None and check.get("role") != role:
                raise RunnerError(
                    "Objective role mismatch for "
                    + objective["id"]
                    + " -> "
                    + check_id
                    + ": expected "
                    + role
                    + ", check role is "
                    + str(check.get("role"))
                )
        for field in ("case_ids", "assertion_paths"):
            values = objective.get(field, [])
            if not isinstance(values, list) or len(values) > 1000 or any(
                not isinstance(v, str) or not v or len(v) > 1000 for v in values
            ) or len(values) != len(set(values)):
                raise RunnerError(f"Objective {field} must contain distinct bounded strings")
        for field in ("business_rule_id", "expected_business_behavior", "business_evidence_needed"):
            value = objective.get(field, "")
            if value != "" and (not isinstance(value, str) or len(value) > 1000 or any(ord(ch) < 32 for ch in value)):
                raise RunnerError(f"Objective {field} must be bounded text")
        if not isinstance(objective.get("exclude_reason", ""), str):
            raise RunnerError("Objective exclude_reason must be text")
    build = scope.get("build", {})
    if not isinstance(build, dict):
        raise RunnerError("Scope build must be an object")
    if build:
        if set(build) != {"check_id", "assertion_path", "expected_value"} or not all(
            isinstance(build.get(k), str) and build[k].strip() for k in build
        ):
            raise RunnerError("Build binding requires check_id, assertion_path and expected_value strings")
        check = checks.get(build["check_id"], {})
        if check.get("type") != "http" or check.get("method", "GET") != "GET":
            raise RunnerError("Build identity requires a read-only native HTTP GET check")
        if not any(a == {"path": build["assertion_path"], "equals": build["expected_value"]}
                   for a in check.get("json_assertions", [])):
            raise RunnerError("Build identity must bind the exact reviewed candidate assertion")


def _binding_gaps(objective: dict, check: dict, root: Path | None) -> list[str]:
    gaps = []
    if not check or not check.get("enabled"):
        return ["Bind and enable an executable check for this behavior."]
    if check["type"] in {"evaluation", "command"}:
        if not objective.get("case_ids"):
            gaps.append("Bind explicit executed case IDs; an aggregate suite is not behavior coverage.")
        if check["type"] == "evaluation" and root is not None:
            config = document((root / check["config"]).resolve())
            cases = config["dataset"]["cases"]
            missing = set(objective.get("case_ids", [])) - {c["case_id"] for c in cases}
            if missing:
                gaps.append("Bound case IDs are absent from the evaluation plan: " + ", ".join(sorted(missing)))
            if config["adapter"]["type"] == "browser_journey":
                weak = [r["case_id"] for r in workflow_signal_strength(cases)["cases"]
                        if r["case_id"] in objective.get("case_ids", []) and r["signal_strength"] != "content_signal"]
                if weak:
                    gaps.append("Visible outcome assertions are missing in workflow cases: " + ", ".join(weak))
    else:
        paths = objective.get("assertion_paths", [])
        if not paths or not set(paths) <= {a["path"] for a in check.get("json_assertions", [])}:
            gaps.append("Bind explicit JSON content/budget assertions; status alone is not behavior coverage.")
    return gaps


def assess_scope(plan: dict, results: list[dict] | None = None, *, root: Path | None = None,
                 build_status: str = "not_observed") -> dict:
    scope = plan.get("scope_contract")
    if scope is None:
        return {"mode": "selected_checks", "complete": False, "objectives": [], "modules": [],
                "gaps": ["No whole-system contract supplied. Results cover attached checks only."],
                "notice": "Selected-check success must not be described as whole-system coverage."}
    planned = results is None
    by_id = {r["id"]: r for r in results or []}
    checks = {c["id"]: c for c in plan["checks"]}
    gaps = []
    if not scope["policy_reviewed"]:
        gaps.append("The owner has not confirmed behavior expectations and release thresholds.")
    if not scope["inventory_totals_reviewed"]:
        gaps.append("Inventory totals are draft counts, not owner-confirmed application scope.")
    actual = Counter(c["kind"] for c in plan["components"])
    totals = [{"kind": kind, "declared": scope["inventory_totals"].get(kind), "mapped": actual[kind]}
              for kind in sorted(set(actual) | set(scope["inventory_totals"]))]
    for row in totals:
        if row["declared"] != row["mapped"]:
            gaps.append(f"Inventory mismatch for {row['kind']}: {row['mapped']} mapped, {row['declared']} declared.")
    if not plan["inventory_confirmed"] or plan.get("discovery", {}).get("truncated"):
        gaps.append("Confirm a complete reviewed inventory; discovery is incomplete or unconfirmed.")
    build = scope.get("build", {})
    if not build or not checks.get(build.get("check_id"), {}).get("enabled"):
        gaps.append("Bind and enable a running-build identity assertion.")
    elif not planned and build_status != "matched_before_and_after":
        gaps.append("Running candidate identity was not matched before and after this run.")
    rows = []
    for objective in scope["objectives"]:
        issues = []
        status = "planned" if planned else "unconfigured"
        if not objective["reviewed"]:
            issues.append("Review the expected behavior independently before claiming coverage.")
        if objective.get("exclude_reason"):
            issues.append("Excluded: " + objective["exclude_reason"] + ". Exclusions remain whole-system gaps.")
            status = "excluded"
        check = checks.get(objective.get("check_id"), {})
        issues.extend(_binding_gaps(objective, check, root))
        result = by_id.get(objective.get("check_id"))
        if not planned and not issues:
            if result is None:
                status = "unexecuted"
                issues.append("The bound check did not execute.")
            elif result["status"] not in {"passed", "failed"}:
                status = "blocked"
                issues.append("Execution was blocked: " + result.get("reason", "missing evidence"))
            elif check["type"] in {"evaluation", "command"}:
                observed = {c["id"]: c for c in result.get("case_results", [])}
                missing = [key for key in objective["case_ids"]
                           if observed.get(key, {}).get("status") not in {"passed", "failed", "executed"}]
                weak = [key for key in objective["case_ids"] if observed.get(key, {}).get("signal_strength")
                        not in (None, "content_signal")]
                if missing or weak:
                    issues.append("Missing, skipped, blocked or weak case evidence: " + ", ".join(sorted(set(missing + weak))))
                    status = "blocked"
                else:
                    status = "failed" if (check["type"] == "evaluation" and result["status"] == "failed") or any(
                        observed[key]["status"] == "failed" for key in objective["case_ids"]
                    ) else "passed"
            else:
                if check["type"] == "http":
                    samples = [result]
                elif check["type"] == "load":
                    samples = result.get("observations", [])
                else:
                    samples = [result.get("restoration_evidence", {})]
                asserted = set.intersection(*[{a["path"] for a in sample.get("assertions", [])}
                                             for sample in samples]) if samples else set()
                if not set(objective["assertion_paths"]) <= asserted:
                    status = "blocked"
                    issues.append("The selected assertions have no recorded execution evidence.")
                else:
                    status = result["status"]
        complete = not issues and (planned or status in {"passed", "failed"})
        rows.append({**objective, "status": status, "complete": complete, "gaps": issues,
                     "action": issues[0] if issues else "Inspect the failed bound assertion or gate." if status == "failed"
                     else "Retain this test and rerun it on the next candidate."})
    modules = []
    for component in plan["components"]:
        obligations = [r for r in rows if r["component_id"] == component["id"]]
        component_gaps = []
        if component.get("enabled") is not True:
            component_gaps.append("Capability state is disabled or unknown; do not claim runtime coverage.")
        for layer in component["required_layers"]:
            for role in (plan["roles"] if layer == "authorization" else [None]):
                if not any(r["layer"] == layer and (role is None or r.get("role") == role) for r in obligations):
                    reason = f"No behavior objective for {layer}" + (f" / {role}" if role else "")
                    component_gaps.append(reason)
                    missing = {"id": f"missing-objective-{len(rows)}", "component_id": component["id"],
                               "title": component["name"] + ": " + reason, "layer": layer, "role": role,
                               "reviewed": False, "check_id": "", "case_ids": [], "assertion_paths": [],
                               "status": "unconfigured", "complete": False, "gaps": [reason],
                               "action": "Define and bind an independent behavior test for this required layer/role."}
                    rows.append(missing)
                    obligations.append(missing)
        modules.append({"component_id": component["id"], "module": component["module"],
                        "complete": not component_gaps and bool(obligations) and all(r["complete"] for r in obligations),
                        "gaps": component_gaps})
    complete = not gaps and bool(rows) and all(r["complete"] for r in rows) and all(m["complete"] for m in modules)
    return {"mode": "whole_system", "phase": "planned" if planned else "executed", "complete": complete,
            "gaps": gaps, "inventory_totals": totals, "objectives": rows, "modules": modules,
            "summary": {"total": len(rows), "complete": sum(r["complete"] for r in rows),
                        "passed": sum(r["status"] == "passed" for r in rows),
                        "failed": sum(r["status"] == "failed" for r in rows)},
            "notice": "Coverage refers to owner-reviewed behaviors and supplied inventory, not every possible behavior. Failed tests count as executed coverage, never as release success. Build identity is observed from the target, not independent source/image attestation."}
