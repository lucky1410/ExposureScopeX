"""Reviewed test objectives tied to explicit cases, not inferred product coverage."""

from __future__ import annotations

from typing import Any

from .runner import RunnerError, sha256


CATEGORIES = {"happy_path", "negative_path", "boundary", "authorization", "recovery", "integration"}


def validate_requirements(raw: object, suites: list[dict], dependencies: list[str]) -> list[dict]:
    from .release import _fields, _identifier, _text

    if not isinstance(raw, list) or not 1 <= len(raw) <= 500:
        raise RunnerError("test_requirements must contain 1 to 500 explicit objectives")
    ids = set()
    by_suite = {s["id"]: s for s in suites}
    result = []
    for item in raw:
        if not isinstance(item, dict):
            raise RunnerError("Each test requirement must be an object")
        _fields(item, {"id", "description", "kind", "category", "persona", "dependency", "bindings"}, "Test requirement")
        key = _identifier(item.get("id"), "requirement.id")
        if key in ids:
            raise RunnerError(f"Duplicate test requirement: {key}")
        ids.add(key)
        kind, category = item.get("kind"), item.get("category")
        if kind not in ("workflow", "decision") or not isinstance(category, str) or category not in CATEGORIES:
            raise RunnerError("Test requirements need a workflow/decision kind and a supported category")
        entry = {"id": key, "description": _text(item.get("description"), "requirement.description"),
                 "kind": kind, "category": category, "bindings": []}
        if "persona" in item:
            if kind != "workflow":
                raise RunnerError("Persona evidence is currently supported for workflow requirements only")
            entry["persona"] = _identifier(item["persona"], "requirement.persona")
        if category == "integration":
            if item.get("dependency") not in dependencies:
                raise RunnerError("Integration requirements must name a declared module dependency")
            entry["dependency"] = item["dependency"]
        elif "dependency" in item:
            raise RunnerError("Only integration requirements may declare a dependency")
        bindings = item.get("bindings", [])
        if not isinstance(bindings, list) or len(bindings) > 100:
            raise RunnerError("requirement.bindings must be an array of at most 100 suite bindings")
        bound_suites = set()
        for binding in bindings:
            if not isinstance(binding, dict):
                raise RunnerError("A requirement binding must be an object")
            _fields(binding, {"suite_id", "case_ids", "assertion"}, "Requirement binding")
            suite_id = _identifier(binding.get("suite_id"), "binding.suite_id")
            if suite_id in bound_suites or suite_id not in by_suite or by_suite[suite_id]["kind"] != kind:
                raise RunnerError("Bindings require distinct suites of the same kind in the same module")
            bound_suites.add(suite_id)
            cases = binding.get("case_ids")
            if not isinstance(cases, list) or not 1 <= len(cases) <= 10000:
                raise RunnerError("A requirement binding needs 1 to 10000 explicit case IDs")
            cases = [_text(c, "binding.case_id") for c in cases]
            if len(set(cases)) != len(cases):
                raise RunnerError("Requirement case IDs must be unique within a suite binding")
            entry["bindings"].append({"suite_id": suite_id, "case_ids": cases,
                                      "assertion": _text(binding.get("assertion"), "binding.assertion")})
        result.append(entry)
    return result


def draft_requirements(kinds: list[str], personas: list[str], dependencies: list[str]) -> list[dict]:
    """Create reviewable objectives, never made-up executable tests or outcomes."""
    from .release import _identifier

    for persona in personas:
        _identifier(persona, "persona")
    if personas and "workflow" not in kinds:
        raise RunnerError("Persona objectives require workflow testing")
    result = []

    def add(key: str, description: str, kind: str, category: str, **extra: str) -> None:
        # Bounded IDs also work with long customer-defined persona/module names.
        key = key if len(key) <= 80 else key[:65] + "-" + sha256(key)[:14]
        result.append({"id": key, "description": description, "kind": kind,
                       "category": category, "bindings": [], **extra})

    if "workflow" in kinds:
        for persona in personas or ["default"]:
            for category, description in (
                ("happy_path", "Complete the module's primary user journey and verify its final visible outcome."),
                ("negative_path", "Verify a rejected or invalid operation has the expected safe, visible outcome."),
                ("recovery", "Verify recovery from an approved simulated empty, unavailable, or interrupted state."),
            ):
                add(f"workflow-{persona}-{category.replace('_', '-')}", description, "workflow", category, persona=persona)
            if personas:
                add(f"workflow-{persona}-authorization", "Verify the reviewed role boundary, including an expected denial without a real production write.",
                    "workflow", "authorization", persona=persona)
    if "decision" in kinds:
        for category, description in (
            ("happy_path", "Compare representative positive decisions against reviewed expected labels."),
            ("negative_path", "Compare representative negative decisions against reviewed expected labels."),
            ("boundary", "Verify ambiguous, insufficient-evidence, and boundary inputs against reviewed expectations."),
        ):
            add("decision-" + category.replace("_", "-"), description, "decision", category)
    for dependency in dependencies:
        add("integration-" + dependency, "Exercise the declared dependency and assert an observable cross-module result in an approved test environment.",
            "workflow" if "workflow" in kinds else "decision", "integration", dependency=dependency)
    return result


def plan_requirement_issues(module: dict, plans: dict[str, list[dict]]) -> list[dict]:
    """Validate case and persona bindings using already-validated local plans."""
    issues = []
    for requirement in module.get("test_requirements", []):
        if not requirement["bindings"]:
            issues.append({"code": "requirement_unbound", "module_id": module["id"], "suite_id": None,
                           "requirement_id": requirement["id"], "action": "Review this objective and use release bind to connect the actual cases and assertion. A generated objective is not a test."})
        for binding in requirement["bindings"]:
            suite_id = binding["suite_id"]
            if suite_id not in plans:
                continue  # The suite-level preflight already explains the invalid/missing plan.
            cases = {case["case_id"]: case for case in plans[suite_id]}
            for case_id in binding["case_ids"]:
                case = cases.get(case_id)
                code = "requirement_case_missing" if case is None else (
                    "requirement_persona_mismatch" if "persona" in requirement and case.get("persona", "default") != requirement["persona"] else None)
                if case and not code and requirement["kind"] == "workflow":
                    assertions = {"expect_text", "expect_visible", "assert_path", "assert_title"}
                    if not any(step.get("type") in assertions for step in case["input"]["journey"]):
                        code = "requirement_assertion_missing"
                if code:
                    issues.append({"code": code, "module_id": module["id"], "suite_id": suite_id,
                                   "requirement_id": requirement["id"], "action": f"Review case {case_id}: it must exist, use the required persona, and include an explicit browser assertion for a workflow objective. Rebind the objective or correct and reapprove the plan."})
    return issues


def evaluate_requirements(module: dict, suites: list[dict]) -> list[dict]:
    by_suite = {s["id"]: s for s in suites}
    results = []
    for requirement in module.get("test_requirements", []):
        cases = []
        for binding in requirement["bindings"]:
            suite = by_suite[binding["suite_id"]]
            rows = suite["case_outcomes"]
            ids = [r["case_id"] for r in rows]
            # Do not certify selected rows from a partial or duplicated outcome ledger.
            complete = (len(ids) == suite["requested_cases"] and len(ids) == len(set(ids))
                        and sum(r["outcome"] in ("passed", "failed") for r in rows) == suite["executed_cases"])
            outcomes = {r["case_id"]: r for r in rows} if complete else {}
            for case_id in binding["case_ids"]:
                row = outcomes.get(case_id, {})
                status = row.get("outcome", "missing")
                if "persona" in requirement and row.get("persona") != requirement["persona"]:
                    status = "missing"
                cases.append({"suite_id": binding["suite_id"], "case_id": case_id, "status": status})
        counts = {status: sum(c["status"] == status for c in cases) for status in ("passed", "failed", "blocked", "missing")}
        status = ("failed" if counts["failed"] else "missing" if not cases or counts["missing"] else
                  "incomplete" if counts["blocked"] else "passed")
        results.append({**requirement, "status": status, "case_count": len(cases), "counts": counts, "cases": cases,
                        "basis": "reviewer_mapped_case_outcomes",
                        "notice": "PRE-D checks the mapped case outcomes and recorded persona, not whether the reviewer chose a sufficient business assertion."})
    return results


def coverage_totals(modules: list[dict]) -> dict[str, Any]:
    requirements = [r for m in modules for r in m.get("test_requirements", [])]
    return {"requirement_count": len(requirements),
            "modules_with_requirements": sum(bool(m.get("test_requirements")) for m in modules),
            **{status: sum(r["status"] == status for r in requirements) for status in ("passed", "failed", "missing", "incomplete")},
            "notice": "Requirement coverage is separate from suite execution and aggregate AI scores. Unlisted behaviors remain outside the evaluated scope."}
