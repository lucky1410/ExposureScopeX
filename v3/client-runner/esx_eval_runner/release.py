"""Evaluate an explicit application release scope against local run evidence."""

from __future__ import annotations

from datetime import datetime, timezone
import math
import re
from typing import Any

from .metric_registry import (
    DECISION_BASELINE_DIMENSIONS,
    DECISION_SUPPORT_DIMENSIONS,
    METRIC_ORDER,
    WORKFLOW_DIMENSIONS,
    metric_title,
)
from .release_coverage import coverage_totals, evaluate_requirements, validate_requirements
from .release_observations import decision_observation, policy_disclosure
from .runner import RunnerError, sha256
from .workflow_signals import read_signal_summary, workflow_signal_advisories
from .confidence import calibration_eligible


MANIFEST_SCHEMA = "pre-d-release-manifest-1.0"
REPORT_SCHEMA = "pre-d-release-report-1.1"
VERDICTS = {
    "ship": "Ship",
    "ship_with_conditions": "Ship with conditions",
    "do_not_ship": "Do not ship",
    "insufficient_evidence": "Insufficient evidence",
}
REVIEW_STATUS_ORDER = ("evaluated", "inspected", "blocked", "untouched")
REVIEW_STATUSES = {"evaluated", "inspected", "blocked", "untouched"}
BASELINE_TIER_DIMENSIONS = frozenset(
    WORKFLOW_DIMENSIONS | DECISION_BASELINE_DIMENSIONS | DECISION_SUPPORT_DIMENSIONS
)
DECISION_RELEVANT_DIMENSIONS = tuple(
    name for name in METRIC_ORDER if name not in WORKFLOW_DIMENSIONS
)

# Explicit numeric fields prevent a typo or a boolean metadata field from
# accidentally becoming a passing release check.
GATE_FIELDS = {
    "classification": {"accuracy", "macro_precision", "macro_recall", "macro_f1", "weighted_f1"},
    "confidence": {"expected_calibration_error", "correctness_brier_score"},
    "workflow_coverage": {"workflow_execution_rate", "workflow_signal_match_rate"},
    "decision_evidence": {"evidence_reference_precision", "evidence_reference_recall", "exact_evidence_reference_rate", "correct_abstention_rate"},
    "groundedness": {"grounded_claim_rate", "contradiction_rate", "insufficient_evidence_rate"},
    "hallucination": {"hallucinated_claim_rate", "hallucination_free_response_rate", "correct_abstention_rate", "false_answer_rate"},
    "security": {"attack_outcome_accuracy", "attack_success_rate", "detection_rate", "false_detection_rate", "evidence_coverage"},
    "trajectory": {"score", "milestone_coverage", "action_efficiency"},
    "tool_use": {"selection_f1", "authorization_rate", "result_validity_rate", "exact_tool_set_rate"},
    "rag": {"context_precision", "recall_at_k", "mean_reciprocal_rank", "faithfulness", "citation_validity"},
    "robustness": {"accuracy", "consistency", "variation_coverage"},
    "judge_agreement": {"pairwise_agreement", "unanimous_case_rate"},
    "reproducibility": {"pairwise_agreement", "unanimous_case_rate"},
    "cost_efficiency": {"p95_latency_ms", "cost_per_case_usd", "timeout_rate"},
}

RECOMMENDATIONS = {
    "classification": ("decision_quality", "Review the mismatched case labels and the application decision path; correct the dataset only if its expected outcome is wrong, then rerun the same pack."),
    "confidence": ("confidence_calibration", "Review confidence generation and calibration on held-out labelled cases. Check constant confidence values and overconfident errors, then rerun the calibration pack."),
    "workflow_coverage": ("workflow", "Inspect the reported browser step, session state, and expected signal. Confirm whether the mismatch is in the app or the assertion, fix it, and rerun the workflow."),
    "decision_evidence": ("evidence_references", "Compare returned evidence IDs and abstention with the labelled case expectations. Fix evidence selection or abstention behavior and rerun; ID alignment alone does not prove claim truth."),
    "groundedness": ("grounding", "Inspect the claim verdicts and supplied source chunks. Check retrieval completeness and response generation, review disputed judge verdicts, then rerun the grounding cases."),
    "hallucination": ("hallucination", "Review unsupported or contradicted claims and required-abstention cases. Correct evidence use or abstention behavior, review disputed judge verdicts, and rerun."),
    "security": ("security_behavior", "Inspect expected and observed policy outcomes for the evaluated cases, repair the implicated authorization or policy check, and rerun both positive and negative controls."),
    "trajectory": ("agent_execution", "Inspect the observed trace for missing milestones, redundant actions, and policy violations; correct orchestration and rerun the affected paths."),
    "tool_use": ("tool_use", "Compare expected tools with observed calls and authorization outcomes; fix selection, permission checks, or result handling and rerun."),
    "rag": ("retrieval", "Review relevant-document labels, retrieved chunks, and citation results; adjust retrieval or context assembly and rerun the labelled retrieval pack."),
    "robustness": ("robustness", "Compare failing input variations with their baseline cases, correct unstable behavior, and rerun all variations."),
    "judge_agreement": ("evaluation_quality", "Review cases where independent judges disagree and clarify the rubric before relying on those judgments."),
    "reproducibility": ("repeatability", "Compare repeated runs with the same inputs and versions; investigate state, nondeterminism, and dependencies before rerunning."),
    "cost_efficiency": ("performance", "Inspect measured usage and timing for slow or expensive cases, optimize the observed bottleneck, and rerun under representative conditions."),
}


def default_gates(kind: str, dimensions: list[str] | None = None) -> list[dict[str, Any]]:
    fields = (
        [("workflow_coverage.workflow_execution_rate", "gte", 1.0),
         ("workflow_coverage.workflow_signal_match_rate", "gte", 1.0)]
        if kind == "workflow" else
        [("classification.accuracy", "gte", 0.95),
         ("classification.macro_f1", "gte", 0.9),
         ("confidence.expected_calibration_error", "lte", 0.15)]
    )
    return [{"signal": signal, "operator": op, "threshold": value, "severity": "blocker"}
            for signal, op, value in fields if dimensions is None or signal.split(".")[0] in dimensions]


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 500 or any(ord(c) < 32 for c in value):
        raise RunnerError(f"{label} must be a non-empty string of at most 500 characters without control characters")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,79}", value):
        raise RunnerError(f"{label} must be a lowercase identifier (letters, digits, hyphens, underscores)")
    return value


def _number(value: object) -> bool:
    try:
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    except OverflowError:
        return False


def _fields(value: dict, allowed: set[str], label: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise RunnerError(f"{label}: unknown fields {', '.join(sorted(unknown))}")


def _review_methods(raw: object) -> list[dict[str, str]]:
    if raw is None:
        return []
    if not isinstance(raw, list) or len(raw) > 100:
        raise RunnerError("review_methods must be a list of at most 100 entries")
    methods = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise RunnerError("Each review method must be an object")
        _fields(item, {"id", "label", "status", "summary", "evidence_pointer"}, "Review method")
        key = _identifier(item.get("id"), "review_method.id")
        if key in seen:
            raise RunnerError(f"Duplicate review method: {key}")
        seen.add(key)
        status = item.get("status")
        if status not in REVIEW_STATUSES:
            raise RunnerError("review_method.status must be evaluated, inspected, blocked, or untouched")
        method = {"id": key, "label": _text(item.get("label"), "review_method.label"),
                  "status": status, "summary": _text(item.get("summary"), "review_method.summary")}
        if "evidence_pointer" in item:
            method["evidence_pointer"] = _text(item.get("evidence_pointer"), "review_method.evidence_pointer")
        methods.append(method)
    return methods


def _population(raw: object, suite_id: str, kind: str) -> dict[str, Any] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise RunnerError(f"Suite {suite_id}: population must be an object")
    _fields(raw, {"available_case_count", "class_counts", "source", "sampling_notes"}, "population")
    available = raw.get("available_case_count")
    if type(available) is not int or not 1 <= available <= 1_000_000_000:
        raise RunnerError(f"Suite {suite_id}: population.available_case_count must be between 1 and 1000000000")
    result: dict[str, Any] = {"available_case_count": available}
    if "source" in raw:
        result["source"] = _text(raw.get("source"), "population.source")
    if "sampling_notes" in raw:
        result["sampling_notes"] = _text(raw.get("sampling_notes"), "population.sampling_notes")
    class_counts = raw.get("class_counts")
    if class_counts is not None:
        if kind != "decision":
            raise RunnerError(f"Suite {suite_id}: population.class_counts is supported only for decision suites")
        if not isinstance(class_counts, dict) or not class_counts:
            raise RunnerError(f"Suite {suite_id}: population.class_counts must be a non-empty object")
        normalized: dict[str, int] = {}
        total = 0
        for key, value in class_counts.items():
            label = _text(key, f"Suite {suite_id} population.class_counts label")
            if type(value) is not int or value < 0:
                raise RunnerError(f"Suite {suite_id}: population.class_counts values must be non-negative integers")
            if label in normalized:
                raise RunnerError(f"Suite {suite_id}: duplicate population.class_counts label {label}")
            normalized[label] = value
            total += value
        if total <= 0 or total > available:
            raise RunnerError(
                f"Suite {suite_id}: population.class_counts must total between 1 and available_case_count"
            )
        result["class_counts"] = normalized
    return result


def _derived_review_methods(
    module: dict[str, Any], suites: list[dict[str, Any]], module_findings: list[dict[str, Any]],
) -> list[dict[str, str]]:
    rows = []
    kinds = sorted(set(module.get("required_kinds", [])) | {suite["kind"] for suite in suites})
    for kind in kinds:
        suite_rows = [suite for suite in suites if suite["kind"] == kind]
        suite_ids = {suite["id"] for suite in suite_rows}
        label = "Workflow execution" if kind == "workflow" else "Decision evaluation"
        if suite_rows and all(
            suite["executed_cases"] > 0 and suite["executed_cases"] == suite["requested_cases"]
            and suite["evidence_complete"] for suite in suite_rows
        ):
            status = "evaluated"
            summary = (
                f"{len(suite_rows)} {kind} suite(s) produced "
                "usable executed evidence for this module."
            )
        elif suite_rows:
            status = "blocked"
            summary = (
                f"At least one attached {kind} suite has incomplete execution or release evidence. "
                "Inspect suite-level blockers and evidence gaps."
            )
        else:
            status = "untouched"
            summary = f"No {kind} suite is attached for this module."
        rows.append({
            "id": f"pre-d-{kind}",
            "label": label,
            "status": status,
            "summary": summary,
            "source": "pre_d_executable_evidence",
            "kind": kind,
            "suite_ids": sorted(suite_ids),
            "finding_ids": sorted(
                finding["id"] for finding in module_findings if finding.get("suite_id") in suite_ids
            ),
        })
    for item in module.get("review_methods", []):
        rows.append({**item, "source": "reviewer_declared"})
    return rows


def _module_review_status(methods: list[dict[str, Any]]) -> str:
    derived = [item for item in methods if item.get("source") == "pre_d_executable_evidence"]
    if any(item["status"] == "blocked" for item in derived):
        return "blocked"
    if any(item["status"] == "untouched" for item in derived):
        touched = any(item["status"] != "untouched" for item in methods)
        return "blocked" if touched else "untouched"
    if any(item["status"] == "evaluated" for item in derived):
        return "evaluated"
    if any(item["status"] in {"inspected", "evaluated"} for item in methods):
        return "inspected"
    if any(item["status"] == "blocked" for item in methods):
        return "blocked"
    return "untouched"


def _suite_dimensions(kind: str) -> tuple[str, ...]:
    return ("workflow_coverage",) if kind == "workflow" else DECISION_RELEVANT_DIMENSIONS


def _dimension_tier(dimension: str) -> str:
    return "baseline" if dimension in BASELINE_TIER_DIMENSIONS else "advanced"


def _suite_dimension_coverage(
    kind: str, gated: set[str], required: list[str] | None, metrics: dict[str, Any],
) -> list[dict[str, Any]]:
    required_set = {value for value in (required or []) if isinstance(value, str)}
    rows = []
    for dimension in _suite_dimensions(kind):
        metric = metrics.get(dimension)
        metric = metric if isinstance(metric, dict) else {}
        measurement_status = str(metric.get("measurement_status", "not_measured"))
        policy_status = (
            "gated" if dimension in gated else
            "required_only" if dimension in required_set else
            "measured_only" if measurement_status == "measured" else
            "request_unknown" if required is None else
            "not_requested"
        )
        entry = {
            "dimension": dimension,
            "title": metric_title(dimension),
            "tier": _dimension_tier(dimension),
            "policy_status": policy_status,
            "measurement_status": measurement_status,
            "trust_status": str(metric.get("trust_status", "missing")),
            "representativeness": metric.get("representativeness", "unknown"),
            "reason": metric.get("reason"),
        }
        if isinstance(metric.get("evidence_source"), str):
            entry["evidence_source"] = metric["evidence_source"]
        rows.append(entry)
    return rows


def _dimension_summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {
        "gated": 0,
        "required_only": 0,
        "measured_only": 0,
        "not_requested": 0,
        "request_unknown": 0,
        "baseline_unexercised": 0,
        "advanced_measured": 0,
    }
    suites = [
        suite
        for item in items
        for suite in (item.get("suites", []) if isinstance(item.get("suites"), list) else [item])
        if isinstance(suite, dict)
    ]
    for suite in suites:
        for entry in suite.get("dimension_coverage", []):
            status = entry.get("policy_status")
            if status in counts:
                counts[status] += 1
            if entry.get("tier") == "baseline" and status == "not_requested":
                counts["baseline_unexercised"] += 1
            if entry.get("tier") == "advanced" and entry.get("measurement_status") == "measured":
                counts["advanced_measured"] += 1
    counts["notice"] = (
        "Baseline-tier dimensions are the first release-ready signals for a suite kind. "
        "Unexercised means PRE-D did not include them in this suite's requested release checks."
        " Requested and gated dimensions may still be unmeasured. Request unknown means the plan or report could not establish what was requested."
    )
    return counts


def _executed_expected_label_counts(metrics: dict[str, Any]) -> dict[str, int]:
    classification = metrics.get("classification")
    if not isinstance(classification, dict):
        return {}
    rows = classification.get("case_results")
    if not isinstance(rows, list):
        return {}
    counts: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("expected_label"), str):
            continue
        counts[row["expected_label"]] = counts.get(row["expected_label"], 0) + 1
    return counts


def _population_coverage(
    suite: dict[str, Any], metrics: dict[str, Any], scored: int,
) -> dict[str, Any] | None:
    if suite["kind"] != "decision":
        return None
    declared = suite.get("population")
    executed_labels = _executed_expected_label_counts(metrics)
    if not declared:
        return {
            "status": "not_declared",
            "executed_case_count": scored,
            "executed_expected_class_counts": executed_labels,
            "notice": (
                "No available labelled population was declared. PRE-D can score the executed pack, "
                "but cannot state what share of the larger labelled population it represents."
            ),
        }
    available = declared["available_case_count"]
    class_counts = declared.get("class_counts", {})
    inconsistent = scored > available or any(executed_labels.get(label, 0) > count for label, count in class_counts.items())
    class_rows = []
    for label, count in class_counts.items():
        executed = executed_labels.get(label, 0)
        class_rows.append({
            "label": label,
            "available_case_count": count,
            "executed_case_count": executed,
            "sample_fraction": round(executed / count, 6) if count and not inconsistent else None,
        })
    return {
        "status": "inconsistent_population" if inconsistent else "declared_population",
        "available_case_count": available,
        "executed_case_count": scored,
        "sample_fraction": round(scored / available, 6) if not inconsistent else None,
        "source": declared.get("source"),
        "sampling_notes": declared.get("sampling_notes"),
        "declared_class_counts": class_counts,
        "executed_expected_class_counts": executed_labels,
        "unrepresented_labels": sorted(
            label for label, count in class_counts.items() if count > 0 and executed_labels.get(label, 0) == 0
        ),
        "undeclared_executed_labels": sorted(set(executed_labels) - set(class_counts)) if class_counts else [],
        "class_coverage": class_rows,
        "notice": (
            "Declared population counts are inconsistent with this executed pack. Correct the population or sampling scope before interpreting a coverage fraction."
            if inconsistent else
            "Population coverage describes only the declared available labelled population. "
            "It does not prove statistical representativeness or production-wide prevalence."
        ),
        **({"unclassified_case_count": available - sum(class_counts.values())} if class_counts else {}),
    }


def _population_summary(modules: list[dict[str, Any]]) -> dict[str, Any]:
    suites = [
        suite for module in modules for suite in module["suites"]
        if suite["kind"] == "decision"
    ]
    declared = [suite["population_coverage"] for suite in suites if suite.get("population_coverage", {}).get("status") in {"declared_population", "inconsistent_population"}]
    inconsistent_count = sum(item["status"] == "inconsistent_population" for item in declared)
    total_available = sum(item["available_case_count"] for item in declared)
    total_executed = sum(item["executed_case_count"] for item in declared)
    return {
        "decision_suite_count": len(suites),
        "declared_population_suite_count": len(declared),
        "inconsistent_population_suite_count": inconsistent_count,
        "missing_population_suite_count": sum(
            suite.get("population_coverage", {}).get("status") == "not_declared" for suite in suites
        ),
        "declared_available_case_count": total_available,
        "executed_case_count_against_declared_populations": total_executed,
        "sample_fraction": round(total_executed / total_available, 6) if total_available and not inconsistent_count else None,
        "notice": (
            "Population coverage is optional descriptive context for decision suites. "
            "Totals sum the declared suite populations, which may overlap; they do not count unique application records. "
            "Without population context, PRE-D reports only the executed pack."
        ),
    }


def validate_manifest(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize policy before any evaluation plan can execute."""
    if raw.get("schema_version") != MANIFEST_SCHEMA:
        raise RunnerError(f"Release manifest schema_version must be {MANIFEST_SCHEMA}")
    _fields(raw, {"schema_version", "application", "policy", "modules"}, "Release manifest")
    app = raw.get("application")
    if not isinstance(app, dict):
        raise RunnerError("Release manifest requires an application object")
    _fields(app, {"id", "version", "inventory_complete"}, "application")
    app_id = _identifier(app.get("id"), "application.id")
    version = _text(app.get("version"), "application.version")
    complete = app.get("inventory_complete", False)
    if not isinstance(complete, bool):
        raise RunnerError("application.inventory_complete must be boolean")
    policy = raw.get("policy", {})
    if not isinstance(policy, dict) or set(policy) - {"max_report_age_hours", "regression_severity", "regression_tolerance"}:
        raise RunnerError("policy supports max_report_age_hours, regression_severity, and regression_tolerance")
    age = policy.get("max_report_age_hours", 24)
    if not _number(age) or not 0 < age <= 8760:
        raise RunnerError("policy.max_report_age_hours must be greater than zero and at most 8760")
    regression_severity = policy.get("regression_severity", "warning")
    tolerance = policy.get("regression_tolerance", 0.0)
    if regression_severity not in {"warning", "blocker"} or not _number(tolerance) or not 0 <= tolerance <= 1:
        raise RunnerError("Regression policy requires warning/blocker severity and a tolerance from 0 to 1")
    modules = raw.get("modules")
    if not isinstance(modules, list) or not 1 <= len(modules) <= 1000:
        raise RunnerError("Release manifest requires between 1 and 1000 modules")
    module_ids: set[str] = set()
    suite_ids: set[str] = set()
    normalized = []
    for module in modules:
        if not isinstance(module, dict):
            raise RunnerError("Each release module must be an object")
        _fields(module, {"id", "name", "owner", "required", "exclusion_reason", "suites", "required_kinds", "depends_on", "test_requirements", "review_methods"}, "Module")
        module_id = _identifier(module.get("id"), "module.id")
        if module_id in module_ids:
            raise RunnerError(f"Duplicate release module: {module_id}")
        module_ids.add(module_id)
        required = module.get("required", True)
        if not isinstance(required, bool):
            raise RunnerError(f"Module {module_id}: required must be boolean")
        reason = module.get("exclusion_reason")
        if not required:
            reason = _text(reason, f"Module {module_id} exclusion_reason")
        elif reason is not None:
            raise RunnerError(f"Module {module_id}: a required module cannot have an exclusion_reason")
        suites = module.get("suites", [])
        if not isinstance(suites, list) or len(suites) > 100:
            raise RunnerError(f"Module {module_id}: suites must be an array of at most 100 plans")
        if not required and suites:
            raise RunnerError(f"Module {module_id}: excluded modules cannot contain executable suites")
        entries = []
        for suite in suites:
            if not isinstance(suite, dict):
                raise RunnerError("Each release suite must be an object")
            _fields(suite, {"id", "kind", "config", "report", "subject_id", "minimum_cases", "gates", "execution_policy", "population"}, "Suite")
            suite_id = _identifier(suite.get("id"), "suite.id")
            if suite_id in suite_ids:
                raise RunnerError(f"Duplicate release suite: {suite_id}")
            suite_ids.add(suite_id)
            kind = suite.get("kind")
            if kind not in {"decision", "workflow"}:
                raise RunnerError(f"Suite {suite_id}: kind must be decision or workflow")
            sources = [key for key in ("config", "report") if key in suite]
            if len(sources) != 1:
                raise RunnerError(f"Suite {suite_id}: specify exactly one config or report path")
            source = sources[0]
            source_path = _text(suite[source], f"Suite {suite_id} {source}")
            subject = _text(suite.get("subject_id"), f"Suite {suite_id} subject_id")
            min_cases = suite.get("minimum_cases", 20 if kind == "decision" else 1)
            if type(min_cases) is not int or not 1 <= min_cases <= 10000:
                raise RunnerError(f"Suite {suite_id}: minimum_cases must be between 1 and 10000")
            gates = suite.get("gates", default_gates(kind))
            if not isinstance(gates, list) or not 1 <= len(gates) <= 100:
                raise RunnerError(f"Suite {suite_id}: gates must contain 1 to 100 checks")
            checked = []
            seen: set[str] = set()
            for gate in gates:
                if not isinstance(gate, dict) or set(gate) - {"signal", "operator", "threshold", "severity"}:
                    raise RunnerError(f"Suite {suite_id}: invalid gate fields")
                signal = gate.get("signal", "")
                if not isinstance(signal, str) or signal.count(".") != 1:
                    raise RunnerError(f"Suite {suite_id}: gate signal must be metric.field")
                metric, field = signal.split(".")
                if field not in GATE_FIELDS.get(metric, set()) or signal in seen:
                    raise RunnerError(f"Suite {suite_id}: unknown or duplicate gate signal {signal}")
                seen.add(signal)
                op, threshold = gate.get("operator"), gate.get("threshold")
                severity = gate.get("severity", "blocker")
                if op not in {"gte", "lte"} or severity not in {"blocker", "warning"}:
                    raise RunnerError(f"Suite {suite_id}: gates require gte/lte and blocker/warning")
                unbounded = metric == "cost_efficiency" and field != "timeout_rate"
                if not _number(threshold) or threshold < 0 or (not unbounded and threshold > 1):
                    raise RunnerError(f"Suite {suite_id}: gate threshold must be a finite {'non-negative value' if unbounded else 'value from 0 to 1'}")
                checked.append({"signal": signal, "operator": op, "threshold": threshold, "severity": severity})
            baseline = set() if kind == "decision" else {"workflow_coverage"}
            if not baseline <= {gate["signal"].split(".")[0] for gate in checked}:
                raise RunnerError(f"Suite {suite_id}: gates must cover {', '.join(sorted(baseline))}")
            if kind == "decision" and any(gate["signal"].startswith("workflow_coverage.") for gate in checked):
                raise RunnerError(f"Suite {suite_id}: decision gates cannot substitute workflow coverage for decision evidence")
            if kind == "workflow" and not {"workflow_coverage.workflow_execution_rate", "workflow_coverage.workflow_signal_match_rate"} <= seen:
                raise RunnerError(f"Suite {suite_id}: workflow gates must check both execution and signal matching")
            execution_policy = suite.get("execution_policy")
            if execution_policy is not None:
                if not isinstance(execution_policy, dict):
                    raise RunnerError(f"Suite {suite_id}: execution_policy must be an object")
                _fields(execution_policy, {"mode", "config_sha256", "isolation_note"}, "execution_policy")
                if (execution_policy.get("mode") not in ("read_only", "isolated_write")
                        or not isinstance(execution_policy.get("config_sha256"), str)
                        or not re.fullmatch(r"[0-9a-f]{64}", execution_policy["config_sha256"])):
                    raise RunnerError(f"Suite {suite_id}: execution approval requires a mode and config_sha256")
                if execution_policy["mode"] == "isolated_write" or "isolation_note" in execution_policy:
                    _text(execution_policy.get("isolation_note"), "execution_policy.isolation_note")
            population = _population(suite.get("population"), suite_id, kind)
            entries.append({"id": suite_id, "kind": kind, source: source_path, "subject_id": subject,
                            "minimum_cases": min_cases, "gates": checked,
                            **({"population": population} if population is not None else {}),
                            **({"execution_policy": dict(execution_policy)} if execution_policy is not None else {})})
        kinds = module.get("required_kinds")
        if kinds is not None and (not isinstance(kinds, list) or not kinds or any(k not in ("decision", "workflow") for k in kinds)
                                  or len(set(kinds)) != len(kinds) or not required):
            raise RunnerError(f"Module {module_id}: required_kinds must contain distinct decision/workflow kinds on a required module")
        dependencies = module.get("depends_on", [])
        if not isinstance(dependencies, list) or any(not isinstance(d, str) for d in dependencies) or len(set(dependencies)) != len(dependencies):
            raise RunnerError(f"Module {module_id}: depends_on must be a list of distinct module IDs")
        requirements = None
        if "test_requirements" in module:
            if not required:
                raise RunnerError("Excluded modules cannot declare executable test requirements")
            requirements = validate_requirements(module["test_requirements"], entries, dependencies)
            if not set(r["kind"] for r in requirements) <= set(kinds or []):
                raise RunnerError("Every requirement kind must be listed in module.required_kinds")
        review_methods = _review_methods(module.get("review_methods"))
        normalized.append({"id": module_id, "name": _text(module.get("name", module_id), "module.name"),
                           "owner": _text(module.get("owner", "Unassigned"), "module.owner"),
                           "required": required, "exclusion_reason": reason, "suites": entries,
                           **({"required_kinds": sorted(kinds)} if kinds is not None else {}),
                           **({"test_requirements": requirements} if requirements is not None else {}),
                           **({"review_methods": review_methods} if review_methods else {}),
                           "depends_on": dependencies})
    if not any(module["required"] for module in normalized):
        raise RunnerError("A release manifest must include at least one required module")
    remaining = {m["id"]: set(m["depends_on"]) for m in normalized}
    if any(not refs <= module_ids or key in refs for key, refs in remaining.items()):
        raise RunnerError("Module dependencies must reference other modules in this inventory")
    resolved: set[str] = set()
    while remaining:
        ready = {key for key, refs in remaining.items() if refs <= resolved}
        if not ready:
            raise RunnerError("Module dependencies contain a cycle")
        resolved.update(ready)
        remaining = {key: refs for key, refs in remaining.items() if key not in ready}
    return {"schema_version": MANIFEST_SCHEMA,
            "application": {"id": app_id, "version": version, "inventory_complete": complete},
            "policy": {"max_report_age_hours": age, "regression_severity": regression_severity,
                       "regression_tolerance": tolerance}, "modules": normalized}


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.astimezone(timezone.utc) if result.tzinfo is not None else None
    except ValueError:
        return None


def _verdict(findings: list[dict[str, Any]]) -> str:
    levels = {item["severity"] for item in findings}
    if "blocker" in levels:
        return "do_not_ship"
    if "gap" in levels:
        return "insufficient_evidence"
    return "ship_with_conditions" if "warning" in levels else "ship"


def build_release_report(
    manifest: dict[str, Any], evidence: dict[str, dict[str, Any]], *, now: datetime | None = None,
    baseline: dict[str, Any] | None = None, history: list[dict[str, Any]] | None = None,
    plan_metadata: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Produce a bounded recommendation without changing the underlying metrics."""
    manifest = validate_manifest(manifest)
    now = now or datetime.now(timezone.utc)
    if baseline is not None:
        from .release_comparison import validate_baseline
        validate_baseline(baseline, manifest["application"]["id"], now)
    if history is not None:
        from .release_comparison import validate_baseline

        if not isinstance(history, list) or any(not isinstance(item, dict) for item in history):
            raise RunnerError("History must be a list of PRE-D release-review JSON reports")
        for item in history:
            validate_baseline(item, manifest["application"]["id"], now)
    findings: list[dict[str, Any]] = []
    advisories: list[dict[str, Any]] = []
    modules: list[dict[str, Any]] = []
    packages: dict[str, str] = {}
    plan_metadata = plan_metadata or {}

    def add(code: str, why: str, action: str, *, module: dict | None = None,
            suite: dict | None = None, severity: str = "gap", category: str = "coverage",
            pointer: str | None = None, cases: list[str] | None = None) -> None:
        if module and not module["required"]:
            severity = "warning"
        findings.append({"id": f"release-{len(findings) + 1:04d}", "code": code,
                         "severity": severity, "category": category,
                         "module_id": module["id"] if module else None,
                         "suite_id": suite["id"] if suite else None,
                         "owner": module["owner"] if module else "Release owner",
                         "why": why, "recommendation": action, "evidence_pointer": pointer,
                         "case_ids": cases or [], "root_cause_status": "not_established"})

    def advise(code: str, why: str, action: str, *, module: dict | None = None,
               suite: dict | None = None, category: str = "coverage_detail",
               pointer: str | None = None, cases: list[str] | None = None) -> None:
        advisories.append({
            "id": f"release-advisory-{len(advisories) + 1:04d}",
            "code": code,
            "category": category,
            "module_id": module["id"] if module else None,
            "suite_id": suite["id"] if suite else None,
            "owner": module["owner"] if module else "Release owner",
            "why": why,
            "recommendation": action,
            "evidence_pointer": pointer,
            "case_ids": cases or [],
        })

    if not manifest["application"]["inventory_complete"]:
        add("inventory_unconfirmed", "The application module inventory has not been confirmed complete.",
            "List all release-relevant modules and exclusions, then set application.inventory_complete to true after review.")
    for module in manifest["modules"]:
        module_start = len(findings)
        if not module["required"]:
            add("module_excluded", module["exclusion_reason"], "Record who accepts this exclusion for the proposed release.",
                module=module, severity="warning")
        if module["required"] and not module["suites"]:
            add("module_untested", "This required module has no evaluation plans.",
                "Add workflow and decision plans appropriate to this module, including role and integration paths where relevant.", module=module)
        for kind in sorted(set(module.get("required_kinds", [])) - {s["kind"] for s in module["suites"]}):
            add("required_kind_missing", f"This module requires {kind} testing but has no {kind} suite.",
                f"Attach an approved {kind} evaluation plan; another test kind cannot establish this coverage.", module=module)
        suite_results = []
        for suite in module["suites"]:
            start = len(findings)
            item = evidence.get(suite["id"], {})
            metadata = plan_metadata.get(suite["id"], {})
            report = item.get("report")
            gates = []
            gated = {gate["signal"].split(".")[0] for gate in suite["gates"]}
            planned_dimensions = metadata.get("required_dimensions")
            if not isinstance(planned_dimensions, list):
                planned_dimensions = None
            result = {"id": suite["id"], "kind": suite["kind"], "gates": gates,
                      "policy_disclosure": policy_disclosure(suite["kind"], suite["gates"]),
                      "subject_id": suite["subject_id"], "minimum_cases": suite["minimum_cases"],
                      "comparison_basis": {}, "case_outcomes": [], "evidence_complete": False,
                      "artifact": item.get("artifact"), "report_sha256": item.get("report_sha256"),
                      "html_artifact": item.get("html_artifact"),
                      "dimension_coverage": _suite_dimension_coverage(suite["kind"], gated, planned_dimensions, {}),
                      "population_coverage": _population_coverage(suite, {}, 0),
                      "requested_cases": 0, "executed_cases": 0}
            strength = read_signal_summary(metadata.get("workflow_signal_strength"))
            if strength is not None:
                result["workflow_signal_strength"] = strength
            suite_results.append(result)
            if not isinstance(report, dict):
                add(item.get("error_code", "run_missing"), item.get("error", "No completed report is available for this plan."),
                    "Resolve the plan or execution problem and run this suite again.", module=module, suite=suite)
                result["verdict"] = _verdict(findings[start:])
                continue
            subject = report.get("subject", {})
            binding = report.get("run_provenance", {})
            execution = report.get("execution", {})
            evaluation = report.get("evaluation", {})
            metrics = report.get("metrics", {})
            valid = all(isinstance(v, dict) for v in (subject, binding, execution, evaluation, metrics))
            if not valid:
                add("invalid_report", "The report has malformed evidence sections.", "Regenerate the local report from the original evaluation configuration.", module=module, suite=suite)
                result["verdict"] = _verdict(findings[start:])
                continue
            expected_browser = suite["kind"] == "workflow"
            identity_ok = (
                report.get("schema_version") in {"esx-local-evaluation-report-1.2", "esx-local-assurance-report-1.2"}
                and report.get("status") == "completed_locally"
                and subject.get("agent_id") == suite["subject_id"]
                and subject.get("subject_version") == manifest["application"]["version"]
                and binding.get("project_key") == manifest["application"]["id"]
                and execution.get("adapter_type") in {"command_json_v1", "command_json_v2", "http_json_target", "browser_journey"}
                and (execution.get("adapter_type") == "browser_journey") == expected_browser
            )
            if not identity_ok:
                add("report_identity_mismatch", "The report does not match this application, subject, version, or evaluation type, or lacks run provenance.",
                    "Regenerate this suite with the current application project_key, subject_id, and subject_version.", module=module, suite=suite, pointer="subject / run_provenance")
            issued = _timestamp(binding.get("issued_at"))
            age = (now - issued).total_seconds() if issued else None
            fresh = age is not None and -300 <= age <= manifest["policy"]["max_report_age_hours"] * 3600
            if not fresh:
                add("report_stale", "This report is too old, has a future timestamp, or lacks a timezone-aware run timestamp.",
                    "Rerun the suite for the release being assessed.", module=module, suite=suite, pointer="run_provenance.issued_at")
            package_id = report.get("package_id")
            unique = isinstance(package_id, str) and bool(package_id) and package_id not in packages
            if not unique:
                add("duplicate_or_missing_run", "The report has no run ID or reuses a run already assigned to another suite.",
                    "Use a distinct evaluation run for each suite; repeated evidence cannot establish additional module coverage.", module=module, suite=suite)
            else:
                packages[package_id] = suite["id"]
            if not (identity_ok and fresh and unique):
                result["verdict"] = _verdict(findings[start:])
                continue
            requested = execution.get("case_count")
            scored = execution.get("scored_case_count")
            blocked = execution.get("blocked_case_count")
            counts_ok = all(type(v) is int and v >= 0 for v in (requested, scored, blocked)) and requested > 0 and scored + blocked == requested
            if not counts_ok:
                add("invalid_execution_counts", "Execution counts are missing or inconsistent.", "Regenerate the report from a complete local run.", module=module, suite=suite)
                result["verdict"] = _verdict(findings[start:])
                continue
            result.update(requested_cases=requested, executed_cases=scored)
            result["run_id"] = package_id
            if not expected_browser:
                observation = decision_observation(report, scored)
                result["decision_observation"] = observation
                if observation and metrics.get("classification", {}).get("measurement_status") != "measured" and observation["incorrect_cases"]:
                    add("observed_decision_errors", f"{observation['incorrect_cases']} of {scored} executed decisions did not match their expected labels. Aggregate classification is unavailable, but these observed errors remain real on this pack.",
                        "Inspect the listed cases and expected outcomes. Fix the decision path or a demonstrably wrong label, then rerun. Add representative classes for broader classification estimates.",
                        module=module, suite=suite, severity="blocker", category="decision_quality",
                        pointer="metrics.classification.case_results", cases=observation["case_ids"])
            result["comparison_basis"] = evaluation.get("comparison_basis", {})
            # Only content-free identifiers/outcomes enter the release snapshot.
            rows = metrics.get("classification", {}).get("case_results", []) if isinstance(metrics.get("classification"), dict) else []
            if suite["kind"] == "workflow":
                rows = execution.get("browser_case_diagnostics", [])
            if isinstance(rows, list):
                result["case_outcomes"] = [
                    {"case_id": r["case_id"], "outcome": r.get("outcome") if expected_browser else ("passed" if r.get("correct") is True else "failed"),
                     **({"persona": r.get("persona")} if expected_browser else {})}
                    for r in rows if isinstance(r, dict) and isinstance(r.get("case_id"), str)
                    and (r.get("outcome") in {"passed", "failed", "blocked"} if expected_browser else type(r.get("correct")) is bool)
                ]
            if expected_browser:
                strength = read_signal_summary(execution.get("workflow_signal_strength"))
                if (strength is not None and strength["case_count"] == requested
                        and {row["case_id"] for row in strength["cases"]}
                        == {row["case_id"] for row in result["case_outcomes"]}):
                    result["workflow_signal_strength"] = strength
            if blocked:
                add("execution_blocked", f"{blocked} of {requested} cases could not execute.",
                    "Review session/setup diagnostics, refresh the approved session or adapter, and rerun blocked cases.",
                    module=module, suite=suite, pointer="execution", category="execution_setup")
            if scored < suite["minimum_cases"]:
                add("too_few_cases", f"{scored} cases executed; this suite requires at least {suite['minimum_cases']}.",
                    "Expand the labelled or workflow pack to the agreed sample size and rerun.", module=module, suite=suite)
            if suite["kind"] == "decision":
                health = evaluation.get("dataset_health", {})
                if (not isinstance(health, dict) or health.get("sample_size") != scored
                        or health.get("unique_case_id_count") != scored):
                    add("dataset_health_missing", "Dataset health is absent or inconsistent with the executed decisions.",
                        "Regenerate the report with the original pack so sample size and distinct case IDs can be checked, including tasks without classification labels.",
                        module=module, suite=suite, pointer="evaluation.dataset_health", category="evaluation_quality")
                else:
                    duplicates = health.get("duplicate_input_count")
                    majority = health.get("majority_class_rate")
                    if (_number(duplicates) and duplicates > 0) or (_number(majority) and majority > 0.8):
                        add("dataset_quality_review", "The dataset contains repeated inputs or a class representing more than 80% of the cases.",
                            "Review duplicate inputs, class balance, and per-class errors. Use representative independent cases before accepting the release estimate.",
                            module=module, suite=suite, severity="warning", category="evaluation_quality", pointer="evaluation.dataset_health")
            required = evaluation.get("required_dimensions")
            if not isinstance(required, list) or not required or not all(isinstance(v, str) for v in required):
                add("required_dimensions_missing", "The run does not list its required metric dimensions.", "Regenerate the report with its evaluation requirements.", module=module, suite=suite)
                required = []
            result["dimension_coverage"] = _suite_dimension_coverage(suite["kind"], gated, required, metrics)
            result["population_coverage"] = _population_coverage(suite, metrics, scored)
            for dimension in sorted(set(required) - gated):
                add("metric_policy_missing", f"{metric_title(dimension)} is required by this run but has no release threshold.",
                    "Add an explicit metric gate for this required dimension before making a release recommendation.", module=module, suite=suite, pointer=f"metrics.{dimension}")
            for dimension in sorted(gated & {"groundedness", "hallucination"}):
                metric = metrics.get(dimension, {})
                if not isinstance(metric, dict) or metric.get("measurement_status") != "measured":
                    continue
                total_key, complete_key = (("requested_case_count", "completed_case_count") if dimension == "groundedness" else ("response_count", "assessed_response_count"))
                if metric.get(total_key) != scored or metric.get(complete_key) != scored:
                    add("semantic_coverage_gap", f"{metric_title(dimension)} does not cover every executed response.",
                        "Collect response text and grounding material for every case and resolve incomplete extraction or judgment before rerunning.",
                        module=module, suite=suite, pointer=f"metrics.{dimension}", category="evaluation_quality")
            for gate in suite["gates"]:
                dimension, field = gate["signal"].split(".")
                metric = metrics.get(dimension, {})
                metric = metric if isinstance(metric, dict) else {}
                observed = metric.get(field)
                trust = metric.get("trust_status", "missing")
                meaningful = _number(observed) and observed >= 0 and (dimension == "cost_efficiency" and field != "timeout_rate" or observed <= 1)
                usable = metric.get("measurement_status") == "measured" and trust == "verified" and metric.get("representativeness") != "non_representative" and meaningful
                if dimension == "confidence" and not calibration_eligible(metric):
                    usable = False
                entry = {**gate, "observed": observed if meaningful else None, "trust": trust, "status": "missing"}
                gates.append(entry)
                category, action = RECOMMENDATIONS[dimension]
                if not usable:
                    why = ("Native probability semantics are not established; mapped or unspecified confidence cannot satisfy a calibration gate." if dimension == "confidence" and not calibration_eligible(metric) else
                           "Target-declared evidence cannot satisfy this release check." if trust == "declared" else
                           "This release check has no complete, representative, locally verified numeric evidence.")
                    add("metric_evidence_gap", f"{gate['signal']}: {why}",
                        "Inspect this metric's evidence requirements in the individual report and collect the missing independent observations.",
                        module=module, suite=suite, pointer=f"metrics.{dimension}", category=category)
                    continue
                if dimension in {"classification", "confidence"} and metric.get("sample_size") != scored:
                    add("metric_sample_mismatch", f"{dimension} sample size does not match the executed cases.",
                        "Regenerate the metric report from this suite's complete results.", module=module, suite=suite, pointer=f"metrics.{dimension}.sample_size")
                    continue
                passed = observed >= gate["threshold"] if gate["operator"] == "gte" else observed <= gate["threshold"]
                if not passed and gate["signal"] == "workflow_coverage.workflow_execution_rate" and blocked:
                    entry["status"] = "incomplete"
                    continue
                entry["status"] = "passed" if passed else "failed"
                if not passed:
                    case_rows = metric.get("case_results", [])
                    case_rows = case_rows if isinstance(case_rows, list) else []
                    cases = [str(row["case_id"]) for row in case_rows
                             if isinstance(row, dict) and "case_id" in row and (
                                 row.get("correct") is False or row.get("overconfident_failure") is True
                                 or row.get("verdict") in ("contradicted", "insufficient")
                                 or (_number(row.get("unsupported_claim_count")) and row["unsupported_claim_count"] > 0)
                                 or row.get("abstention_result") == "failed_required_abstention")]
                    if dimension == "workflow_coverage":
                        diagnostics = execution.get("browser_case_diagnostics", [])
                        if isinstance(diagnostics, list):
                            cases = [str(row["case_id"]) for row in diagnostics if isinstance(row, dict) and row.get("outcome") == "failed" and "case_id" in row]
                    add("threshold_failed", f"{gate['signal']} was {observed:g}; policy requires {gate['operator']} {gate['threshold']:g}.",
                        action, module=module, suite=suite, severity=gate["severity"], category=category,
                        pointer=f"metrics.{dimension}.{field}", cases=list(dict.fromkeys(cases)))
            conf = metrics.get("confidence", {})
            if suite["kind"] == "decision" and 0 < scored < 20:
                add("small_decision_pack", "Fewer than 20 cases were evaluated; this is a small local pack even though the configured minimum may be met.",
                    "Use a larger representative held-out pack before generalizing the recommendation.", module=module, suite=suite, severity="warning", category="evaluation_quality")
            if isinstance(conf, dict) and conf.get("measurement_status") == "measured" and calibration_eligible(conf):
                if conf.get("confidence_diversity_warning") is True:
                    add("confidence_diversity", f"Only {conf.get('unique_confidence_count', 'few')} distinct confidence values were observed.",
                        RECOMMENDATIONS["confidence"][1], module=module, suite=suite, severity="warning", category="confidence_calibration", pointer="metrics.confidence")
                if conf.get("calibration_warning") is True and not any(f["suite_id"] == suite["id"] and f["code"] == "threshold_failed" and f["category"] == "confidence_calibration" for f in findings[start:]):
                    add("calibration_warning", "The run flagged weak confidence calibration.", RECOMMENDATIONS["confidence"][1], module=module, suite=suite, severity="warning", category="confidence_calibration", pointer="metrics.confidence")
            for dimension in sorted(gated & {"groundedness", "hallucination"}):
                metric = metrics.get(dimension, {})
                if isinstance(metric, dict) and metric.get("verification_basis") == "independent_local_semantic_judge":
                    add("semantic_judge_review", f"{metric_title(dimension)} uses an independent local model judge whose claim extraction and verdicts can be wrong.",
                        "Review disputed claims and validate the judge against human-labelled cases before accepting the semantic result for release.",
                        module=module, suite=suite, severity="warning", category="evaluation_quality", pointer=f"metrics.{dimension}")
            result["verdict"] = _verdict(findings[start:])
            result["evidence_complete"] = not any(f["severity"] == "gap" for f in findings[start:])
        # Include scope cautions even when a suite could not produce a report.
        for suite in suite_results:
            if suite["kind"] == "decision":
                unexercised = [row["title"] for row in suite["dimension_coverage"]
                               if row["tier"] == "baseline" and row["policy_status"] == "not_requested"]
                if unexercised:
                    advise("baseline_dimension_unexercised",
                           "Baseline-tier decision dimensions were left unexercised: " + ", ".join(unexercised) + ".",
                           "Add these dimensions to evaluation.required_dimensions and add at least one explicit release gate to exercise the baseline decision evidence.",
                           module=module, suite=suite, category="decision_quality", pointer="evaluation.required_dimensions")
                population = suite["population_coverage"]
                if population["status"] == "not_declared":
                    advise("population_context_missing",
                           "This decision suite has no declared labelled population context. Its execution counts describe only the supplied pack.",
                           "Declare suite.population.available_case_count and optional class_counts to compare this pack with the available labelled population.",
                           module=module, suite=suite, category="evaluation_quality", pointer="suite.population")
                elif population["status"] == "inconsistent_population":
                    advise("population_context_inconsistent", population["notice"],
                           "Check the total and per-class population counts, repeated cases, and sampling scope. Coverage fractions are withheld until the counts agree.",
                           module=module, suite=suite, category="evaluation_quality", pointer="suite.population")
            else:
                strength = suite.get("workflow_signal_strength")
                if strength is None:
                    advise("workflow_signal_unknown", "The available evidence does not record the workflow assertion strength.",
                           "Rerun the workflow plan with this runner to include a content-free assertion summary. Review the source plan before interpreting PASS as rendered-content coverage.",
                           module=module, suite=suite, category="workflow", pointer="execution.workflow_signal_strength")
                else:
                    for caution in workflow_signal_advisories(strength):
                        advise(caution["code"], caution["summary"], caution["action"], module=module, suite=suite,
                               category="workflow", pointer="workflow_signal_strength", cases=caution["case_ids"])
        requirements = evaluate_requirements(module, suite_results)
        for requirement in requirements:
            if requirement["status"] != "passed":
                failed = requirement["status"] == "failed"
                add("requirement_failed" if failed else "requirement_coverage_gap",
                    f"{requirement['id']}: mapped test outcomes are {requirement['status']}. {requirement['description']}",
                    ("Inspect the mapped case and its expected result. A browser mismatch requires assertion review, not an assumed product defect. Fix the observed problem and rerun."
                     if failed else "Bind and execute every required case with the correct persona. Resolve missing or blocked outcomes; an attached suite alone does not satisfy this objective."),
                    module=module, severity="blocker" if failed else "gap", category="test_objectives",
                    pointer=f"modules.{module['id']}.test_requirements.{requirement['id']}",
                    cases=[c["case_id"] for c in requirement["cases"] if c["status"] != "passed"])
        dependency_coverage = []
        for dependency in module["depends_on"]:
            checks = [r for r in requirements if r.get("dependency") == dependency]
            status = ("declared_only" if not checks else "mapped_cases_passed" if all(r["status"] == "passed" for r in checks)
                      else "mapped_cases_failed" if any(r["status"] == "failed" for r in checks) else "incomplete")
            dependency_coverage.append({"module_id": dependency, "status": status,
                                        "requirement_ids": [r["id"] for r in checks]})
            if not checks:
                add("dependency_path_untested", f"Dependency {dependency} is declared, but no integration objective is mapped to executed cases.",
                    "Add an integration requirement with an observable cross-module assertion. Passing each module separately does not establish their integration.",
                    module=module, category="dependency_coverage")
        module_findings = findings[module_start:]
        review_methods = _derived_review_methods(module, suite_results, module_findings)
        modules.append({"id": module["id"], "name": module["name"], "owner": module["owner"],
                        "required": module["required"], "exclusion_reason": module["exclusion_reason"],
                        "verdict": _verdict(module_findings), "suites": suite_results,
                        "depends_on": module["depends_on"],
                        "dependency_coverage": dependency_coverage,
                        "test_requirements": requirements,
                        "test_requirements_sha256": sha256(module.get("test_requirements", [])),
                        "review_methods": review_methods,
                        "review_status": _module_review_status(review_methods),
                        "dimension_summary": _dimension_summary(suite_results),
                        "advisory_ids": [a["id"] for a in advisories if a["module_id"] == module["id"]],
                        "coverage_basis": "declared_requirements" if "required_kinds" in module else "attached_plans_only",
                        "coverage": [{
                            "kind": kind,
                            "required": kind in module.get("required_kinds", {s["kind"] for s in suite_results}),
                            "planned_suites": sum(s["kind"] == kind for s in suite_results),
                            "executed_suites": sum(s["kind"] == kind and s["executed_cases"] > 0 for s in suite_results),
                            "status": ("missing" if not any(s["kind"] == kind for s in suite_results) else
                                       "incomplete" if any(f["severity"] == "gap" and f["suite_id"] in {s["id"] for s in suite_results if s["kind"] == kind} for f in module_findings) else "complete"),
                        } for kind in sorted(set(module.get("required_kinds", [])) | {s["kind"] for s in suite_results})],
                        "finding_ids": [f["id"] for f in module_findings]})
    by_id = {m["id"]: m for m in modules}
    comparison = None
    history_summary = None
    if baseline is not None:
        from .release_comparison import compare_releases
        comparison, changes = compare_releases(manifest, modules, baseline)
        for change in changes:
            module = by_id.get(change.pop("module_id", None))
            suite_id = change.pop("suite_id", None)
            add(module=module, suite={"id": suite_id} if suite_id else None, **change)
    if history:
        from .release_comparison import summarize_history

        history_summary = summarize_history(manifest, modules, history)
    unavailable = {m["id"] for m in modules if not m["required"] or _verdict([f for f in findings if f["module_id"] == m["id"]]) in {"do_not_ship", "insufficient_evidence"}}
    while True:
        expanded = unavailable | {m["id"] for m in modules if set(m["depends_on"]) & unavailable}
        if expanded == unavailable:
            break
        unavailable = expanded
    for module in modules:
        if module["required"]:
            for dependency in sorted(set(module["depends_on"]) & unavailable):
                add("dependency_not_ready", f"Required dependency {dependency} is excluded, incomplete, or has a blocking result.",
                    "Resolve the dependency findings and rerun affected integration paths; a standalone passing suite does not prove the dependency works.",
                    module=module, category="dependency_coverage", pointer=f"modules.{dependency}")
    for module in modules:
        module_findings = [f for f in findings if f["module_id"] == module["id"]]
        module["verdict"] = _verdict(module_findings)
        module["finding_ids"] = [f["id"] for f in module_findings]
    review_scope = {
        **{status: sum(module["review_status"] == status for module in modules) for status in REVIEW_STATUS_ORDER},
        "method_count": sum(len(module.get("review_methods", [])) for module in modules),
        "notice": (
            "Evaluated means all attached executable suites completed with usable evidence for the declared test kinds; their checks may still fail. "
            "Inspected means only reviewer-declared activity is recorded, including external evaluations. "
            "Blocked means planned executable review did not complete cleanly or a required executable method remains untouched. "
            "Untouched means no executable evidence or review method is recorded."
        ),
    }
    verdict = _verdict(findings)
    return {"schema_version": REPORT_SCHEMA, "generated_at": now.isoformat(),
            "application": manifest["application"], "manifest_sha256": sha256(manifest),
            "policy": manifest["policy"], "verdict": verdict, "verdict_label": VERDICTS[verdict],
            "scope_statement": "Release recommendation for the declared modules, tested version, executed cases, and explicit thresholds. Inventory completeness is supplied by the release owner.",
            "summary": {"module_count": len(modules), "required_module_count": sum(m["required"] for m in modules),
                        "suite_count": sum(len(m["suites"]) for m in modules),
                        "blockers": sum(f["severity"] == "blocker" for f in findings),
                        "evidence_gaps": sum(f["severity"] == "gap" for f in findings),
                        "conditions": sum(f["severity"] == "warning" for f in findings),
                        "advisories": len(advisories)},
            "modules": modules, "findings": sorted(findings, key=lambda f: {"blocker": 0, "gap": 1, "warning": 2}[f["severity"]]),
            "advisories": advisories,
            "review_scope": review_scope,
            "dimension_coverage": _dimension_summary(modules),
            "population_coverage": _population_summary(modules),
            "test_coverage": coverage_totals(modules),
            "comparison": comparison,
            "history": history_summary,
            "limitations": ["A passing pack establishes results on its cases; it does not establish correctness for every production input.",
                            "Recommendations identify areas to investigate. Exact code-level root causes require additional evidence.",
                            "Report hashes identify local artifacts; they do not certify the target's implementation or dataset independence."],
            "uploaded": False}
