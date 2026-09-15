"""Deterministic assessment benchmark scoring against versioned ground truth."""

from __future__ import annotations

from collections import Counter
from typing import Any


SUCCESSFUL_STAGE_STATUSES = {"completed"}
REPORTED_STAGE_STATUSES = SUCCESSFUL_STAGE_STATUSES | {"skipped", "warning", "failed", "cancelled", "timed_out", "not_run"}


def _ratio(numerator: int, denominator: int, *, empty: float = 0.0) -> float:
    return round(numerator / denominator, 4) if denominator else empty


def _case_metrics(cases: list[dict[str, Any]], observed_ids: set[str]) -> dict[str, Any]:
    truth = {str(case["id"]): bool(case.get("vulnerable")) for case in cases}
    tp = sum(1 for case_id, vulnerable in truth.items() if vulnerable and case_id in observed_ids)
    fn = sum(1 for case_id, vulnerable in truth.items() if vulnerable and case_id not in observed_ids)
    fp = sum(1 for case_id, vulnerable in truth.items() if not vulnerable and case_id in observed_ids)
    tn = sum(1 for case_id, vulnerable in truth.items() if not vulnerable and case_id not in observed_ids)
    precision = _ratio(tp, tp + fp, empty=1.0)
    recall = _ratio(tp, tp + fn, empty=1.0)
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": _ratio(fp, fp + tn),
    }


def score_assessment_benchmark(
    *,
    cases: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    execution_manifest: list[dict[str, Any]],
    quality_gates: dict[str, float | int],
    scope_violations: int = 0,
) -> dict[str, Any]:
    """Score findings, evidence, scope containment, and execution-accounting quality."""
    case_ids = {str(case["id"]) for case in cases}
    observed_ids = {
        str(item["benchmark_case_id"])
        for item in observations
        if item.get("benchmark_case_id") is not None
    }
    unknown_observations = sorted(observed_ids - case_ids)
    mapped_observed_ids = observed_ids & case_ids
    overall = _case_metrics(cases, mapped_observed_ids)

    categories: dict[str, dict[str, Any]] = {}
    for category in sorted({str(case.get("category") or "uncategorized") for case in cases}):
        category_cases = [case for case in cases if str(case.get("category") or "uncategorized") == category]
        categories[category] = _case_metrics(category_cases, mapped_observed_ids)

    positive_observations = [
        item for item in observations
        if str(item.get("benchmark_case_id")) in case_ids
        and next(case for case in cases if str(case["id"]) == str(item.get("benchmark_case_id"))).get("vulnerable")
    ]
    evidenced = sum(
        1 for item in positive_observations
        if item.get("evidence_sha256") and item.get("source_artifact_sha256") and item.get("screenshot_sha256")
    )
    evidence_completeness = _ratio(evidenced, len(positive_observations), empty=1.0)

    planned_stages = [item for item in execution_manifest if item.get("planned")]
    status_counts = Counter(str(item.get("status") or "missing") for item in planned_stages)
    unreported = sum(1 for item in planned_stages if str(item.get("status") or "missing") not in REPORTED_STAGE_STATUSES)
    successful = sum(1 for item in planned_stages if item.get("status") in SUCCESSFUL_STAGE_STATUSES)
    execution_coverage = _ratio(successful, len(planned_stages), empty=1.0)

    gate_values = {
        "precision_min": overall["precision"],
        "recall_min": overall["recall"],
        "f1_min": overall["f1"],
        "evidence_completeness_min": evidence_completeness,
        "scope_violations_max": scope_violations,
        "unreported_stage_outcomes_max": unreported,
    }
    failures: list[dict[str, Any]] = []
    for gate, actual in gate_values.items():
        if gate not in quality_gates:
            continue
        expected = quality_gates[gate]
        passed = actual <= expected if gate.endswith("_max") else actual >= expected
        if not passed:
            failures.append({"gate": gate, "expected": expected, "actual": actual})

    return {
        "schema_version": "1.0.0",
        "case_count": len(cases),
        "observation_count": len(observations),
        "overall": overall,
        "categories": categories,
        "unknown_observations": unknown_observations,
        "evidence": {
            "required": len(positive_observations),
            "complete": evidenced,
            "completeness": evidence_completeness,
        },
        "execution": {
            "planned": len(planned_stages),
            "successful": successful,
            "coverage": execution_coverage,
            "unreported": unreported,
            "status_counts": dict(status_counts),
        },
        "scope_violations": scope_violations,
        "release_gate": {"passed": not failures, "failures": failures, "gates": quality_gates},
    }


def score_repeatability(scorecards: list[dict[str, Any]], maximum_variance: float) -> dict[str, Any]:
    """Measure metric drift across repeated runs of the same immutable fixture."""
    variances = {}
    for metric in ("precision", "recall", "f1"):
        values = [float(card["overall"][metric]) for card in scorecards]
        variances[metric] = round(max(values) - min(values), 4) if values else 0.0
    observed_max = max(variances.values(), default=0.0)
    return {
        "runs": len(scorecards),
        "metric_variance": variances,
        "maximum_variance": observed_max,
        "threshold": maximum_variance,
        "passed": len(scorecards) >= 2 and observed_max <= maximum_variance,
    }
