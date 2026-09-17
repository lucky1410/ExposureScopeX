"""Deterministic, offline metric calculations for the ESX client runner.

The customer adapter produces redacted local observations and this module scores
them on the same machine. It has no network or model dependency.
"""

from __future__ import annotations

from collections import defaultdict
from itertools import combinations
import math
from typing import Any


METRIC_CALCULATION_VERSION = "pred-local-metrics-1.0"


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _rounded(value: float) -> float:
    return round(value, 6)


def _unavailable(reason: str, **partial: Any) -> dict[str, Any]:
    return {"measurement_status": "not_measurable", "reason": reason, **partial}


def _not_applicable(reason: str) -> dict[str, Any]:
    """Keep a metric out of a scorecard when its evidence type is incompatible."""
    return {"measurement_status": "not_applicable", "reason": reason}


def claims_metrics(claims: list[dict[str, Any]] | None) -> dict[str, Any]:
    if not claims:
        return _unavailable("No claims with evidence references were supplied; groundedness cannot be inferred.")
    unsupported = [
        claim["claim_id"]
        for claim in claims
        if not claim["evidence_ids"]
        or not claim["citations_valid"]
        or claim["evidence_integrity_valid"] is not True
        or claim["entailment_score"] < 0.8
    ]
    return {
        "measurement_status": "measured",
        "claim_count": len(claims),
        "supported_claim_rate": _rounded(1 - _ratio(len(unsupported), len(claims))),
        "unsupported_claim_rate": _rounded(_ratio(len(unsupported), len(claims))),
        "citation_validity_rate": _rounded(_ratio(sum(bool(c["evidence_ids"]) and c["citations_valid"] for c in claims), len(claims))),
        "evidence_integrity_rate": _rounded(_ratio(sum(c["evidence_integrity_valid"] is True for c in claims), len(claims))),
        "unsupported_claim_ids": unsupported,
        "definition": "Evidence-grounded proxy based on cited, integrity-verified artifacts.",
    }


def _validate_decision_inputs(
    expected: list[str], predicted: list[str],
    confidences: list[float] | None = None, case_ids: list[str] | None = None,
) -> None:
    if not isinstance(expected, list) or not isinstance(predicted, list):
        raise ValueError("expected and predicted labels must be lists")
    if len(expected) != len(predicted):
        raise ValueError("expected and predicted labels must have equal lengths")
    if any(not isinstance(label, str) or not label for label in [*expected, *predicted]):
        raise ValueError("expected and predicted labels must be non-empty strings")
    if confidences is not None:
        if not isinstance(confidences, list) or len(confidences) != len(expected):
            raise ValueError("confidence values must cover every labelled case")
        if any(
            not isinstance(value, (int, float)) or isinstance(value, bool)
            or not math.isfinite(float(value)) or value < 0 or value > 1
            for value in confidences
        ):
            raise ValueError("confidence values must be finite numbers between 0 and 1")
    if case_ids is not None:
        if (
            not isinstance(case_ids, list) or len(case_ids) != len(expected)
            or any(not isinstance(item, str) or not item for item in case_ids)
            or len(set(case_ids)) != len(case_ids)
        ):
            raise ValueError("case IDs must be unique non-empty strings covering every labelled case")


def _case_references(expected: list[str], case_ids: list[str] | None) -> list[str]:
    if case_ids is not None:
        return case_ids
    return [f"position-{index:04d}" for index in range(1, len(expected) + 1)]


def classification_metrics(
    expected: list[str], predicted: list[str], case_ids: list[str] | None = None,
) -> dict[str, Any]:
    _validate_decision_inputs(expected, predicted, case_ids=case_ids)
    if not expected:
        return _unavailable(
            "No cases reached an application workflow; classification quality is unavailable.",
            labels=[], ground_truth_class_count=0, confusion_matrix={}, sample_size=0,
        )
    labels = sorted(set(expected) | set(predicted))
    matrix = {actual: {guess: 0 for guess in labels} for actual in labels}
    for actual, guess in zip(expected, predicted, strict=True):
        matrix[actual][guess] += 1
    total = len(expected)
    per_class: dict[str, dict[str, Any]] = {}
    raw_per_class: dict[str, dict[str, float]] = {}
    for label in labels:
        tp = matrix[label][label]
        fp = sum(matrix[actual][label] for actual in labels if actual != label)
        fn = sum(matrix[label][guess] for guess in labels if guess != label)
        tn = total - tp - fp - fn
        support = sum(matrix[label].values())
        precision = _ratio(tp, tp + fp)
        recall = _ratio(tp, tp + fn)
        f1 = _ratio(2 * precision * recall, precision + recall)
        false_positive_rate = _ratio(fp, fp + tn)
        false_negative_rate = _ratio(fn, fn + tp)
        raw_per_class[label] = {
            "precision": precision, "recall": recall, "f1": f1,
            "false_positive_rate": false_positive_rate,
            "false_negative_rate": false_negative_rate,
        }
        per_class[label] = {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn, "support": support,
            "precision": _rounded(precision), "recall": _rounded(recall),
            "f1": _rounded(f1),
            "false_positive_rate": _rounded(false_positive_rate),
            "false_negative_rate": _rounded(false_negative_rate),
        }

    def macro(metric: str) -> float:
        return _ratio(sum(item[metric] for item in raw_per_class.values()), len(labels))

    def weighted(metric: str) -> float:
        return _ratio(sum(raw_per_class[label][metric] * per_class[label]["support"] for label in labels), total)

    result = {
        "labels": labels,
        "ground_truth_class_count": len(set(expected)),
        "confusion_matrix": matrix,
        "accuracy": _rounded(_ratio(sum(matrix[label][label] for label in labels), total)),
        "macro_precision": _rounded(macro("precision")),
        "macro_recall": _rounded(macro("recall")),
        "macro_f1": _rounded(macro("f1")),
        "macro_false_positive_rate": _rounded(macro("false_positive_rate")),
        "macro_false_negative_rate": _rounded(macro("false_negative_rate")),
        "weighted_f1": _rounded(weighted("f1")),
        "per_class": per_class,
        "sample_size": total,
        "calculation_version": METRIC_CALCULATION_VERSION,
        "case_results": [
            {
                "case_id": case_id, "expected_label": actual,
                "predicted_label": guess, "correct": actual == guess,
            }
            for case_id, actual, guess in zip(
                _case_references(expected, case_ids), expected, predicted, strict=True,
            )
        ],
    }
    if len(set(expected)) < 2:
        return _unavailable("At least two ground-truth classes are required for classification quality metrics.", **result)
    return {"measurement_status": "measured", **result}


def confidence_metrics(
    expected: list[str], predicted: list[str], confidences: list[float],
    case_ids: list[str] | None = None,
) -> dict[str, Any]:
    _validate_decision_inputs(expected, predicted, confidences, case_ids)
    if not expected:
        return _unavailable(
            "No cases reached an application workflow; confidence calibration is unavailable.",
            sample_size=0, bins=[],
        )
    if len(set(expected)) < 2:
        return _unavailable(
            "At least two ground-truth classes are required for a decision-grade confidence scorecard; a one-class workflow plan cannot validate confidence behavior.",
            sample_size=len(expected), ground_truth_class_count=len(set(expected)), bins=[],
        )
    correctness = [float(actual == guess) for actual, guess in zip(expected, predicted, strict=True)]
    brier = _ratio(sum((confidence - correct) ** 2 for confidence, correct in zip(confidences, correctness, strict=True)), len(correctness))
    ece = 0.0
    bins = []
    for index in range(10):
        lower, upper = index / 10, (index + 1) / 10
        members = [position for position, confidence in enumerate(confidences) if lower <= confidence <= upper and (index == 9 or confidence < upper)]
        if not members:
            continue
        accuracy = _ratio(sum(correctness[position] for position in members), len(members))
        average = _ratio(sum(confidences[position] for position in members), len(members))
        ece += _ratio(len(members), len(confidences)) * abs(accuracy - average)
        bins.append({"lower": lower, "upper": upper, "count": len(members), "accuracy": _rounded(accuracy), "average_confidence": _rounded(average)})
    unique_confidence_count = len(set(confidences))
    rounded_ece = _rounded(ece)
    calibration_warning = rounded_ece > 0.15
    confidence_diversity_warning = unique_confidence_count < 5
    return {
        "measurement_status": "measured",
        "sample_size": len(expected),
        "ground_truth_class_count": len(set(expected)),
        "unique_confidence_count": unique_confidence_count,
        "correct_outcome_count": int(sum(correctness)),
        "incorrect_outcome_count": len(correctness) - int(sum(correctness)),
        "correctness_brier_score": _rounded(brier),
        "expected_calibration_error": rounded_ece,
        "bins": bins,
        "calibration_warning": calibration_warning,
        "confidence_diversity_warning": confidence_diversity_warning,
        "case_results": [
            {
                "case_id": case_id, "expected_label": actual,
                "predicted_label": guess, "confidence": confidence,
                "correct": actual == guess,
                "overconfident_failure": actual != guess and confidence >= 0.8,
            }
            for case_id, actual, guess, confidence in zip(
                _case_references(expected, case_ids), expected, predicted, confidences, strict=True,
            )
        ],
        "limitations": [
            *(
                ["Fewer than 20 labelled cases: the formula is exact for this set, but not a stable release-quality estimate."]
                if len(expected) < 20 else []
            ),
            *(
                [f"Only {unique_confidence_count} unique confidence value(s) were observed; at least 5 are needed to assess confidence behavior across useful levels."]
                if confidence_diversity_warning else []
            ),
        ],
        "definition": "Calibration of observed model confidence against labelled prediction correctness.",
        "calculation_version": METRIC_CALCULATION_VERSION,
    }


def decision_evidence_metrics(observations: object) -> dict[str, Any]:
    """Measure explicit evidence-reference and abstention behavior locally.

    Identifier overlap is intentionally reported as evidence-reference
    alignment, not groundedness. Groundedness also needs per-claim support and
    citation-integrity observations from a local adapter or telemetry source.
    """
    if not isinstance(observations, list) or not observations:
        return _not_applicable("This run did not request decision evidence or abstention observations.")
    records = [item for item in observations if isinstance(item, dict)]
    evidence_cases = [item for item in records if "expected_evidence_ids" in item]
    abstention_cases = [item for item in records if "must_abstain" in item]
    if not evidence_cases and not abstention_cases:
        return _not_applicable("This run did not include decision evidence or abstention expectations.")
    missing_evidence = [item.get("case_id", "unknown") for item in evidence_cases if "observed_evidence_ids" not in item]
    missing_abstention = [item.get("case_id", "unknown") for item in abstention_cases if "abstained" not in item]
    result: dict[str, Any] = {
        "decision_case_count": len(records),
        "evidence_reference_case_count": len(evidence_cases),
        "abstention_case_count": len(abstention_cases),
        "definition": "Evidence-reference alignment and abstention behavior from explicit local decision metadata; this is not a groundedness or hallucination score.",
    }
    if missing_evidence or missing_abstention:
        gaps = []
        if missing_evidence:
            gaps.append("evidence IDs for " + ", ".join(str(item) for item in missing_evidence[:5]))
        if missing_abstention:
            gaps.append("abstained flag for " + ", ".join(str(item) for item in missing_abstention[:5]))
        return _unavailable("The decision endpoint did not return " + " and ".join(gaps) + ".", **result)
    if evidence_cases:
        expected_ids = [
            evidence_id for item in evidence_cases
            for evidence_id in item.get("expected_evidence_ids", [])
        ]
        observed_ids = [
            evidence_id for item in evidence_cases
            for evidence_id in item.get("observed_evidence_ids", [])
        ]
        matching = sum(
            len(set(item.get("expected_evidence_ids", [])) & set(item.get("observed_evidence_ids", [])))
            for item in evidence_cases
        )
        exact = sum(
            set(item.get("expected_evidence_ids", [])) == set(item.get("observed_evidence_ids", []))
            for item in evidence_cases
        )
        result.update({
            "evidence_reference_precision": _rounded(_ratio(matching, len(observed_ids))),
            "evidence_reference_recall": _rounded(_ratio(matching, len(expected_ids))),
            "exact_evidence_reference_rate": _rounded(_ratio(exact, len(evidence_cases))),
        })
    if abstention_cases:
        correct = sum(item.get("must_abstain") is item.get("abstained") for item in abstention_cases)
        false_abstentions = sum(not item.get("must_abstain") and item.get("abstained") for item in abstention_cases)
        missed_abstentions = sum(item.get("must_abstain") and not item.get("abstained") for item in abstention_cases)
        result.update({
            "correct_abstention_rate": _rounded(_ratio(correct, len(abstention_cases))),
            "false_abstention_count": false_abstentions,
            "missed_abstention_count": missed_abstentions,
        })
    return {"measurement_status": "measured", **result}


def workflow_coverage_metrics(execution: dict[str, Any] | None) -> dict[str, Any]:
    """Measure browser journey coverage without relabelling it as model quality."""
    if not execution or execution.get("adapter_type") != "browser_journey":
        return _not_applicable("Workflow coverage applies only to declared browser journeys.")
    requested = execution.get("case_count", 0)
    diagnostics = execution.get("browser_case_diagnostics", [])
    if not isinstance(requested, int) or requested < 1 or not isinstance(diagnostics, list):
        return _unavailable("Browser execution diagnostics are incomplete; workflow coverage cannot be calculated.")
    completed = [item for item in diagnostics if isinstance(item, dict) and item.get("outcome") in {"passed", "failed"}]
    passed = [item for item in completed if item.get("outcome") == "passed"]
    failed = [item for item in completed if item.get("outcome") == "failed"]
    blocked = [item for item in diagnostics if isinstance(item, dict) and item.get("outcome") == "blocked"]
    return {
        "measurement_status": "measured",
        "requested_case_count": requested,
        "executed_case_count": len(completed),
        "passed_case_count": len(passed),
        "assertion_review_case_count": len(failed),
        "session_blocked_case_count": len(blocked),
        "workflow_execution_rate": _rounded(_ratio(len(completed), requested)),
        "workflow_signal_match_rate": _rounded(_ratio(len(passed), len(completed))) if completed else None,
        "definition": "Declared browser journeys that reached their approved observable signal. This is workflow coverage, not an AI-model quality score.",
    }


def security_metrics(security: dict[str, Any] | None) -> dict[str, Any]:
    cases = security.get("cases", []) if security else []
    if not cases:
        return _unavailable("No labelled security cases were supplied; attack and detection rates are unavailable.")
    tp = sum(case["expected_detection"] and case["observed_detection"] for case in cases)
    fp = sum(not case["expected_detection"] and case["observed_detection"] for case in cases)
    fn = sum(case["expected_detection"] and not case["observed_detection"] for case in cases)
    tn = sum(not case["expected_detection"] and not case["observed_detection"] for case in cases)
    positives, negatives = tp + fn, fp + tn
    result = {
        "case_count": len(cases),
        "attack_success_rate": _rounded(_ratio(sum(case["observed_attack_success"] for case in cases), len(cases))),
        "attack_outcome_accuracy": _rounded(_ratio(sum(case["expected_attack_success"] == case["observed_attack_success"] for case in cases), len(cases))),
        "detection_rate": _rounded(_ratio(tp, positives)) if positives else None,
        "false_detection_rate": _rounded(_ratio(fp, negatives)) if negatives else None,
        "detection_confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "evidence_coverage": _rounded(_ratio(sum(bool(c["evidence_ids"]) and c["evidence_integrity_valid"] is True for c in cases), len(cases))),
        "definition": "Detection rate is recall against labelled expected detections.",
    }
    if not positives or not negatives:
        return _unavailable("Security evaluation requires both positive and negative detection controls.", **result)
    return {"measurement_status": "measured", **result}


def trajectory_metrics(trajectory: dict[str, Any] | None) -> dict[str, Any]:
    if not trajectory or not trajectory.get("required_milestones"):
        return _unavailable("No expected trajectory milestones were supplied; trajectory correctness is unavailable.")
    required, observed = set(trajectory["required_milestones"]), set(trajectory["observed_milestones"])
    coverage = _ratio(len(required & observed), len(required))
    efficiency = 1 - _ratio(trajectory["redundant_actions"], trajectory["action_count"]) if trajectory["action_count"] else 0.0
    compliant = not (trajectory["policy_violations"] or trajectory["scope_violations"] or trajectory["tool_misuse_events"])
    return {
        "measurement_status": "measured", "milestone_coverage": _rounded(coverage),
        "missing_milestones": sorted(required - observed), "action_efficiency": _rounded(max(0.0, efficiency)),
        "policy_compliant": compliant, "policy_violations": trajectory["policy_violations"],
        "scope_violations": trajectory["scope_violations"], "tool_misuse_events": trajectory["tool_misuse_events"],
        "score": _rounded(coverage * 0.6 + max(0.0, efficiency) * 0.2 + (1.0 if compliant else 0.0) * 0.2),
    }


def tool_use_metrics(tool_use: dict[str, Any] | None) -> dict[str, Any]:
    """Measure tool selection and control enforcement from labelled local traces."""
    cases = tool_use.get("cases", []) if tool_use else []
    if not cases:
        return _unavailable("No labelled tool-use observations were supplied; tool selection and execution controls cannot be measured.")
    expected_total = sum(len(case["expected_tool_names"]) for case in cases)
    observed_total = sum(len(case["observed_tool_names"]) for case in cases)
    matching = sum(
        len(set(case["expected_tool_names"]) & set(case["observed_tool_names"]))
        for case in cases
    )
    precision = _ratio(matching, observed_total)
    recall = _ratio(matching, expected_total)
    selection_f1 = _ratio(2 * precision * recall, precision + recall)
    exact = [
        case["case_id"] for case in cases
        if set(case["expected_tool_names"]) != set(case["observed_tool_names"])
    ]
    unauthorized = [case["case_id"] for case in cases if not case["authorized"]]
    invalid_results = [case["case_id"] for case in cases if not case["result_valid"]]
    evidence_covered = [
        case for case in cases
        if case["evidence_ids"] and case["evidence_integrity_valid"] is True
    ]
    return {
        "measurement_status": "measured",
        "case_count": len(cases),
        "selection_precision": _rounded(precision),
        "selection_recall": _rounded(recall),
        "selection_f1": _rounded(selection_f1),
        "exact_tool_set_rate": _rounded(_ratio(len(cases) - len(exact), len(cases))),
        "authorization_rate": _rounded(_ratio(len(cases) - len(unauthorized), len(cases))),
        "result_validity_rate": _rounded(_ratio(len(cases) - len(invalid_results), len(cases))),
        "evidence_coverage": _rounded(_ratio(len(evidence_covered), len(cases))),
        "unexpected_or_missing_tool_case_ids": exact,
        "unauthorized_tool_case_ids": unauthorized,
        "invalid_tool_result_case_ids": invalid_results,
        "definition": "Labelled expected tools compared with redacted observed tool names and execution-control outcomes.",
    }


def rag_metrics(rag: dict[str, Any] | None) -> dict[str, Any]:
    if not rag or not rag.get("relevant_document_ids"):
        return _unavailable("No labelled relevant-document set was supplied; RAG quality cannot be measured.")
    k = rag.get("k") or max(1, len(rag["retrieved_document_ids"]))
    retrieved = rag["retrieved_document_ids"][:k]
    relevant, cited, retrieved_set = set(rag["relevant_document_ids"]), set(rag["cited_document_ids"]), set(retrieved)
    hits = [document for document in retrieved if document in relevant]
    reciprocal_rank = next((1 / index for index, document in enumerate(retrieved, start=1) if document in relevant), 0.0)
    faithfulness = claims_metrics(rag["answer_claims"])
    result = {
        "k": k, "context_precision": _rounded(_ratio(len(hits), len(retrieved))),
        "recall_at_k": _rounded(_ratio(len(set(hits)), len(relevant))),
        "mean_reciprocal_rank": _rounded(reciprocal_rank),
        "citation_validity": _rounded(_ratio(len(cited & relevant & retrieved_set), len(cited))) if cited else 0.0,
        "faithfulness": faithfulness.get("supported_claim_rate") if faithfulness["measurement_status"] == "measured" else None,
        "uncited_relevant_documents": sorted(relevant - cited),
    }
    if faithfulness["measurement_status"] != "measured":
        return _unavailable("RAG retrieval metrics are available, but answer claims were not supplied for faithfulness.", **result)
    return {"measurement_status": "measured", **result}


def robustness_metrics(robustness: dict[str, Any] | None) -> dict[str, Any]:
    cases = robustness.get("perturbations", []) if robustness else []
    if not cases:
        return _unavailable("No controlled perturbations were supplied; robustness cannot be inferred.")
    if robustness["baseline_label"] is not None and all(case["predicted_label"] is not None for case in cases):
        consistency = _ratio(sum(case["predicted_label"] == robustness["baseline_label"] for case in cases), len(cases))
        consistency_basis = "predicted_label"
    else:
        consistency = _ratio(sum(case["correct"] == robustness["baseline_correct"] for case in cases), len(cases))
        consistency_basis = "correctness"
    expected_variations = {"paraphrase", "perturbation", "repeat"}
    tested = {case["variation_type"] for case in cases}
    by_type = {}
    for variation_type in sorted(expected_variations):
        members = [case for case in cases if case["variation_type"] == variation_type]
        by_type[variation_type] = {"case_count": len(members), "accuracy": _rounded(_ratio(sum(case["correct"] for case in members), len(members))) if members else None}
    return {
        "measurement_status": "measured", "case_count": len(cases),
        "accuracy": _rounded(_ratio(sum(case["correct"] for case in cases), len(cases))),
        "consistency": _rounded(consistency), "consistency_basis": consistency_basis,
        "worst_confidence_drop": _rounded(max(0.0, max(robustness["baseline_confidence"] - case["confidence"] for case in cases))),
        "variation_coverage": _rounded(_ratio(len(tested), len(expected_variations))),
        "missing_variation_types": sorted(expected_variations - tested), "by_variation_type": by_type,
        "failed_case_ids": [case["case_id"] for case in cases if not case["correct"]],
    }


def _agreement(value: dict[str, Any] | None, actor_key: str, count_key: str, definition: str) -> dict[str, Any]:
    decisions = value.get("decisions", []) if value else []
    if not decisions:
        return _unavailable(f"No {count_key.replace('_count', '')} decisions were supplied; agreement is unavailable.")
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for decision in decisions:
        groups[decision["case_id"]].append(decision)
    qualified = {case_id: entries for case_id, entries in groups.items() if len({entry[actor_key] for entry in entries}) >= 2}
    if not qualified:
        return _unavailable(f"At least two distinct {actor_key} values per case are required.")
    total_pairs = agreeing_pairs = unanimous = 0
    disagreements = []
    for case_id, entries in qualified.items():
        if len({entry["verdict"] for entry in entries}) == 1:
            unanimous += 1
        else:
            disagreements.append(case_id)
        for left, right in combinations(entries, 2):
            total_pairs += 1
            agreeing_pairs += left["verdict"] == right["verdict"]
    return {"measurement_status": "measured", "case_count": len(qualified), count_key: len({entry[actor_key] for entry in decisions}), "pairwise_agreement": _rounded(_ratio(agreeing_pairs, total_pairs)), "unanimous_case_rate": _rounded(_ratio(unanimous, len(qualified))), "disagreement_case_ids": sorted(disagreements), "definition": definition}


def _percentile(values: list[int], percentile: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, min(len(ordered) - 1, math.ceil(len(ordered) * percentile) - 1))] if ordered else 0


def cost_efficiency_metrics(cost: dict[str, Any] | None, expected: list[str], predicted: list[str]) -> dict[str, Any]:
    observations = cost.get("observations", []) if cost else []
    if not observations:
        return _unavailable("No redacted provider or metered usage observations were supplied; cost and efficiency cannot be measured.")
    if len(observations) != len(expected):
        return _unavailable("Cost observations must cover every labelled evaluation case before efficiency can be measured.", observation_count=len(observations), labelled_case_count=len(expected))
    total_cost = sum(item["cost_usd"] for item in observations)
    total_tokens = sum(item["input_tokens"] + item["output_tokens"] for item in observations)
    correct_count = sum(actual == guess for actual, guess in zip(expected, predicted, strict=True))
    latencies = [item["latency_ms"] for item in observations]
    return {
        "measurement_status": "measured", "cost_source": cost["cost_source"], "case_count": len(observations),
        "total_cost_usd": _rounded(total_cost), "cost_per_case_usd": _rounded(_ratio(total_cost, len(observations))),
        "cost_per_correct_case_usd": _rounded(_ratio(total_cost, correct_count)) if correct_count else None,
        "input_tokens": sum(item["input_tokens"] for item in observations), "output_tokens": sum(item["output_tokens"] for item in observations),
        "total_tokens": total_tokens, "tokens_per_case": _rounded(_ratio(total_tokens, len(observations))),
        "request_count": sum(item["request_count"] for item in observations),
        "requests_per_case": _rounded(_ratio(sum(item["request_count"] for item in observations), len(observations))),
        "retry_count": sum(item["retry_count"] for item in observations), "tool_call_count": sum(item["tool_call_count"] for item in observations),
        "cache_hit_rate": _rounded(_ratio(sum(item["cache_hit"] for item in observations), len(observations))),
        "fallback_rate": _rounded(_ratio(sum(item["fallback_used"] for item in observations), len(observations))),
        "timeout_rate": _rounded(_ratio(sum(item["timed_out"] for item in observations), len(observations))),
        "median_latency_ms": _percentile(latencies, 0.50), "p95_latency_ms": _percentile(latencies, 0.95), "max_latency_ms": max(latencies),
    }


def _annotate_metric_trust(
    package: dict[str, Any], metrics: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """State what PRE-D verified versus what the target merely declared.

    Schema validation makes evidence structurally usable; it does not make a
    target-provided semantic judgment independent. Trace-derived operational
    facts can be verified locally, while semantic support/outcome assertions
    remain declared until PRE-D independently validates them.
    """
    execution = package.get("execution", {})
    execution = execution if isinstance(execution, dict) else {}
    local_evidence = execution.get("local_evidence", {})
    local_evidence = local_evidence if isinstance(local_evidence, dict) else {}
    telemetry_dimensions = {
        item for item in local_evidence.get("derived_dimensions", [])
        if isinstance(item, str)
    }
    baseline_verified = {
        "workflow_coverage", "classification", "confidence", "decision_evidence",
    }
    trace_verified = {
        "trajectory", "tool_use", "judge_agreement", "reproducibility",
    }
    annotated: dict[str, dict[str, Any]] = {}
    for name, raw_metric in metrics.items():
        metric = dict(raw_metric)
        if metric.get("measurement_status") != "measured":
            metric.update({
                "trust_status": "missing",
                "evidence_source": "No complete compatible local evidence was measured.",
                "representativeness": "not_applicable",
            })
            annotated[name] = metric
            continue

        telemetry_derived = name in telemetry_dimensions
        cost_is_metered = name == "cost_efficiency" and metric.get("cost_source") == "metered"
        if name in baseline_verified:
            trust_status = "verified"
            evidence_source = {
                "workflow_coverage": "Observed directly by the local PRE-D browser runner.",
                "classification": "Calculated locally from labelled expectations and returned decisions.",
                "confidence": "Calculated locally from decision correctness and returned confidence values.",
                "decision_evidence": "Calculated locally from expected and returned evidence IDs and abstention outcomes.",
            }[name]
        elif telemetry_derived and (name in trace_verified or cost_is_metered):
            trust_status = "verified"
            evidence_source = "Calculated from redacted events observed by the local PRE-D telemetry collector."
        else:
            trust_status = "declared"
            evidence_source = (
                "Calculated from schema-validated semantic evidence emitted by the target through local telemetry."
                if telemetry_derived else
                "Calculated from schema-validated measurements declared by the target adapter."
            )

        metric["trust_status"] = trust_status
        metric["evidence_source"] = evidence_source
        metric["representativeness"] = "representative"
        if name == "cost_efficiency" and all(
            metric.get(field) == 0
            for field in (
                "total_cost_usd", "total_tokens", "median_latency_ms",
                "p95_latency_ms", "max_latency_ms",
            )
        ):
            metric["trust_status"] = "declared"
            metric["representativeness"] = "non_representative"
            limitations = metric.get("limitations", [])
            limitations = list(limitations) if isinstance(limitations, list) else []
            limitations.append(
                "All cost, token, and latency observations are zero; this result is structurally valid but not representative of real execution usage."
            )
            metric["limitations"] = limitations
        annotated[name] = metric
    return annotated


def summarize_metric_trust(
    metrics: dict[str, dict[str, Any]], names: list[str] | None = None,
) -> dict[str, int]:
    """Count active metrics by evidence trust without inflating missing scores."""
    selected = names if names is not None else list(metrics)
    counts = {"verified": 0, "declared": 0, "missing": 0, "non_representative": 0}
    for name in selected:
        metric = metrics.get(name, {})
        status = metric.get("trust_status", "missing") if isinstance(metric, dict) else "missing"
        counts[status if status in counts else "missing"] += 1
        if isinstance(metric, dict) and metric.get("representativeness") == "non_representative":
            counts["non_representative"] += 1
    return counts


def calculate_local_metrics(package: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Calculate every supported local metric from an already validated package."""
    evaluation = package["evaluation"]
    expected = evaluation["expected_labels"]
    predicted = evaluation["predicted_labels"]
    confidences = evaluation["confidences"]
    case_ids = evaluation.get("case_ids")
    case_ids = case_ids if isinstance(case_ids, list) else None
    execution = package.get("execution")
    execution = execution if isinstance(execution, dict) else None
    is_browser_journey = bool(execution and execution.get("adapter_type") == "browser_journey")
    # Packages keep validated measurements directly on evaluation so their
    # schema remains compatible with the optional shared-platform upload.
    measurements = evaluation
    metrics = {
        "workflow_coverage": workflow_coverage_metrics(execution),
        "classification": (
            _not_applicable("Browser pass/fail assertions are workflow evidence, not model-classification predictions.")
            if is_browser_journey else classification_metrics(expected, predicted, case_ids)
        ),
        "confidence": (
            _not_applicable("The browser runner does not observe model confidence and never infers it from an assertion result.")
            if is_browser_journey else confidence_metrics(expected, predicted, confidences, case_ids)
        ),
        "decision_evidence": decision_evidence_metrics(measurements.get("decision_observations")),
        "groundedness": claims_metrics(measurements.get("claims")),
        "security": security_metrics(measurements.get("security")),
        "trajectory": trajectory_metrics(measurements.get("trajectory")),
        "tool_use": tool_use_metrics(measurements.get("tool_use")),
        "rag": rag_metrics(measurements.get("rag")),
        "robustness": robustness_metrics(measurements.get("robustness")),
        "judge_agreement": _agreement(measurements.get("judge_agreement"), "judge_id", "judge_count", "Judge agreement measures consistency, not correctness."),
        "reproducibility": _agreement(measurements.get("reproducibility"), "run_id", "run_count", "Repeated-run agreement measures stability, not correctness."),
        "cost_efficiency": cost_efficiency_metrics(measurements.get("cost_efficiency"), expected, predicted),
    }
    return _annotate_metric_trust(package, metrics)
