"""Deterministic, offline metric calculations for the ESX client runner.

The customer adapter produces redacted local observations and this module scores
them on the same machine. It has no network or model dependency.
"""

from __future__ import annotations

from collections import defaultdict
from itertools import combinations
import math
from typing import Any


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _rounded(value: float) -> float:
    return round(value, 6)


def _unavailable(reason: str, **partial: Any) -> dict[str, Any]:
    return {"measurement_status": "not_measurable", "reason": reason, **partial}


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


def classification_metrics(expected: list[str], predicted: list[str]) -> dict[str, Any]:
    labels = sorted(set(expected) | set(predicted))
    matrix = {actual: {guess: 0 for guess in labels} for actual in labels}
    for actual, guess in zip(expected, predicted, strict=True):
        matrix[actual][guess] += 1
    total = len(expected)
    per_class: dict[str, dict[str, Any]] = {}
    for label in labels:
        tp = matrix[label][label]
        fp = sum(matrix[actual][label] for actual in labels if actual != label)
        fn = sum(matrix[label][guess] for guess in labels if guess != label)
        tn = total - tp - fp - fn
        support = sum(matrix[label].values())
        precision = _ratio(tp, tp + fp)
        recall = _ratio(tp, tp + fn)
        per_class[label] = {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn, "support": support,
            "precision": _rounded(precision), "recall": _rounded(recall),
            "f1": _rounded(_ratio(2 * precision * recall, precision + recall)),
            "false_positive_rate": _rounded(_ratio(fp, fp + tn)),
            "false_negative_rate": _rounded(_ratio(fn, fn + tp)),
        }

    def macro(metric: str) -> float:
        return _ratio(sum(item[metric] for item in per_class.values()), len(labels))

    def weighted(metric: str) -> float:
        return _ratio(sum(item[metric] * item["support"] for item in per_class.values()), total)

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
    }
    if len(set(expected)) < 2:
        return _unavailable("At least two ground-truth classes are required for classification quality metrics.", **result)
    return {"measurement_status": "measured", **result}


def confidence_metrics(expected: list[str], predicted: list[str], confidences: list[float]) -> dict[str, Any]:
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
    return {"measurement_status": "measured", "correctness_brier_score": _rounded(brier), "expected_calibration_error": _rounded(ece), "bins": bins, "definition": "Calibration of predicted-label confidence against correctness."}


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


def calculate_local_metrics(package: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Calculate every supported local metric from an already validated package."""
    evaluation = package["evaluation"]
    expected = evaluation["expected_labels"]
    predicted = evaluation["predicted_labels"]
    confidences = evaluation["confidences"]
    # Packages keep validated measurements directly on evaluation so their
    # schema remains compatible with the optional shared-platform upload.
    measurements = evaluation
    return {
        "classification": classification_metrics(expected, predicted),
        "confidence": confidence_metrics(expected, predicted, confidences),
        "groundedness": claims_metrics(measurements.get("claims")),
        "security": security_metrics(measurements.get("security")),
        "trajectory": trajectory_metrics(measurements.get("trajectory")),
        "rag": rag_metrics(measurements.get("rag")),
        "robustness": robustness_metrics(measurements.get("robustness")),
        "judge_agreement": _agreement(measurements.get("judge_agreement"), "judge_id", "judge_count", "Judge agreement measures consistency, not correctness."),
        "reproducibility": _agreement(measurements.get("reproducibility"), "run_id", "run_count", "Repeated-run agreement measures stability, not correctness."),
        "cost_efficiency": cost_efficiency_metrics(measurements.get("cost_efficiency"), expected, predicted),
    }
