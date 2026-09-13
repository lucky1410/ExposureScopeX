from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class GroundTruthCase:
    case_id: str
    expected_positive: bool
    applicable_profiles: frozenset[str]
    required_evidence_kinds: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class BenchmarkObservation:
    observation_id: str
    case_id: str | None
    evidence_kinds: frozenset[str] = field(default_factory=frozenset)


PROFILE_BENCHMARK_THRESHOLDS = {
    "light": {"precision": 0.95, "recall": 0.80, "evidence_completeness": 1.0},
    "medium": {"precision": 0.95, "recall": 0.90, "evidence_completeness": 1.0},
    "aggressive": {"precision": 0.95, "recall": 0.95, "evidence_completeness": 1.0},
}


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def benchmark_thresholds(profile: str) -> dict[str, float]:
    thresholds = PROFILE_BENCHMARK_THRESHOLDS.get(profile)
    if thresholds is None:
        raise ValueError(f"unknown benchmark profile: {profile!r}")
    return dict(thresholds)


def measured_quality_gate(score: dict) -> dict:
    thresholds = benchmark_thresholds(str(score.get("profile") or ""))
    checks = {
        "precision": float(score.get("precision") or 0.0) >= thresholds["precision"],
        "recall": float(score.get("recall") or 0.0) >= thresholds["recall"],
        "evidence_completeness": float(score.get("evidence_completeness") or 0.0) >= thresholds["evidence_completeness"],
    }
    return {
        "eligible": all(checks.values()),
        "thresholds": thresholds,
        "checks": checks,
        "reason": None if all(checks.values()) else "Measured benchmark metrics do not yet meet the declared profile quality thresholds.",
    }


def score_vulnerability_benchmark(
    *,
    dataset_version: str,
    profile: str,
    truth_cases: list[GroundTruthCase],
    observations: list[BenchmarkObservation],
) -> dict:
    if not dataset_version.strip():
        raise ValueError("dataset_version is required")
    applicable = [case for case in truth_cases if profile in case.applicable_profiles]
    if not applicable:
        raise ValueError(f"dataset has no labelled cases applicable to profile {profile!r}")
    if len({case.case_id for case in applicable}) != len(applicable):
        raise ValueError("ground-truth case IDs must be unique")
    if len({item.observation_id for item in observations}) != len(observations):
        raise ValueError("observation IDs must be unique")

    truth = {case.case_id: case for case in applicable}
    positive_ids = {case.case_id for case in applicable if case.expected_positive}
    negative_ids = set(truth) - positive_ids
    grouped: dict[str, list[BenchmarkObservation]] = {}
    unmatched: list[str] = []
    for observation in observations:
        if observation.case_id is None or observation.case_id not in truth:
            unmatched.append(observation.observation_id)
            continue
        grouped.setdefault(observation.case_id, []).append(observation)

    detected_ids = set(grouped)
    true_positive_ids = sorted(positive_ids & detected_ids)
    false_negative_ids = sorted(positive_ids - detected_ids)
    false_positive_case_ids = sorted(negative_ids & detected_ids)
    true_negative_ids = sorted(negative_ids - detected_ids)
    false_positive_count = len(false_positive_case_ids) + len(unmatched)
    duplicate_count = sum(max(0, len(items) - 1) for items in grouped.values())

    evidence_failures: list[str] = []
    for case_id in true_positive_ids:
        case = truth[case_id]
        if not any(case.required_evidence_kinds <= item.evidence_kinds for item in grouped[case_id]):
            evidence_failures.append(case_id)

    tp = len(true_positive_ids)
    fp = false_positive_count
    fn = len(false_negative_ids)
    tn = len(true_negative_ids)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = _ratio(2 * precision * recall, precision + recall)
    result = {
        "schema_version": "1.0",
        "dataset_version": dataset_version,
        "profile": profile,
        "sample_size": len(applicable),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "specificity": _ratio(tn, tn + fp),
        "false_positive_rate": _ratio(fp, fp + tn),
        "false_negative_rate": _ratio(fn, fn + tp),
        "evidence_completeness": _ratio(tp - len(evidence_failures), tp) if tp else 1.0,
        "duplicate_observation_count": duplicate_count,
        "true_positive_case_ids": true_positive_ids,
        "false_positive_case_ids": false_positive_case_ids,
        "false_positive_observation_ids": sorted(unmatched),
        "false_negative_case_ids": false_negative_ids,
        "evidence_failure_case_ids": sorted(evidence_failures),
    }
    result["accuracy"] = _ratio(tp + tn, tp + fp + fn + tn) if negative_ids else None
    result["limitations"] = [
        "Metrics apply only to the declared dataset version, profile, and applicable cases.",
        "A matched case is not release-eligible until its required evidence oracle passes.",
        "Accuracy is omitted when the dataset has no explicit negative controls.",
    ]
    result["quality_gate"] = measured_quality_gate(result)
    return result
