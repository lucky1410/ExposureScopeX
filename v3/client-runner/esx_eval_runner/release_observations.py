"""Bounded case observations and policy disclosures for PRE-D release evidence."""

from __future__ import annotations

import math


def decision_observation(report: dict, scored: int) -> dict | None:
    """Summarize complete case rows without asserting aggregate metric validity.

    Return sample_size, correct_cases, incorrect_cases, accuracy (a fraction),
    case_ids for errors in source order, and scope_caveat. Include class_count
    only when dataset health supplies an integer from one through scored.
    Missing, malformed, duplicate, or partial case evidence returns None.
    Measurement/trust statuses and aggregate scores are deliberately not used.
    """
    if not isinstance(report, dict) or type(scored) is not int or scored <= 0:
        return None
    metrics = report.get("metrics")
    if not isinstance(metrics, dict):
        return None
    classification = metrics.get("classification")
    if not isinstance(classification, dict):
        return None
    sample_size = classification.get("sample_size")
    rows = classification.get("case_results")
    if (type(sample_size) is not int or sample_size != scored
            or not isinstance(rows, list) or len(rows) != scored):
        return None

    seen: set[str] = set()
    errors: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or type(row.get("correct")) is not bool:
            return None
        case_id = row.get("case_id")
        if (not isinstance(case_id, str) or not case_id.strip()
                or any(ord(char) < 32 for char in case_id) or case_id in seen):
            return None
        seen.add(case_id)
        if row["correct"] is False:
            errors.append(case_id)

    correct = scored - len(errors)
    result = {
        "sample_size": scored,
        "correct_cases": correct,
        "incorrect_cases": len(errors),
        "accuracy": correct / scored,
        "case_ids": errors,
        "scope_caveat": (
            "Observed correctness covers only these scored cases. It does not "
            "establish broad or all-class classification quality, representativeness, "
            "or calibration, and does not change aggregate metric trust."
        ),
    }
    evaluation = report.get("evaluation")
    health = evaluation.get("dataset_health") if isinstance(evaluation, dict) else None
    class_count = health.get("class_count") if isinstance(health, dict) else None
    if type(class_count) is int and 1 <= class_count <= scored:
        result["class_count"] = class_count
        if class_count == 1:
            result["scope_caveat"] += " Only one expected class is represented."
    return result


def policy_disclosure(kind: str, gates: list[dict]) -> dict:
    """Compare normalized policy fields with release.default_gates by signal.

    Return kind, matches_defaults, changes, and a notice about the baseline's
    scope. Each change has signal, change (modified/missing/added), baseline,
    and selected; an absent side is None. Gate details include severity.
    Order and non-policy result metadata do not affect equality. Omitted
    severity defaults to blocker, matching manifest normalization. Empty gates
    disclose all defaults as missing. Malformed or duplicate gates raise
    ValueError. This comparison does not assign risk levels or release verdicts.
    """
    from .release import GATE_FIELDS, default_gates

    if kind not in ("decision", "workflow"):
        raise ValueError("kind must be decision or workflow")
    if not isinstance(gates, list):
        raise ValueError("gates must be a list of normalized gate objects")

    selected = {}
    for gate in gates:
        if not isinstance(gate, dict):
            raise ValueError("each gate must be an object")
        signal = gate.get("signal")
        if not isinstance(signal, str) or signal.count(".") != 1:
            raise ValueError("gate signal must be metric.field")
        metric, field = signal.split(".")
        if field not in GATE_FIELDS.get(metric, set()) or signal in selected:
            raise ValueError("gate signal must be known and unique")
        operator = gate.get("operator")
        severity = gate.get("severity", "blocker")
        if operator not in ("gte", "lte") or severity not in ("blocker", "warning"):
            raise ValueError("gates require gte/lte and blocker/warning")
        threshold = gate.get("threshold")
        try:
            finite = type(threshold) in (int, float) and math.isfinite(threshold)
        except OverflowError:
            finite = False
        unbounded = metric == "cost_efficiency" and field != "timeout_rate"
        if not finite or threshold < 0 or (not unbounded and threshold > 1):
            raise ValueError("gate threshold must satisfy normalized numeric bounds")
        selected[signal] = {
            "signal": signal, "operator": operator,
            "threshold": threshold, "severity": severity,
        }

    baseline = {gate["signal"]: gate for gate in default_gates(kind)}
    changes = []
    for signal in sorted(baseline.keys() | selected.keys()):
        before, after = baseline.get(signal), selected.get(signal)
        if before == after:
            continue
        changes.append({
            "signal": signal,
            "change": "added" if before is None else "missing" if after is None else "modified",
            "baseline": dict(before) if before is not None else None,
            "selected": dict(after) if after is not None else None,
        })
    return {
        "kind": kind,
        "matches_defaults": not changes,
        "changes": changes,
        "notice": (
            "Default gates are starting points, not universal release standards. "
            "Differences describe selected policy; they do not establish release risk "
            "or readiness."
        ),
    }
