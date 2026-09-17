"""Self-contained local HTML report generation."""

from __future__ import annotations

import html
import json
from typing import Any

from .evidence_requirements import METRIC_REQUIREMENTS, build_measurement_readiness, metric_names
from .local_metrics import summarize_metric_trust


def _escape(value: object) -> str:
    return html.escape(str(value))


def _title(name: str) -> str:
    return METRIC_REQUIREMENTS.get(name, {}).get("title", name.replace("_", " ").title())


def _metric_status(metric: object) -> str:
    return str(metric.get("measurement_status", "not_measurable")) if isinstance(metric, dict) else "not_measurable"


def _trust_status(metric: object) -> str:
    if not isinstance(metric, dict) or metric.get("measurement_status") != "measured":
        return "missing"
    # Older reports did not retain provenance. Treat them conservatively.
    status = str(metric.get("trust_status", "declared"))
    return {"self_attested": "declared", "not_measured": "missing"}.get(status, status)


def _trust_label(status: str) -> str:
    return {
        "verified": "VERIFIED",
        "declared": "DECLARED",
    }.get(status, "MISSING")


def _status_label(status: str) -> str:
    return {
        "measured": "MEASURED",
        "not_applicable": "NOT RUN",
        "not_requested": "NOT REQUESTED",
    }.get(status, "EVIDENCE NEEDED")


def _primary_signal(name: str, metric: dict[str, Any]) -> str:
    fields = {
        "workflow_coverage": ("workflow_execution_rate", "Workflow execution", "percent"),
        "classification": ("accuracy", "Accuracy", "percent"),
        "confidence": ("expected_calibration_error", "Expected calibration error", "number"),
        "decision_evidence": ("correct_abstention_rate", "Correct abstention", "percent"),
        "groundedness": ("supported_claim_rate", "Supported claims", "percent"),
        "security": ("attack_outcome_accuracy", "Attack outcome accuracy", "percent"),
        "trajectory": ("score", "Trajectory score", "percent"),
        "tool_use": ("selection_f1", "Tool selection F1", "percent"),
        "rag": ("faithfulness", "Faithfulness", "percent"),
        "robustness": ("accuracy", "Stable outcomes", "percent"),
        "judge_agreement": ("pairwise_agreement", "Pairwise agreement", "percent"),
        "reproducibility": ("pairwise_agreement", "Run agreement", "percent"),
        "cost_efficiency": ("p95_latency_ms", "P95 latency", "milliseconds"),
    }
    key, label, unit = fields.get(name, ("score", "Local score", "number"))
    value = metric.get(key)
    if value is None:
        return "Evidence captured locally."
    if unit == "percent" and isinstance(value, (int, float)):
        return f"{label}: {value * 100:.1f}%"
    if unit == "milliseconds":
        return f"{label}: {value} ms"
    return f"{label}: {value}"


def _metric_score(name: str, metric: dict[str, Any], trust: str) -> str:
    if metric.get("measurement_status") != "measured":
        return "Not scored"
    if name == "classification":
        return (
            f"Accuracy {float(metric.get('accuracy', 0)) * 100:.1f}% | "
            f"Precision {float(metric.get('macro_precision', 0)) * 100:.1f}% | "
            f"Recall {float(metric.get('macro_recall', 0)) * 100:.1f}% | "
            f"F1 {float(metric.get('macro_f1', 0)) * 100:.1f}%"
        )
    if name == "confidence":
        return (
            f"ECE {float(metric.get('expected_calibration_error', 0)):.3f} | "
            f"Brier {float(metric.get('correctness_brier_score', 0)):.3f} | "
            f"{int(metric.get('unique_confidence_count', 0))} confidence levels"
        )
    score = _primary_signal(name, metric)
    return f"TARGET-DECLARED VALUE ONLY: {score}" if trust == "declared" else score


def _metric_why(name: str, metric: dict[str, Any], trust: str) -> str:
    if metric.get("measurement_status") != "measured":
        return str(metric.get("reason", "The required local evidence was not supplied."))
    if name == "classification":
        return f"PRE-D compared {metric.get('sample_size', 0)} labelled dataset outcomes with decisions returned by the local target."
    if name == "confidence":
        return "PRE-D compared returned confidence values with correctness across the labelled decision pack."
    if trust == "declared":
        return "The target supplied structurally valid evidence, but PRE-D did not independently validate its semantic meaning."
    return "PRE-D calculated this result from independently observed local execution evidence."


def _metric_action(name: str, metric: dict[str, Any], trust: str) -> str:
    if metric.get("measurement_status") != "measured":
        requirement = METRIC_REQUIREMENTS.get(name, {})
        return "Add " + str(requirement.get("application_emits", "the required local evidence")) + " and rerun."
    if name == "classification":
        failures = [item for item in metric.get("case_results", []) if isinstance(item, dict) and not item.get("correct")]
        return (
            f"Review the {len(failures)} failed case(s), correct the decision logic or labels, then rerun the same pack."
            if failures else
            "Retain this labelled pack and rerun it after product or model changes to detect regressions."
        )
    if name == "confidence":
        actions = []
        if metric.get("calibration_warning"):
            actions.append("review confidence generation or calibration")
        if metric.get("confidence_diversity_warning"):
            actions.append("return at least 5 meaningful confidence levels")
        return ("; ".join(actions).capitalize() + ", then rerun.") if actions else "Retain the calibration baseline and rerun after decision-model changes."
    if metric.get("representativeness") == "non_representative":
        return "Capture representative non-zero local usage observations, then rerun."
    if trust == "declared":
        return "Connect an independently observed local evidence source before using this result as a release gate."
    return "Review affected cases and rerun the same pack after changes."


def _metric_cards(metrics: dict[str, Any], names: list[str]) -> str:
    cards = []
    for name in names:
        metric = metrics.get(name, {})
        metric = metric if isinstance(metric, dict) else {}
        trust = _trust_status(metric)
        title = _title(name)
        if trust == "declared":
            title = {
                "groundedness": "Declared evidence support",
                "trajectory": "Declared trajectory milestones",
            }.get(name, title)
        representative = metric.get("representativeness") == "non_representative"
        representative_badge = "<span class='representativeness'>NON-REPRESENTATIVE</span>" if representative else ""
        declared_warning = (
            "<p class='trust-warning'>TARGET-DECLARED EVIDENCE. PRE-D DID NOT INDEPENDENTLY VALIDATE THIS VALUE.</p>"
            if trust == "declared" else ""
        )
        cards.append(
            f"<article class='metric-card {_escape(trust)}'>"
            f"<span class='state'>{_escape(_trust_label(trust))}</span>{representative_badge}"
            f"<h3>{_escape(title)}</h3>{declared_warning}<dl>"
            f"<dt>Status</dt><dd>{_escape(_trust_label(trust).title())}</dd>"
            f"<dt>Score</dt><dd>{_escape(_metric_score(name, metric, trust))}</dd>"
            f"<dt>Why</dt><dd>{_escape(_metric_why(name, metric, trust))}</dd>"
            f"<dt>Evidence source</dt><dd>{_escape(metric.get('evidence_source', 'No complete compatible local evidence.'))}</dd>"
            f"<dt>Action</dt><dd>{_escape(_metric_action(name, metric, trust))}</dd>"
            f"</dl></article>"
        )
    return "".join(cards)


def _trust_summary(report: dict[str, Any], metrics: dict[str, Any], names: list[str]) -> str:
    summary = report.get("metric_trust_summary")
    if not isinstance(summary, dict):
        summary = summarize_metric_trust(metrics, names)
    verified = int(summary.get("verified", 0))
    declared = int(summary.get("declared", summary.get("self_attested", 0)))
    missing = int(summary.get("missing", summary.get("not_measured", 0)))
    flagged = [
        _title(name) for name in names
        if isinstance(metrics.get(name), dict) and metrics[name].get("representativeness") == "non_representative"
    ]
    flag = (
        " Non-representative is a warning attached to: " + ", ".join(flagged) + "."
        if flagged else ""
    )
    return """<section class='panel trust-summary'><div class='heading'><div><p class='eyebrow'>METRIC TRUST</p><h2>What PRE-D verified</h2></div><p>PRE-D Local measured some metrics directly and accepted some metrics as target-declared evidence. These are not equally trustworthy.""" + _escape(flag) + """</p></div>
    <div class='quick-grid'><div class='verified'><strong>""" + _escape(verified) + """</strong><span>Verified</span></div><div class='declared'><strong>""" + _escape(declared) + """</strong><span>Declared</span></div><div class='missing'><strong>""" + _escape(missing) + """</strong><span>Missing</span></div></div></section>"""


def _decision_summary(report: dict[str, Any]) -> str:
    execution = report.get("execution", {})
    metrics = report.get("metrics", {})
    if not isinstance(execution, dict) or execution.get("adapter_type") == "browser_journey" or not isinstance(metrics, dict):
        return ""
    classification = metrics.get("classification", {})
    confidence = metrics.get("confidence", {})
    if _trust_status(classification) != "verified" or _trust_status(confidence) != "verified":
        return ""
    sample_size = int(classification.get("sample_size", 0))
    correct = sum(
        1 for item in classification.get("case_results", [])
        if isinstance(item, dict) and item.get("correct") is True
    )
    return """<section class='panel decision-summary'><div class='heading'><div><p class='eyebrow'>VERIFIED DECISION BASELINE</p><h2>Classification and confidence</h2></div><p>These headline results come from labelled expectations compared with decisions and confidence returned by the local target.</p></div>
    <div class='quick-grid'><div class='verified'><strong>""" + _escape(f"{correct}/{sample_size}") + """</strong><span>Correct decisions</span></div><div class='verified'><strong>""" + _escape(f"{float(classification.get('macro_f1', 0)) * 100:.1f}%") + """</strong><span>Macro F1</span></div><div class='verified'><strong>""" + _escape(f"{float(confidence.get('expected_calibration_error', 0)):.3f}") + """</strong><span>Verified ECE / review warning</span></div></div></section>"""


def _confidence_warning(metrics: dict[str, Any]) -> str:
    metric = metrics.get("confidence", {})
    if not isinstance(metric, dict) or metric.get("measurement_status") != "measured":
        return ""
    ece = metric.get("expected_calibration_error")
    brier = metric.get("correctness_brier_score")
    if not isinstance(ece, (int, float)):
        return ""
    diversity_warning = bool(metric.get("confidence_diversity_warning"))
    if ece > 0.15:
        state, headline = "CALIBRATION WARNING", "Confidence is unreliable on this pack"
    elif diversity_warning:
        state, headline = "CONFIDENCE RANGE WARNING", "Too few confidence levels were observed"
    else:
        state, headline = "CALIBRATION OBSERVED", "Confidence calibration was measured"
    detail = f"Expected calibration error: {ece * 100:.1f}%."
    if isinstance(brier, (int, float)):
        detail += f" Correctness Brier score: {brier:.3f}."
    detail += f" Unique confidence levels: {int(metric.get('unique_confidence_count', 0))}."
    detail += " Perfect accuracy can still coexist with poorly calibrated confidence."
    return (
        f"<section class='panel confidence-warning'><span class='state'>{_escape(state)}</span>"
        f"<h2>{_escape(headline)}</h2><p>{_escape(detail)}</p></section>"
    )


def _layer_card(title: str, state: str, detail: str) -> str:
    css_state = state.lower().replace(" ", "-")
    return (
        f"<article class='layer-card {_escape(css_state)}'><span class='state'>{_escape(state)}</span>"
        f"<h3>{_escape(title)}</h3><p>{_escape(detail)}</p></article>"
    )


def _evaluation_layers(report: dict[str, Any]) -> str:
    """Show the independent local evidence layers before their implementation detail."""
    execution = report.get("execution", {})
    execution = execution if isinstance(execution, dict) else {}
    evaluation = report.get("evaluation", {})
    evaluation = evaluation if isinstance(evaluation, dict) else {}
    metrics = report.get("metrics", {})
    metrics = metrics if isinstance(metrics, dict) else {}
    required = evaluation.get("required_dimensions", [])
    required = [item for item in required if isinstance(item, str)] if isinstance(required, list) else []
    is_browser = execution.get("adapter_type") == "browser_journey"
    classification = metrics.get("classification", {})
    confidence = metrics.get("confidence", {})
    decision_evidence = metrics.get("decision_evidence", {})
    if is_browser:
        decision = _layer_card(
            "Decision evaluation", "NOT RUN",
            "This browser plan checked visible workflow signals. It did not call a decision endpoint or observe model labels, confidence, evidence IDs, or abstention.",
        )
    elif _metric_status(classification) == "measured" and _metric_status(confidence) == "measured":
        sample_size = classification.get("sample_size", 0) if isinstance(classification, dict) else 0
        evidence_note = " Decision evidence and abstention were also measured." if _metric_status(decision_evidence) == "measured" else ""
        decision_state = (
            "VERIFIED"
            if _trust_status(classification) == "verified" and _trust_status(confidence) == "verified"
            else "MEASURED / REVIEW"
        )
        decision = _layer_card(
            "Decision evaluation", decision_state,
            f"{sample_size} labelled local decisions were evaluated. {_primary_signal('classification', classification)}.{evidence_note}",
        )
    else:
        reason = "The local endpoint must return a label and a 0-1 confidence for each labelled case."
        if isinstance(classification, dict) and classification.get("reason"):
            reason = str(classification["reason"])
        decision = _layer_card("Decision evaluation", "EVIDENCE NEEDED", reason)

    provenance = execution.get("local_evidence", {})
    provenance = provenance if isinstance(provenance, dict) else {}
    records = provenance.get("record_count", 0)
    records = records if isinstance(records, int) and records >= 0 else 0
    dimensions = provenance.get("derived_dimensions", [])
    dimensions = [item for item in dimensions if isinstance(item, str)] if isinstance(dimensions, list) else []
    telemetry = _layer_card(
        "PRE-D telemetry evidence", "CONNECTED" if records else "NOT CONNECTED",
        (
            f"{records} redacted local record(s) supplied complete evidence for {', '.join(item.replace('_', ' ') for item in dimensions) or 'no advanced dimensions yet'}."
            if records else
            "No redacted local telemetry was supplied. This does not invalidate workflow or decision results; it limits only trace-dependent metrics."
        ),
    )

    advanced = [item for item in required if item not in {"classification", "confidence", "workflow_coverage"}]
    pending = [item for item in advanced if _metric_status(metrics.get(item)) != "measured"]
    trust_review = [
        item for item in required
        if _metric_status(metrics.get(item)) == "measured"
        and (
            _trust_status(metrics.get(item)) == "declared"
            or (isinstance(metrics.get(item), dict) and metrics[item].get("representativeness") == "non_representative")
        )
    ]
    calibration_error = confidence.get("expected_calibration_error") if isinstance(confidence, dict) else None
    calibration_review = isinstance(calibration_error, (int, float)) and calibration_error > 0.15
    if is_browser:
        readiness = _layer_card(
            "PRE-D local release readiness", "WORKFLOW EVIDENCE ONLY",
            "Workflow reachability is available for review. Decision-quality readiness was not evaluated because this run did not use a decision endpoint or local adapter.",
        )
    elif _metric_status(classification) == "measured" and _metric_status(confidence) == "measured":
        readiness = _layer_card(
            "PRE-D local release readiness", "DEEP EVIDENCE PENDING" if pending else ("REVIEW REQUIRED" if trust_review or calibration_review else "EVIDENCE READY"),
            (
                "Decision baseline is measured locally. Add telemetry or adapter evidence before making claims about " + ", ".join(_title(item).lower() for item in pending) + "."
                if pending else
                (
                    "Every requested metric is structurally measured, but target-declared or non-representative results still require review: " + ", ".join(_title(item).lower() for item in trust_review) + "."
                    if trust_review else (
                        "Decision evidence is locally verified, but confidence calibration requires review before release."
                        if calibration_review else
                        "Every metric requested by this plan has compatible locally verified evidence. Review the detailed evidence before making your team's release decision."
                    )
                )
            ),
        )
    else:
        readiness = _layer_card(
            "PRE-D local release readiness", "DECISION EVIDENCE INCOMPLETE",
            "This run cannot support a decision-quality release review until labelled outcomes and observed confidence are measured locally.",
        )
    return """<section class='panel'>
    <div class='heading'><div><p class='eyebrow'>PRE-D LOCAL RESULT</p><h2>What this run actually evaluated</h2></div>
    <p>Browser workflows, decision evaluation, and telemetry are independent evidence layers. None silently stands in for another.</p></div>
    <div class='layer-grid'>""" + decision + telemetry + readiness + "</div></section>"


def _browser_summary(report: dict[str, Any]) -> str:
    execution = report.get("execution", {})
    if not isinstance(execution, dict) or execution.get("adapter_type") != "browser_journey":
        return ""
    requested = int(execution.get("requested_case_count", execution.get("case_count", 0)))
    passed = int(execution.get("passed_case_count", 0))
    review = int(execution.get("failed_case_count", 0))
    blocked = int(execution.get("blocked_case_count", 0))
    session = str(execution.get("browser_session_status", "not_requested")).replace("_", " ")
    if blocked:
        headline = "Protected workflow not reached"
        detail = "Authentication or session setup needs attention before the blocked journeys can test the application. This is not an application defect."
    elif review:
        headline = "Coverage reached; signal needs refinement"
        detail = "The browser reached every planned workflow, but an approved pass signal did not match. This is an assertion review item, not a confirmed product defect."
    else:
        headline = "Workflow evidence captured"
        detail = "Every declared browser journey reached its approved visible signal. This is useful workflow evidence, not an AI decision-quality measurement."
    return """<section class='panel browser-summary'><div class='heading'><div><p class='eyebrow'>BROWSER WORKFLOW RESULT</p><h2>""" + _escape(headline) + """</h2></div><p>""" + _escape(detail) + """</p></div>
    <div class='quick-grid'><div><strong>""" + _escape(session) + "</strong><span>Session</span></div><div><strong>" + _escape(f"{passed}/{requested}") + "</strong><span>Visible signals matched</span></div><div><strong>" + _escape(review) + "</strong><span>Signals to refine</span></div></div></section>"


def _dataset_health(report: dict[str, Any]) -> str:
    evaluation = report.get("evaluation", {})
    health = evaluation.get("dataset_health", {}) if isinstance(evaluation, dict) else {}
    if not isinstance(health, dict) or not health:
        return ""
    distribution = health.get("class_distribution", {})
    distribution = distribution if isinstance(distribution, dict) else {}
    classes = ", ".join(f"{label}: {count}" for label, count in sorted(distribution.items())) or "No labelled classes"
    warnings = health.get("warnings", [])
    warnings = [str(item) for item in warnings if isinstance(item, str)] if isinstance(warnings, list) else []
    warning_html = (
        "<div class='warning-list'><strong>Review before release</strong><ul>"
        + "".join(f"<li>{_escape(item)}</li>" for item in warnings) + "</ul></div>"
        if warnings else "<p class='health-ok'>No dataset-structure warning was detected.</p>"
    )
    return """<section class='detail-section'><p class='eyebrow'>DATASET HEALTH</p><h2>Is this score pack credible?</h2>
    <div class='quick-grid'><div><strong>""" + _escape(health.get("sample_size", 0)) + """</strong><span>Labelled cases</span></div><div><strong>""" + _escape(health.get("class_count", 0)) + """</strong><span>Expected classes</span></div><div><strong>""" + _escape(health.get("duplicate_input_count", 0)) + """</strong><span>Duplicate inputs</span></div></div><p><b>Class distribution:</b> """ + _escape(classes) + "</p>" + warning_html + "</section>"


def _decision_metric_details(metrics: dict[str, Any]) -> str:
    classification = metrics.get("classification", {})
    confidence = metrics.get("confidence", {})
    if not isinstance(classification, dict) or classification.get("measurement_status") != "measured":
        return ""
    confidence = confidence if isinstance(confidence, dict) else {}
    confidence_cases = {
        item.get("case_id"): item for item in confidence.get("case_results", [])
        if isinstance(item, dict) and isinstance(item.get("case_id"), str)
    }
    case_rows = []
    for item in classification.get("case_results", []):
        if not isinstance(item, dict):
            continue
        confidence_item = confidence_cases.get(item.get("case_id"), {})
        result = "Correct" if item.get("correct") else "Incorrect"
        if confidence_item.get("overconfident_failure"):
            result = "Overconfident failure"
        confidence_value = confidence_item.get("confidence")
        confidence_text = f"{float(confidence_value):.3f}" if isinstance(confidence_value, (int, float)) else "Not available"
        case_rows.append(
            "<tr><td>" + _escape(item.get("case_id", "unknown")) + "</td><td>"
            + _escape(item.get("expected_label", "")) + "</td><td>"
            + _escape(item.get("predicted_label", "")) + "</td><td>"
            + _escape(confidence_text) + "</td><td>" + _escape(result) + "</td></tr>"
        )

    labels = classification.get("labels", [])
    labels = [str(item) for item in labels] if isinstance(labels, list) else []
    matrix = classification.get("confusion_matrix", {})
    matrix = matrix if isinstance(matrix, dict) else {}
    matrix_head = "<th>Expected \\ Predicted</th>" + "".join(f"<th>{_escape(label)}</th>" for label in labels)
    matrix_rows = "".join(
        "<tr><th>" + _escape(actual) + "</th>" + "".join(
            f"<td>{_escape(matrix.get(actual, {}).get(predicted, 0) if isinstance(matrix.get(actual), dict) else 0)}</td>"
            for predicted in labels
        ) + "</tr>"
        for actual in labels
    )
    per_class = classification.get("per_class", {})
    per_class = per_class if isinstance(per_class, dict) else {}
    class_rows = "".join(
        "<tr><td>" + _escape(label) + "</td><td>" + _escape(values.get("support", 0))
        + "</td><td>" + _escape(f"{float(values.get('precision', 0)) * 100:.1f}%")
        + "</td><td>" + _escape(f"{float(values.get('recall', 0)) * 100:.1f}%")
        + "</td><td>" + _escape(f"{float(values.get('f1', 0)) * 100:.1f}%") + "</td></tr>"
        for label, values in sorted(per_class.items()) if isinstance(values, dict)
    )
    bin_rows = "".join(
        "<tr><td>" + _escape(f"{float(item.get('lower', 0)):.1f}-{float(item.get('upper', 0)):.1f}")
        + "</td><td>" + _escape(item.get("count", 0))
        + "</td><td>" + _escape(f"{float(item.get('average_confidence', 0)) * 100:.1f}%")
        + "</td><td>" + _escape(f"{float(item.get('accuracy', 0)) * 100:.1f}%") + "</td></tr>"
        for item in confidence.get("bins", []) if isinstance(item, dict)
    )
    return """<section class='detail-section'><p class='eyebrow'>DECISION DETAILS</p><h2>Cases behind the score</h2>
    <table><thead><tr><th>Case</th><th>Expected</th><th>Observed</th><th>Confidence</th><th>Result</th></tr></thead><tbody>""" + "".join(case_rows) + """</tbody></table>
    <h3>Confusion matrix</h3><table><thead><tr>""" + matrix_head + "</tr></thead><tbody>" + matrix_rows + """</tbody></table>
    <h3>Per-class quality</h3><table><thead><tr><th>Class</th><th>Support</th><th>Precision</th><th>Recall</th><th>F1</th></tr></thead><tbody>""" + class_rows + """</tbody></table>
    <h3>Confidence calibration bins</h3><table><thead><tr><th>Confidence range</th><th>Cases</th><th>Average confidence</th><th>Accuracy</th></tr></thead><tbody>""" + bin_rows + "</tbody></table></section>"


def _measurement_readiness(readiness: object) -> str:
    entries = readiness if isinstance(readiness, list) else []
    rows = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", "not_measurable"))
        trust = str(item.get("trust_status", "missing"))
        badge = _trust_label(trust) if status == "measured" else _status_label(status)
        observation = str(item.get("reason", "") or item.get("next_step", "No compatible local evidence was supplied."))
        rows.append(
            "<details class='readiness-card'><summary>"
            f"<span><strong>{_escape(item.get('title', 'Local metric'))}</strong><small>{_escape(observation)}</small></span>"
            f"<b>{_escape(badge)}</b></summary><div><p><b>YOU DEFINE</b>{_escape(item.get('user_supplies', 'A customer-approved local expectation.'))}</p>"
            f"<p><b>APPLICATION EMITS</b>{_escape(item.get('application_emits', 'Compatible redacted local evidence.'))}</p>"
            f"<p><b>MINIMUM EVIDENCE</b>{_escape(item.get('minimum', 'A complete validated local evidence set.'))}</p>"
            f"<p><b>LOCAL SOURCE</b>{_escape(item.get('source', 'Local adapter or telemetry evidence.'))}</p>"
            f"<p><b>NEXT ACTION</b>{_escape(item.get('next_step', 'Supply a complete validated local evidence set, then rerun.'))}</p></div></details>"
        )
    return """<section class='detail-section'><p class='eyebrow'>MEASUREMENT READINESS</p><h2>Evidence requirements</h2>
    <p>Each metric states what your team defines, what the application must emit locally, and the minimum evidence PRE-D requires. Evidence IDs alone measure reference alignment, not whether an answer's claims are grounded.</p>""" + "".join(rows) + "</section>"


def _evidence_preflight(preflight: object) -> str:
    """Render archived pre-run expectations from older report schemas."""
    if not isinstance(preflight, dict) or not isinstance(preflight.get("metrics"), list):
        return ""
    rows = []
    for item in preflight["metrics"]:
        if not isinstance(item, dict):
            continue
        missing = item.get("missing", [])
        missing_text = " ".join(str(value) for value in missing if isinstance(value, str)) or "No remaining preflight gap."
        rows.append(
            "<details class='readiness-card'><summary><span><b>" + _escape(str(item.get("status", "unknown")).replace("_", " ").upper())
            + "</b><strong>" + _escape(item.get("title", item.get("metric", "Metric")))
            + "</strong><small>" + _escape(item.get("case_coverage", "No case coverage information."))
            + "</small></span><span>" + _escape(item.get("source", "local evidence")) + "</span></summary><div>"
            + "<p><b>MISSING OR PENDING</b>" + _escape(missing_text) + "</p>"
            + "<p><b>MINIMUM EVIDENCE</b>" + _escape(item.get("minimum", "A complete validated local evidence set."))
            + "</p></div></details>"
        )
    if not rows:
        return ""
    return """<section class='detail-section'><p class='eyebrow'>ARCHIVED PRE-RUN EXPECTATION</p><h2>What the plan expected before execution</h2>
    <p>This historical preflight did not observe the completed run. Final metric states and measurement readiness below supersede it.</p>""" + "".join(rows) + "</section>"


def _coverage_details(report: dict[str, Any]) -> str:
    coverage = report.get("coverage", {})
    coverage = coverage if isinstance(coverage, dict) else {}
    discovered = coverage.get("discovered", {}) if isinstance(coverage.get("discovered"), dict) else {}
    approved = coverage.get("approved", {}) if isinstance(coverage.get("approved"), dict) else {}
    executed = coverage.get("executed", {}) if isinstance(coverage.get("executed"), dict) else {}
    trust = coverage.get("metric_trust", {}) if isinstance(coverage.get("metric_trust"), dict) else {}
    if executed.get("kind") == "decision_evaluation":
        title = "Decision evaluation coverage"
        values = (
            ("Executed", executed.get("case_count", 0)),
            ("Correct", executed.get("correct_case_count", 0)),
            ("Incorrect", executed.get("incorrect_case_count", 0)),
            ("Blocked", executed.get("blocked_case_count", 0)),
        )
    else:
        title = "Browser workflow coverage"
        values = (
            ("Executed", executed.get("case_count", 0)),
            ("Passed", executed.get("passed_case_count", 0)),
            ("Assertion review", executed.get("failed_case_count", 0)),
            ("Blocked", executed.get("blocked_case_count", 0)),
        )
    cards = "".join(f"<div><strong>{_escape(value)}</strong><span>{_escape(label)}</span></div>" for label, value in values)
    trust_cards = "".join(
        f"<div class='{state}'><strong>{_escape(trust.get(state + '_count', 0))}</strong><span>{state.title()} metrics</span></div>"
        for state in ("verified", "declared", "missing")
    )
    return """<section class='detail-section'><p class='eyebrow'>SCOPE AND COVERAGE</p><h2>""" + _escape(title) + """</h2>
    <p>Discovery identifies local candidates. Execution counts cases; metric trust separately states what PRE-D verified, accepted as declared, or could not measure.</p><div class='quick-grid'>""" + cards + "</div><div class='quick-grid metric-trust-grid'>" + trust_cards + "</div></section>"


def _diagnostics(report: dict[str, Any]) -> str:
    execution = report.get("execution", {})
    execution = execution if isinstance(execution, dict) else {}
    diagnostics = execution.get("browser_case_diagnostics", [])
    if not isinstance(diagnostics, list) or not diagnostics:
        return ""
    rows = "".join(
        "<tr>"
        f"<td>{_escape(item.get('case_id', 'unknown'))}</td><td>{_escape(item.get('outcome', 'unknown'))}</td>"
        f"<td>{_escape(item.get('failure_stage', 'workflow_execution'))}</td><td>{_escape(item.get('failure_kind', ''))}</td></tr>"
        for item in diagnostics if isinstance(item, dict)
    )
    return """<section class='detail-section'><p class='eyebrow'>BROWSER TRACE</p><h2>Workflow diagnostics</h2>
    <table><thead><tr><th>Case</th><th>Outcome</th><th>Stage</th><th>Detail</th></tr></thead><tbody>""" + rows + "</tbody></table></section>"


def render_local_report(report: dict[str, Any]) -> str:
    """Render a local-only report that prioritizes the run boundary over detail."""
    subject = report.get("subject", {})
    subject = subject if isinstance(subject, dict) else {}
    evaluation = report.get("evaluation", {})
    evaluation = evaluation if isinstance(evaluation, dict) else {}
    metrics = report.get("metrics", {})
    metrics = metrics if isinstance(metrics, dict) else {}
    required_dimensions = evaluation.get("required_dimensions", [])
    names = metric_names(metrics, required_dimensions)
    readiness = report.get("measurement_readiness")
    if not isinstance(readiness, list):
        readiness = build_measurement_readiness(metrics, required_dimensions)
    preflight = report.get("evidence_preflight")
    payload = _escape(json.dumps(report, indent=2, ensure_ascii=True))
    method = str(evaluation.get("scorecard_type", "local_evaluation")).replace("_", " ")
    decision_task = evaluation.get("decision_task")
    task_meta = (
        "<div>TASK <span>" + _escape(decision_task) + "</span></div>"
        if isinstance(decision_task, str) and decision_task else ""
    )
    advanced_declared = sum(
        1 for name in names
        if name not in {"workflow_coverage", "classification", "confidence", "decision_evidence"}
        and _trust_status(metrics.get(name)) == "declared"
    )
    declared_label = "metric was" if advanced_declared == 1 else "metrics were"
    validation_verb = "was" if advanced_declared == 1 else "were"
    declared_notice = (
        f"<p class='declared-notice'>{advanced_declared} advanced {declared_label} accepted as target-declared evidence and {validation_verb} not independently validated.</p>"
        if advanced_declared else ""
    )
    return """<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>PRE-D Local Evaluation Report</title><style>
:root{--ink:#0b1416;--panel:#142328;--line:#395055;--muted:#b9c5c3;--lime:#c9f36b;--coral:#ff8464;--gold:#f5cc67;--green:#6fdb9a;--white:#f8fbf7}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 100% 0,#243f3f 0,transparent 31rem),var(--ink);color:var(--white);font:16px Georgia,serif}main{max-width:1180px;margin:0 auto;padding:28px}.hero,.panel{border:1px solid var(--line);background:rgba(20,35,40,.95)}.hero{padding:38px;background:linear-gradient(135deg,rgba(28,51,54,.98),rgba(13,25,28,.98));box-shadow:10px 10px 0 rgba(0,0,0,.22)}.hero-top,.heading{display:flex;justify-content:space-between;gap:24px;align-items:flex-start}.eyebrow,.state{margin:0 0 12px;color:var(--coral);font:700 11px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.16em}.hero h1{margin:0;font-size:clamp(40px,6vw,72px);font-weight:400;line-height:.92;letter-spacing:-.05em}.hero h1 em{color:var(--coral)}.hero p{max-width:670px;color:var(--muted);font-size:18px;line-height:1.5}.hero .declared-notice{max-width:none;padding:12px 14px;border:1px solid var(--coral);background:rgba(255,132,100,.1);color:#ffd4c8;font:700 12px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.04em}.local-badge{padding:8px 10px;color:var(--lime);border:1px solid rgba(201,243,107,.45);font:700 10px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em;white-space:nowrap}.hero-meta{display:flex;gap:14px;flex-wrap:wrap;margin-top:30px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font:12px ui-monospace,SFMono-Regular,Consolas,monospace}.hero-meta span{color:var(--white)}.panel{margin-top:18px;padding:26px}.heading h2,.detail-section h2,.confidence-warning h2{margin:0;font-size:31px;font-weight:400;letter-spacing:-.035em}.heading>p{max-width:480px;margin:4px 0;color:var(--muted);line-height:1.5}.layer-grid,.metric-grid,.quick-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-top:22px}.layer-card,.metric-card,.quick-grid>div{min-height:154px;padding:18px;background:#101d20;border:1px solid var(--line)}.layer-card,.metric-card{border-top:4px solid var(--gold)}.layer-card.measured,.layer-card.connected,.layer-card.evidence-ready,.layer-card.verified-locally,.metric-card.verified{border-top-color:var(--green)}.layer-card.not-run,.layer-card.not-connected,.layer-card.workflow-evidence-only,.metric-card.missing,.metric-card.not-measured{border-top-color:#718a92}.metric-card.declared{border:2px dashed var(--coral);background:repeating-linear-gradient(135deg,#161f20,#161f20 12px,#192527 12px,#192527 24px)}.layer-card h3,.metric-card h3{margin:10px 0 0;font-size:21px;font-weight:400}.layer-card p,.confidence-warning p{margin:18px 0 0;color:var(--muted);font-size:14px;line-height:1.45}.layer-card.measured .state,.layer-card.connected .state,.layer-card.evidence-ready .state,.layer-card.verified-locally .state,.metric-card.verified .state{color:var(--green)}.metric-card .state{display:inline-block;color:var(--gold)}.metric-card.declared .state{color:var(--coral)}.metric-card .trust-warning{margin:14px 0 0;padding:8px;border-left:3px solid var(--coral);color:#ffd4c8;font:700 10px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.04em;line-height:1.45}.metric-card dl{display:grid;grid-template-columns:112px 1fr;gap:9px 12px;margin:18px 0 0}.metric-card dt{color:var(--muted);font:700 9px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em;text-transform:uppercase}.metric-card dd{margin:0;color:var(--white);font-size:13px;line-height:1.4}.metric-card.declared dd{color:#d6c5bd}.representativeness{display:inline-block;margin-left:8px;padding:3px 6px;border:1px solid var(--coral);color:var(--coral);font:700 9px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em}.quick-grid>div{min-height:104px;border-top:3px solid #597077}.quick-grid>div.verified{border-top-color:var(--green)}.quick-grid>div.declared,.quick-grid>div.self-attested{border-top-color:var(--coral);background:#211b1a}.quick-grid>div.missing{border-top-color:#718a92}.quick-grid strong{display:block;color:var(--lime);font-size:28px;font-weight:400}.quick-grid>div.declared strong{color:var(--coral)}.quick-grid span{display:block;margin-top:10px;color:var(--muted);font:700 10px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.09em;text-transform:uppercase}.decision-summary{border-left:4px solid var(--green)}.browser-summary{border-left:4px solid #718a92}.confidence-warning{border-left:4px solid var(--gold)}.confidence-warning .state{display:block;color:var(--gold)}details{margin-top:18px;border:1px solid var(--line);background:#0b1416}details>summary{padding:16px;color:var(--lime);cursor:pointer;font:700 11px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em}.detail-section{padding:24px;border-top:1px solid var(--line)}.detail-section:first-of-type{border-top:0}.detail-section>p:not(.eyebrow){max-width:760px;color:var(--muted);line-height:1.5}.detail-section h3{margin:28px 0 10px;font-weight:400}.warning-list{margin-top:18px;padding:14px;border-left:4px solid var(--gold);background:#101d20}.warning-list strong{color:var(--gold)}.warning-list li{margin-top:8px;color:var(--muted);line-height:1.4}.health-ok{color:var(--green)!important}.readiness-card{margin-top:8px;border:1px solid var(--line);background:#101d20}.readiness-card summary{display:flex;justify-content:space-between;gap:12px;padding:14px;cursor:pointer}.readiness-card summary strong{display:block;font-weight:400}.readiness-card summary small{display:block;margin-top:5px;color:var(--muted);font-size:13px;line-height:1.35}.readiness-card summary b,.readiness-card div b{color:var(--gold);font:700 10px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em}.readiness-card div{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:0 14px 14px}.readiness-card div p{margin:0;color:var(--muted);font-size:13px;line-height:1.45}.readiness-card div p b{display:block;margin-bottom:5px;color:var(--white)}table{width:100%;border-collapse:collapse;font:13px ui-monospace,SFMono-Regular,Consolas,monospace}th,td{padding:11px 8px;border-top:1px solid var(--line);text-align:left}th{color:var(--muted);font-size:10px;letter-spacing:.08em;text-transform:uppercase}pre{overflow:auto;margin:0;padding:16px;color:#cce0dd;background:#050b0d;font:12px ui-monospace,SFMono-Regular,Consolas,monospace;line-height:1.45}@media(max-width:720px){main{padding:12px}.hero,.panel{padding:20px}.hero-top,.heading{display:block}.local-badge{display:inline-block;margin-top:16px}.readiness-card div{grid-template-columns:1fr}.metric-card dl{grid-template-columns:1fr}.detail-section{overflow-x:auto}}@media print{body{background:#fff;color:#111}main{max-width:none;padding:0}.hero,.panel,.layer-card,.metric-card,.quick-grid>div,.readiness-card,details{background:#fff;color:#111;box-shadow:none;border-color:#888}.hero p,.heading>p,.layer-card p,.detail-section>p:not(.eyebrow),.readiness-card summary small,.readiness-card div p{color:#333}.metric-card dd{color:#111}}</style></head><body><main>
<section class='hero'><div class='hero-top'><div><p class='eyebrow'>PRE-D / LOCAL EVALUATION REPORT</p><h1>Evidence before <em>assurance.</em></h1></div><span class='local-badge'>LOCAL ONLY / NOT UPLOADED</span></div><p>One report, three distinct local evidence layers: application workflow, AI decisions, and operational telemetry. Missing evidence stays visible; it is never converted into a product verdict.</p>""" + declared_notice + """<div class='hero-meta'><div>SUBJECT <span>""" + _escape(subject.get("agent_id", "unknown")) + "</span></div><div>VERSION <span>" + _escape(subject.get("subject_version", "unknown")) + "</span></div><div>DATASET <span>" + _escape(subject.get("dataset_version", "unknown")) + "</span></div><div>METHOD <span>" + _escape(method) + "</span></div>" + task_meta + "<div>RUNNER <span>" + _escape(report.get("runner_version", "unknown")) + "</span></div></div></section>" + _decision_summary(report) + _trust_summary(report, metrics, names) + _confidence_warning(metrics) + _evaluation_layers(report) + _browser_summary(report) + """<details><summary>VIEW DETAILED LOCAL METRICS</summary><section class='detail-section'><p class='eyebrow'>SCORECARD</p><h2>Metric trust and results</h2><div class='metric-grid'>""" + _metric_cards(metrics, names) + "</div></section>" + _dataset_health(report) + _decision_metric_details(metrics) + _evidence_preflight(preflight) + _measurement_readiness(readiness) + "</details><details><summary>VIEW SCOPE, COVERAGE, AND DIAGNOSTICS</summary>" + _coverage_details(report) + _diagnostics(report) + "</details><details><summary>VIEW REDACTED RESULT DATA</summary><pre>" + payload + "</pre></details></main></body></html>"
