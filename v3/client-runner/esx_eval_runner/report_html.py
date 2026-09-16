"""Self-contained local HTML report generation."""

from __future__ import annotations

import html
import json
from typing import Any


_METRIC_ORDER = (
    "workflow_coverage", "classification", "confidence", "decision_evidence",
    "groundedness", "security", "trajectory", "tool_use", "rag", "robustness",
    "judge_agreement", "reproducibility", "cost_efficiency",
)

_MEASUREMENT_GUIDANCE = {
    "workflow_coverage": {
        "title": "Browser workflow evidence",
        "required": "A declared browser journey with an approved observable signal and local step diagnostics.",
        "source": "Local Playwright browser execution only.",
    },
    "classification": {
        "title": "Classification quality",
        "required": "One expected outcome and one observed outcome for every completed case. At least two expected classes are needed for a meaningful quality score.",
        "source": "Labelled local test cases plus a decision endpoint or adapter result.",
    },
    "confidence": {
        "title": "Confidence calibration",
        "required": "An observed confidence from 0 to 1 for every completed labelled decision case.",
        "source": "Local decision endpoint or adapter response metadata.",
    },
    "decision_evidence": {
        "title": "Decision evidence",
        "required": "Expected evidence IDs or abstention requirements, plus matching opaque fields from the local decision endpoint.",
        "source": "Local decision API or local adapter response metadata.",
    },
    "groundedness": {
        "title": "Groundedness",
        "required": "Answer claims linked to cited evidence IDs, an integrity check, and a local support assessment for each claim.",
        "source": "Redacted local adapter claims or telemetry evidence.",
    },
    "security": {
        "title": "Security behavior",
        "required": "Labelled positive and negative controls, observed outcomes, and evidence IDs.",
        "source": "Approved security test pack and local adapter or telemetry evidence.",
    },
    "trajectory": {
        "title": "Agent trajectory",
        "required": "Expected milestones plus ordered local trace events, including policy and scope violations.",
        "source": "Redacted local agent trace or framework telemetry.",
    },
    "tool_use": {
        "title": "Tool-use quality",
        "required": "Expected tool names, observed tool names, and authorization and result-validity outcomes for each case.",
        "source": "Redacted local tool trace and expectation map.",
    },
    "rag": {
        "title": "RAG quality",
        "required": "Expected relevant document IDs, retrieved and cited document IDs, and answer-claim support evidence.",
        "source": "Local retrieval trace, citation metadata, and redacted evidence.",
    },
    "robustness": {
        "title": "Robustness",
        "required": "Baseline and perturbed versions of the same labelled case with observed outcomes.",
        "source": "Local perturbation pack and adapter results.",
    },
    "judge_agreement": {
        "title": "Judge agreement",
        "required": "Per-case decisions from at least two approved judges.",
        "source": "Local or customer-approved private judge outputs.",
    },
    "reproducibility": {
        "title": "Repeatability",
        "required": "Per-case outputs from at least two independent runs of the same configuration.",
        "source": "Repeated local-run result records.",
    },
    "cost_efficiency": {
        "title": "Cost and latency",
        "required": "Redacted per-case cost, token, request, retry, tool-call, timeout, and latency observations.",
        "source": "Local provider usage metadata or instrumentation.",
    },
}


def _escape(value: object) -> str:
    return html.escape(str(value))


def _title(name: str) -> str:
    return _MEASUREMENT_GUIDANCE.get(name, {}).get("title", name.replace("_", " ").title())


def _metric_status(metric: object) -> str:
    return str(metric.get("measurement_status", "not_measurable")) if isinstance(metric, dict) else "not_measurable"


def _status_label(status: str) -> str:
    return {"measured": "MEASURED", "not_applicable": "NOT RUN"}.get(status, "EVIDENCE NEEDED")


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


def _metric_names(metrics: dict[str, Any]) -> list[str]:
    names = [
        name for name in _METRIC_ORDER
        if name in metrics and _metric_status(metrics.get(name)) != "not_applicable"
    ]
    names.extend(name for name in metrics if name not in names and _metric_status(metrics.get(name)) != "not_applicable")
    return names


def _metric_cards(metrics: dict[str, Any], names: list[str]) -> str:
    cards = []
    for name in names:
        metric = metrics.get(name, {})
        metric = metric if isinstance(metric, dict) else {}
        status = _metric_status(metric)
        measured = status == "measured"
        detail = _primary_signal(name, metric) if measured else str(metric.get("reason", "No compatible local evidence was supplied."))
        limitations = metric.get("limitations", [])
        if measured and isinstance(limitations, list) and limitations:
            detail += " " + str(limitations[0])
        cards.append(
            "<article class='metric-card'>"
            f"<span class='state {_escape(status)}'>{_escape(_status_label(status))}</span>"
            f"<h3>{_escape(_title(name))}</h3><p>{_escape(detail)}</p></article>"
        )
    return "".join(cards)


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
        decision = _layer_card(
            "Decision evaluation", "MEASURED",
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
    if is_browser:
        readiness = _layer_card(
            "PRE-D local release readiness", "WORKFLOW EVIDENCE ONLY",
            "Workflow reachability is available for review. Decision-quality readiness was not evaluated because this run did not use a decision endpoint or local adapter.",
        )
    elif _metric_status(classification) == "measured" and _metric_status(confidence) == "measured":
        readiness = _layer_card(
            "PRE-D local release readiness", "DEEP EVIDENCE PENDING" if pending else "EVIDENCE READY",
            (
                "Decision baseline is measured locally. Add telemetry or adapter evidence before making claims about " + ", ".join(_title(item).lower() for item in pending) + "."
                if pending else
                "Every metric requested by this plan has compatible local evidence. Review the detailed evidence before making your team's release decision."
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


def _measurement_readiness(metrics: dict[str, Any]) -> str:
    rows = []
    for name in _metric_names(metrics):
        metric = metrics.get(name, {})
        metric = metric if isinstance(metric, dict) else {}
        guidance = _MEASUREMENT_GUIDANCE.get(name, {"title": _title(name), "required": "Compatible local evidence.", "source": "Local adapter or telemetry."})
        status = _metric_status(metric)
        observation = _primary_signal(name, metric) if status == "measured" else str(metric.get("reason", "No compatible local evidence was supplied."))
        rows.append(
            "<details class='readiness-card'><summary>"
            f"<span><strong>{_escape(guidance['title'])}</strong><small>{_escape(observation)}</small></span>"
            f"<b>{_escape(_status_label(status))}</b></summary><div><p><b>TO MEASURE</b>{_escape(guidance['required'])}</p>"
            f"<p><b>LOCAL SOURCE</b>{_escape(guidance['source'])}</p></div></details>"
        )
    return """<section class='detail-section'><p class='eyebrow'>MEASUREMENT READINESS</p><h2>Evidence requirements</h2>
    <p>Only local, redacted evidence creates a score. Evidence IDs alone measure reference alignment, not whether an answer's claims are grounded.</p>""" + "".join(rows) + "</section>"


def _coverage_details(report: dict[str, Any]) -> str:
    coverage = report.get("coverage", {})
    coverage = coverage if isinstance(coverage, dict) else {}
    discovered = coverage.get("discovered", {}) if isinstance(coverage.get("discovered"), dict) else {}
    approved = coverage.get("approved", {}) if isinstance(coverage.get("approved"), dict) else {}
    executed = coverage.get("executed", {}) if isinstance(coverage.get("executed"), dict) else {}
    measured = coverage.get("measured", {}) if isinstance(coverage.get("measured"), dict) else {}
    values = (
        ("Discovered", discovered.get("component_count", 0)),
        ("Approved", approved.get("component_count", 0)),
        ("Executed", executed.get("case_count", 0)),
        ("Measured", f"{measured.get('dimension_count', 0)}/{measured.get('required_dimension_count', 0)}"),
    )
    cards = "".join(f"<div><strong>{_escape(value)}</strong><span>{_escape(label)}</span></div>" for label, value in values)
    return """<section class='detail-section'><p class='eyebrow'>SCOPE AND COVERAGE</p><h2>Discovery is not execution</h2>
    <p>Discovery identifies local candidates. Only approved and completed cases count as coverage; only validated evidence creates a metric.</p><div class='quick-grid'>""" + cards + "</div></section>"


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
    names = _metric_names(metrics)
    payload = _escape(json.dumps(report, indent=2, ensure_ascii=True))
    method = str(evaluation.get("scorecard_type", "local_evaluation")).replace("_", " ")
    decision_task = evaluation.get("decision_task")
    task_meta = (
        "<div>TASK <span>" + _escape(decision_task) + "</span></div>"
        if isinstance(decision_task, str) and decision_task else ""
    )
    return """<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>PRE-D Local Evaluation Report</title><style>
:root{--ink:#0b1416;--panel:#142328;--line:#395055;--muted:#b9c5c3;--lime:#c9f36b;--coral:#ff8464;--gold:#f5cc67;--green:#6fdb9a;--white:#f8fbf7}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 100% 0,#243f3f 0,transparent 31rem),var(--ink);color:var(--white);font:16px Georgia,serif}main{max-width:1180px;margin:0 auto;padding:28px}.hero,.panel{border:1px solid var(--line);background:rgba(20,35,40,.95)}.hero{padding:38px;background:linear-gradient(135deg,rgba(28,51,54,.98),rgba(13,25,28,.98));box-shadow:10px 10px 0 rgba(0,0,0,.22)}.hero-top,.heading{display:flex;justify-content:space-between;gap:24px;align-items:flex-start}.eyebrow,.state{margin:0 0 12px;color:var(--coral);font:700 11px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.16em}.hero h1{margin:0;font-size:clamp(40px,6vw,72px);font-weight:400;line-height:.92;letter-spacing:-.05em}.hero h1 em{color:var(--coral)}.hero p{max-width:670px;color:var(--muted);font-size:18px;line-height:1.5}.local-badge{padding:8px 10px;color:var(--lime);border:1px solid rgba(201,243,107,.45);font:700 10px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em;white-space:nowrap}.hero-meta{display:flex;gap:14px;flex-wrap:wrap;margin-top:30px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font:12px ui-monospace,SFMono-Regular,Consolas,monospace}.hero-meta span{color:var(--white)}.panel{margin-top:18px;padding:26px}.heading h2,.detail-section h2{margin:0;font-size:31px;font-weight:400;letter-spacing:-.035em}.heading>p{max-width:480px;margin:4px 0;color:var(--muted);line-height:1.5}.layer-grid,.metric-grid,.quick-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-top:22px}.layer-card,.metric-card,.quick-grid>div{min-height:154px;padding:18px;background:#101d20;border:1px solid var(--line)}.layer-card{border-top:4px solid var(--gold)}.layer-card.measured,.layer-card.connected,.layer-card.evidence-ready{border-top-color:var(--green)}.layer-card.not-run,.layer-card.not-connected,.layer-card.workflow-evidence-only{border-top-color:#718a92}.layer-card h3,.metric-card h3{margin:10px 0 0;font-size:21px;font-weight:400}.layer-card p,.metric-card p{margin:18px 0 0;color:var(--muted);font-size:14px;line-height:1.45}.layer-card.measured .state,.layer-card.connected .state,.layer-card.evidence-ready .state{color:var(--green)}.metric-card .state{display:block;color:var(--gold)}.quick-grid>div{min-height:104px;border-top:3px solid #597077}.quick-grid strong{display:block;color:var(--lime);font-size:28px;font-weight:400}.quick-grid span{display:block;margin-top:10px;color:var(--muted);font:700 10px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.09em;text-transform:uppercase}.browser-summary{border-left:4px solid #718a92}details{margin-top:18px;border:1px solid var(--line);background:#0b1416}details>summary{padding:16px;color:var(--lime);cursor:pointer;font:700 11px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em}.detail-section{padding:24px;border-top:1px solid var(--line)}.detail-section:first-of-type{border-top:0}.detail-section>p:not(.eyebrow){max-width:760px;color:var(--muted);line-height:1.5}.readiness-card{margin-top:8px;border:1px solid var(--line);background:#101d20}.readiness-card summary{display:flex;justify-content:space-between;gap:12px;padding:14px;cursor:pointer}.readiness-card summary strong{display:block;font-weight:400}.readiness-card summary small{display:block;margin-top:5px;color:var(--muted);font-size:13px;line-height:1.35}.readiness-card summary b,.readiness-card div b{color:var(--gold);font:700 10px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em}.readiness-card div{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:0 14px 14px}.readiness-card div p{margin:0;color:var(--muted);font-size:13px;line-height:1.45}.readiness-card div p b{display:block;margin-bottom:5px;color:var(--white)}table{width:100%;border-collapse:collapse;font:13px ui-monospace,SFMono-Regular,Consolas,monospace}th,td{padding:11px 8px;border-top:1px solid var(--line);text-align:left}th{color:var(--muted);font-size:10px;letter-spacing:.08em;text-transform:uppercase}pre{overflow:auto;margin:0;padding:16px;color:#cce0dd;background:#050b0d;font:12px ui-monospace,SFMono-Regular,Consolas,monospace;line-height:1.45}@media(max-width:720px){main{padding:12px}.hero,.panel{padding:20px}.hero-top,.heading{display:block}.local-badge{display:inline-block;margin-top:16px}.readiness-card div{grid-template-columns:1fr}}@media print{body{background:#fff;color:#111}main{max-width:none;padding:0}.hero,.panel,.layer-card,.metric-card,.quick-grid>div,.readiness-card,details{background:#fff;color:#111;box-shadow:none;border-color:#888}.hero p,.heading>p,.layer-card p,.metric-card p,.detail-section>p:not(.eyebrow),.readiness-card summary small,.readiness-card div p{color:#333}}</style></head><body><main>
<section class='hero'><div class='hero-top'><div><p class='eyebrow'>PRE-D / LOCAL EVALUATION REPORT</p><h1>Evidence before <em>assurance.</em></h1></div><span class='local-badge'>LOCAL ONLY / NOT UPLOADED</span></div><p>One report, three distinct local evidence layers: application workflow, AI decisions, and operational telemetry. Missing evidence stays visible; it is never converted into a product verdict.</p><div class='hero-meta'><div>SUBJECT <span>""" + _escape(subject.get("agent_id", "unknown")) + "</span></div><div>VERSION <span>" + _escape(subject.get("subject_version", "unknown")) + "</span></div><div>DATASET <span>" + _escape(subject.get("dataset_version", "unknown")) + "</span></div><div>METHOD <span>" + _escape(method) + "</span></div>" + task_meta + "<div>RUNNER <span>" + _escape(report.get("runner_version", "unknown")) + "</span></div></div></section>" + _evaluation_layers(report) + _browser_summary(report) + """<details><summary>VIEW DETAILED LOCAL METRICS</summary><section class='detail-section'><p class='eyebrow'>SCORECARD</p><h2>Measured dimensions</h2><div class='metric-grid'>""" + _metric_cards(metrics, names) + "</div></section>" + _measurement_readiness(metrics) + "</details><details><summary>VIEW SCOPE, COVERAGE, AND DIAGNOSTICS</summary>" + _coverage_details(report) + _diagnostics(report) + "</details><details><summary>VIEW REDACTED RESULT DATA</summary><pre>" + payload + "</pre></details></main></body></html>"
