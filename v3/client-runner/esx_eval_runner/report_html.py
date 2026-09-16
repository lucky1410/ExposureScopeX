"""Self-contained local HTML report generation."""

from __future__ import annotations

import html
import json
from typing import Any


_METRIC_ORDER = (
    "workflow_coverage", "classification", "confidence", "groundedness", "security", "trajectory", "tool_use",
    "rag", "robustness", "judge_agreement", "reproducibility", "cost_efficiency",
)

_MEASUREMENT_GUIDANCE = {
    "workflow_coverage": {
        "title": "Workflow assurance",
        "required": "A declared browser journey with an approved observable signal and local step diagnostics.",
        "source": "Local Playwright browser execution only.",
    },
    "classification": {
        "title": "Classification quality",
        "required": "One expected outcome and one observed outcome for every completed case. At least two expected classes are needed for a meaningful quality score.",
        "source": "Labelled local test cases plus the adapter or browser result.",
    },
    "confidence": {
        "title": "Confidence calibration",
        "required": "An observed confidence from 0 to 1 for every completed labelled case.",
        "source": "Adapter result or model response metadata.",
    },
    "groundedness": {
        "title": "Groundedness",
        "required": "Answer claims linked to cited evidence IDs, an integrity check, and a local support assessment for each claim.",
        "source": "Redacted adapter claims or local telemetry evidence.",
    },
    "security": {
        "title": "Security behavior",
        "required": "Labelled positive and negative security controls, observed attack and detection outcomes, and evidence IDs.",
        "source": "Approved security test pack and local adapter evidence.",
    },
    "trajectory": {
        "title": "Agent trajectory",
        "required": "Expected milestones plus ordered local tool or agent trace events, including policy and scope violations.",
        "source": "Redacted agent trace or framework telemetry.",
    },
    "tool_use": {
        "title": "Tool-use quality",
        "required": "Expected tool names for every labelled case, observed tool names, and explicit authorization and result-validity outcomes for each executed call.",
        "source": "Redacted tool trace plus the telemetry tool-use expectation map.",
    },
    "rag": {
        "title": "RAG quality",
        "required": "Expected relevant document IDs, retrieved document IDs in rank order, cited document IDs, and answer claims for faithfulness.",
        "source": "Retrieval trace, citation metadata, and redacted adapter evidence.",
    },
    "robustness": {
        "title": "Robustness",
        "required": "Baseline and perturbed versions of the same labelled case, with observed outcomes for both.",
        "source": "Local perturbation test pack and adapter results.",
    },
    "judge_agreement": {
        "title": "Judge agreement",
        "required": "Per-case decisions from at least two approved judges. Agreement measures consistency, not correctness.",
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
        "source": "Provider usage metadata or local instrumentation.",
    },
}


def _escape(value: object) -> str:
    return html.escape(str(value))


def _title(name: str) -> str:
    return _MEASUREMENT_GUIDANCE.get(name, {}).get("title", name.replace("_", " ").title())


def _metric_status(metric: object) -> str:
    if not isinstance(metric, dict):
        return "not_measurable"
    return str(metric.get("measurement_status", "not_measurable"))


def _primary_signal(name: str, metric: dict[str, Any]) -> str:
    fields = {
        "workflow_coverage": ("workflow_execution_rate", "Workflow execution", "percent"),
        "classification": ("accuracy", "Accuracy", "percent"),
        "confidence": ("expected_calibration_error", "Expected calibration error", "number"),
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
    names.extend(
        name for name in metrics
        if name not in names and _metric_status(metrics.get(name)) != "not_applicable"
    )
    return names


def _metric_cards(metrics: dict[str, Any], names: list[str] | None = None) -> str:
    cards = []
    for name in names if names is not None else _metric_names(metrics):
        metric = metrics.get(name, {})
        if not isinstance(metric, dict):
            metric = {}
        status = _metric_status(metric)
        measured = status == "measured"
        detail = _primary_signal(name, metric) if measured else str(metric.get("reason", "No compatible local evidence was supplied."))
        limitations = metric.get("limitations", [])
        if measured and isinstance(limitations, list) and limitations:
            detail += " " + str(limitations[0])
        cards.append(
            "<article class='metric-card'>"
            f"<div class='metric-top'><h3>{_escape(_title(name))}</h3><span class='badge {_escape(status)}'>{'MEASURED' if measured else 'EVIDENCE NEEDED'}</span></div>"
            f"<p>{_escape(detail)}</p></article>"
        )
    return "".join(cards)


def _measurement_readiness_section(metrics: dict[str, Any]) -> str:
    """Explain the source requirements for every locally calculated metric."""
    names = _metric_names(metrics)
    rows = []
    for name in names:
        metric = metrics.get(name, {})
        if not isinstance(metric, dict):
            metric = {}
        guidance = _MEASUREMENT_GUIDANCE.get(name, {
            "title": _title(name),
            "required": "A compatible, redacted local observation for this planned dimension.",
            "source": "Local adapter or telemetry evidence.",
        })
        status = _metric_status(metric)
        measured = status == "measured"
        observation = _primary_signal(name, metric) if measured else str(metric.get("reason", "No compatible local evidence was supplied."))
        rows.append(
            f"<details class='readiness-card {_escape(status)}'{' open' if not measured else ''}>"
            "<summary>"
            f"<span><strong>{_escape(guidance['title'])}</strong><small>{_escape(observation)}</small></span>"
            f"<b>{'MEASURED' if measured else 'EVIDENCE NEEDED'}</b>"
            "</summary><div class='readiness-detail'>"
            f"<p><span>TO MEASURE</span>{_escape(guidance['required'])}</p>"
            f"<p><span>LOCAL SOURCE</span>{_escape(guidance['source'])}</p>"
            "</div></details>"
        )
    return """<section class='readiness panel'>
    <div class='section-heading'><div><p class='eyebrow'>MEASUREMENT READINESS</p><h2>What this run can prove</h2></div>
    <p>Scores are calculated only from local, redacted evidence. Browser journeys prove user-visible workflow behavior; they cannot see retrieval, citations, tool calls, or model usage unless local telemetry or an adapter supplies those signals.</p></div>
    <div class='readiness-list'>""" + "".join(rows) + """</div>
    <p class='boundary-note'><strong>Important:</strong> EVIDENCE NEEDED means the signal was absent or insufficient. It does not mean the application passed, failed, or was not tested.</p>
    </section>"""


def _evidence_source_section(report: dict[str, Any]) -> str:
    execution = report.get("execution", {})
    execution = execution if isinstance(execution, dict) else {}
    provenance = execution.get("local_evidence", {})
    provenance = provenance if isinstance(provenance, dict) else {}
    record_count = provenance.get("record_count", 0)
    record_count = record_count if isinstance(record_count, int) and record_count >= 0 else 0
    dimensions = provenance.get("derived_dimensions", [])
    dimensions = [item.replace("_", " ") for item in dimensions if isinstance(item, str)] if isinstance(dimensions, list) else []
    trace = "Captured" if provenance.get("trace_captured") is True else "Not captured"
    detail = ", ".join(dimensions) if dimensions else "No complete metric input was derived automatically."
    return """<section class='evidence-source panel'>
    <div class='section-heading'><div><p class='eyebrow'>EVIDENCE PROVENANCE</p><h2>Automatic local evidence</h2></div>
    <p>PRE-D accepts only redacted operational metadata. This panel shows evidence volume and derivation, never prompt text, model outputs, retrieved content, tool arguments, credentials, or cookies.</p></div>
    <div class='coverage-grid'><div class='coverage-stat'><strong>""" + _escape(record_count) + "</strong><span>Redacted records</span><small>Accepted from the local collector or connector.</small></div><div class='coverage-stat'><strong>" + _escape(len(dimensions)) + "</strong><span>Derived dimensions</span><small>" + _escape(detail) + "</small></div><div class='coverage-stat'><strong>" + _escape(trace) + "</strong><span>Trace envelope</span><small>Metadata-only execution evidence for agent and tool activity.</small></div></div></section>"


def _executive_readout(report: dict[str, Any]) -> str:
    """Give reviewers an honest, high-level conclusion before metric detail."""
    coverage = report.get("coverage", {})
    coverage = coverage if isinstance(coverage, dict) else {}
    executed = coverage.get("executed", {})
    measured = coverage.get("measured", {})
    executed = executed if isinstance(executed, dict) else {}
    measured = measured if isinstance(measured, dict) else {}
    requested = int(executed.get("requested_case_count", 0))
    completed = int(executed.get("case_count", 0))
    blocked = int(executed.get("blocked_case_count", 0))
    measured_count = int(measured.get("dimension_count", 0))
    required_count = int(measured.get("required_dimension_count", 0))
    execution = report.get("execution", {})
    execution = execution if isinstance(execution, dict) else {}
    if execution.get("adapter_type") == "browser_journey":
        conclusion = (
            "This is a browser workflow-assurance run. A completed journey proves only its approved user-visible signal; "
            "it does not create a model classification or confidence score."
        )
    elif blocked:
        conclusion = f"{blocked} protected workflow case(s) stopped before session setup completed. This is a runner coverage boundary, not an application finding."
    elif completed == 0:
        conclusion = "No workflow reached the application. This run cannot support a product-quality conclusion."
    elif required_count and measured_count < required_count:
        conclusion = "The completed workflow evidence is partial. Missing metric inputs are explicitly identified below and are not treated as passing results."
    else:
        conclusion = "All requested metric dimensions for the completed workflow have compatible local evidence. Review the metric definitions and evidence trace before making a release decision."
    facts = (
        ("Workflow coverage", f"{completed}/{requested}", "Completed cases / requested cases"),
        ("Metric evidence", f"{measured_count}/{required_count}", "Measured dimensions / required dimensions"),
        ("Session boundary", blocked, "Protected cases blocked before workflow execution"),
    )
    cards = "".join(
        "<div class='coverage-stat'>"
        f"<strong>{_escape(value)}</strong><span>{_escape(name)}</span><small>{_escape(detail)}</small></div>"
        for name, value, detail in facts
    )
    return """<section class='executive panel'>
    <div class='section-heading'><div><p class='eyebrow'>EXECUTIVE READOUT</p><h2>What this run establishes</h2></div>
    <p>""" + _escape(conclusion) + "</p></div><div class='coverage-grid'>" + cards + "</div></section>"


def _browser_smoke_summary(report: dict[str, Any]) -> str:
    """Translate browser diagnostics into a plain-language coverage conclusion."""
    execution = report.get("execution", {})
    if not isinstance(execution, dict) or execution.get("adapter_type") != "browser_journey":
        return ""
    requested = int(execution.get("requested_case_count", 0))
    passed = int(execution.get("passed_case_count", 0))
    review = int(execution.get("failed_case_count", 0))
    blocked = int(execution.get("blocked_case_count", 0))
    session = str(execution.get("browser_session_status", "not_requested")).replace("_", " ")
    if blocked:
        headline = "Protected workflow not reached"
        detail = "Authentication or session setup needs attention before the blocked journeys can test the application. This is not a product defect."
    elif review:
        headline = "Coverage reached; signal needs refinement"
        detail = "The browser reached every planned workflow, but one or more approved success signals did not match. Review those assertions before treating them as application defects."
    else:
        headline = "Coverage proven for this plan"
        detail = "Every declared browser journey reached its approved visible signal. This confirms workflow reachability only, not deeper AI-quality behavior."
    return """<section class='smoke-summary panel'>
    <div class='section-heading'><div><p class='eyebrow'>BROWSER-ONLY SMOKE SUMMARY</p><h2>""" + _escape(headline) + """</h2></div>
    <p>""" + _escape(detail) + """</p></div><div class='coverage-grid'>
    <div class='coverage-stat'><strong>""" + _escape(session) + """</strong><span>Session</span><small>Authenticated session state is local and scoped to the approved application.</small></div>
    <div class='coverage-stat'><strong>""" + _escape(f"{passed}/{requested}") + """</strong><span>Visible signals matched</span><small>Completed journeys whose approved observable signal was present.</small></div>
    <div class='coverage-stat'><strong>""" + _escape(review) + """</strong><span>Signals to refine</span><small>Assertion review items, not confirmed application defects.</small></div>
    </div></section>"""


def _coverage_section(report: dict[str, Any]) -> str:
    coverage = report.get("coverage")
    if not isinstance(coverage, dict):
        return ""
    discovered = coverage.get("discovered", {})
    approved = coverage.get("approved", {})
    executed = coverage.get("executed", {})
    measured = coverage.get("measured", {})
    if not all(isinstance(value, dict) for value in (discovered, approved, executed, measured)):
        return ""
    blocked = int(executed.get("blocked_case_count", 0))
    reviews = int(executed.get("failed_case_count", 0))
    requested = executed.get("requested_case_count", executed.get("case_count", 0))
    outcome = (
        f"{blocked} browser case(s) stopped at session setup. They did not reach an application workflow and are not product findings. "
        if blocked else ""
    ) + (
        f"{reviews} executed browser assertion(s) need reviewer validation; an assertion mismatch is not an independently confirmed application defect."
        if reviews else "No browser assertion is presented as an independently confirmed application defect."
    )
    facts = (
        ("Discovered", discovered.get("component_count", 0), "Candidate components from local review"),
        ("Approved", approved.get("component_count", 0), "Components explicitly placed in scope"),
        ("Requested", requested, "Cases the plan asked the runner to attempt"),
        ("Executed", executed.get("case_count", 0), "Cases that reached an application workflow"),
        ("Session blocks", blocked, "Cases that never entered the protected workflow"),
        ("Measured", f"{measured.get('dimension_count', 0)}/{measured.get('required_dimension_count', 0)}", "Metric dimensions supported by evidence"),
    )
    cards = "".join(
        "<div class='coverage-stat'>"
        f"<strong>{_escape(value)}</strong><span>{_escape(name)}</span><small>{_escape(detail)}</small></div>"
        for name, value, detail in facts
    )
    areas = coverage.get("capability_areas", [])
    rows = "".join(
        "<tr>"
        f"<td>{_escape(str(item.get('capability_area', 'general')).replace('_', ' '))}</td>"
        f"<td>{_escape(item.get('discovered', 0))}</td><td>{_escape(item.get('approved', 0))}</td>"
        f"<td>{_escape(item.get('executed', 0))}</td><td>{_escape(item.get('passed', 0))}</td>"
        f"<td>{_escape(item.get('failed', 0))}</td><td>{_escape(item.get('blocked', 0))}</td></tr>"
        for item in areas if isinstance(item, dict)
    ) if isinstance(areas, list) else ""
    table = (
        "<div class='table-wrap'><table><thead><tr><th>Capability area</th><th>Discovered</th><th>Approved</th><th>Executed</th><th>Passed</th><th>Review</th><th>Blocked</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></div>" if rows else ""
    )
    return """<section class='coverage panel'>
    <div class='section-heading'><div><p class='eyebrow'>COVERAGE INTEGRITY</p><h2>Discovery is not execution</h2></div>
    <p>Only a completed workflow is executed coverage. Only validated evidence can create a measured score. This distinction prevents discovery breadth from becoming false confidence.</p></div>
    <div class='coverage-grid'>""" + cards + "</div>" + f"<p class='boundary-note'>{_escape(outcome)}</p>{table}</section>"


def _next_actions(report: dict[str, Any]) -> str:
    metrics = report.get("metrics", {})
    execution = report.get("execution", {})
    coverage = report.get("coverage", {})
    metrics = metrics if isinstance(metrics, dict) else {}
    execution = execution if isinstance(execution, dict) else {}
    coverage = coverage if isinstance(coverage, dict) else {}
    executed = coverage.get("executed", {}) if isinstance(coverage.get("executed"), dict) else {}
    actions: list[tuple[str, str]] = []
    if int(executed.get("blocked_case_count", 0)):
        actions.append(("Establish the approved session", "Run the local interactive browser-auth flow for the selected test persona, then reuse its scoped session for post-login journeys."))
    if executed.get("case_count", 0) == 0 and not int(executed.get("blocked_case_count", 0)):
        actions.append(("Run an approved workflow", "Confirm the planned route and expected user-visible signal, then execute the approved browser or adapter case."))
    gaps = [name for name in ("groundedness", "rag", "trajectory", "tool_use", "security") if _metric_status(metrics.get(name)) != "measured"]
    if gaps:
        actions.append(("Connect deeper evidence", "Add redacted local telemetry or adapter observations for " + ", ".join(_title(name).lower() for name in gaps) + "."))
    if _metric_status(metrics.get("cost_efficiency")) != "measured":
        actions.append(("Capture operational usage", "Supply redacted provider usage and timing metadata to calculate local cost and latency."))
    if not actions:
        actions.append(("Review the retained evidence", "All displayed dimensions have local evidence. Review the Assurance Graph and raw redacted result data before making a release decision."))
    items = "".join(
        "<article class='action-card'><span>0" + str(index) + "</span>"
        f"<div><h3>{_escape(title)}</h3><p>{_escape(detail)}</p></div></article>"
        for index, (title, detail) in enumerate(actions[:3], start=1)
    )
    session = str(execution.get("browser_session_status", "not_requested")).replace("_", " ")
    return """<section class='next-actions panel'>
    <div class='section-heading'><div><p class='eyebrow'>NEXT SAFE ACTION</p><h2>Close the evidence gap</h2></div>
    <p>Browser session: """ + _escape(session) + """. These actions preserve the local-only boundary and do not request raw prompts, customer data, or production credentials.</p></div>
    <div class='action-grid'>""" + items + "</div></section>"


def _diagnostic_section(report: dict[str, Any]) -> str:
    execution = report.get("execution", {})
    if not isinstance(execution, dict):
        return ""
    diagnostics = execution.get("browser_case_diagnostics", [])
    if not isinstance(diagnostics, list) or not diagnostics:
        return ""
    rows = "".join(
        "<tr>"
        f"<td>{_escape(item.get('case_id', 'unknown'))}</td>"
        f"<td>{_escape(str(item.get('capability_area', 'general')).replace('_', ' '))}</td>"
        f"<td>{_escape(str(item.get('persona', 'default')).replace('_', ' '))}</td>"
        f"<td>{_escape(str(item.get('outcome', 'unknown')).replace('_', ' '))}</td>"
        f"<td>{_escape(str(item.get('failure_stage', 'workflow_execution')).replace('_', ' '))}</td>"
        f"<td>{_escape(item.get('completed_step_count', 0))}/{_escape(item.get('total_attempt_count', 0))}</td>"
        f"<td>{_escape(item.get('failed_action', item.get('failure_kind', '')))}{_selector_suggestion_text(item)}</td></tr>"
        for item in diagnostics if isinstance(item, dict)
    )
    session = str(execution.get("browser_session_status", "not_requested")).replace("_", " ")
    return """<section class='diagnostics panel'>
    <div class='section-heading'><div><p class='eyebrow'>BROWSER TRACE</p><h2>Execution diagnostics</h2></div>
    <p>Session: """ + _escape(session) + """. A session-setup block means the browser did not enter the protected workflow; it is a runner coverage boundary, not a product finding.</p></div>
    <div class='table-wrap'><table><thead><tr><th>Case</th><th>Area</th><th>Persona</th><th>Outcome</th><th>Stage</th><th>Steps</th><th>Failure point</th></tr></thead><tbody>""" + rows + "</tbody></table></div></section>"


def _selector_suggestion_text(item: dict[str, Any]) -> str:
    suggestions = item.get("selector_suggestions", [])
    if not isinstance(suggestions, list):
        return ""
    safe = [str(value) for value in suggestions[:3] if isinstance(value, str)]
    if not safe:
        return ""
    return "<br><small>Local selector candidates: " + _escape(", ".join(safe)) + "</small>"


def _graph_section(report: dict[str, Any]) -> str:
    graph = report.get("assurance_graph", {})
    if not isinstance(graph, dict):
        return ""
    summary = graph.get("summary", {})
    nodes = graph.get("nodes", [])
    if not isinstance(summary, dict) or not isinstance(nodes, list):
        return ""
    items = "".join(
        "<li>"
        f"<strong>{_escape(node.get('label', 'unknown'))}</strong>"
        f"<span>{_escape(node.get('kind', 'unknown'))} / {_escape(node.get('status', 'unknown'))}</span></li>"
        for node in nodes if isinstance(node, dict)
    )
    return """<section class='graph panel'>
    <div class='section-heading'><div><p class='eyebrow'>ASSURANCE TRACE</p><h2>What supports this result</h2></div>
    <p>Scope: """ + _escape(summary.get("scope_status", "unknown")) + " | Confirmed components: " + _escape(summary.get("confirmed_component_count", 0)) + " | " + _escape(summary.get("release_reason", "No release rationale was supplied.")) + "</p></div>" + f"<ul>{items}</ul></section>"


def render_local_report(report: dict[str, Any]) -> str:
    """Render a content-safe report without external assets or network calls."""
    subject = report.get("subject", {})
    subject = subject if isinstance(subject, dict) else {}
    metrics = report.get("metrics", {})
    metrics = metrics if isinstance(metrics, dict) else {}
    metric_names = _metric_names(metrics)
    workflow_names = [name for name in metric_names if name == "workflow_coverage"]
    model_names = [name for name in metric_names if name != "workflow_coverage"]
    measured = sum(_metric_status(metrics[name]) == "measured" for name in metric_names)
    total = len(metric_names)
    posture = "Evidence complete" if total and measured == total else "Evidence incomplete"
    payload = _escape(json.dumps(report, indent=2, ensure_ascii=True))
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PRE-D Local Evaluation Report</title><style>
:root{--ink:#0b1416;--panel:#142328;--line:#395055;--paper:#f5f1e9;--muted:#b9c5c3;--lime:#c9f36b;--coral:#ff8464;--gold:#f5cc67;--green:#6fdb9a;--white:#f8fbf7}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 100% 0,#243f3f 0,transparent 31rem),#0b1416;color:var(--white);font:16px Georgia,serif}main{max-width:1280px;margin:0 auto;padding:28px}.hero{padding:38px;background:linear-gradient(135deg,rgba(28,51,54,.98),rgba(13,25,28,.98));border:1px solid var(--line);box-shadow:10px 10px 0 rgba(0,0,0,.22)}.hero-top,.section-heading,.metric-top,summary{display:flex;justify-content:space-between;gap:24px;align-items:flex-start}.eyebrow{margin:0 0 12px;color:var(--coral);font:700 11px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.16em}.hero h1{max-width:740px;margin:0;font-size:clamp(38px,6vw,74px);line-height:.9;font-weight:400;letter-spacing:-.055em}.hero h1 em{color:var(--coral);font-weight:400}.hero-copy{max-width:610px;margin:22px 0 0;color:var(--muted);font-size:18px;line-height:1.5}.local-badge,.badge{display:inline-block;padding:8px 10px;border:1px solid var(--line);font:700 10px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em;white-space:nowrap}.local-badge{color:var(--lime);border-color:rgba(201,243,107,.45)}.hero-meta{display:flex;gap:14px;flex-wrap:wrap;margin-top:32px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font:12px ui-monospace,SFMono-Regular,Consolas,monospace}.hero-meta span{color:var(--white)}.posture{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(230px,.75fr);gap:14px;margin:18px 0}.posture-card{padding:24px;background:var(--paper);color:var(--ink);border-left:5px solid var(--coral)}.posture-card h2{margin:4px 0 8px;font-size:30px;font-weight:400;letter-spacing:-.03em}.posture-card p{margin:0;line-height:1.45;color:#435452}.posture-stat{padding:24px;background:#183529;border:1px solid #315846}.posture-stat strong{display:block;color:var(--lime);font-size:44px;font-weight:400;line-height:1}.posture-stat span{display:block;margin-top:8px;color:var(--muted);font:11px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.1em;text-transform:uppercase}.panel{margin-top:18px;padding:26px;background:rgba(20,35,40,.94);border:1px solid var(--line)}.section-heading h2{margin:0;font-size:32px;font-weight:400;letter-spacing:-.035em}.section-heading>p{max-width:500px;margin:4px 0;color:var(--muted);line-height:1.5}.metric-grid,.coverage-grid,.action-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-top:22px}.metric-card{min-height:145px;padding:17px;background:#101d20;border:1px solid var(--line)}.metric-card h3{margin:0;font-size:17px;font-weight:400}.metric-card p{margin:22px 0 0;color:var(--muted);font-size:14px;line-height:1.42}.badge.measured{color:var(--green);border-color:rgba(111,219,154,.5)}.badge.not_measurable{color:var(--gold);border-color:rgba(245,204,103,.5)}.readiness-list{display:grid;gap:8px;margin-top:20px}.readiness-card{background:#101d20;border:1px solid var(--line);border-left:4px solid var(--gold)}.readiness-card.measured{border-left-color:var(--green)}.readiness-card summary{padding:16px;cursor:pointer;list-style:none}.readiness-card summary::-webkit-details-marker{display:none}.readiness-card summary strong{display:block;font-size:18px;font-weight:400}.readiness-card summary small{display:block;max-width:700px;margin-top:4px;color:var(--muted);font-size:13px;line-height:1.4}.readiness-card summary b{color:var(--gold);font:700 10px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em;white-space:nowrap}.readiness-card.measured summary b{color:var(--green)}.readiness-detail{display:grid;grid-template-columns:1fr 1fr;gap:20px;padding:0 16px 16px}.readiness-detail p{margin:0;color:var(--muted);line-height:1.5}.readiness-detail span{display:block;margin-bottom:5px;color:var(--white);font:700 10px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.1em}.boundary-note{margin:18px 0 0;padding:14px;border-left:4px solid var(--gold);background:#312b1c;color:#f4e7bd;line-height:1.48}.coverage-stat{min-height:137px;padding:17px;background:#101d20;border-top:3px solid #597077}.coverage-stat strong{display:block;color:var(--lime);font-size:34px;font-weight:400}.coverage-stat span{display:block;margin-top:8px;font:700 11px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em;text-transform:uppercase}.coverage-stat small{display:block;margin-top:8px;color:var(--muted);font-size:12px;line-height:1.35}.table-wrap{overflow-x:auto;margin-top:18px}table{width:100%;border-collapse:collapse;font:13px ui-monospace,SFMono-Regular,Consolas,monospace}th,td{padding:12px 8px;border-top:1px solid var(--line);text-align:left;vertical-align:top}th{color:var(--muted);font-size:10px;letter-spacing:.08em;text-transform:uppercase}.action-card{display:flex;gap:16px;padding:18px;background:linear-gradient(130deg,#193229,#102024);border:1px solid #35604a}.action-card>span{color:var(--lime);font-size:34px;line-height:1}.action-card h3{margin:2px 0 7px;font-size:18px;font-weight:400}.action-card p{margin:0;color:var(--muted);font-size:14px;line-height:1.45}.graph ul{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:8px;padding:0;margin:22px 0 0;list-style:none}.graph li{padding:12px;border:1px solid var(--line);background:#101d20}.graph strong{display:block;font-size:14px}.graph span{display:block;margin-top:5px;color:var(--muted);font:11px ui-monospace,SFMono-Regular,Consolas,monospace}details.raw{margin-top:18px;padding:16px;background:#0b1416;border:1px solid var(--line)}details.raw summary{cursor:pointer;font:700 11px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em}pre{overflow:auto;margin:14px 0 0;padding:16px;background:#050b0d;color:#cce0dd;font:12px ui-monospace,SFMono-Regular,Consolas,monospace;line-height:1.45}@media(max-width:720px){main{padding:12px}.hero,.panel{padding:20px}.hero-top,.section-heading{display:block}.local-badge{margin-top:16px}.posture{grid-template-columns:1fr}.readiness-detail{grid-template-columns:1fr}.section-heading>p{margin-top:14px}.hero h1{font-size:48px}}@media print{body{background:#fff;color:#111}main{max-width:none;padding:0}.hero,.panel,.metric-card,.readiness-card,.coverage-stat,.action-card,.graph li{background:#fff;color:#111;box-shadow:none;border-color:#888}.hero-copy,.section-heading>p,.metric-card p,.readiness-card summary small,.readiness-detail p,.coverage-stat small,.action-card p,.graph span{color:#333}.hero h1 em,.eyebrow{color:#a33}.posture-card{border-color:#a33}.posture-stat{background:#eee;color:#111}.posture-stat strong{color:#164}.boundary-note{background:#fff4d8;color:#111}.local-badge,.badge{color:#111!important;border-color:#555!important}}</style></head><body><main>
<section class="hero"><div class="hero-top"><div><p class="eyebrow">PRE-D / LOCAL ASSURANCE REPORT</p><h1>Evidence before <em>confidence.</em></h1></div><span class="local-badge">LOCAL ONLY / NOT UPLOADED</span></div><p class="hero-copy">A decision-grade account of what reached the application, what was measured, and which evidence is still required. It does not turn missing access or hidden telemetry into a product verdict.</p><div class="hero-meta"><div>SUBJECT <span>""" + _escape(subject.get("agent_id", "unknown")) + "</span></div><div>VERSION <span>" + _escape(subject.get("subject_version", "unknown")) + "</span></div><div>DATASET <span>" + _escape(subject.get("dataset_version", "unknown")) + "</span></div><div>RUNNER <span>" + _escape(report.get("runner_version", "unknown")) + "</span></div></div></section>" + """
<section class="posture"><article class="posture-card"><p class="eyebrow">EVIDENCE POSTURE</p><h2>""" + _escape(posture) + "</h2><p>" + _escape(report.get("notice", "This report was calculated locally.")) + '</p></article><article class="posture-stat"><strong>' + _escape(f"{measured}/{total}") + "</strong><span>Metric dimensions measured</span></article></section>" + """
""" + _executive_readout(report) + (
"""<section class="panel"><div class="section-heading"><div><p class="eyebrow">WORKFLOW ASSURANCE SCORECARD</p><h2>Declared journeys, measured honestly</h2></div><p>A pass means the approved browser journey reached its observable signal. It is not a model classification, confidence, safety, or groundedness score.</p></div><div class="metric-grid">""" + _metric_cards(metrics, workflow_names) + "</div></section>"
if workflow_names else ""
) + _browser_smoke_summary(report) + """<section class="panel"><div class="section-heading"><div><p class="eyebrow">MODEL AND EVIDENCE SCORECARD</p><h2>Evidence-backed AI measurements</h2></div><p>These measurements are separate from browser workflow coverage. A score is shown only when compatible local labels, observed outputs, and telemetry evidence were supplied.</p></div><div class="metric-grid">""" + _metric_cards(metrics, model_names) + "</div></section>" + _evidence_source_section(report) + _measurement_readiness_section(metrics) + _coverage_section(report) + _next_actions(report) + _diagnostic_section(report) + _graph_section(report) + """<details class="raw"><summary>VIEW REDACTED RESULT DATA</summary><pre>""" + payload + "</pre></details></main></body></html>"
