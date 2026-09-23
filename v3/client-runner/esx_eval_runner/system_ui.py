"""Local-only guided review and progressive-disclosure system evidence reports."""

from __future__ import annotations

import html
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import secrets
from urllib.parse import urlsplit
import webbrowser

from .runner import RunnerError
from .system_inventory import LAYERS, add_role_matrix, check_template, document, identifier
from .system_engine import plan_digest, validate_plan


STYLE = """
:root{--bg:#050914;--panel:#0b1628;--panel-strong:#101f38;--ink:#f6f8ff;--muted:#9db5d7;--accent:#ff315d;--accent-2:#35d7ff;--line:rgba(80,177,255,.25);--good:#7df7c2;--warn:#ffd166;--bad:#ff4d6d;--shadow:0 32px 90px rgba(0,0,0,.46);--glass:rgba(10,24,45,.76)}
*{box-sizing:border-box}body{margin:0;color:var(--ink);background:radial-gradient(circle at 12% -8%,rgba(53,215,255,.27),transparent 30%),radial-gradient(circle at 86% 10%,rgba(255,49,93,.22),transparent 34%),linear-gradient(135deg,#040711 0%,#071326 46%,#100712 100%);font:16px "Space Grotesk","Sora","Aptos Display","Bahnschrift",sans-serif}body:before{content:"";position:fixed;inset:0;pointer-events:none;background:linear-gradient(rgba(255,255,255,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.03) 1px,transparent 1px);background-size:48px 48px;mask-image:linear-gradient(to bottom,rgba(0,0,0,.9),transparent 82%)}
main{max-width:1280px;margin:auto;padding:48px 30px 74px}h1{font-size:clamp(44px,7vw,86px);line-height:.9;max-width:940px;margin:10px 0 20px;letter-spacing:-3px;text-wrap:balance}h2{font-size:30px;letter-spacing:-.8px}h3{font-size:21px;letter-spacing:-.25px}p{line-height:1.65}
.eyebrow,button,label,th,nav,small,.verdict-badge{font-family:"Geist Mono","IBM Plex Mono","Cascadia Code","Courier New",monospace}.eyebrow{color:var(--accent-2);letter-spacing:2.6px;text-transform:uppercase;text-shadow:0 0 22px rgba(53,215,255,.35)}.subtitle{color:var(--muted);font-size:18px;max-width:760px}.hero{position:relative;overflow:hidden;display:grid;grid-template-columns:minmax(0,1.55fr) minmax(300px,.9fr);gap:26px;align-items:stretch;background:linear-gradient(135deg,rgba(53,215,255,.13),rgba(255,49,93,.12)),var(--glass);border:1px solid rgba(124,207,255,.34);border-radius:30px;padding:38px;box-shadow:var(--shadow),inset 0 1px 0 rgba(255,255,255,.13);margin:0 0 24px;backdrop-filter:blur(18px)}.hero:after{content:"";position:absolute;right:-120px;top:-120px;width:360px;height:360px;border-radius:50%;background:radial-gradient(circle,rgba(255,49,93,.26),transparent 63%);filter:blur(4px)}.hero-copy{position:relative;z-index:1;min-width:0}.hero .grid{margin-top:28px}.verdict-panel{position:relative;z-index:1;background:linear-gradient(160deg,rgba(5,12,24,.9),rgba(22,10,25,.82));border:1px solid rgba(255,49,93,.32);border-radius:24px;padding:26px;display:flex;flex-direction:column;gap:14px;box-shadow:inset 0 1px 0 rgba(255,255,255,.1),0 20px 50px rgba(255,49,93,.09)}.verdict-badge{display:inline-flex;align-self:flex-start;border-radius:999px;padding:8px 12px;font-size:12px;font-weight:800;letter-spacing:1px;text-transform:uppercase;background:rgba(255,49,93,.1);border:1px solid rgba(255,49,93,.45)}.verdict-panel strong{font-size:25px;line-height:1.16}.verdict-panel.insufficient_evidence .verdict-badge,.verdict-panel.blocked .verdict-badge{color:var(--warn);border-color:rgba(255,209,102,.6);background:rgba(255,209,102,.08)}.verdict-panel.do_not_ship .verdict-badge,.verdict-panel.failed .verdict-badge{color:var(--bad);border-color:rgba(255,77,109,.68);background:rgba(255,77,109,.13)}.verdict-panel.checks_passed_within_reviewed_scope .verdict-badge,.verdict-panel.passed .verdict-badge{color:var(--good);border-color:rgba(125,247,194,.58);background:rgba(125,247,194,.09)}
section,.card{background:var(--glass);border:1px solid var(--line);border-radius:22px;padding:26px;margin:22px 0;box-shadow:0 20px 60px rgba(0,0,0,.24),inset 0 1px 0 rgba(255,255,255,.08);backdrop-filter:blur(14px)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:15px}.card{margin:0;background:linear-gradient(180deg,rgba(18,37,68,.76),rgba(8,18,34,.72));transition:transform .18s ease,border-color .18s ease,box-shadow .18s ease}.card:hover{transform:translateY(-2px);border-color:rgba(53,215,255,.55);box-shadow:0 22px 60px rgba(53,215,255,.08)}.number{font-size:38px;font-weight:900;letter-spacing:-1px;background:linear-gradient(90deg,var(--ink),var(--accent-2));-webkit-background-clip:text;background-clip:text;color:transparent}small,.muted{color:var(--muted)}a{color:var(--accent-2)}nav{display:flex;gap:10px;flex-wrap:wrap;margin:20px 0 24px}nav a{border:1px solid rgba(53,215,255,.28);border-radius:999px;padding:9px 13px;text-decoration:none;background:rgba(53,215,255,.055);color:#dff7ff;box-shadow:inset 0 1px 0 rgba(255,255,255,.08)}nav a:hover{border-color:rgba(255,49,93,.65);color:#fff;background:rgba(255,49,93,.12)}button{background:linear-gradient(135deg,var(--accent-2),var(--accent));border:0;border-radius:10px;padding:12px 18px;cursor:pointer;color:#061020;font-weight:900}button.secondary{background:linear-gradient(135deg,var(--good),var(--accent-2))}button:disabled{opacity:.5}
.metric-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:15px}.metric-card{margin:0;min-height:190px;display:flex;flex-direction:column;gap:10px}.status-pill{align-self:flex-start;border:1px solid var(--line);border-radius:999px;padding:6px 10px;font:700 11px "Geist Mono","IBM Plex Mono","Cascadia Code","Courier New",monospace;letter-spacing:.8px;text-transform:uppercase}.status-pill.verified,.status-pill.measured{color:var(--good);border-color:rgba(125,247,194,.55);background:rgba(125,247,194,.08)}.status-pill.declared,.status-pill.partial{color:var(--warn);border-color:rgba(255,209,102,.55);background:rgba(255,209,102,.08)}.status-pill.blocked,.status-pill.missing,.status-pill.not_measured{color:var(--bad);border-color:rgba(255,77,109,.55);background:rgba(255,77,109,.1)}.metric-score{font-size:25px;font-weight:900;letter-spacing:-.5px}.metric-card p{margin:.1rem 0}.metric-card details{margin-top:auto}.compact-list{margin:.25rem 0 0;padding-left:18px}.compact-list li{margin:.25rem 0}
.explain{border-left:3px solid rgba(53,215,255,.55);padding-left:12px;color:#dbe8fb}.explain strong{color:#fff}.section-intro{font-size:18px;color:var(--muted);max-width:940px}.plain-title{font-size:clamp(30px,4vw,48px);letter-spacing:-1.3px}
input,select,textarea{width:100%;background:rgba(4,11,23,.86);color:var(--ink);border:1px solid var(--line);border-radius:10px;padding:11px;margin:8px 0 16px}input[type=checkbox]{width:auto;margin:10px}label{display:block;font-size:13px;color:#c9d9ef}details{border-top:1px solid var(--line);padding:17px 0}summary{cursor:pointer;font-size:20px}table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:13px;border-bottom:1px solid rgba(80,177,255,.16);vertical-align:top}th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:1px}.scroll{overflow:auto}.failed,.blocked,.observed_defect,.blocked_evidence{color:var(--bad)}.passed,.evaluated,.verified{color:var(--good)}.partial,.configured_not_run,.planned_only,.missing,.declared,.coverage_gap,.setup_gap{color:var(--warn)}.not_applicable,.informational{color:var(--muted)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:rgba(3,8,18,.56);border:1px solid rgba(80,177,255,.16);border-radius:14px;padding:14px}code{font-family:"Geist Mono","IBM Plex Mono","Cascadia Code","Courier New",monospace}#status{white-space:pre-wrap}small,p,summary{overflow-wrap:anywhere}.grid>*{min-width:0}@media(max-width:760px){main{padding:24px 14px}.hero{grid-template-columns:minmax(0,1fr);padding:22px;border-radius:22px}section{padding:17px}td,th{padding:9px}.grid{grid-template-columns:minmax(0,1fr)}h1{letter-spacing:-2px}}
"""


PRIMARY_AI_METRICS = [
    "classification",
    "confidence",
    "decision_evidence",
    "groundedness",
    "hallucination",
    "rag",
    "security",
    "tool_use",
    "trajectory",
    "robustness",
    "judge_agreement",
    "reproducibility",
    "cost_efficiency",
    "workflow_coverage",
]

METRIC_LABELS = {
    "classification": "Classification",
    "confidence": "Confidence calibration",
    "decision_evidence": "Decision evidence and abstention",
    "groundedness": "Groundedness",
    "hallucination": "Hallucination",
    "rag": "RAG retrieval",
    "security": "Security",
    "tool_use": "Tool use",
    "trajectory": "Trajectory",
    "robustness": "Robustness",
    "judge_agreement": "Judge agreement",
    "reproducibility": "Repeatability",
    "cost_efficiency": "Cost and latency",
    "workflow_coverage": "Workflow coverage",
}

METRIC_ACTIONS = {
    "classification": "Add labelled cases and returned labels from a local endpoint or adapter.",
    "confidence": "Return calibrated confidence for the predicted label and include enough confidence variation.",
    "decision_evidence": "Return evidence IDs, abstention state and expected abstention/evidence rules per case.",
    "groundedness": "Provide response text, source chunks and an independent local grounding judge.",
    "hallucination": "Provide response claims, source evidence, abstention expectations and a local hallucination judge.",
    "rag": "Provide retrieved documents, relevance labels and expected evidence coverage per case.",
    "security": "Add labelled prompt-injection, unsafe-action, authz and tenant-isolation cases.",
    "tool_use": "Capture tool calls, allowed tools, authorization decisions and expected tool outcomes.",
    "trajectory": "Capture observed runtime steps, tool sequence and milestone expectations.",
    "robustness": "Run repeated or perturbed cases and provide expected stability rules.",
    "judge_agreement": "Run multiple judges or repeated judge trials for the same cases.",
    "reproducibility": "Run the same pack multiple times and keep comparable run history.",
    "cost_efficiency": "Capture tokens, latency, model/runtime cost and throughput per case.",
    "workflow_coverage": "Run browser/API workflows with stable visible or response assertions.",
}

METRIC_CALCULATION_TEXT = {
    "classification": "Compares the application returned label with the expected label for each labelled case, then derives accuracy, precision, recall and F1 from the confusion matrix.",
    "confidence": "Compares returned confidence against whether the predicted label was correct, then calculates calibration signals such as ECE and Brier score.",
    "decision_evidence": "Checks whether returned evidence IDs and abstention behavior match the expected evidence and abstention rules for each case.",
    "groundedness": "Extracts claims from the response, compares each claim against supplied source chunks, then scores support, contradiction or insufficient evidence.",
    "hallucination": "Uses the same claim/evidence material to count unsupported claims and failed abstentions, then reports hallucination-free and unsupported-claim rates.",
    "rag": "Compares retrieved documents/chunks against expected relevant evidence and coverage requirements.",
    "security": "Runs labelled security cases such as prompt injection, unsafe action blocking, authorization and tenant isolation expectations.",
    "tool_use": "Compares observed tool calls with allowed/expected tools, authorization decisions and result validity.",
    "trajectory": "Compares observed runtime steps, tool sequence and milestones with the expected workflow trace.",
    "robustness": "Compares repeated or perturbed runs against expected stability and pass-rate rules.",
    "judge_agreement": "Compares repeated judge or multi-judge outputs for the same cases.",
    "reproducibility": "Compares repeated executions of the same pack across runs.",
    "cost_efficiency": "Aggregates captured tokens, runtime, cost, timeouts and latency observations.",
    "workflow_coverage": "Checks whether browser/API workflows reached the expected pages, responses or visible signals.",
}

METRIC_MEASURES = {
    "classification": "AI decision-label correctness over labelled decision cases.",
    "confidence": "Confidence calibration for returned AI decision labels.",
    "decision_evidence": "Whether decisions used the expected evidence references and abstention behavior.",
    "groundedness": "Whether response claims are supported by supplied local evidence.",
    "hallucination": "Whether responses contain unsupported claims or miss required abstentions.",
    "rag": "Whether retrieved evidence was relevant and covered the expected source material.",
    "security": "Whether configured security, authorization and unsafe-action cases behaved as expected.",
    "tool_use": "Whether observed tool calls matched allowed tools, authorization and expected outcomes.",
    "trajectory": "Whether the observed execution path matched expected steps and milestones.",
    "robustness": "Whether repeated or perturbed cases stayed stable enough for the configured gate.",
    "judge_agreement": "Whether repeated or multiple judge decisions agreed on the same cases.",
    "reproducibility": "Whether repeated runs of the same cases produced stable outcomes.",
    "cost_efficiency": "Cost, token, latency and timeout telemetry for evaluated cases.",
    "workflow_coverage": "Browser/API workflow reachability and visible or response signal coverage.",
}

METRIC_CATEGORIES = {
    "classification": "AI quality",
    "confidence": "AI quality",
    "decision_evidence": "AI quality",
    "groundedness": "AI quality",
    "hallucination": "AI quality",
    "rag": "RAG / knowledge",
    "security": "Security",
    "tool_use": "Tool use",
    "trajectory": "Trajectory",
    "robustness": "Reliability",
    "judge_agreement": "Evaluation quality",
    "reproducibility": "Reliability",
    "cost_efficiency": "Cost / latency",
    "workflow_coverage": "Workflow coverage",
}


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def verdict_copy(report: dict) -> dict[str, str]:
    verdict = report.get("verdict", "unknown")
    if verdict == "checks_passed_within_reviewed_scope":
        return {
            "tone": "checks_passed_within_reviewed_scope",
            "label": "Reviewed scope passed",
            "headline": "Reviewed checks passed within the approved evidence scope.",
            "body": "Use this as a scoped release signal only; uncovered modules and dimensions still need explicit evidence before making a full-platform claim.",
        }
    if verdict == "do_not_ship":
        return {
            "tone": "do_not_ship",
            "label": "Do not ship",
            "headline": "Reviewed evidence found at least one release-blocking failure.",
            "body": "Start with the failed checks and observed-defect findings, then rerun against the same candidate after the fix is verified.",
        }
    if verdict == "insufficient_evidence":
        return {
            "tone": "insufficient_evidence",
            "label": "Insufficient evidence",
            "headline": "Not enough executed evidence for a full-platform release claim.",
            "body": "This is a coverage and evidence-strength verdict: review the blocked checks, missing modules and setup actions before treating the product as release-ready.",
        }
    if verdict == "blocked":
        return {
            "tone": "blocked",
            "label": "Blocked",
            "headline": "Execution was blocked before PRE-D could form a release conclusion.",
            "body": "Resolve the setup or collection blocker, then rerun so the report can distinguish application defects from missing evidence.",
        }
    label = verdict.replace("_", " ").capitalize()
    return {
        "tone": "unknown",
        "label": label,
        "headline": f"Release evidence review completed with verdict: {label}.",
        "body": "Inspect the executive summary and traceable findings for the precise evidence basis.",
    }


def report_hero(report: dict, cards: str) -> str:
    verdict = verdict_copy(report)
    project = report.get("project_id", "project")
    version = report.get("application_version", "candidate")
    return (
        '<section class="hero">'
        '<div class="hero-copy">'
        '<p class="eyebrow">PRE-D / RELEASE EVIDENCE REVIEW</p>'
        '<h1>Release evidence review</h1>'
        f'<p class="subtitle">{_esc(project)} / {_esc(version)}. {_esc(report.get("notice", ""))}</p>'
        f'<div class="grid">{cards}</div>'
        '</div>'
        f'<aside class="verdict-panel {_esc(verdict["tone"])}">'
        f'<span class="verdict-badge">Verdict: {_esc(verdict["label"])}</span>'
        f'<strong>{_esc(verdict["headline"])}</strong>'
        f'<p>{_esc(verdict["body"])}</p>'
        '</aside>'
        '</section>'
    )


def _metric_requested_dimensions(report: dict) -> set[str]:
    requested: set[str] = set()
    matrix = report.get("module_evaluation_summary")
    if isinstance(matrix, dict):
        for area in matrix.get("areas", []):
            for key in ("verified_metrics", "declared_metrics", "missing_requested_metrics"):
                requested.update(str(value) for value in area.get(key, []) if value)
        for row in matrix.get("modules", []):
            for key in ("verified_metrics", "declared_metrics", "missing_requested_metrics"):
                requested.update(str(value) for value in row.get(key, []) if value)
    for component in report.get("coverage", []):
        for item in component.get("dimension_inventory", []):
            if item.get("dimension"):
                requested.add(str(item["dimension"]))
    for row in report.get("checks", []):
        requested.update(str(value) for value in row.get("metrics", {}).keys())
    return requested


def _metric_status_counts(report: dict) -> dict[str, int]:
    counts = {"verified": 0, "declared": 0, "partial": 0, "missing": 0}
    for dimension in _metric_dimensions(report):
        entries = _metric_entries(report, dimension)
        included = _included_metric_entries(entries)
        label, _ = _metric_state(included, entries, dimension in _metric_requested_dimensions(report))
        if label == "Verified":
            counts["verified"] += 1
        elif label == "Declared":
            counts["declared"] += 1
        elif label == "Partial":
            counts["partial"] += 1
        else:
            counts["missing"] += 1
    return counts


def _metric_dimensions(report: dict) -> list[str]:
    seen = set()
    dimensions = []
    for dimension in PRIMARY_AI_METRICS + sorted(_metric_requested_dimensions(report)):
        if dimension not in seen:
            seen.add(dimension)
            dimensions.append(dimension)
    return dimensions


def _metric_entries(report: dict, dimension: str) -> list[dict]:
    entries = []
    for row in report.get("checks", []):
        metric = row.get("metrics", {}).get(dimension)
        if isinstance(metric, dict):
            entries.append({"check": row, "metric": metric})
    return entries


def _included_metric_entries(entries: list[dict]) -> list[dict]:
    return [
        entry for entry in entries
        if entry["metric"].get("measurement_status") in {"measured", "partial"}
    ]


def _excluded_metric_entries(entries: list[dict]) -> list[dict]:
    return [
        entry for entry in entries
        if entry["metric"].get("measurement_status") not in {"measured", "partial"}
    ]


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _fmt_number(value: object) -> str:
    if not _is_number(value):
        return str(value)
    if abs(float(value)) >= 100:
        return f"{float(value):.0f}"
    return f"{float(value):.3f}".rstrip("0").rstrip(".")


def _metric_score(dimension: str, entries: list[dict]) -> str:
    preferred = {
        "classification": ["accuracy", "macro_f1", "macro_precision", "macro_recall"],
        "confidence": ["expected_calibration_error", "correctness_brier_score", "unique_confidence_count"],
        "decision_evidence": ["correct_abstention_rate", "evidence_reference_precision", "evidence_reference_recall"],
        "groundedness": ["grounded_claim_rate", "supported_claim_rate", "contradicted_claim_rate", "insufficient_claim_rate"],
        "hallucination": ["hallucination_free_response_rate", "unsupported_claim_rate", "hallucinated_claim_rate", "correct_abstention_rate"],
        "rag": ["retrieval_relevance", "evidence_coverage", "retrieval_precision", "retrieval_recall"],
        "security": ["unsafe_action_block_rate", "prompt_injection_block_rate", "authorization_rate", "tenant_isolation_rate"],
        "tool_use": ["selection_f1", "authorization_rate", "valid_result_rate", "exact_tool_set_rate"],
        "trajectory": ["score", "milestone_completion_rate", "tool_sequence_match_rate"],
        "robustness": ["stability_rate", "pass_rate", "variance"],
        "judge_agreement": ["agreement_rate", "cohen_kappa", "judge_agreement_rate"],
        "reproducibility": ["repeatability_rate", "outcome_stability_rate"],
        "cost_efficiency": ["p95_latency_ms", "cost_per_case_usd", "total_cost_usd", "telemetry_coverage_rate", "timeout_rate"],
        "workflow_coverage": ["workflow_execution_rate", "workflow_signal_match_rate", "page_reach_rate"],
    }
    metrics = [entry["metric"] for entry in entries]
    metrics.sort(key=lambda m: (m.get("trust_status") != "verified", m.get("measurement_status") != "measured"))
    labels = {
        "accuracy": "accuracy",
        "macro_f1": "macro-F1",
        "macro_precision": "precision",
        "macro_recall": "recall",
        "expected_calibration_error": "ECE",
        "correctness_brier_score": "Brier",
        "correct_abstention_rate": "abstention",
        "grounded_claim_rate": "grounded",
        "supported_claim_rate": "supported",
        "hallucination_free_response_rate": "hallucination-free",
        "unsupported_claim_rate": "unsupported claims",
        "hallucinated_claim_rate": "hallucinated claims",
        "workflow_execution_rate": "workflow execution",
        "workflow_signal_match_rate": "signal match",
        "p95_latency_ms": "p95 latency ms",
        "cost_per_case_usd": "USD/case",
        "total_cost_usd": "total USD",
        "telemetry_coverage_rate": "telemetry coverage",
    }
    parts = []
    for metric in metrics:
        for key in preferred.get(dimension, []):
            if _is_number(metric.get(key)):
                parts.append(f'{labels.get(key, key.replace("_", " "))}: {_fmt_number(metric[key])}')
            if len(parts) == 2:
                return " | ".join(parts)
        if parts:
            return " | ".join(parts)
    for metric in metrics:
        for key, value in metric.items():
            if key.endswith("_rate") or key in {"score", "accuracy", "macro_f1"}:
                if _is_number(value):
                    return f'{key.replace("_", " ")}: {_fmt_number(value)}'
    if any(metric.get("measurement_status") == "measured" for metric in metrics):
        return "Measured"
    return "No score"


def _metric_state(included: list[dict], all_entries: list[dict], requested: bool) -> tuple[str, str]:
    if any(e["metric"].get("measurement_status") == "partial" for e in included):
        return "Partial", "partial"
    if any(e["metric"].get("measurement_status") == "measured" and e["metric"].get("trust_status") == "verified" for e in included):
        return "Verified", "verified"
    if any(e["metric"].get("measurement_status") == "measured" and e["metric"].get("trust_status") == "declared" for e in included):
        return "Declared", "declared"
    if any(e["metric"].get("measurement_status") == "measured" for e in included):
        return "Measured", "measured"
    if all_entries and any(e["check"].get("status") == "blocked" for e in all_entries):
        return "Blocked", "blocked"
    if all_entries:
        return "Not measured", "not_measured"
    if requested:
        return "Missing", "missing"
    return "Missing", "missing"


def _metric_reason(dimension: str, included: list[dict], all_entries: list[dict], label: str, requested: bool) -> str:
    if label == "Verified":
        return f"Calculated from included local evidence in {len(included)} check(s)."
    if label == "Declared":
        return "Accepted from target-declared local evidence; not independently verified."
    if label == "Measured":
        return "Measured, but provenance is not marked verified."
    if label == "Partial":
        return "Some compatible evidence was present, but the denominator was incomplete."
    if label == "Blocked":
        return "Configured evidence exists, but execution or gate status blocked a release-grade result."
    if requested:
        return "Requested by the system plan or coverage map, but no measured evidence reached this report."
    if dimension in {"groundedness", "hallucination"}:
        return "Not run in this system report; semantic evidence was not connected."
    return "No measured evidence for this dimension in this system report."


def _entry_case_count(entry: dict) -> int | None:
    count = entry["check"].get("case_count")
    return int(count) if _is_number(count) else None


def _metric_evidence_text(entries: list[dict]) -> str:
    if not entries:
        return "None."
    case_total = 0
    has_case_count = False
    statuses = {}
    checks = []
    for entry in entries:
        check = entry["check"]
        checks.append(str(check.get("id", "unknown")))
        statuses[check.get("status", "unknown")] = statuses.get(check.get("status", "unknown"), 0) + 1
        count = _entry_case_count(entry)
        if count is not None:
            has_case_count = True
            case_total += count
    status_text = ", ".join(f"{count} {status}" for status, count in sorted(statuses.items()))
    case_text = f"{case_total} case(s)" if has_case_count else "case count not reported"
    check_text = ", ".join(checks[:3])
    if len(checks) > 3:
        check_text += f", +{len(checks) - 3} more"
    return f"{len(entries)} check(s): {check_text}; {case_text}; statuses: {status_text}."


def _metric_denominator_text(dimension: str, included: list[dict], all_entries: list[dict]) -> str:
    if included:
        observed = sum(count for entry in included for count in [_entry_case_count(entry)] if count is not None)
        if observed:
            denominator = "included case(s)"
            if dimension in {"classification", "confidence", "decision_evidence"}:
                denominator = "labelled AI decision case(s)"
            elif dimension == "workflow_coverage":
                denominator = "workflow case(s)"
            elif dimension == "security":
                denominator = "security case/check(s)"
            elif dimension == "cost_efficiency":
                denominator = "case(s) with usage telemetry"
            return f"{observed} {denominator}."
    if all_entries:
        observed = sum(count for entry in all_entries for count in [_entry_case_count(entry)] if count is not None)
        if observed:
            return f"0 compatible measured cases included; {observed} nearby case(s) were excluded or not measurable."
    return "No compatible denominator reached this metric."


def _metric_excluded_text(entries: list[dict]) -> str:
    if not entries:
        return "None."
    parts = []
    for entry in entries[:4]:
        check = entry["check"]
        metric = entry["metric"]
        status = str(metric.get("measurement_status", "not_measured")).replace("_", " ")
        reason = str(metric.get("reason", "Not compatible evidence for this metric."))
        parts.append(f'{check.get("id", "unknown")}: {status} ({reason})')
    if len(entries) > 4:
        parts.append(f"{len(entries) - 4} more excluded check(s).")
    return " ".join(parts)


def ai_quality_metrics_panel(report: dict) -> str:
    requested = _metric_requested_dimensions(report)
    counts = _metric_status_counts(report)
    cards = []
    detail_rows = []
    for dimension in _metric_dimensions(report):
        entries = _metric_entries(report, dimension)
        included = _included_metric_entries(entries)
        excluded = _excluded_metric_entries(entries)
        label, css_class = _metric_state(included, entries, dimension in requested)
        score = _metric_score(dimension, included)
        reason = _metric_reason(dimension, included, entries, label, dimension in requested)
        calculation = METRIC_CALCULATION_TEXT.get(dimension, "Calculated from the supplied local metric evidence for this dimension.")
        included_text = _metric_evidence_text(included)
        excluded_text = _metric_excluded_text(excluded)
        denominator = _metric_denominator_text(dimension, included, entries)
        category = METRIC_CATEGORIES.get(dimension, "Evaluation evidence")
        measure = METRIC_MEASURES.get(dimension, "Local metric evidence for this dimension.")
        checks = [entry["check"].get("id", "unknown") for entry in included]
        artifact = ""
        for entry in included or entries:
            value = entry["check"].get("artifact")
            if isinstance(value, str) and Path(value).name == value and value.endswith(".json"):
                artifact = f'<a href="{_esc(value[:-5] + ".html")}">Open detailed local report</a>'
                break
        check_list = "".join(f"<li>{_esc(check)}</li>" for check in checks[:5])
        extra = f"<li>{_esc(len(checks) - 5)} more check(s)</li>" if len(checks) > 5 else ""
        if not check_list:
            check_list = "<li>No compatible measured check contributed to this metric.</li>"
        cards.append(
            f'<article class="card metric-card"><span class="status-pill {css_class}">{_esc(label)}</span>'
            f'<h3>{_esc(METRIC_LABELS.get(dimension, dimension.replace("_", " ").title()))}</h3>'
            f'<p><strong>Category:</strong> {_esc(category)}</p>'
            f'<div class="metric-score">{_esc(score)}</div><p>{_esc(reason)}</p>'
            f'<p class="explain"><strong>What this measured:</strong> {_esc(measure)}</p>'
            f'<p class="explain"><strong>How calculated:</strong> {_esc(calculation)}</p>'
            f'<p class="explain"><strong>Evidence included:</strong> {_esc(included_text)}</p>'
            f'<p class="explain"><strong>Evidence excluded:</strong> {_esc(excluded_text)}</p>'
            f'<p class="explain"><strong>Denominator:</strong> {_esc(denominator)}</p>'
            f'<p><strong>Action:</strong> {_esc(METRIC_ACTIONS.get(dimension, "Attach measured evidence and rerun."))}</p>'
            f'{artifact}'
            f'<details><summary>Checks and evidence</summary><ul class="compact-list">{check_list}{extra}</ul></details></article>'
        )
        detail_rows.append(
            f'<tr><td>{_esc(METRIC_LABELS.get(dimension, dimension.replace("_", " ").title()))}</td>'
            f'<td>{_esc(category)}</td><td class="{css_class}">{_esc(label)}</td><td>{_esc(score)}</td>'
            f'<td>{_esc(denominator)}</td><td>{_esc(reason)}</td><td>{_esc(METRIC_ACTIONS.get(dimension, "Attach measured evidence and rerun."))}</td></tr>'
        )
    return (
        '<section id="ai-quality"><p class="eyebrow">AI SCORECARD</p>'
        '<h2 class="plain-title">AI metrics and scoring evidence</h2>'
        '<p class="section-intro">This section answers four practical questions for every AI metric: did PRE-D score it, is the score independently verified or target-declared, how was it calculated, and what evidence did it use?</p>'
        f'<div class="grid"><div class="card"><small>Verified scores</small><div class="number">{_esc(counts["verified"])}</div><p class="muted">Calculated from local labels, observed traces or independently checked evidence.</p></div>'
        f'<div class="card"><small>Declared scores</small><div class="number">{_esc(counts["declared"])}</div><p class="muted">Accepted from target-provided payloads and clearly marked as not independently verified.</p></div>'
        f'<div class="card"><small>Partial scores</small><div class="number">{_esc(counts["partial"])}</div><p class="muted">Some evidence exists, but the denominator is incomplete.</p></div>'
        f'<div class="card"><small>Missing scores</small><div class="number">{_esc(counts["missing"])}</div><p class="muted">Not enough evidence reached the report, so PRE-D does not invent a score.</p></div></div>'
        f'<div class="metric-grid">{"".join(cards)}</div>'
        f'<details><summary>Open metric evidence table</summary><div class="scroll"><table><tr><th>Metric</th><th>Category</th><th>Status</th><th>Score</th><th>Denominator</th><th>Meaning</th><th>Fix</th></tr>{"".join(detail_rows)}</table></div></details>'
        '</section>'
    )


def scope_panel(report: dict) -> str:
    scope = report.get("scope_contract", {})
    if scope.get("mode") != "whole_system":
        return '<section id="scope"><h2>Selected checks, not whole-system coverage</h2><p>No reviewed whole-system behavior contract was supplied. A passing result applies only to the attached checks.</p></section>'
    summary = scope["summary"]
    gaps = list(scope["gaps"])
    gaps.extend(m["module"] + ": " + gap for m in scope["modules"] for gap in m["gaps"])
    def objective_text(objective: dict) -> str:
        rule = f'<br><small>Business rule: {_esc(objective["business_rule_id"])}</small>' if objective.get("business_rule_id") else ""
        expected = f'<br><small>{_esc(objective["expected_business_behavior"])}</small>' if objective.get("expected_business_behavior") else ""
        return _esc(objective["title"]) + rule + expected
    rows = ''.join(f'<tr><td>{objective_text(o)}</td><td>{_esc(o.get("role") or "Not role-specific")}</td><td class="{_esc(o["status"])}">{_esc(o["status"])}</td><td>{_esc(o.get("check_id") or "Not bound")}<br><small>{_esc(", ".join(o.get("case_ids", []) or o.get("assertion_paths", [])))}</small></td><td>{_esc(o["action"])}</td></tr>' for o in scope["objectives"])
    counts = ''.join(f'<li>{_esc(t["kind"])}: {t["mapped"]} mapped / {_esc(t["declared"])} declared</li>' for t in scope["inventory_totals"])
    issues = '<ul>' + ''.join(f'<li>{_esc(g)}</li>' for g in gaps) + '</ul>' if gaps else '<p>No inventory or policy gaps in the reviewed scope.</p>'
    build = report.get("build_verification", {})
    return f'<section id="scope"><p class="eyebrow">WHOLE-SYSTEM SCOPE</p><h2>{summary["complete"]} / {summary["total"]} behavior objectives evaluated</h2><p>{summary["passed"]} passed; {summary["failed"]} failed. Failed objectives count as evaluated, not as release success.</p><p>Candidate identity: <strong>{_esc(build.get("status", "not_observed").replace("_", " "))}</strong>.</p>{issues}<details><summary>Inventory reconciliation</summary><ul>{counts}</ul></details><details><summary>Behavior evidence and next actions</summary><div class="scroll"><table><tr><th>Expected behavior</th><th>Role</th><th>Result</th><th>Bound evidence</th><th>Next action</th></tr>{rows}</table></div></details><p class="muted">{_esc(scope["notice"])}</p></section>'


def render_report(report: dict) -> str:
    integrity = report.get("source_integrity", {})
    files = integrity.get("files", [])
    source_rows = "".join(f'<li>{_esc(f["change"])}: {_esc(f["path"])}</li>' for f in files)
    issues = integrity.get("after", {}).get("issues") or integrity.get("before", {}).get("issues") or integrity.get("after_issues") or integrity.get("before_issues") or []
    issue_rows = "".join(f'<li>{_esc(issue.get("path", "repository"))}: {_esc(issue.get("reason", "unknown"))}</li>' for issue in issues)
    status = integrity.get("status", "not_configured")
    source = f'<section id="source-integrity"><p class="eyebrow">APPLICATION SOURCE</p><h2>{_esc(integrity.get("status", "not_configured").replace("_", " ").capitalize())}</h2><p>{_esc(integrity.get("notice", "No source fingerprint was configured for this run."))}</p>'
    if status == "changed":
        source += '<p class="blocked">Source changed: drift was observed during the run. Execution stopped. Review the file changes and rerun against a stable candidate; the responsible process is not established.</p>'
    elif status == "incomplete":
        source += '<p class="blocked">Source fingerprinting was incomplete. This is not proof of source drift; review scan limits, excluded paths, unreadable files or links before relying on source-integrity protection.</p>'
    elif status == "not_configured":
        source += '<p class="blocked">Source protection was not configured for this run. This is different from a failed or incomplete fingerprint.</p>'
    source += f'<details><summary>File changes and fingerprint coverage</summary><ul>{source_rows or "<li>No changed files recorded.</li>"}</ul><p>Files hashed: {_esc(len(integrity.get("before", {}).get("files", {})))}</p><p>Bytes hashed: {_esc(integrity.get("before", {}).get("bytes_hashed", "unknown"))}</p><p>Scan issues: </p><ul>{issue_rows or "<li>No scan issues recorded.</li>"}</ul><p>Excluded cache/build directories: {_esc(", ".join(integrity.get("before", {}).get("excluded_directories", [])))}</p></details></section>'
    delta = report.get("changes")
    comparison = '<section id="changes"><h2>Changes since your baseline</h2><p>No baseline was supplied. Select an earlier accepted system report with <code>--baseline</code> to compare results.</p></section>'
    if delta:
        s = delta["summary"]
        rows = "".join(f'<tr><td>{_esc(r["check_id"])}</td><td>{_esc(r["before_status"])}</td><td>{_esc(r["after_status"])}</td><td>{_esc("Regression" if r["regression"] else r["status"].replace("_", " "))}</td><td>{_esc("; ".join(d["signal"] + ": " + str(d["before"]) + " to " + str(d["after"]) for d in r["metric_deltas"]) or "No comparable numeric change")}</td></tr>' for r in delta["checks"])
        changes = "".join(f'<li>{_esc(c["kind"])}: {_esc(c.get("id", c.get("check_id", "")))} {_esc(c.get("change", str(c.get("before")) + " to " + str(c.get("after"))))}</li>' for c in delta["changes"])
        comparison = f'<section id="changes"><p class="eyebrow">BASELINE COMPARISON</p><h2>{s["regressions"]} regressions in comparable checks</h2><p>{s["changed_fields"]} scope/result changes; {s["changed_source_files"]} source files changed; {s["incomparable_checks"]} checks need a new comparable baseline.</p><p>{_esc(delta["notice"])}</p><details><summary>Check outcomes</summary><div class="scroll"><table><tr><th>Check</th><th>Baseline</th><th>Current</th><th>Interpretation</th><th>Verified signal changes</th></tr>{rows}</table></div></details><details><summary>Scope and evidence changes</summary><ul>{changes}</ul></details><small>Baseline run {_esc(delta["baseline_run_id"])} / Current run {_esc(delta["current_run_id"])}<br>Comparison {_esc(delta["changes_sha256"])}</small></section>'
    page = _render_report(report)
    return page.replace('<a href="#findings">', '<a href="#changes">What changed</a><a href="#source-integrity">Source integrity</a><a href="#evidence-gaps">Evidence gaps</a><a href="#findings">').replace('<section id="findings">', comparison + source + evidence_gap_panel(report.get("evidence_gap_report"), include_nested=False) + '<section id="findings">')


def _render_report(report: dict) -> str:
    s = report["summary"]
    module_summary = report.get("module_evaluation_summary", {}).get("summary", {})
    metric_counts = _metric_status_counts(report)
    card_items = [
        ("Checks executed", s["checks_executed"]),
        ("Failed checks", s["failed"]),
        ("Blocked checks", s["blocked"]),
        ("Verified AI metrics", metric_counts["verified"]),
    ]
    if module_summary:
        card_items.extend([
            ("Areas with evidence", f'{module_summary.get("areas_with_executed_evidence", 0)}/{module_summary.get("area_count", 0)}'),
            ("Modules with evidence", f'{module_summary.get("modules_with_executed_evidence", 0)}/{module_summary.get("module_count", 0)}'),
        ])
    cards = "".join(f'<div class="card"><small>{_esc(label)}</small><div class="number">{_esc(value)}</div></div>' for label, value in card_items)
    findings = []
    details = []
    for row in report["checks"]:
        if row["status"] != "passed":
            interpretation = check_interpretation(row)
            findings.append(f'<article><h3 class="{_esc(row["status"])}">{_esc(row["id"])}: {_esc(row["reason"])}</h3><p>{_esc(interpretation)}</p><p>{_esc(row.get("action", "Review the detailed evidence."))}</p><small>Components: {_esc(", ".join(row["component_ids"]))}. Root cause: not established.</small></article>')
        raw = {k: v for k, v in row.items() if k != "metrics"}
        metric_rows = []
        for dimension, metric in row.get("metrics", {}).items():
            metric_rows.append(f'<tr><td>{_esc(dimension)}</td><td>{_esc(metric.get("trust_status", "missing"))}</td><td>{_esc(metric.get("measurement_status", "not_measured"))}</td><td>{_esc(metric.get("reason", metric.get("definition", "See detailed local metric report")))}</td></tr>')
        link = ""
        artifact = row.get("artifact")
        if isinstance(artifact, str) and Path(artifact).name == artifact and artifact.endswith(".json"):
            link = f'<p><a href="{_esc(artifact[:-5] + ".html")}">Open full local AI/browser report</a></p>'
        details.append(f'<details><summary>{_esc(row["id"])} <span class="{_esc(row["status"])}">{_esc(row["status"])}</span></summary>{link}<pre>{_esc(json.dumps(raw, indent=2))}</pre><div class="scroll"><table>{"".join(metric_rows)}</table></div></details>')
    coverage = "".join(f'<tr><td>{_esc(c["module"])}</td><td>{_esc(c["name"])}</td><td>{"Executed" if c["complete"] else "Gap"}</td><td>{_esc("; ".join(c["gaps"]) or "All reviewed required checks executed; this is not proof of every behavior.")}{dimension_details(c)}</td></tr>' for c in report["coverage"])
    weak = [r["id"] for r in report["checks"] if r.get("strength") == "status_only"]
    caution = f'<p class="blocked">Status-only checks: {_esc(", ".join(weak))}. These prove response status, not correct content or business behavior.</p>' if weak else ""
    caution += "".join(f'<p class="blocked">{_esc(row["id"])}: {_esc(advice["summary"])} {_esc(advice["action"])}</p>' for row in report["checks"] for advice in row.get("workflow_advisories", []))
    definition = "Fully covered components require every reviewed required layer/dimension for that component to reach executed pass/fail evidence. A run can execute checks and still show few or zero fully covered components when required layers remain missing, blocked, disabled, unbound, or status-only."
    return f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PRE-D release evidence review</title><style>{STYLE}</style><main>{report_hero(report, cards)}<nav><a href="#executive-summary">Summary</a><a href="#report-guide">How to read</a><a href="#ai-quality">AI scorecard</a><a href="#harness-recommendations">Fix plan</a><a href="#findings">Immediate issues</a><a href="#traceability">Findings and proof</a><a href="#module-evaluation">Coverage map</a><a href="#scope">Behavior coverage</a><a href="#coverage">Modules</a><a href="#evidence">Evidence appendix</a></nav>{executive_summary_panel(report)}{report_guide_panel()}{ai_quality_metrics_panel(report)}<p class="muted">{_esc(definition)}</p>{caution}{harness_recommendations_panel(report.get("harness_recommendations"))}<section id="findings"><p class="eyebrow">IMMEDIATE ISSUES</p><h2>What needs attention now</h2>{"".join(findings) or "<p>No executed check failed. Review uncovered components before drawing a release conclusion.</p>"}</section>{finding_register_panel(report.get("finding_register"), title="FINDINGS AND PROOF")}{module_evaluation_panel(report)}{scope_panel(report)}<section id="coverage"><p class="eyebrow">MODULE DETAILS</p><h2>Module coverage details</h2><p>Open this only when you need component-level proof. The summary and AI scorecard sections above are the intended starting point.</p><details><summary>Open module coverage table</summary><div class="scroll"><table><tr><th>Module</th><th>Component</th><th>Execution</th><th>Boundary / next step</th></tr>{coverage}</table></div></details></section><section id="evidence"><p class="eyebrow">EVIDENCE APPENDIX</p><h2>Inspect raw evidence</h2><p>Raw per-check evidence is preserved for audit, but it is intentionally collapsed so the report remains readable.</p><details><summary>Open per-check raw evidence</summary>{"".join(details)}</details></section><small>Run {_esc(report["run_id"])} | {_esc(report["created_at"])} | {_esc(report.get("report_sha256", ""))}</small></main></html>'


def executive_summary_panel(report: dict) -> str:
    summary = report.get("summary", {})
    findings = report.get("finding_register", {}).get("summary", {})
    harness = report.get("harness_recommendations", {}).get("summary", {})
    module = report.get("module_evaluation_summary", {}).get("summary", {})
    source = report.get("source_integrity", {})
    verdict = report.get("verdict", "unknown").replace("_", " ")
    observed = findings.get("observed_defect_count", 0)
    blocked = findings.get("blocked_evidence_count", 0)
    coverage = findings.get("coverage_gap_count", 0)
    setup = findings.get("setup_gap_count", 0)
    if report.get("verdict") == "checks_passed_within_reviewed_scope":
        headline = "Reviewed checks passed, but unreviewed scope still stays outside the claim."
    elif report.get("verdict") == "do_not_ship":
        headline = "Do not ship: at least one reviewed check failed."
    else:
        headline = "Insufficient evidence: fix the listed harness gaps before making a platform trust claim."
    proved = (
        f'What this report proved: {_esc(summary.get("checks_executed", 0))} reviewed check(s) executed; '
        f'{_esc(summary.get("failed", 0))} failed; {_esc(summary.get("blocked", 0))} were blocked; '
        f'{_esc(module.get("areas_with_executed_evidence", 0))}/{_esc(module.get("area_count", 0))} evaluation areas have executed evidence; '
        f'source status is {_esc(source.get("status", "not_configured").replace("_", " "))}.'
    )
    uncovered = (
        f'What remains uncovered: {_esc(coverage)} coverage gap(s) and {_esc(setup)} setup/config gap(s). '
        'These are missing evidence work items, not application defects.'
    )
    return (
        '<section id="executive-summary"><p class="eyebrow">EXECUTIVE SUMMARY</p>'
        f'<h2>{_esc(headline)}</h2>'
        f'<p><strong>Verdict:</strong> {_esc(verdict)}. '
        f'{_esc(summary.get("checks_executed", 0))} checks executed; '
        f'{_esc(summary.get("failed", 0))} failed; {_esc(summary.get("blocked", 0))} blocked. '
        f'{_esc(summary.get("complete_components", 0))}/{_esc(summary.get("components", 0))} components are fully covered across their required evidence, while partial evidence is shown in the area/module sections.</p>'
        f'<p>{proved}</p><p>{uncovered}</p>'
        f'<div class="grid"><div class="card"><small>Observed defects</small><div class="number">{_esc(observed)}</div></div>'
        f'<div class="card"><small>Blocked evidence</small><div class="number">{_esc(blocked)}</div></div>'
        f'<div class="card"><small>Harness recommendations</small><div class="number">{_esc(harness.get("recommendation_count", 0))}</div></div>'
        f'<div class="card"><small>Evaluation areas with evidence</small><div class="number">{_esc(module.get("areas_with_executed_evidence", 0))}/{_esc(module.get("area_count", 0))}</div></div></div>'
        f'<p class="muted">Coverage backlog: {_esc(coverage)} generated review item(s). This is intentionally not treated as a product-defect score.</p>'
        '<p class="muted">Read this summary first. Detailed module maps, raw evidence and all findings are preserved below as expandable audit sections.</p>'
        '</section>'
    )


def report_guide_panel() -> str:
    return (
        '<section id="report-guide"><p class="eyebrow">REPORT GUIDE</p>'
        '<h2>How to read this report</h2>'
        '<p class="section-intro">PRE-D is written for both product stakeholders and developers. The top sections use plain language; the lower sections preserve audit-grade proof for anyone who needs to verify the result.</p>'
        '<div class="grid">'
        '<div class="card"><h3>For a product owner</h3><p>Start with the executive summary, failed or blocked checks, and fix plan. Treat missing evidence as a coverage gap, not as a hidden pass.</p></div>'
        '<div class="card"><h3>For a developer</h3><p>Use the AI scorecard to see the metric, score, calculation method, evidence considered and exact next action.</p></div>'
        '<div class="card"><h3>For an auditor</h3><p>Open findings and proof, source integrity, module details and the evidence appendix to trace each claim back to a check or artifact.</p></div>'
        '</div>'
        '<p class="explain"><strong>Simple rule:</strong> verified means PRE-D independently calculated the result from local evidence; declared means the application supplied the evidence and PRE-D schema-checked it; missing means no honest score is available yet.</p>'
        '</section>'
    )


def check_interpretation(row: dict) -> str:
    reason = row.get("reason")
    status = row.get("status")
    case_count = row.get("case_count") or row.get("planned_case_count")
    blocked_cases = row.get("blocked_case_count", 0)
    if status == "failed" and reason == "metric_gates":
        return "Measured evidence ran and failed one or more configured gates."
    if status == "blocked" and reason == "metric_gates" and case_count and blocked_cases == 0:
        return "Cases produced evidence, but a required metric gate could not be satisfied or was not decision-grade for this pack. This is gate-blocked evidence, not a transport timeout."
    if status == "blocked" and reason == "external_test_results":
        return "The external suite returned results, but PRE-D could not treat the suite as clean release evidence under the configured gate or skipped/blocked-result policy."
    if status == "blocked":
        return "PRE-D could not collect the intended release evidence for this check; this is neither pass nor product defect without the blocked evidence."
    return "Review the detailed evidence and configured gate for this check."


def finding_register_panel(register: dict | None, *, anchor: str = "traceability", title: str = "TRACEABLE FINDINGS") -> str:
    if not isinstance(register, dict):
        return ""
    summary = register.get("summary", {})
    def row_html(finding: dict) -> str:
        proof = finding.get("proof", {})
        if isinstance(proof, dict):
            proof_text = "; ".join(
                f"{key}: {value}" for key, value in proof.items()
                if key in {"check_id", "component_id", "module", "status", "reason", "evidence_type", "missing_layers", "missing_metric_dimensions", "source_integrity_status"}
            ) or json.dumps(proof, sort_keys=True)[:400]
        else:
            proof_text = str(proof)
        return (
            f'<tr><td><strong>{_esc(finding.get("finding_id", ""))}</strong><br><small>{_esc(finding.get("audit_hash", ""))}</small></td>'
            f'<td class="{_esc(finding.get("finding_class", "informational"))}">{_esc(finding.get("finding_class", "informational").replace("_", " "))}<br><small>{_esc(finding.get("coverage_priority", finding.get("severity", "")))} priority</small></td>'
            f'<td>{_esc(finding.get("category", ""))}<br><small>{_esc(finding.get("title", ""))}</small></td>'
            f'<td>{_esc(finding.get("source", ""))}<br><small>{_esc(finding.get("evidence_type", ""))} / {_esc(finding.get("confidence", ""))}</small></td>'
            f'<td>{_esc(proof_text)}</td><td>{_esc(finding.get("owner_action", ""))}</td></tr>'
        )
    findings = register.get("findings", [])
    preview_rows = "".join(row_html(finding) for finding in findings[:12])
    all_rows = "".join(row_html(finding) for finding in findings[:250])
    extra_note = (
        f'<p class="muted">Showing the first 12 findings here. The expandable table keeps up to 250 findings in the HTML; the JSON register keeps the complete set.</p>'
        if len(findings) > 12 else ""
    )
    return (
        f'<section id="{_esc(anchor)}"><p class="eyebrow">{_esc(title)}</p>'
        f'<h2>{_esc(summary.get("execution_finding_count", 0))} executed finding(s), {_esc(summary.get("coverage_gap_count", 0))} coverage gap(s)</h2>'
        f'<p>{_esc(register.get("notice", ""))}</p>'
        '<p class="muted">Observed defects and blocked evidence come from executed checks. Coverage gaps prove missing evidence, not product defects.</p>'
        f'<div class="grid"><div class="card"><small>Observed defects</small><div class="number">{_esc(summary.get("observed_defect_count", 0))}</div></div>'
        f'<div class="card"><small>Blocked evidence</small><div class="number">{_esc(summary.get("blocked_evidence_count", 0))}</div></div>'
        f'<div class="card"><small>Coverage gaps</small><div class="number">{_esc(summary.get("coverage_gap_count", 0))}</div></div>'
        f'<div class="card"><small>Setup/config gaps</small><div class="number">{_esc(summary.get("setup_gap_count", 0))}</div></div></div>'
        f'{extra_note}<details><summary>Open finding preview</summary><div class="scroll"><table><tr><th>Finding</th><th>Class / priority</th><th>Category</th><th>Source / provenance</th><th>Proof</th><th>Action</th></tr>{preview_rows or "<tr><td colspan=6>No findings recorded.</td></tr>"}</table></div></details>'
        f'<details><summary>Open all traceable findings shown in this report</summary><div class="scroll"><table><tr><th>Finding</th><th>Class / priority</th><th>Category</th><th>Source / provenance</th><th>Proof</th><th>Action</th></tr>{all_rows or "<tr><td colspan=6>No findings recorded.</td></tr>"}</table></div></details>'
        f'<details><summary>Finding register summary</summary><pre>{_esc(json.dumps(summary, indent=2))}</pre></details>'
        '</section>'
    )


def harness_recommendations_panel(recommendations: dict | None, *, anchor: str = "harness-recommendations") -> str:
    if not isinstance(recommendations, dict):
        return ""
    summary = recommendations.get("summary", {})
    rows = []
    for item in recommendations.get("recommendations", [])[:12]:
        criteria = "".join(f'<li>{_esc(value)}</li>' for value in item.get("acceptance_criteria", []))
        inputs = ", ".join(item.get("owner_input_needed", []))
        class_counts = (
            f'{_esc(item.get("observed_defect_count", 0))} observed, '
            f'{_esc(item.get("blocked_evidence_count", 0))} blocked, '
            f'{_esc(item.get("coverage_gap_count", 0))} coverage gap(s)'
        )
        scope_note = ""
        if int(item.get("coverage_gap_count", 0) or 0) and not int(item.get("observed_defect_count", 0) or 0):
            scope_note = "Scope: uncovered modules/components, not checks already measured elsewhere."
        rows.append(
            f'<tr><td class="{_esc(item.get("priority", "medium"))}">{_esc(item.get("priority", ""))}</td>'
            f'<td><strong>{_esc(item.get("title", ""))}</strong><br><small>{_esc(item.get("why", ""))}</small></td>'
            f'<td>{_esc(item.get("implementation", ""))}</td>'
            f'<td><ul>{criteria}</ul></td>'
            f'<td>{_esc(inputs)}<br><small>{class_counts}. {_esc(scope_note)} Linked IDs may overlap across workstreams: {_esc(", ".join(item.get("based_on_finding_ids", [])[:5]))}</small></td></tr>'
        )
    return (
        f'<section id="{_esc(anchor)}"><p class="eyebrow">FIX PLAN / HARNESS ENGINEERING RECOMMENDATIONS</p>'
        f'<h2>What should the team fix next?</h2>'
        f'<p>{_esc(recommendations.get("notice", ""))}</p>'
        f'<p class="muted">{_esc(summary.get("recommendation_count", 0))} recommended workstream(s). Linked findings can overlap across workstreams. Coverage-gap links are harness work, not separate product defects.</p>'
        f'<details open><summary>Open harness engineering recommendations</summary><div class="scroll"><table><tr><th>Priority</th><th>Recommendation</th><th>Implementation</th><th>Acceptance criteria</th><th>Input needed / linked proof</th></tr>{"".join(rows) or "<tr><td colspan=5>No harness recommendations generated.</td></tr>"}</table></div></details>'
        f'<details><summary>Recommendation register summary</summary><pre>{_esc(json.dumps(summary, indent=2))}</pre></details>'
        '</section>'
    )


def _authorization_summary(report: dict) -> dict[str, int]:
    checks = [
        row for row in report.get("checks", [])
        if row.get("layer") == "authorization" or "authorization" in row.get("id", "") or row.get("id", "").startswith("authz-")
    ]
    executed = sum(1 for row in checks if row.get("status") in {"passed", "failed", "blocked"})
    failed = sum(1 for row in checks if row.get("status") == "failed")
    backlog = 0
    for component in report.get("coverage", []):
        gaps = component.get("gaps", [])
        if any("authorization" in str(gap).lower() for gap in gaps):
            backlog += 1
    return {"executed": executed, "failed": failed, "backlog": backlog}


def module_evaluation_panel(report: dict) -> str:
    matrix = report.get("module_evaluation_summary")
    if not isinstance(matrix, dict):
        return ""
    summary = matrix.get("summary", {})
    report_summary = report.get("summary", {})
    authz = _authorization_summary(report)
    rows = []
    for area in matrix.get("areas", []):
        metrics = ", ".join(area.get("verified_metrics") or area.get("declared_metrics") or area.get("missing_requested_metrics") or [])
        rows.append(
            f'<tr><td><strong>{_esc(area["title"])}</strong><br><small>{_esc(area["description"])}</small></td>'
            f'<td class="{_esc(area["status"])}">{_esc(area["status"].replace("_", " "))}</td>'
            f'<td class="{_esc(area["evidence_strength"])}">{_esc(area["evidence_strength"].replace("_", " "))}</td>'
            f'<td>{_esc(area["executed_check_count"])} / {_esc(area["configured_check_count"])} checks<br>'
            f'<small>{_esc(area["complete_component_count"])} / {_esc(area["discovered_component_count"])} components complete</small></td>'
            f'<td>{_esc(metrics or "No metric evidence")}</td>'
            f'<td>{_esc(area["result_basis"])}<br><small>{_esc(area["action"])}</small></td></tr>'
        )
    module_rows = []
    for row in matrix.get("modules", []):
        module_rows.append(
            f'<tr><td>{_esc(row["module"])}</td><td class="{_esc(row["status"])}">{_esc(row["status"].replace("_", " "))}</td>'
            f'<td>{_esc(", ".join(row.get("categories", [])) or "uncategorized")}</td>'
            f'<td>{_esc(row["executed_check_count"])} / {_esc(row["configured_check_count"])}</td>'
            f'<td>{_esc(", ".join(row.get("verified_metrics", [])) or "No verified metric groups")}</td>'
            f'<td>{_esc(row["next_action"])}</td></tr>'
        )
    return (
        '<section id="module-evaluation"><p class="eyebrow">COVERAGE MAP</p>'
        f'<h2>Which parts of the application had usable evidence?</h2>'
        f'<p class="section-intro">{_esc(summary.get("areas_with_executed_evidence", 0))} / {_esc(summary.get("area_count", 0))} evaluation areas have executed evidence. This section is a coverage map: it explains what PRE-D actually touched and what still needs evidence.</p>'
        f'<p>{_esc(matrix.get("notice", ""))}</p>'
        f'<div class="grid"><div class="card"><small>Areas tested</small><div class="number">{_esc(summary.get("areas_evaluated", 0))}</div></div>'
        f'<div class="card"><small>Failed areas</small><div class="number">{_esc(summary.get("areas_with_failures", 0))}</div></div>'
        f'<div class="card"><small>Blocked areas</small><div class="number">{_esc(summary.get("areas_blocked", 0))}</div></div>'
        f'<div class="card"><small>Verified metric groups</small><div class="number">{_esc(summary.get("verified_metric_groups", 0))}</div></div>'
        f'<div class="card"><small>Authorization checks executed</small><div class="number">{_esc(authz["executed"])}</div><small>{_esc(authz["failed"])} failed. {_esc(authz["backlog"])} component(s) still mention authorization gaps.</small></div>'
        f'<div class="card"><small>Strictly complete components</small><div class="number">{_esc(report_summary.get("complete_components", 0))}/{_esc(report_summary.get("components", 0))}</div><small>This is the strict all-required-evidence count, not the execution count.</small></div></div>'
        f'<details><summary>Open evaluation area table</summary><div class="scroll"><table><tr><th>Evaluation area</th><th>Status</th><th>Evidence</th><th>Execution</th><th>Metrics</th><th>Meaning / next action</th></tr>{"".join(rows)}</table></div></details>'
        f'<details><summary>Per-module result map</summary><div class="scroll"><table><tr><th>Module</th><th>Status</th><th>Categories</th><th>Checks</th><th>Verified metrics</th><th>Next action</th></tr>{"".join(module_rows)}</table></div></details>'
        '</section>'
    )


def evidence_gap_panel(gaps: dict | None, *, include_nested: bool = True) -> str:
    if not isinstance(gaps, dict):
        return ""
    summary = gaps.get("summary", {})
    command_status = gaps.get("command_status", {})
    status_message = ""
    if isinstance(command_status, dict) and command_status.get("exit_reason"):
        status_message = (
            f'<p><strong>{_esc(command_status.get("status", ""))}.</strong> '
            f'{_esc(command_status.get("exit_reason", ""))}</p>'
        )
    action_rows = "".join(
        f'<tr><td class="{_esc(item.get("priority", "medium"))}">{_esc(item.get("priority", ""))}</td>'
        f'<td>{_esc(item.get("category", ""))}</td><td>{_esc(item.get("message", ""))}</td>'
        f'<td>{_esc(item.get("action", ""))}</td></tr>'
        for item in gaps.get("action_items", [])[:100]
    )
    module_rows = "".join(
        f'<tr><td>{_esc(row.get("module", ""))}</td><td>{_esc(row.get("component", ""))}</td>'
        f'<td>{_esc(", ".join(row.get("missing_layers", [])) or "None")}</td>'
        f'<td>{_esc(", ".join(row.get("missing_metric_dimensions", [])) or "None")}</td>'
        f'<td>{_esc(row.get("action", ""))}</td></tr>'
        for row in gaps.get("module_gaps", [])[:200]
    )
    workflow_rows = "".join(
        f'<tr><td>{_esc(row.get("check_id", ""))}</td><td>{_esc(", ".join(row.get("case_ids", [])))}</td>'
        f'<td>{_esc(row.get("message", ""))}</td><td>{_esc(row.get("action", ""))}</td></tr>'
        for row in gaps.get("weak_workflows", [])[:100]
    )
    nested_sections = ""
    if include_nested:
        nested_sections = (
            harness_recommendations_panel(gaps.get("harness_recommendations"), anchor="evidence-gap-harness-recommendations")
            + finding_register_panel(gaps.get("finding_register"), anchor="evidence-gap-traceability", title="EVIDENCE-GAP TRACEABILITY")
        )
    else:
        nested_sections = '<p class="muted">Full fix plan and traceable findings are shown once in the main report sections below, so this evidence-gap section only lists the repair backlog.</p>'
    setup = setup_plan_panel(gaps.get("setup_plan"))
    return (
        '<section id="evidence-gaps"><p class="eyebrow">EVIDENCE GAP REPORT</p>'
        f'<h2>{_esc(summary.get("action_item_count", 0))} action item(s) before a stronger platform claim</h2>'
        f'<div class="grid"><div class="card"><small>Component gaps</small><div class="number">{_esc(summary.get("component_gap_count", 0))}</div></div>'
        f'<div class="card"><small>Workflow gaps</small><div class="number">{_esc(summary.get("workflow_gap_count", 0))}</div></div>'
        f'<div class="card"><small>Blocked checks</small><div class="number">{_esc(summary.get("blocked_check_count", 0))}</div></div>'
        f'<div class="card"><small>Not executed checks</small><div class="number">{_esc(summary.get("not_executed_check_count", 0))}</div></div></div>'
        f'{status_message}'
        f'<p>{_esc(gaps.get("notice", ""))}</p>'
        f'{nested_sections}'
        f'<details><summary>Next actions</summary><div class="scroll"><table><tr><th>Priority</th><th>Category</th><th>Gap</th><th>Fix</th></tr>{action_rows or "<tr><td colspan=4>No gap actions recorded.</td></tr>"}</table></div></details>'
        f'<details><summary>Module gaps</summary><div class="scroll"><table><tr><th>Module</th><th>Component</th><th>Missing layers</th><th>Missing metrics</th><th>Fix</th></tr>{module_rows or "<tr><td colspan=5>No module gaps recorded.</td></tr>"}</table></div></details>'
        f'<details><summary>Workflow assertion gaps</summary><div class="scroll"><table><tr><th>Check</th><th>Cases</th><th>Gap</th><th>Fix</th></tr>{workflow_rows or "<tr><td colspan=4>No weak workflow assertions recorded.</td></tr>"}</table></div></details>'
        f'{setup}</section>'
    )


def setup_plan_panel(setup: dict | None) -> str:
    if not isinstance(setup, dict):
        return ""
    summary = setup.get("summary", {})
    step_rows = []
    component_rows = []
    for step in setup.get("steps", []):
        commands = "<br>".join(f'<code>{_esc(command)}</code>' for command in step.get("commands", []))
        actions = "".join(f'<li>{_esc(action)}</li>' for action in step.get("actions", []))
        step_rows.append(
            f'<tr><td class="{_esc(step.get("priority", "medium"))}">{_esc(step.get("priority", ""))}</td>'
            f'<td><strong>{_esc(step.get("title", ""))}</strong><br><small>{_esc(step.get("why", ""))}</small></td>'
            f'<td><ul>{actions}</ul></td><td>{commands}</td></tr>'
        )
        for item in step.get("component_actions", [])[:250]:
            component_rows.append(
                f'<tr><td>{_esc(item.get("module", ""))}</td><td>{_esc(item.get("component", ""))}</td>'
                f'<td>{_esc(", ".join(item.get("missing_layers", [])) or "None")}</td>'
                f'<td>{_esc(", ".join(item.get("missing_metric_dimensions", [])) or "None")}</td>'
                f'<td>{_esc("; ".join(item.get("recommended_templates", [])) or "custom_check")}</td>'
                f'<td>{_esc(item.get("summary", ""))}</td></tr>'
            )
    return (
        '<section id="full-platform-setup"><p class="eyebrow">FULL-PLATFORM SETUP CHECKLIST</p>'
        f'<h2>{_esc(summary.get("step_count", 0))} setup step(s), {_esc(summary.get("component_action_count", 0))} component action(s)</h2>'
        f'<p>{_esc(setup.get("notice", ""))}</p>'
        f'<div class="scroll"><table><tr><th>Priority</th><th>Step</th><th>Actions</th><th>Commands</th></tr>{"".join(step_rows) or "<tr><td colspan=4>No setup steps recorded.</td></tr>"}</table></div>'
        f'<details><summary>Missing module/dimension repair map</summary><div class="scroll"><table><tr><th>Module</th><th>Component</th><th>Missing layers</th><th>Missing metrics</th><th>Suggested pack</th><th>Required input</th></tr>{"".join(component_rows) or "<tr><td colspan=6>No component repair actions recorded.</td></tr>"}</table></div></details>'
        '</section>'
    )


def render_evidence_gap_report(gaps: dict) -> str:
    title = "Evidence gap repair plan"
    return (
        f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{_esc(title)}</title><style>{STYLE}</style><main><p class="eyebrow">PRE-D / EVIDENCE GAP REPORT</p>'
        f'<h1>{_esc(title)}</h1><p>{_esc(gaps.get("notice", ""))}</p>'
        '<nav><a href="#evidence-gaps">Summary</a><a href="#evidence-gap-harness-recommendations">Harness recommendations</a><a href="#evidence-gap-traceability">Traceable findings</a><a href="#full-platform-setup">Setup checklist</a></nav>'
        f'{evidence_gap_panel(gaps)}'
        f'<details><summary>Raw readiness JSON</summary><pre>{_esc(json.dumps(gaps.get("readiness", {}), indent=2))}</pre></details>'
        '</main></html>'
    )


def dimension_details(component: dict) -> str:
    rows = component.get("dimension_inventory", [])
    if not rows:
        return ""
    pending = [r["dimension"] for r in rows if r["tier"] == "baseline" and r["status"] in {"not_requested", "requested_not_measured"}]
    notice = '<p class="blocked">Baseline metrics not exercised: ' + _esc(", ".join(pending)) + '.</p>' if pending else ""
    entries = "".join(f'<p><strong>{_esc(r["dimension"])}</strong> / {_esc(r["tier"])} / {_esc(r["status"])}</p>' for r in rows)
    return notice + '<details><summary>Metric coverage</summary>' + entries + '</details>'


def setup_html(plan: dict, token: str, path: Path) -> str:
    from .system_readiness import full_platform_setup_plan
    initial = json.dumps({"plan": plan, "token": token, "digest": plan_digest(plan), "plan_path": str(path),
                          "setup_plan": full_platform_setup_plan(plan, path.parent)}).replace("<", "\\u003c").replace("&", "\\u0026")
    return f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PRE-D system setup</title><style>{STYLE}</style><main><p class="eyebrow">PRE-D / LOCAL SYSTEM SETUP</p><h1>From discovered surface to reviewed evidence.</h1><p>No target is called here. Review scope, choose assertions and attach existing AI/browser plans. Approve execution separately from the CLI.</p><p><small>{_esc(path)}</small></p><section><h2>1. Confirm the system</h2><div class="grid"><label>Application version<input id="version"></label><label>Target base URL<input id="base"></label><label>Environment<select id="environment"><option>local</option><option>staging</option></select></label></div><label>Isolation / disposable tenant setup<input id="isolation"></label><label><input type="checkbox" id="confirmed">I reviewed the inventory and required layers, including missing and disabled capabilities.</label><div id="components"></div><details><summary>Add a missing component or role matrix</summary><label>Component name<input id="component-name"></label><label>Module<input id="component-module"></label><button id="add-component">Add component</button><label>Roles (comma-separated)<input id="roles"></label><button id="add-roles">Draft API role matrix</button></details></section><section><h2>2. Review executable checks</h2><p>Do not use today\'s target output as its own expected answer. Status-only checks are narrow evidence. Identities reference environment variables, never stored passwords.</p><div id="checks"></div></section><section><h2>3. Add a check or existing evaluation</h2><label>Component<select id="component"></select></label><label>Check ID<input id="checkid"></label><label>Check template<select id="template"><option value="http">HTTP content / integration</option><option value="tenant">Cross-tenant isolation</option><option value="command">Code or security test suite (JUnit)</option><option value="load">Bounded read-only load</option><option value="recovery">Isolated failure and recovery</option></select></label><button id="add-check">Add disabled draft</button><label>Existing local esx-eval.json path<input id="config"></label><button id="bind">Attach AI/browser plan for review</button></section><section><h2>4. Save, then approve</h2><button id="save">Save reviewed plan</button><pre>esx-eval system approve --plan &quot;{_esc(path)}&quot;\nesx-eval system preflight --plan &quot;{_esc(path)}&quot;\nesx-eval system run --plan &quot;{_esc(path)}&quot; --out ./new-system-run --history ./pred-history.sqlite</pre><p role="status" id="status"></p></section></main><script>const initial={initial};</script>' + SETUP_SCRIPT + '</html>'


SETUP_SCRIPT = r"""<script>
let plan=initial.plan,digest=initial.digest,proposal=null,setupPlan=initial.setup_plan||null,planPath=initial.plan_path||'<system-plan.json>';
const byId=id=>document.getElementById(id);
const el=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n};
const cmd=text=>String(text).replaceAll('<system-plan.json>',planPath);
function field(parent,title,value,change){const label=el('label',title),input=el('input');input.value=value;input.oninput=()=>change(input.value);label.append(input);parent.append(label);return input;}
function jsonField(parent,title,value,change){const label=el('label',title),input=el('textarea');input.rows=4;input.value=JSON.stringify(value,null,2);input.oninput=()=>{try{change(JSON.parse(input.value));input.setCustomValidity('');byId('status').textContent=''}catch{input.setCustomValidity('Invalid JSON');byId('status').textContent='Correct invalid JSON before saving.'}};label.append(input);parent.append(label);}
function render(){
byId('version').value=plan.application_version;byId('base').value=plan.base_url;byId('confirmed').checked=plan.inventory_confirmed===true;
byId('environment').value=plan.environment;byId('isolation').value=plan.isolation_note||'';byId('roles').value=plan.roles.join(', ');
byId('components').replaceChildren();byId('component').replaceChildren();
plan.components.forEach(c=>{const d=el('details'),s=el('summary',c.name+' / '+c.module);d.append(s);field(d,'Module grouping',c.module,v=>c.module=v);d.append(el('p','Source: '+(c.evidence||[]).map(e=>e.source).join(', ')));field(d,'Required layers: functional, workflow, ai, integration, code, authorization, security, reliability',c.required_layers.join(', '),v=>c.required_layers=v.split(',').map(x=>x.trim()).filter(Boolean));field(d,'Feature flag name (optional)',c.feature_flag||'',v=>c.feature_flag=v);field(d,'Capability enabled: true / false / unknown',String(c.enabled??'unknown'),v=>c.enabled=v==='true'?true:v==='false'?false:'unknown');field(d,'Dependency component IDs (comma-separated)',(c.depends_on||[]).join(', '),v=>c.depends_on=v.split(',').map(x=>x.trim()).filter(Boolean));d.append(el('small','Component ID: '+c.id));byId('components').append(d);const option=el('option',c.name);option.value=c.id;byId('component').append(option)});
byId('checks').replaceChildren();plan.checks.forEach(c=>{const d=el('details');d.append(el('summary',c.id+' / '+c.layer),el('p',c.authoring_note||''));const label=el('label','Enable and mark reviewed');const box=el('input');box.type='checkbox';box.checked=c.enabled&&c.reviewed;box.onchange=()=>{c.enabled=box.checked;c.reviewed=box.checked};label.prepend(box);d.append(label);
field(d,'Layer',c.layer,v=>c.layer=v);field(d,'Mapped component IDs (comma-separated)',c.component_ids.join(', '),v=>c.component_ids=v.split(',').map(x=>x.trim()).filter(Boolean));field(d,'Timeout seconds',c.timeout_seconds||30,v=>c.timeout_seconds=Number(v));
if(['http','load','recovery'].includes(c.type)){field(d,'Method',c.method,v=>c.method=v);field(d,'Path',c.path,v=>c.path=v);field(d,'Expected HTTP statuses',c.expected_status.join(', '),v=>c.expected_status=v.split(',').filter(x=>x.trim()).map(x=>Number(x.trim())));field(d,'Role',c.role||'anonymous',v=>c.role=v);
let header=Object.keys(c.headers_from_env||{})[0]||'Authorization',env=Object.values(c.headers_from_env||{})[0]||'';
field(d,'Identity header name',header,v=>{const values={...c.headers_from_env};delete values[header];header=v;if(env)values[header]=env;c.headers_from_env=values});field(d,'Identity environment variable',env,v=>{env=v;c.headers_from_env={...c.headers_from_env};if(v)c.headers_from_env[header]=v;else delete c.headers_from_env[header]});
jsonField(d,'All identity headers (environment variable names only)',c.headers_from_env||{},v=>c.headers_from_env=v);
jsonField(d,'JSON assertions: [{"path":"ready","equals":true}]',c.json_assertions||[],v=>c.json_assertions=v);
if(!['GET','HEAD','OPTIONS'].includes(c.method))jsonField(d,'JSON request body (approved fixtures only)',c.json_body||{},v=>c.json_body=v);}
if(c.type==='load'){field(d,'Requests (1..100)',c.requests,v=>c.requests=Number(v));field(d,'Concurrency (1..8)',c.concurrency,v=>c.concurrency=Number(v));field(d,'P95 latency budget ms',c.max_p95_ms,v=>c.max_p95_ms=Number(v));}
if(c.type==='command'){jsonField(d,'Test command argv',c.command,v=>c.command=v);field(d,'Working directory',c.cwd||'.',v=>c.cwd=v);field(d,'Fresh JUnit XML result path',c.result_file,v=>c.result_file=v);}
if(c.type==='recovery'){jsonField(d,'Injection command argv (isolated only)',c.inject_command,v=>c.inject_command=v);jsonField(d,'Cleanup/recovery command argv',c.recover_command,v=>c.recover_command=v);field(d,'Expected disrupted HTTP statuses',c.disruption_expected_status.join(', '),v=>c.disruption_expected_status=v.split(',').map(Number));field(d,'Recovery deadline seconds',c.recovery_timeout_seconds,v=>c.recovery_timeout_seconds=Number(v));}
if(c.type==='evaluation'){d.append(el('p','Requested dimensions: '+(c.requested_dimensions||[]).join(', ')));jsonField(d,'Reviewed metric gates',c.gates,v=>{if(!Array.isArray(v))throw Error();c.gates=v});}
byId('checks').append(d)});
renderScope();
renderOnboarding();
renderSetupChecklist();
}
function renderSetupChecklist(){
let host=byId('setup-checklist');if(!host){host=el('section');host.id='setup-checklist';const main=document.querySelector('main');const after=byId('onboarding');main.insertBefore(host,after?after.nextSibling:main.querySelector('section'));}
if(!setupPlan){host.replaceChildren(el('h2','Full-platform setup checklist unavailable'));return;}
const summary=setupPlan.summary||{};host.replaceChildren(el('p','PRE-D / FULL-PLATFORM SETUP'),el('h2',(summary.step_count||0)+' setup steps, '+(summary.component_action_count||0)+' module actions'));
host.append(el('p',setupPlan.notice||'These steps are authoring guidance only; they do not execute the target or modify application code.'));
const pre=el('pre',cmd('esx-eval system agent-tasks --plan "<system-plan.json>" --out "./agent-tasks.json"\nesx-eval system draft-packs --plan "<system-plan.json>" --out "./coverage-drafts.json"\nesx-eval system evidence-gaps --plan "<system-plan.json>" --out "./evidence-gaps.json"'));host.append(pre);
(setupPlan.steps||[]).forEach(step=>{const d=el('details');d.open=step.priority==='high';d.append(el('summary',step.priority.toUpperCase()+': '+step.title),el('p',step.why||''));const ul=el('ul');(step.actions||[]).forEach(a=>ul.append(el('li',a)));d.append(ul);if((step.commands||[]).length)d.append(el('pre',step.commands.map(cmd).join('\n')));if((step.component_actions||[]).length){const table=el('table');table.innerHTML='<tr><th>Module</th><th>Component</th><th>Missing</th><th>Pack</th><th>Input needed</th></tr>';step.component_actions.slice(0,100).forEach(item=>{const row=document.createElement('tr');row.innerHTML='<td></td><td></td><td></td><td></td><td></td>';row.children[0].textContent=item.module;row.children[1].textContent=item.component;row.children[2].textContent=[...(item.missing_layers||[]),...(item.missing_metric_dimensions||[])].join(', ')||'Review';row.children[3].textContent=(item.recommended_templates||[]).join(', ')||'custom_check';row.children[4].textContent=item.summary||'';table.append(row)});d.append(table);}host.append(d);});
}
function renderOnboarding(){
let host=byId('onboarding');if(!host){host=el('section');host.id='onboarding';const main=document.querySelector('main');main.insertBefore(host,main.querySelector('section'));}
host.replaceChildren(el('p','PRE-D / REUSABLE SETUP'),el('h2','Discover once. Review changes on the next build.'));
host.append(el('p',plan.profile?'Profile revision '+plan.profile.revision+'. Checks, roles and evidence bindings are retained across refreshes.':'This plan uses the earlier setup flow. Use system bootstrap to create a protected reusable profile.'));
if(plan.source_protection){host.append(el('p','Application code access: read-only. PRE-D output stays outside the repository. Saved source fingerprint: '+plan.source_protection.snapshot.status+'. Preflight verifies the current files before execution.'));}
const cards=el('div');cards.className='grid';for(const [label,count] of [['Discovered components',plan.components.length],['Reviewed checks',plan.checks.filter(c=>c.enabled&&c.reviewed).length],['Unbound behaviors',(plan.scope_contract?.objectives||[]).filter(o=>!o.check_id).length]]){const card=el('div');card.className='card';card.append(el('small',label),el('h3',String(count)));cards.append(card);}host.append(cards);
if(plan.profile_changes){const d=el('details');d.open=true;d.append(el('summary','Changes requiring review'),el('p',plan.profile_changes.added_components.length+' new components, '+plan.profile_changes.changed_components.length+' changed contracts, '+plan.profile_changes.not_rediscovered_components.length+' no longer discovered. Existing checks are retained.'),el('p',plan.profile_changes.source.changed_file_count+' changed source files.'));host.append(d);}
const actions=el('div');actions.className='grid';const refresh=el('button','Refresh discovery');refresh.disabled=!plan.profile;refresh.onclick=()=>post('refresh').catch(e=>byId('status').textContent=e.message);actions.append(refresh);
const draft=el('button','Draft behavior suggestions');draft.onclick=()=>post('assist').catch(e=>byId('status').textContent=e.message);actions.append(draft);host.append(actions);
const ai=el('details');ai.append(el('summary','Use a local planning model'),el('p','The local model can inspect inventory metadata and draft suggestions. It receives no source contents, credentials or response bodies. It cannot execute tests or modify application code.'));
const model=field(ai,'Installed Ollama model name','',()=>{}),button=el('button','Generate local model suggestions');button.onclick=async()=>{if(!model.value.trim()){byId('status').textContent='Enter an installed local model name.';return;}button.disabled=true;byId('status').textContent='Inspecting inventory with the local model. No target calls are made.';try{await post('assist',{model:model.value.trim()})}catch(e){byId('status').textContent=e.message;button.disabled=false}};ai.append(button);host.append(ai);
if(proposal){const box=el('details');box.open=true;box.append(el('summary','Review suggested behaviors'),el('p',proposal.producer==='local_model'?'Generated by your local model. Confirm the intended behaviors before accepting.':'Generated from deterministic templates. These are drafting aids.'),el('p','Suggestions address '+(proposal.suggested_component_count??'unknown')+' / '+proposal.inventory_component_count+' discovered components. All other components remain in the scope review.'));
const selected=new Set();proposal.suggestions.forEach(s=>{const label=el('label',s.module+' / '+s.title),check=el('input');check.type='checkbox';check.onchange=()=>check.checked?selected.add(s.id):selected.delete(s.id);label.prepend(check);box.append(label,el('p',s.reason));});
const accept=el('button','Accept selected as draft objectives');accept.onclick=()=>post('accept',{proposal,selected:[...selected]}).catch(e=>byId('status').textContent=e.message);box.append(accept);host.append(box);}
const tasks=(plan.onboarding||[]).filter(t=>t.kind!=='execution'||!plan.checks.some(c=>c.enabled&&c.reviewed&&c.component_ids.includes(t.component_id)));if(tasks.length){const d=el('details');d.append(el('summary','Inputs still needed ('+tasks.length+')'));tasks.slice(0,100).forEach(t=>d.append(el('p',t.component_id+': '+t.action)));if(tasks.length>100)d.append(el('p','More items are available in the saved profile.'));host.append(d);}
}
function renderScope(){
let host=byId('scope-review');if(!host){host=el('section');host.id='scope-review';const main=document.querySelector('main');main.insertBefore(host,main.querySelector('section:last-of-type'));}host.replaceChildren(el('h2','Whole-system behavior contract'));
host.append(el('p','A module attachment is not proof of every behavior. Name the critical outcomes and bind each to explicit cases or content assertions. Exclusions remain coverage gaps.'));
const scope=plan.scope_contract;
if(!scope){const button=el('button','Draft whole-system obligations');button.onclick=()=>post('scope').catch(e=>byId('status').textContent=e.message);host.append(button);return;}
for(const [key,title] of [['policy_reviewed','The owner reviewed expected behaviors and thresholds.'],['inventory_totals_reviewed','The owner confirmed the inventory totals, including unmapped areas.']]){const label=el('label',title),box=el('input');box.type='checkbox';box.checked=scope[key];box.onchange=()=>scope[key]=box.checked;label.prepend(box);host.append(label);}
const totals=el('details');totals.append(el('summary','Declared inventory totals'));for(const kind of new Set([...Object.keys(scope.inventory_totals),...plan.components.map(c=>c.kind)])){field(totals,kind+' total',scope.inventory_totals[kind]??'',v=>scope.inventory_totals[kind]=Number(v));}host.append(totals);
const build=el('details');build.append(el('summary','Running-build identity (before and after testing)'),el('p','Bind a GET check that asserts a build fingerprint supplied by the running application. A version label alone is not a source or container attestation. Complete all three fields together.'));
for(const [key,title] of [['check_id','Build check ID'],['assertion_path','JSON assertion path'],['expected_value','Expected running build ID / digest']])field(build,title,(scope.build||{})[key]||'',v=>{scope.build=scope.build||{};scope.build[key]=v});host.append(build);
scope.objectives.forEach(o=>{const d=el('details');d.append(el('summary',o.title+(o.reviewed?' / reviewed':' / review needed')));field(d,'Expected behavior',o.title,v=>o.title=v);if(o.business_rule_id){d.append(el('p','Business rule: '+o.business_rule_id));field(d,'Intended business behavior',o.expected_business_behavior||'',v=>o.expected_business_behavior=v);field(d,'Evidence needed',o.business_evidence_needed||'',v=>o.business_evidence_needed=v);}field(d,'Role (blank if not role-specific)',o.role||'',v=>o.role=v||null);const label=el('label','Expected behavior independently reviewed'),box=el('input');box.type='checkbox';box.checked=o.reviewed;box.onchange=()=>o.reviewed=box.checked;label.prepend(box);d.append(label);const select=el('select');select.append(el('option',''));plan.checks.filter(c=>c.component_ids.includes(o.component_id)&&c.layer===o.layer).forEach(c=>{const option=el('option',c.id);option.value=c.id;select.append(option)});select.value=o.check_id||'';select.onchange=()=>o.check_id=select.value;const binding=el('label','Bound check');binding.append(select);d.append(binding);field(d,'Case IDs (evaluation/JUnit, comma-separated)',(o.case_ids||[]).join(', '),v=>o.case_ids=v.split(',').map(x=>x.trim()).filter(Boolean));field(d,'JSON assertion paths (HTTP/load/recovery, comma-separated)',(o.assertion_paths||[]).join(', '),v=>o.assertion_paths=v.split(',').map(x=>x.trim()).filter(Boolean));field(d,'Exclusion reason (still a whole-system gap)',o.exclude_reason||'',v=>o.exclude_reason=v);d.append(el('small','Component: '+o.component_id+' / Layer: '+o.layer));host.append(d);});
const add=el('details');add.append(el('summary','Add another critical behavior'));const name=field(add,'Behavior description','',()=>{}),component=el('select');plan.components.forEach(c=>{const option=el('option',c.name);option.value=c.id;component.append(option)});add.append(component);const layer=field(add,'Layer','functional',()=>{}),button=el('button','Add behavior for review');button.onclick=()=>{if(!name.value.trim())return;scope.objectives.push({id:'objective-'+crypto.randomUUID(),title:name.value.trim(),component_id:component.value,layer:layer.value,role:layer.value==='authorization'?plan.roles[0]:null,reviewed:false,check_id:'',case_ids:[],assertion_paths:[]});renderScope();};add.append(button);host.append(add);
}
async function post(action,extra={}){if([...document.querySelectorAll('textarea')].some(x=>!x.checkValidity()))throw Error('Correct invalid JSON before saving.');plan.application_version=byId('version').value;plan.base_url=byId('base').value;plan.environment=byId('environment').value;plan.isolation_note=byId('isolation').value;plan.inventory_confirmed=byId('confirmed').checked;const response=await fetch('/'+action,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:initial.token,digest,plan,...extra})});const result=await response.json();if(!response.ok)throw Error(result.error);plan=result.plan;digest=result.digest;setupPlan=result.setup_plan||setupPlan;proposal=result.proposal||null;render();byId('status').textContent=result.message;}
byId('save').onclick=()=>post('save').catch(e=>byId('status').textContent=e.message);
byId('bind').onclick=()=>post('bind',{config:byId('config').value,id:byId('checkid').value,component:byId('component').value}).catch(e=>byId('status').textContent=e.message);
byId('add-check').onclick=()=>post('add',{kind:byId('template').value,id:byId('checkid').value,component:byId('component').value}).catch(e=>byId('status').textContent=e.message);
byId('add-roles').onclick=()=>post('roles',{roles:byId('roles').value.split(',').map(x=>x.trim()).filter(Boolean)}).catch(e=>byId('status').textContent=e.message);
byId('add-component').onclick=()=>post('component',{name:byId('component-name').value,module:byId('component-module').value}).catch(e=>byId('status').textContent=e.message);
render();
</script>"""


def setup_handler(path: Path, token: str):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *args):
            pass

        def allowed(self) -> bool:
            expected = f"127.0.0.1:{self.server.server_port}"
            origin = self.headers.get("Origin")
            return self.headers.get("Host") == expected and (origin is None or origin == "http://" + expected)

        def reply(self, status: int, payload: bytes, content_type: str):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if not self.allowed() or self.path != "/":
                self.reply(403, b"Forbidden", "text/plain")
                return
            self.reply(200, setup_html(document(path), token, path).encode(), "text/html; charset=utf-8")

        def do_POST(self):
            from .system_cli import bind_evaluation, write_json
            try:
                if not self.allowed() or self.path not in {"/save", "/bind", "/add", "/roles", "/component", "/scope", "/refresh", "/assist", "/accept"}:
                    raise RunnerError("Forbidden local setup request")
                size = int(self.headers.get("Content-Length", "0"))
                if not 1 <= size <= 8_000_000:
                    raise RunnerError("Invalid request length")
                data = json.loads(self.rfile.read(size))
                if not isinstance(data, dict) or not isinstance(data.get("plan"), dict):
                    raise RunnerError("Setup requests require a JSON object containing a plan object")
                if not secrets.compare_digest(str(data.get("token", "")), token):
                    raise RunnerError("Invalid review token")
                stored = document(path)
                if data.get("digest") != plan_digest(stored):
                    raise RunnerError("Plan changed on disk; reload before saving")
                plan = data["plan"]
                if plan.get("source_protection") != stored.get("source_protection") or plan.get("profile") != stored.get("profile"):
                    raise RunnerError("Source protection and discovery inputs cannot be changed through the setup form")
                plan.pop("approval", None)
                proposal = None
                if self.path == "/refresh":
                    from .system_profile import refresh_profile
                    plan = refresh_profile(plan)
                elif self.path == "/assist":
                    from .system_assistant import propose
                    proposal = propose(plan, model=data.get("model"), max_turns=3, timeout=30)
                elif self.path == "/accept":
                    from .system_assistant import apply_suggestions
                    plan = apply_suggestions(plan, data["proposal"], data["selected"])
                elif self.path == "/scope":
                    from .system_scope import draft_scope
                    if "scope_contract" in plan:
                        raise RunnerError("Scope contract already exists; edit it rather than replace it")
                    plan["scope_contract"] = draft_scope(plan)
                elif self.path == "/bind":
                    bind_evaluation(plan, path.parent, config_path=Path(data["config"]), components=[data["component"]], check_id=data["id"])
                elif self.path == "/add":
                    component = next((c for c in plan["components"] if c["id"] == data["component"]), None)
                    if not component:
                        raise RunnerError("Choose an existing component")
                    row = check_template(data["kind"], component, data["id"])
                    plan["checks"].append(row)
                    if data["kind"] == "tenant" and "tenant-b" not in plan["roles"]:
                        plan["roles"].append("tenant-b")
                    if row["layer"] not in component["required_layers"]:
                        component["required_layers"].append(row["layer"])
                elif self.path == "/roles":
                    add_role_matrix(plan, data["roles"])
                elif self.path == "/component":
                    plan["components"].append({"id": identifier("declared", data["module"], data["name"]),
                        "name": data["name"], "module": data["module"], "kind": "declared",
                        "required_layers": ["functional"], "depends_on": [], "enabled": "unknown",
                        "evidence": [{"source": "operator", "basis": "reviewed_declaration"}]})
                    plan["inventory_confirmed"] = False
                validate_plan(plan, path.parent)
                from .audit import append_audit_event, verify_audit_log
                audit = path.with_suffix(".audit.jsonl")
                from .system_safety import guard_output
                guard_output(plan, audit)
                if audit.exists():
                    verify_audit_log(audit)
                write_json(path, plan, replace=True)
                append_audit_event(audit, "setup_" + self.path[1:], {"before_sha256": data["digest"], "after_sha256": plan_digest(plan),
                                                                  "proposal_sha256": proposal.get("proposal_sha256") if proposal else None})
                from .system_readiness import full_platform_setup_plan
                output = {"plan": plan, "digest": plan_digest(plan), "proposal": proposal,
                          "setup_plan": full_platform_setup_plan(plan, path.parent),
                          "message": "Saved for review. Approval invalidated; no target called."}
                self.reply(200, json.dumps(output).encode(), "application/json")
            except (RunnerError, OSError, ValueError, KeyError, TypeError) as exc:
                self.reply(400, json.dumps({"error": str(exc)}).encode(), "application/json")
    return Handler


def serve_system_setup(path: Path) -> None:
    validate_plan(document(path), path.parent)
    server = HTTPServer(("127.0.0.1", 0), setup_handler(path, secrets.token_urlsafe(32)))
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"PRE-D local system setup: {url} (no target calls; Ctrl+C to stop)", flush=True)
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
