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
:root{--bg:#101a1d;--panel:#192a2d;--ink:#eff5ef;--muted:#b1c6c4;--accent:#ff936e;--line:#385052;--good:#c7ee84}
*{box-sizing:border-box}body{margin:0;color:var(--ink);background:radial-gradient(at 0 0,#274139,transparent 55%),var(--bg);font:16px Georgia,serif}
main{max-width:1220px;margin:auto;padding:42px 28px}h1{font-size:clamp(32px,5vw,62px);line-height:1.04;max-width:900px}h2{font-size:28px}h3{font-size:21px}p{line-height:1.6}
.eyebrow,button,label,th,nav,small{font-family:'Courier New',monospace}.eyebrow{color:var(--accent);letter-spacing:2px}section,.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:24px;margin:20px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px}.card{margin:0}.number{font-size:38px}small,.muted{color:var(--muted)}a{color:var(--accent)}nav{display:flex;gap:22px;flex-wrap:wrap}button{background:var(--accent);border:0;border-radius:6px;padding:12px 18px;cursor:pointer;color:#101a1d;font-weight:bold}button.secondary{background:var(--good)}button:disabled{opacity:.5}
input,select,textarea{width:100%;background:#0f2022;color:var(--ink);border:1px solid var(--line);border-radius:5px;padding:10px;margin:8px 0 16px}input[type=checkbox]{width:auto;margin:10px}label{display:block;font-size:13px}details{border-top:1px solid var(--line);padding:16px 0}summary{cursor:pointer;font-size:20px}table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:12px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-size:12px}.scroll{overflow:auto}.failed,.blocked{color:#ffc4a6}.passed,.evaluated,.verified{color:var(--good)}.partial,.configured_not_run,.planned_only,.missing,.declared{color:#ffd59c}.not_applicable{color:var(--muted)}pre{white-space:pre-wrap;overflow-wrap:anywhere}code{font-family:'Courier New',monospace}#status{white-space:pre-wrap}small,p,summary{overflow-wrap:anywhere}.grid>*{min-width:0}@media(max-width:600px){main{padding:24px 14px}section{padding:16px}td,th{padding:8px}.grid{grid-template-columns:minmax(0,1fr)}}
"""


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


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
    return page.replace('<a href="#findings">', '<a href="#changes">What changed</a><a href="#source-integrity">Source integrity</a><a href="#evidence-gaps">Evidence gaps</a><a href="#findings">').replace('<section id="findings">', comparison + source + evidence_gap_panel(report.get("evidence_gap_report")) + '<section id="findings">')


def _render_report(report: dict) -> str:
    s = report["summary"]
    title = report["verdict"].replace("_", " ").capitalize()
    module_summary = report.get("module_evaluation_summary", {}).get("summary", {})
    card_items = [
        ("Components with required checks executed", f'{s["complete_components"]}/{s["components"]}'),
        ("Checks executed", s["checks_executed"]), ("Failed checks", s["failed"]), ("Blocked checks", s["blocked"]),
    ]
    if module_summary:
        card_items.extend([
            ("Evaluation areas with evidence", f'{module_summary.get("areas_with_executed_evidence", 0)}/{module_summary.get("area_count", 0)}'),
            ("Modules with evidence", f'{module_summary.get("modules_with_executed_evidence", 0)}/{module_summary.get("module_count", 0)}'),
        ])
    cards = "".join(f'<div class="card"><small>{_esc(label)}</small><div class="number">{_esc(value)}</div></div>' for label, value in card_items)
    findings = []
    details = []
    for row in report["checks"]:
        if row["status"] != "passed":
            findings.append(f'<article><h3 class="{_esc(row["status"])}">{_esc(row["id"])}: {_esc(row["reason"])}</h3><p>{_esc(row.get("action", "Review the detailed evidence."))}</p><small>Components: {_esc(", ".join(row["component_ids"]))}. Root cause: not established.</small></article>')
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
    definition = "A component is counted as executed only when each required reviewed layer has an enabled check that ran to a pass/fail terminal state. Drafted, disabled, unbound, blocked, or status-only evidence remains a gap."
    return f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PRE-D system review</title><style>{STYLE}</style><main><p class="eyebrow">PRE-D / SYSTEM RELEASE REVIEW</p><h1>{_esc(title)}</h1><p>{_esc(report["project_id"])} / {_esc(report["application_version"])}</p><nav><a href="#executive-summary">Executive summary</a><a href="#harness-recommendations">Harness recommendations</a><a href="#findings">What to fix</a><a href="#traceability">Traceable findings</a><a href="#module-evaluation">Module evaluation map</a><a href="#scope">Behavior coverage</a><a href="#coverage">Modules</a><a href="#evidence">Evidence</a></nav><p>{_esc(report["notice"])}</p><div class="grid">{cards}</div>{executive_summary_panel(report)}<p class="muted">{_esc(definition)}</p>{caution}{harness_recommendations_panel(report.get("harness_recommendations"))}<section id="findings"><h2>What needs attention</h2>{"".join(findings) or "<p>No executed check failed. Review uncovered components before drawing a release conclusion.</p>"}</section>{finding_register_panel(report.get("finding_register"))}{module_evaluation_panel(report)}{scope_panel(report)}<section id="coverage"><h2>Coverage, not assumptions</h2><details><summary>Open module coverage table</summary><div class="scroll"><table><tr><th>Module</th><th>Component</th><th>Execution</th><th>Boundary / next step</th></tr>{coverage}</table></div></details></section><section id="evidence"><h2>Inspect the evidence</h2><details><summary>Open per-check raw evidence</summary>{"".join(details)}</details></section><small>Run {_esc(report["run_id"])} | {_esc(report["created_at"])} | {_esc(report.get("report_sha256", ""))}</small></main></html>'


def executive_summary_panel(report: dict) -> str:
    summary = report.get("summary", {})
    findings = report.get("finding_register", {}).get("summary", {})
    harness = report.get("harness_recommendations", {}).get("summary", {})
    module = report.get("module_evaluation_summary", {}).get("summary", {})
    verdict = report.get("verdict", "unknown").replace("_", " ")
    if report.get("verdict") == "checks_passed_within_reviewed_scope":
        headline = "Reviewed checks passed, but unreviewed scope still stays outside the claim."
    elif report.get("verdict") == "do_not_ship":
        headline = "Do not ship: at least one reviewed check failed."
    else:
        headline = "Insufficient evidence: fix the listed harness gaps before making a platform trust claim."
    return (
        '<section id="executive-summary"><p class="eyebrow">EXECUTIVE SUMMARY</p>'
        f'<h2>{_esc(headline)}</h2>'
        f'<p><strong>Verdict:</strong> {_esc(verdict)}. '
        f'{_esc(summary.get("checks_executed", 0))} checks executed; '
        f'{_esc(summary.get("failed", 0))} failed; {_esc(summary.get("blocked", 0))} blocked. '
        f'{_esc(summary.get("complete_components", 0))}/{_esc(summary.get("components", 0))} components have required executed evidence.</p>'
        f'<div class="grid"><div class="card"><small>Proof-backed findings</small><div class="number">{_esc(findings.get("finding_count", 0))}</div></div>'
        f'<div class="card"><small>Harness recommendations</small><div class="number">{_esc(harness.get("recommendation_count", 0))}</div></div>'
        f'<div class="card"><small>Evaluation areas with evidence</small><div class="number">{_esc(module.get("areas_with_executed_evidence", 0))}/{_esc(module.get("area_count", 0))}</div></div>'
        f'<div class="card"><small>High-priority harness work</small><div class="number">{_esc(harness.get("high_priority_count", 0))}</div></div></div>'
        '<p class="muted">Read this top section first. Detailed module maps, raw evidence and all findings are preserved below as expandable audit sections.</p>'
        '</section>'
    )


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
            f'<td class="{_esc(finding.get("severity", "info"))}">{_esc(finding.get("severity", ""))}</td>'
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
        f'<h2>{_esc(summary.get("finding_count", 0))} proof-backed finding(s)</h2>'
        f'<p>{_esc(register.get("notice", ""))}</p>'
        f'<div class="grid"><div class="card"><small>Verified</small><div class="number">{_esc(summary.get("by_confidence", {}).get("verified", 0))}</div></div>'
        f'<div class="card"><small>Missing evidence</small><div class="number">{_esc(summary.get("by_evidence_type", {}).get("missing_evidence", 0))}</div></div>'
        f'<div class="card"><small>Observed traces</small><div class="number">{_esc(summary.get("by_evidence_type", {}).get("observed_trace", 0))}</div></div>'
        f'<div class="card"><small>Read-only</small><div class="number">{_esc(summary.get("read_only_finding_count", 0))}</div></div></div>'
        f'{extra_note}<div class="scroll"><table><tr><th>Finding</th><th>Severity</th><th>Category</th><th>Source / provenance</th><th>Proof</th><th>Action</th></tr>{preview_rows or "<tr><td colspan=6>No findings recorded.</td></tr>"}</table></div>'
        f'<details><summary>Open all traceable findings shown in this report</summary><div class="scroll"><table><tr><th>Finding</th><th>Severity</th><th>Category</th><th>Source / provenance</th><th>Proof</th><th>Action</th></tr>{all_rows or "<tr><td colspan=6>No findings recorded.</td></tr>"}</table></div></details>'
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
        rows.append(
            f'<tr><td class="{_esc(item.get("priority", "medium"))}">{_esc(item.get("priority", ""))}</td>'
            f'<td><strong>{_esc(item.get("title", ""))}</strong><br><small>{_esc(item.get("why", ""))}</small></td>'
            f'<td>{_esc(item.get("implementation", ""))}</td>'
            f'<td><ul>{criteria}</ul></td>'
            f'<td>{_esc(inputs)}<br><small>{_esc(item.get("finding_count", 0))} finding(s): {_esc(", ".join(item.get("based_on_finding_ids", [])[:5]))}</small></td></tr>'
        )
    return (
        f'<section id="{_esc(anchor)}"><p class="eyebrow">HARNESS ENGINEERING RECOMMENDATIONS</p>'
        f'<h2>{_esc(summary.get("recommendation_count", 0))} workstream(s) to improve evidence strength</h2>'
        f'<p>{_esc(recommendations.get("notice", ""))}</p>'
        f'<div class="scroll"><table><tr><th>Priority</th><th>Recommendation</th><th>Implementation</th><th>Acceptance criteria</th><th>Input needed / linked proof</th></tr>{"".join(rows) or "<tr><td colspan=5>No harness recommendations generated.</td></tr>"}</table></div>'
        f'<details><summary>Recommendation register summary</summary><pre>{_esc(json.dumps(summary, indent=2))}</pre></details>'
        '</section>'
    )


def module_evaluation_panel(report: dict) -> str:
    matrix = report.get("module_evaluation_summary")
    if not isinstance(matrix, dict):
        return ""
    summary = matrix.get("summary", {})
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
        '<section id="module-evaluation"><p class="eyebrow">MODULE EVALUATION MAP</p>'
        f'<h2>{_esc(summary.get("areas_with_executed_evidence", 0))} / {_esc(summary.get("area_count", 0))} evaluation areas have executed evidence</h2>'
        f'<p>{_esc(matrix.get("notice", ""))}</p>'
        f'<div class="grid"><div class="card"><small>Evaluated areas</small><div class="number">{_esc(summary.get("areas_evaluated", 0))}</div></div>'
        f'<div class="card"><small>Failed areas</small><div class="number">{_esc(summary.get("areas_with_failures", 0))}</div></div>'
        f'<div class="card"><small>Blocked areas</small><div class="number">{_esc(summary.get("areas_blocked", 0))}</div></div>'
        f'<div class="card"><small>Verified metric groups</small><div class="number">{_esc(summary.get("verified_metric_groups", 0))}</div></div></div>'
        f'<div class="scroll"><table><tr><th>Evaluation area</th><th>Status</th><th>Evidence</th><th>Execution</th><th>Metrics</th><th>Meaning / next action</th></tr>{"".join(rows)}</table></div>'
        f'<details><summary>Per-module result map</summary><div class="scroll"><table><tr><th>Module</th><th>Status</th><th>Categories</th><th>Checks</th><th>Verified metrics</th><th>Next action</th></tr>{"".join(module_rows)}</table></div></details>'
        '</section>'
    )


def evidence_gap_panel(gaps: dict | None) -> str:
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
        f'{harness_recommendations_panel(gaps.get("harness_recommendations"), anchor="evidence-gap-harness-recommendations")}'
        f'{finding_register_panel(gaps.get("finding_register"), anchor="evidence-gap-traceability", title="EVIDENCE-GAP TRACEABILITY")}'
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
    title = "PRE-D evidence gaps"
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
