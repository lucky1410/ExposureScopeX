"""Self-contained local HTML report generation."""

from __future__ import annotations

import html
import json
from typing import Any


def render_local_report(report: dict[str, Any]) -> str:
    """Render a content-safe report without external assets or network calls."""
    subject = report["subject"]
    cards = []
    for name, metric in report["metrics"].items():
        status = metric.get("measurement_status", "unknown")
        summary = metric.get("reason") if status == "not_measurable" else ", ".join(
            f"{key.replace('_', ' ')}: {value}" for key, value in metric.items()
            if key in {"accuracy", "macro_f1", "supported_claim_rate", "attack_outcome_accuracy", "score", "recall_at_k", "pass_rate", "agreement_rate", "consistent_rate", "total_cost_usd", "p95_latency_ms"}
        ) or "Evidence measured locally."
        cards.append(f"<article><h2>{html.escape(name.replace('_', ' ').title())}</h2><p class='{html.escape(status)}'>{html.escape(status.replace('_', ' ').upper())}</p><p>{html.escape(str(summary))}</p></article>")
    graph = report.get("assurance_graph", {})
    summary = graph.get("summary", {}) if isinstance(graph, dict) else {}
    graph_items = "".join(
        f"<li><strong>{html.escape(str(node.get('label', 'unknown')))}</strong> <span>{html.escape(str(node.get('kind', 'unknown')))} | {html.escape(str(node.get('status', 'unknown')))}</span></li>"
        for node in graph.get("nodes", []) if isinstance(node, dict)
    ) if isinstance(graph, dict) else ""
    graph_section = ""
    if graph:
        graph_section = f"<section class='graph'><h2>Assurance Graph</h2><p>Scope: {html.escape(str(summary.get('scope_status')))} | Confirmed components: {html.escape(str(summary.get('confirmed_component_count')))} | Measured metrics: {html.escape(str(summary.get('measured_metric_count')))} of {html.escape(str(summary.get('required_metric_count')))}</p><p>{html.escape(str(summary.get('release_reason')))}</p><ul>{graph_items}</ul></section>"
    coverage = report.get("coverage", {})
    discovered = coverage.get("discovered", {}) if isinstance(coverage, dict) else {}
    approved = coverage.get("approved", {}) if isinstance(coverage, dict) else {}
    executed = coverage.get("executed", {}) if isinstance(coverage, dict) else {}
    measured = coverage.get("measured", {}) if isinstance(coverage, dict) else {}
    capability_areas = coverage.get("capability_areas", []) if isinstance(coverage, dict) else []
    coverage_section = ""
    if coverage:
        area_rows = "".join(
            f"<tr><td>{html.escape(str(item.get('capability_area', 'general')).replace('_', ' '))}</td><td>{html.escape(str(item.get('discovered', 0)))}</td><td>{html.escape(str(item.get('approved', 0)))}</td><td>{html.escape(str(item.get('executed', 0)))}</td><td>{html.escape(str(item.get('passed', 0)))}</td><td>{html.escape(str(item.get('failed', 0)))}</td></tr>"
            for item in capability_areas if isinstance(item, dict)
        )
        area_table = ""
        if area_rows:
            area_table = f"<h3>Capability-area coverage</h3><table><thead><tr><th>Area</th><th>Discovered</th><th>Approved</th><th>Executed</th><th>Passed</th><th>Failed</th></tr></thead><tbody>{area_rows}</tbody></table>"
        coverage_section = f"""<section class='coverage'><h2>Coverage boundary</h2>
        <div class='coverage-grid'><div><strong>{html.escape(str(discovered.get('component_count', 0)))}</strong><span>Discovered components</span></div><div><strong>{html.escape(str(approved.get('component_count', 0)))}</strong><span>Approved components</span></div><div><strong>{html.escape(str(executed.get('case_count', 0)))}</strong><span>Executed cases</span></div><div><strong>{html.escape(str(measured.get('dimension_count', 0)))}/{html.escape(str(measured.get('required_dimension_count', 0)))}</strong><span>Measured dimensions</span></div></div>
        <p>Discovery is not execution. A component is covered only by an executed case, and a metric is measured only with validated local evidence.</p>{area_table}</section>"""
    execution = report.get("execution", {})
    diagnostics = execution.get("browser_case_diagnostics", []) if isinstance(execution, dict) else []
    diagnostic_section = ""
    if isinstance(diagnostics, list) and diagnostics:
        rows = "".join(
            f"<tr><td>{html.escape(str(item.get('case_id', 'unknown')))}</td><td>{html.escape(str(item.get('capability_area', 'general')).replace('_', ' '))}</td><td>{html.escape(str(item.get('persona', 'default')).replace('_', ' '))}</td><td>{html.escape(str(item.get('coverage_scope', 'unknown')).replace('_', ' '))}</td><td>{html.escape(str(item.get('outcome', 'unknown')))}</td><td>{html.escape(str(item.get('completed_step_count', 0)))}/{html.escape(str(item.get('total_attempt_count', 0)))}</td><td>{html.escape(str(item.get('failed_action', item.get('failure_kind', ''))))}</td><td>{'saved locally' if item.get('failure_screenshot_available') else 'not captured'}</td></tr>"
            for item in diagnostics if isinstance(item, dict)
        )
        diagnostic_section = f"<section class='diagnostics'><h2>Browser execution diagnostics</h2><p>Session: {html.escape(str(execution.get('browser_session_status', 'not_requested')).replace('_', ' '))}. Steps show completed/attempted actions. Browser-health counts are stored in the redacted result data; screenshots are opt-in and remain in the local evidence folder.</p><table><thead><tr><th>Case</th><th>Area</th><th>Persona</th><th>Coverage</th><th>Outcome</th><th>Steps / attempts</th><th>Failure point</th><th>Screenshot</th></tr></thead><tbody>{rows}</tbody></table></section>"
    payload = html.escape(json.dumps(report, indent=2, ensure_ascii=True))
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ESX Local Evaluation Report</title><style>
body{{margin:0;background:#f3f0e9;color:#1c2828;font:16px Georgia,serif}}main{{max-width:1100px;margin:36px auto;padding:32px;background:#fffdf8;border:1px solid #263735;box-shadow:7px 7px 0 #263735}}h1{{font-size:42px;margin:0 0 8px}}.meta{{color:#526661;font-family:monospace}}.grid,.coverage-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin:28px 0}}article,.graph,.coverage,.diagnostics{{border:1px solid #263735;padding:18px;background:#f9f7f0}}.graph,.coverage,.diagnostics{{margin:28px 0}}.graph ul{{columns:2;padding-left:20px}}.graph li{{margin:8px 0}}.graph span{{font:12px ui-monospace,monospace;color:#526661}}.coverage-grid{{margin:0 0 14px}}.coverage-grid div{{padding:14px;background:#eaf0e9;border-left:4px solid #507765}}.coverage-grid strong{{display:block;font:28px Georgia,serif}}.coverage-grid span{{font:12px ui-monospace,monospace;text-transform:uppercase}}h2{{font-size:20px;margin:0 0 12px}}.measured{{color:#145c38;font-weight:bold}}.not_measurable{{color:#8b4d10;font-weight:bold}}table{{width:100%;border-collapse:collapse;font:13px ui-monospace,monospace}}th,td{{text-align:left;border-top:1px solid #c5d1c8;padding:9px 6px;vertical-align:top}}details{{border-top:1px solid #263735;padding-top:18px}}pre{{white-space:pre-wrap;word-break:break-word;background:#172220;color:#edf4ee;padding:16px;font:12px ui-monospace,monospace}}@media(max-width:600px){{main{{margin:0;border:0;box-shadow:none;padding:20px}}h1{{font-size:32px}}.graph ul{{columns:1}}table{{font-size:11px}}th,td{{padding:6px 3px}}}}</style></head><body><main>
<p class="meta">LOCAL-ONLY REPORT | NOT UPLOADED</p><h1>Pre-release evaluation</h1><p>{html.escape(str(subject['agent_id']))} {html.escape(str(subject['subject_version']))} | Dataset: {html.escape(str(subject['dataset_version']))}</p><p>{html.escape(str(report['notice']))}</p><section class="grid">{''.join(cards)}</section>{coverage_section}{diagnostic_section}{graph_section}<details><summary>View the redacted result data</summary><pre>{payload}</pre></details></main></body></html>'''
