"""Self-contained local HTML report generation."""

from __future__ import annotations

import html
import json
from typing import Any


def render_local_report(report: dict[str, Any]) -> str:
    """Render a report without external assets, network calls, or raw test inputs."""
    subject = report["subject"]
    cards = []
    for name, metric in report["metrics"].items():
        status = metric.get("measurement_status", "unknown")
        summary = metric.get("reason") if status == "not_measurable" else ", ".join(
            f"{key.replace('_', ' ')}: {value}" for key, value in metric.items()
            if key in {"accuracy", "macro_f1", "supported_claim_rate", "attack_outcome_accuracy", "score", "recall_at_k", "pass_rate", "agreement_rate", "consistent_rate", "total_cost_usd", "p95_latency_ms"}
        ) or "Evidence measured locally."
        cards.append(f"<article><h2>{html.escape(name.replace('_', ' ').title())}</h2><p class='{html.escape(status)}'>{html.escape(status.replace('_', ' ').upper())}</p><p>{html.escape(str(summary))}</p></article>")
    payload = html.escape(json.dumps(report, indent=2, ensure_ascii=True))
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>ESX Local Evaluation Report</title><style>
body{{margin:0;background:#f3f0e9;color:#1c2828;font:16px Georgia,serif}}main{{max-width:1100px;margin:36px auto;padding:32px;background:#fffdf8;border:1px solid #263735;box-shadow:7px 7px 0 #263735}}h1{{font-size:42px;margin:0 0 8px}}.meta{{color:#526661;font-family:monospace}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px;margin:28px 0}}article{{border:1px solid #263735;padding:18px;background:#f9f7f0}}h2{{font-size:20px;margin:0 0 12px}}.measured{{color:#145c38;font-weight:bold}}.not_measurable{{color:#8b4d10;font-weight:bold}}details{{border-top:1px solid #263735;padding-top:18px}}pre{{white-space:pre-wrap;word-break:break-word;background:#172220;color:#edf4ee;padding:16px;font:12px ui-monospace,monospace}}@media(max-width:600px){{main{{margin:0;border:0;box-shadow:none;padding:20px}}h1{{font-size:32px}}}}</style></head><body><main>
<p class="meta">LOCAL-ONLY REPORT | NOT UPLOADED</p><h1>Pre-release evaluation</h1><p>{html.escape(str(subject['agent_id']))} {html.escape(str(subject['subject_version']))} | Dataset: {html.escape(str(subject['dataset_version']))}</p><p>{html.escape(str(report['notice']))}</p><section class="grid">{''.join(cards)}</section><details><summary>View the redacted result data</summary><pre>{payload}</pre></details></main></body></html>'''
