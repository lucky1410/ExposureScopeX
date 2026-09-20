"""Self-contained local release review with evidence and actionable findings."""

from __future__ import annotations

import html
from typing import Any
from urllib.parse import quote

from .release import VERDICTS


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _execution_section(report: dict[str, Any]) -> str:
    execution = report.get("execution_review")
    if not isinstance(execution, dict):
        return "<section id='execution'><h2>Execution scope</h2><p>This artifact does not record whether suites were run during the review or supplied as existing reports. Do not assume new execution.</p></section>"
    titles = {"all_modules": "All-module execution", "configured_suites": "Configured-suites execution",
              "report_review_only": "Existing report review, not a new test run"}
    preflight = execution.get("preflight") or {}
    issues = "".join("<li><b>" + _e(" / ".join(str(i[k]) for k in ("module_id", "suite_id") if i.get(k)) or "Application inventory")
                     + ":</b> " + _e(i["action"]) + "</li>" for i in preflight.get("issues", []))
    missing = ", ".join(execution["not_fully_executed_module_ids"]) or "None"
    return ("<section id='execution'><h2>" + _e(titles[execution["mode"]]) + "</h2>"
            + ("<p class='action'><b>Preflight blocked: no suites were started.</b> Complete every module's plans and approvals first.</p>" if preflight.get("status") == "blocked" else "")
            + "<p class='action'><b>" + _e(execution["modules_fully_executed_here"]) + " of " + _e(execution["module_count"])
            + " modules fully executed in this invocation.</b><br>" + _e(execution["modules_with_execution_evidence"])
            + " modules have accepted execution evidence, including any reused reports.</p>"
            + "<p>Suite execution attempts: " + _e(execution["suite_attempt_count"]) + ". Existing reports reused: "
            + _e(execution["reused_report_count"]) + ". Baseline comparison: "
            + ("performed; inspect comparability below" if execution["baseline_comparison_performed"] else "not performed") + ".</p>"
            + "<p><b>Not fully executed here:</b> " + _e(missing) + ".</p><p>" + _e(execution["notice"]) + "</p>"
            + ("<h3>Before an all-module run</h3><ul>" + issues + "</ul>" if issues else "") + "</section>")


def _coverage_section(report: dict[str, Any]) -> str:
    rows = []
    for module in report["modules"]:
        coverage = {c["kind"]: c for c in module.get("coverage", [])}
        cells = []
        for kind in ("workflow", "decision"):
            item = coverage.get(kind)
            text = "Excluded" if not module["required"] else "Not specified"
            if item:
                text = f"{item['status'].title()} ({item['executed_suites']}/{item['planned_suites']} suites executed)"
            elif module.get("coverage_basis") == "declared_requirements":
                text = "Not required by this scope"
            cells.append("<td>" + _e(text) + "</td>")
        dependency_status = {d["module_id"]: d["status"] for d in module.get("dependency_coverage", [])}
        dependencies = "<br>".join("<a href='#module-" + _e(d) + "'>" + _e(d) + "</a>: "
                                   + _e(dependency_status.get(d, "declared_only").replace("_", " "))
                                   for d in module.get("depends_on", [])) or "None declared"
        basis = "Explicit requirements" if module.get("coverage_basis") == "declared_requirements" else "Attached plans only"
        rows.append("<tr><td><a href='#module-" + _e(module["id"]) + "'>" + _e(module["name"]) + "</a><br><small>" + basis + "</small></td>" + "".join(cells) + "<td>" + dependencies + "</td></tr>")
    return ("<section id='coverage'><h2>What was covered</h2><p>Complete means the configured suites executed with usable evidence, not that their checks passed. "
            "Attached plans alone do not establish that every needed test type or integration was included.</p>"
            "<div class='table-wrap'><table><thead><tr><th>Module / scope basis</th><th>Workflow tests</th><th>Decision tests</th><th>Dependencies</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table></div></section>")


def _review_scope_section(report: dict[str, Any]) -> str:
    scope = report.get("review_scope") or {}
    summary = "".join(
        "<div><strong>" + _e(scope.get(status, 0)) + "</strong><span>" + label + "</span></div>"
        for status, label in (
            ("evaluated", "Modules with executed PRE-D evidence"),
            ("inspected", "Modules reviewed without executable evidence"),
            ("blocked", "Modules with incomplete required executable review"),
            ("untouched", "Modules with no recorded review"),
        )
    )
    rows = []
    for module in report["modules"]:
        methods = module.get("review_methods", [])
        workflow = next((item for item in methods if item.get("source") == "pre_d_executable_evidence" and item.get("kind") == "workflow"), None)
        decision = next((item for item in methods if item.get("source") == "pre_d_executable_evidence" and item.get("kind") == "decision"), None)
        other = [
            "<b>" + _e(item.get("label", item.get("id", "Review"))) + ":</b> "
            + _e(item.get("status", "unknown").replace("_", " ").title())
            + "<br><small>" + _e(item.get("summary", "")) + "</small>"
            for item in methods if item.get("source") != "pre_d_executable_evidence"
        ]
        rows.append(
            "<tr><td><a href='#module-" + _e(module["id"]) + "'>" + _e(module["name"]) + "</a></td>"
            + "<td>" + _e(module.get("review_status", "untouched").replace("_", " ").title()) + "</td>"
            + "<td>" + _e((workflow or {}).get("status", "untouched").replace("_", " ").title())
            + "<br><small>" + _e((workflow or {}).get("summary", "No workflow review recorded.")) + "</small></td>"
            + "<td>" + _e((decision or {}).get("status", "untouched").replace("_", " ").title())
            + "<br><small>" + _e((decision or {}).get("summary", "No decision review recorded.")) + "</small></td>"
            + "<td>" + ("".join(other) if other else "None recorded") + "</td></tr>"
        )
    return (
        "<section id='scope'><h2>Review scope matrix</h2><p>"
        + _e(scope.get("notice", ""))
        + "</p><div class='stats'>" + summary + "</div><div class='table-wrap'><table><thead><tr>"
        + "<th>Module</th><th>Overall review status</th><th>Workflow execution</th><th>Decision evaluation</th><th>Additional review methods</th>"
        + "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div></section>"
    )


def _advisory_section(report: dict[str, Any]) -> str:
    advisories = report.get("advisories", [])
    if not advisories:
        return (
            "<section id='advisories'><details><summary>No additional coverage advisories</summary><div class='inside'>"
            "<p>PRE-D did not find extra non-blocking coverage cautions for this declared scope.</p>"
            "</div></details></section>"
        )
    cards = []
    for item in advisories:
        location = " / ".join(str(item[key]) for key in ("module_id", "suite_id") if item.get(key)) or "Application scope"
        location_html = _e(location)
        if item.get("suite_id") or item.get("module_id"):
            anchor = "suite-" + item["suite_id"] if item.get("suite_id") else "module-" + item["module_id"]
            location_html = "<a href='#" + _e(anchor) + "'>" + location_html + "</a>"
        cases = "<p><b>Cases:</b> " + _e(", ".join(item["case_ids"])) + "</p>" if item.get("case_ids") else ""
        pointer = "<p><b>Evidence:</b> <code>" + _e(item["evidence_pointer"]) + "</code></p>" if item.get("evidence_pointer") else ""
        cards.append(
            "<article class='finding advisory'><p class='eyebrow'>ADVISORY / " + _e(item["category"].replace("_", " "))
            + "</p><h3>" + location_html + "</h3><p>" + _e(item["why"]) + "</p><p class='action'><b>Strengthen next:</b> "
            + _e(item["recommendation"]) + "</p><p><b>Owner:</b> " + _e(item["owner"]) + "</p>" + cases + pointer
            + "<small>This is a non-blocking coverage caution. It does not change the release verdict on its own.</small></article>"
        )
    return (
        "<section id='advisories'><h2>Coverage advisories</h2><p>"
        "These items do not block release by themselves, but they explain where the current plan can still overstate what PASS proves."
        "</p>" + "".join(cards) + "</section>"
    )


def _dimension_section(report: dict[str, Any]) -> str:
    summary = report.get("dimension_coverage") or {}
    rows = []
    for module in report["modules"]:
        for suite in module["suites"]:
            for item in suite.get("dimension_coverage", []):
                note = item.get("reason") or item.get("evidence_source") or ""
                trust = item.get("trust_status", "missing")
                measurement = item.get("measurement_status", "not_measured")
                rows.append(
                    "<tr><td><a href='#module-" + _e(module["id"]) + "'>" + _e(module["name"]) + "</a><br><small>"
                    + _e(suite["id"]) + "</small></td><td>" + _e(item["title"])
                    + "</td><td>" + _e(item["tier"].title())
                    + "</td><td>" + _e(item["policy_status"].replace("_", " ").title())
                    + "</td><td>" + _e(measurement.replace("_", " ").title())
                    + "<br><small>Trust: " + _e(trust.replace("_", " ")) + "</small></td><td>"
                    + _e(note or "No additional detail.") + "</td></tr>"
                )
    cards = "".join(
        "<div><strong>" + _e(summary.get(key, 0)) + "</strong><span>" + label + "</span></div>"
        for key, label in (
            ("gated", "Gated dimensions"),
            ("baseline_unexercised", "Baseline-tier left unexercised"),
            ("advanced_measured", "Advanced dimensions measured"),
            ("not_requested", "Dimensions not requested"),
            ("request_unknown", "Request status unavailable"),
        )
    )
    return (
        "<section id='dimensions'><h2>Metric dimension coverage</h2><p>"
        + _e(summary.get("notice", ""))
        + "</p><div class='stats'>" + cards + "</div><div class='table-wrap'><table><thead><tr>"
        + "<th>Module / suite</th><th>Dimension</th><th>Tier</th><th>Release policy</th><th>Observed state</th><th>Detail</th>"
        + "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div></section>"
    )


def _history_section(report: dict[str, Any]) -> str:
    history = report.get("history")
    if not history:
        return (
            "<section id='history'><details><summary>No multi-run history</summary><div class='inside'>"
            "<p>Supply one or more <code>--history previous-release.json</code> artifacts to see conservative pack trends across more than one past run.</p>"
            "</div></details></section>"
        )
    summary = history.get("summary", {})
    cards = "".join(
        "<div><strong>" + _e(summary.get(key, 0)) + "</strong><span>" + label + "</span></div>"
        for key, label in (
            ("regressed", "Signals worse than latest comparable history"),
            ("improved", "Signals better than latest comparable history"),
            ("unchanged", "Signals unchanged"),
            ("not_comparable", "Signals without comparable history"),
        )
    )
    reports = "".join(
        "<li>" + _e(item["version"]) + " / " + _e(item["generated_at"]) + " / " + _e(item["verdict"].replace("_", " ").title()) + "</li>"
        for item in history.get("reports", [])
    )
    rows = []
    for row in history.get("metrics", []):
        points = "".join(
            "<li>" + _e(point["version"]) + ": "
            + _e(point["status"].replace("_", " ").title())
            + (" (" + _e(point["reason"]) + ")" if point.get("reason") else "")
            + (" / observed " + _e(point["observed"]) if point.get("observed") is not None else "")
            + "</li>"
            for point in row.get("points", [])
        )
        delta = "Not compared" if row.get("delta_from_latest") is None else f"{row['delta_from_latest']:+.6g}"
        rows.append(
            "<tr><td>" + _e(row["module_id"] + " / " + row["suite_id"]) + "<br><small>" + _e(row["signal"]) + "</small></td>"
            + "<td>" + _e(row.get("latest_previous_version") or "Unavailable")
            + "<br><small>" + _e(row.get("latest_previous") if row.get("latest_previous") is not None else "No comparable value") + "</small></td>"
            + "<td>" + _e(row.get("current") if row.get("current") is not None else "Unavailable") + "</td>"
            + "<td>" + _e(delta) + "</td>"
            + "<td>" + _e(row["status"].replace("_", " ").title())
            + "<br><small>" + _e(row.get("reason") or "No additional detail.") + "</small></td>"
            + "<td><details><summary>" + _e(row.get("comparable_history_count", 0)) + " comparable runs</summary><div class='inside'><ul>"
            + (points or "<li>No comparable history points.</li>") + "</ul></div></details></td></tr>"
        )
    return (
        "<section id='history'><h2>Historical trend context</h2><p>"
        + _e(history.get("notice", ""))
        + "</p><div class='stats'>" + cards + "</div>"
        + ("<h3>Supplied prior reports</h3><ul>" + reports + "</ul>" if reports else "")
        + "<div class='table-wrap'><table><thead><tr><th>Suite / check</th><th>Latest comparable history</th><th>Current</th><th>Delta</th><th>Trend</th><th>History</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table></div></section>"
    )


def _suite_dimension_detail(suite: dict[str, Any]) -> str:
    coverage = suite.get("dimension_coverage", [])
    baseline = [item["title"] for item in coverage if item.get("tier") == "baseline" and item.get("policy_status") == "not_requested"]
    measured = [item["title"] for item in coverage if item.get("measurement_status") == "measured" and item.get("tier") == "advanced"]
    parts = []
    if baseline:
        parts.append("<p><b>Baseline-tier dimensions left unexercised:</b> " + _e(", ".join(baseline)) + ".</p>")
    if measured:
        parts.append("<p><b>Advanced dimensions measured:</b> " + _e(", ".join(measured)) + ".</p>")
    return "".join(parts)


def _workflow_signal_detail(suite: dict[str, Any]) -> str:
    strength = suite.get("workflow_signal_strength")
    if not isinstance(strength, dict):
        return ""
    notes = []
    if strength.get("content_signal_count"):
        notes.append(f"{strength['content_signal_count']} content-signal case(s)")
    if strength.get("title_signal_only_count"):
        notes.append(f"{strength['title_signal_only_count']} title-only case(s)")
    if strength.get("route_signal_only_count"):
        notes.append(f"{strength['route_signal_only_count']} route-only case(s)")
    if strength.get("element_state_only_count"):
        notes.append(f"{strength['element_state_only_count']} element-state-only case(s)")
    if strength.get("no_explicit_signal_count"):
        notes.append(f"{strength['no_explicit_signal_count']} case(s) without a final assertion")
    summary = ", ".join(notes) if notes else "No signal-strength summary recorded."
    weak_cases = [
        row["case_id"] for row in strength.get("cases", [])
        if isinstance(row, dict) and row.get("signal_strength") != "content_signal"
    ]
    return (
        "<details><summary>Workflow signal strength</summary><div class='inside'><p>Planned checks; execution outcomes are reported separately.</p><p><b>" + _e(summary)
        + "</b><br>" + _e(strength.get("notice", "")) + "</p>"
        + ("<p><b>Weaker cases:</b> " + _e(", ".join(weak_cases)) + "</p>" if weak_cases else "")
        + "</div></details>"
    )


def _suite_population_detail(suite: dict[str, Any]) -> str:
    coverage = suite.get("population_coverage")
    if not isinstance(coverage, dict):
        return ""
    if coverage.get("status") == "not_declared":
        return "<p><b>Population context:</b> " + _e(coverage.get("notice", "")) + "</p>"
    class_rows = "".join(
        "<tr><td>" + _e(item["label"]) + "</td><td>" + _e(item["available_case_count"]) + "</td><td>"
        + _e(item["executed_case_count"]) + "</td><td>"
        + _e(f"{item['sample_fraction']:.2%}" if item.get("sample_fraction") is not None else "Unavailable")
        + "</td></tr>"
        for item in coverage.get("class_coverage", [])
    )
    fraction = coverage.get("sample_fraction")
    summary = (
        f"{coverage['executed_case_count']} executed / {coverage['available_case_count']} available "
        + (f"({fraction:.2%})" if fraction is not None else "")
    )
    extras = []
    if coverage.get("source"):
        extras.append("Source: " + str(coverage["source"]))
    if coverage.get("sampling_notes"):
        extras.append("Sampling notes: " + str(coverage["sampling_notes"]))
    if coverage.get("unrepresented_labels"):
        extras.append("Unrepresented labels in this run: " + ", ".join(coverage["unrepresented_labels"]))
    if coverage.get("undeclared_executed_labels"):
        extras.append("Executed labels outside declared population map: " + ", ".join(coverage["undeclared_executed_labels"]))
    return (
        "<details><summary>Population coverage</summary><div class='inside'><p><b>" + _e(summary)
        + "</b><br>" + _e(coverage.get("notice", "")) + "</p>"
        + ("<p>" + _e(" | ".join(extras)) + "</p>" if extras else "")
        + ("<div class='table-wrap'><table><thead><tr><th>Label</th><th>Declared available</th><th>Executed</th><th>Sample fraction</th></tr></thead><tbody>"
           + class_rows + "</tbody></table></div>" if class_rows else "")
        + "</div></details>"
    )


def _requirements_detail(module: dict) -> str:
    requirements = module.get("test_requirements", [])
    if not requirements:
        return "<p><b>Test depth not specified.</b> Attached suites do not establish role, negative-path, recovery, or integration coverage.</p>"
    rows = []
    for requirement in requirements:
        bindings = "".join("<li><a href='#suite-" + _e(b["suite_id"]) + "'>" + _e(b["suite_id"])
                           + "</a>: " + _e(", ".join(b["case_ids"])) + "<br>Reviewed assertion: " + _e(b["assertion"]) + "</li>"
                           for b in requirement["bindings"])
        cases = "".join("<li>" + _e(c["suite_id"] + " / " + c["case_id"] + ": " + c["status"]) + "</li>" for c in requirement["cases"])
        rows.append("<tr><td><b>" + _e(requirement["id"]) + "</b><br>" + _e(requirement["description"])
                    + "</td><td>" + _e(requirement["kind"] + " / " + requirement["category"].replace("_", " "))
                    + "<br>Persona: " + _e(requirement.get("persona", "Not specified"))
                    + "</td><td>" + _e(requirement["status"].title()) + "<br>" + _e(requirement["counts"]["passed"])
                    + " / " + _e(requirement["case_count"]) + " mapped cases passed</td><td><details><summary>Case evidence</summary><div class='inside'><ul>"
                    + (bindings or "<li>No real cases bound. Use release bind after reviewing the objective.</li>")
                    + cases + "</ul></div></details></td></tr>")
    passed = sum(r["status"] == "passed" for r in requirements)
    return ("<details><summary>Test objectives: " + str(passed) + " / " + str(len(requirements))
            + " passed</summary><div class='inside'><p>These results follow reviewer-mapped assertions and recorded case outcomes. "
            "They do not independently prove that an assertion fully tests a business requirement or enforces a role.</p>"
            "<div class='table-wrap'><table><thead><tr><th>Objective</th><th>Area / persona</th><th>Outcome</th><th>Evidence</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table></div></div></details>")


def _requirements_summary(report: dict) -> str:
    coverage = report.get("test_coverage")
    if not coverage or not coverage["requirement_count"]:
        return "<p class='action'><b>Test-depth coverage has not been specified.</b> All-module execution alone does not establish that roles, failure paths, or integrations were tested.</p>"
    return ("<p class='action'><b>" + _e(coverage["passed"]) + " / " + _e(coverage["requirement_count"])
            + " declared test objectives passed.</b> " + _e(coverage["failed"]) + " failed; "
            + _e(coverage["missing"] + coverage["incomplete"]) + " missing or blocked. "
            + _e(coverage["modules_with_requirements"]) + " / " + _e(report["summary"]["module_count"])
            + " modules have explicit test objectives.<br>" + _e(coverage["notice"]) + "</p>")


def _policy_detail(suite: dict) -> str:
    policy = suite.get("policy_disclosure")
    if not policy:
        return ""
    if policy["matches_defaults"]:
        return "<p><b>Threshold policy:</b> PRE-D starting defaults. Review their suitability for your application's risk.</p>"
    rows = []
    for change in policy["changes"]:
        def label(value):
            return "Not configured" if value is None else f"{value['operator']} {value['threshold']:g} ({value['severity']})"
        rows.append("<li>" + _e(change["signal"]) + ": starting default " + _e(label(change["baseline"]))
                    + "; selected " + _e(label(change["selected"])) + ".</li>")
    return ("<p class='action'><b>Custom release thresholds.</b> These are the selected policy, not an independent production-readiness standard.</p>"
            "<details><summary>Threshold changes from starting defaults</summary><div class='inside'><ul>"
            + "".join(rows) + "</ul><p>" + _e(policy["notice"]) + "</p></div></details>")


def _comparison_section(report: dict[str, Any]) -> str:
    comparison = report.get("comparison")
    if not comparison:
        return "<section id='changes'><details><summary>No baseline comparison</summary><div class='inside'><p>Current release checks are evaluated independently. Use <code>--baseline previous-release.json</code> to compare matching local packs.</p></div></details></section>"
    counts = comparison["summary"]
    rows = []
    for row in comparison["metrics"]:
        delta = "Not compared" if row["delta"] is None else f"{row['delta']:+.6g}"
        status = row["status"].replace("_", " ").title()
        rows.append("<tr><td>" + _e(row["module_id"] + " / " + row["suite_id"]) + "<br>" + _e(row["signal"])
                    + "</td><td>" + _e(row["baseline"] if row["baseline"] is not None else "Unavailable")
                    + "</td><td>" + _e(row["candidate"] if row["candidate"] is not None else "Unavailable")
                    + "</td><td>" + _e(delta) + "</td><td>" + _e(status)
                    + ("<br><small>" + _e(row["reason"]) + "</small>" if row["reason"] else "") + "</td></tr>")
    cases = []
    for change in comparison["case_changes"]:
        if change["regressed"] or change["improved"]:
            cases.append("<li><b>" + _e(change["suite_id"]) + "</b>: newly failing cases: " + _e(", ".join(change["regressed"]) or "None")
                         + "; now passing: " + _e(", ".join(change["improved"]) or "None") + ".</li>")
        elif change["status"] == "not_comparable":
            cases.append("<li><b>" + _e(change["suite_id"]) + "</b>: case-level comparison unavailable. " + _e(change["reason"]) + "</li>")
    scope = "".join("<li>" + _e(c["detail"]) + "</li>" for c in comparison["scope_changes"])
    artifact = comparison.get("artifact")
    link = "<p><a href='./" + quote(str(artifact), safe="/.") + "'>Open baseline JSON</a></p>" if artifact else ""
    return ("<section id='changes'><h2>What changed since the baseline</h2><p>" + _e(comparison["baseline_version"]) + " to "
            + _e(comparison["candidate_version"]) + ". Baseline recommendation: " + _e(VERDICTS[comparison["baseline_verdict"]])
            + ".</p><p class='action'><b>" + _e(counts["regressed"]) + " regressed checks / " + _e(counts["improved"])
            + " improved / " + _e(counts["unchanged"]) + " unchanged / " + _e(counts["not_comparable"]) + " not comparable</b></p>"
            + "<p>" + _e(comparison["notice"]) + "</p>"
            + ("<h3>Case changes</h3><ul>" + "".join(cases) + "</ul>" if cases else "")
            + ("<h3>Scope and policy changes</h3><ul>" + scope + "</ul>" if scope else "")
            + "<details><summary>Inspect metric deltas and comparison reasons</summary><div class='inside table-wrap'><table><thead>"
            + "<tr><th>Suite / check</th><th>Baseline</th><th>Candidate</th><th>Delta</th><th>Interpretation</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table></div></details>" + link + "</section>")


def render_release_report(report: dict[str, Any]) -> str:
    app = report["application"]
    summary = report["summary"]
    findings = report["findings"]
    module_cards = []
    for module in report["modules"]:
        suite_cards = []
        for suite in module["suites"]:
            observation = suite.get("decision_observation")
            observed = ("<p class='action'><b>Observed decisions: " + _e(observation["correct_cases"]) + " correct / "
                        + _e(observation["incorrect_cases"]) + " incorrect.</b> " + _e(f"{observation['accuracy']:.1%}")
                        + " on this pack.<br>" + _e(observation["scope_caveat"]) + "</p>") if observation else ""
            rows = "".join(
                "<tr><td>" + _e(g["signal"]) + "</td><td>" + _e(g["observed"] if g["observed"] is not None else "Unavailable")
                + "</td><td>" + _e(g["operator"]) + " " + _e(g["threshold"]) + "</td><td>" + _e(g["trust"])
                + "</td><td>" + _e(g["status"]) + "</td></tr>" for g in suite["gates"]
            )
            artifact = suite.get("artifact")
            # Links are encoded as local relative paths, never interpreted as
            # URL schemes or active HTML from report metadata.
            link = ("<p><a href='./" + quote(str(artifact), safe="/.") + "'>Open source report JSON</a></p>") if artifact else ""
            if suite.get("html_artifact"):
                link = "<p><a href='./" + quote(str(suite["html_artifact"]), safe="/.") + "'>Open detailed evaluation report</a></p>" + link
            suite_cards.append(
                "<details id='suite-" + _e(suite["id"]) + "'><summary>" + _e(suite["id"]) + " <span>" + _e(VERDICTS[suite["verdict"]]) + "</span></summary>"
                + "<div class='inside'><p>" + _e(suite["executed_cases"]) + " / " + _e(suite["requested_cases"])
                + " cases executed. Evaluation: " + _e(suite["kind"]) + ".</p>"
                + observed + _workflow_signal_detail(suite) + _suite_dimension_detail(suite) + _suite_population_detail(suite) + _policy_detail(suite)
                + ("<div class='table-wrap'><table><thead><tr><th>Check</th><th>Observed</th><th>Required</th><th>Evidence</th><th>Result</th></tr></thead><tbody>" + rows + "</tbody></table></div>" if rows else "<p>No usable gate results.</p>")
                + link + "</div></details>"
            )
        module_cards.append(
            "<article class='module' id='module-" + _e(module["id"]) + "'><div class='module-head'><div><p class='eyebrow'>"
            + ("REQUIRED MODULE" if module["required"] else "EXCLUSION") + "</p><h3>" + _e(module["name"])
            + "</h3><p>Owner: " + _e(module["owner"]) + "</p></div><span class='badge " + _e(module["verdict"]) + "'>"
            + _e(VERDICTS[module["verdict"]]) + "</span></div>"
            + ("<p>" + _e(module["exclusion_reason"]) + "</p>" if module["exclusion_reason"] else "")
            + _requirements_detail(module)
            + ("".join(suite_cards) or "<p>No evaluation plans attached.</p>") + "</article>"
        )
    issues = []
    for issue in findings:
        location = " / ".join(str(issue[k]) for k in ("module_id", "suite_id") if issue.get(k)) or "Application scope"
        location_html = _e(location)
        if issue.get("suite_id") or issue.get("module_id"):
            anchor = "suite-" + issue["suite_id"] if issue.get("suite_id") else "module-" + issue["module_id"]
            location_html = "<a href='#" + _e(anchor) + "'>" + location_html + "</a>"
        cases = "<p><b>Cases:</b> " + _e(", ".join(issue["case_ids"])) + "</p>" if issue["case_ids"] else ""
        pointer = "<p><b>Evidence:</b> <code>" + _e(issue["evidence_pointer"]) + "</code></p>" if issue["evidence_pointer"] else ""
        issues.append(
            "<article class='finding " + _e(issue["severity"]) + "'><p class='eyebrow'>" + _e(issue["severity"].upper())
            + " / " + _e(issue["category"].replace("_", " ")) + "</p><h3>" + location_html + "</h3><p>"
            + _e(issue["why"]) + "</p><p class='action'><b>Next action:</b> " + _e(issue["recommendation"])
            + "</p><p><b>Owner:</b> " + _e(issue["owner"]) + "</p>" + cases + pointer
            + "<small>Root cause requires investigation; the evidence above identifies the affected evaluation area.</small></article>"
        )
    stats = "".join("<div><strong>" + _e(summary[key]) + "</strong><span>" + label + "</span></div>" for key, label in
                    (("module_count", "Modules in inventory"), ("suite_count", "Evaluation plans"), ("blockers", "Blocking results"), ("evidence_gaps", "Evidence gaps"), ("conditions", "Conditions to review"), ("advisories", "Coverage advisories")))
    explanations = {
        "ship": "Every required plan met the declared checks with sufficient local evidence for this scope.",
        "ship_with_conditions": "The declared checks support a conditional recommendation. Review the conditions and exclusions below.",
        "do_not_ship": "At least one blocking release check failed. Address the observed result and rerun the affected evaluation.",
        "insufficient_evidence": "Required scope or evidence is incomplete. Complete the identified evaluations before making a release decision.",
    }
    limitations = "".join("<li>" + _e(line) + "</li>" for line in report["limitations"])
    return """<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>PRE-D Release Review</title><style>
:root{color-scheme:dark;--bg:#0b1416;--panel:#142328;--border:#395055;--text:#f8fbf7;--muted:#b9c5c3;--lime:#c9f36b;--coral:#ff8464;--gold:#f5cc67}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top right,#294742,transparent 65%),var(--bg);color:var(--text);font:16px Georgia,serif;line-height:1.55}main{max-width:1200px;margin:auto;padding:40px 24px}h1,h2,h3,p{margin-top:0}h1{font-size:clamp(36px,6vw,70px);line-height:1.05;font-weight:400;margin:14px 0}h2{font-size:30px;font-weight:400}h3{font-size:23px;font-weight:400;margin-bottom:8px}p{color:var(--muted)}a{color:var(--lime)}.eyebrow,code,.badge,summary,.stats span,small{font-family:ui-monospace,Consolas,monospace}.eyebrow{color:var(--coral);font-size:11px;letter-spacing:.14em}.hero{padding:36px;background:linear-gradient(125deg,#203934,#102124);border:1px solid var(--border)}.hero h1{color:var(--lime)}.hero.do_not_ship h1{color:var(--coral)}.hero.insufficient_evidence h1,.hero.ship_with_conditions h1{color:var(--gold)}.scope{font-size:14px;max-width:820px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));border:1px solid var(--border);margin:20px 0 38px}.stats>div{padding:20px;border-right:1px solid var(--border);background:var(--panel)}.stats strong{display:block;font-size:32px;font-weight:400}.stats span{font-size:10px;color:var(--muted)}.module,.finding{padding:24px;border:1px solid var(--border);background:var(--panel);margin-bottom:16px}.module-head{display:flex;justify-content:space-between;gap:16px}.badge{height:fit-content;padding:6px 10px;border:1px solid var(--gold);color:var(--gold);font-size:11px;white-space:nowrap}.badge.ship{border-color:var(--lime);color:var(--lime)}.badge.do_not_ship{border-color:var(--coral);color:var(--coral)}.finding{border-left:4px solid var(--gold)}.finding.blocker{border-left-color:var(--coral)}.finding.advisory{border-left-color:var(--border)}.action{background:#0e1b1e;padding:14px;color:var(--text)}small{color:var(--muted);font-size:11px}details{border:1px solid var(--border);margin-top:12px;background:#0e1b1e}summary{padding:14px;cursor:pointer;font-size:12px}summary span{float:right;color:var(--gold)}.inside{padding:16px}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font:12px ui-monospace,Consolas,monospace}td,th{padding:12px 8px;border-bottom:1px solid var(--border);text-align:left}th{color:var(--muted)}nav{display:flex;gap:24px;margin-bottom:28px}footer{border-top:1px solid var(--border);margin-top:28px;padding-top:20px}code{overflow-wrap:anywhere}li{margin-bottom:10px;color:var(--muted)}@media(max-width:700px){main{padding:16px}.hero,.module,.finding{padding:20px}.stats{grid-template-columns:repeat(2,1fr)}.module-head{display:block}.badge{display:inline-block;margin-bottom:12px}summary span{float:none;display:block;margin-top:8px}nav{flex-wrap:wrap}}@media print{body{background:white;color:black}.hero,.module,.finding,.stats>div,details,.action{background:white;color:black}p,small,li{color:#333}h1{color:black!important}nav{display:none}}
section{margin-bottom:36px}td{overflow-wrap:anywhere}.table-wrap{border:1px solid var(--border)}nav{flex-wrap:wrap}
</style></head><body><main><nav><a href='#execution'>What actually ran</a><a href='#actions'>What needs attention</a><a href='#advisories'>Advisories</a><a href='#changes'>What changed</a><a href='#history'>History</a><a href='#scope'>Review scope</a><a href='#dimensions'>Dimensions</a><a href='#coverage'>Coverage</a><a href='#modules'>Module results</a><a href='#basis'>Evaluation basis</a></nav>""" + (
        "<header class='hero " + _e(report["verdict"]) + "'><p class='eyebrow'>PRE-D / APPLICATION RELEASE REVIEW / LOCAL</p><h1>"
        + _e(report["verdict_label"]) + "</h1><h2>" + _e(app["id"]) + " <small>" + _e(app["version"])
        + "</small></h2><p>" + explanations[report["verdict"]] + "</p><p class='scope'>" + _e(report["scope_statement"])
        + "</p></header><div class='stats'>" + stats + "</div>" + _requirements_summary(report) + _execution_section(report) + "<section id='actions'><h2>What needs attention</h2>"
        + ("".join(issues) or "<p>All declared release checks passed. Review the scope and evaluation basis before shipping.</p>")
        + "</section>" + _advisory_section(report) + _comparison_section(report) + _history_section(report) + _review_scope_section(report) + _dimension_section(report) + _coverage_section(report)
        + "<section id='modules'><h2>Module results</h2>" + "".join(module_cards)
        + "</section><footer id='basis'><h2>Evaluation basis</h2><p>Generated " + _e(report["generated_at"])
        + ". Policy maximum report age: " + _e(report["policy"]["max_report_age_hours"]) + " hours.</p><p>Manifest fingerprint: <code>"
        + _e(report["manifest_sha256"]) + "</code></p><ul>" + limitations + "</ul><p>Results remain local. Nothing was uploaded.</p></footer></main></body></html>"
    )
