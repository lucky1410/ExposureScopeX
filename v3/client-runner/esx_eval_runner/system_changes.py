"""Traceable comparisons with explicit test-protocol and evidence comparability."""

from __future__ import annotations

from .runner import RunnerError, sha256
from .system_history import signals, candidate_matches
from .system_safety import source_diff


def verify_report(report: dict) -> None:
    if report.get("schema_version") != "pre-d-system-report-1.0" or report.get("report_sha256") != sha256({k: v for k, v in report.items() if k != "report_sha256"}):
        raise RunnerError("Comparison requires an unchanged, complete PRE-D system report")


def compare_reports(before: dict, after: dict) -> dict:
    verify_report(before)
    verify_report(after)
    if before["project_id"] != after["project_id"]:
        raise RunnerError("Comparison reports must belong to the same project")
    if before["run_id"] == after["run_id"]:
        raise RunnerError("Choose two different run IDs for comparison")
    changes, comparisons = [], []
    for field in ("application_version", "plan_sha256", "verdict", "inventory_confirmed"):
        if before.get(field) != after.get(field):
            changes.append({"kind": field, "before": before.get(field), "after": after.get(field)})
    for field in ("roles", "environment", "base_url"):
        a, b = before.get("review_context", {}).get(field), after.get("review_context", {}).get(field)
        if a != b:
            changes.append({"kind": field, "before": a, "after": b})
    for category, field, key in (("component", "coverage", "component_id"), ("check", "checks", "id")):
        a, b = ({r[key]: r for r in report[field]} for report in (before, after))
        for identity in sorted(set(a) | set(b)):
            if identity not in a or identity not in b:
                changes.append({"kind": category, "id": identity, "change": "added" if identity not in a else "removed"})
            elif category == "component":
                for property_name in ("complete", "gaps", "required_layers", "module", "enabled"):
                    if a[identity].get(property_name) != b[identity].get(property_name):
                        changes.append({"kind": "component_" + property_name, "id": identity,
                                        "before": a[identity].get(property_name), "after": b[identity].get(property_name)})
    prior = {r["id"]: r for r in before["checks"]}
    valid_candidate = candidate_matches(before) and candidate_matches(after)
    for current in after["checks"]:
        previous = prior.get(current["id"])
        if previous is None:
            continue
        comparable = (valid_candidate and before["protocol_version"] == after["protocol_version"]
                      and bool(current.get("comparison_sha256"))
                      and current["comparison_sha256"] == previous.get("comparison_sha256"))
        row = {"check_id": current["id"], "before_status": previous["status"], "after_status": current["status"],
               "comparable": comparable, "status": "comparable" if comparable else "protocol_or_candidate_changed",
               "before_result_sha256": sha256(previous), "after_result_sha256": sha256(current), "metric_deltas": []}
        row["regression"] = comparable and previous["status"] == "passed" and current["status"] != "passed"
        if comparable:
            a, b = signals(previous), signals(current)
            for signal in sorted(set(a) & set(b)):
                if a[signal] != b[signal]:
                    row["metric_deltas"].append({"signal": signal, "before": a[signal], "after": b[signal], "delta": b[signal] - a[signal]})
        for dimension in sorted(set(previous.get("metrics", {})) | set(current.get("metrics", {}))):
            a = previous.get("metrics", {}).get(dimension, {})
            b = current.get("metrics", {}).get(dimension, {})
            for field in ("trust_status", "measurement_status"):
                if a.get(field) != b.get(field):
                    changes.append({"kind": field, "check_id": current["id"], "dimension": dimension, "before": a.get(field), "after": b.get(field)})
        comparisons.append(row)
    before_source = before.get("source_integrity", {}).get("after")
    after_source = after.get("source_integrity", {}).get("before")
    source = source_diff(before_source, after_source) if before_source and after_source else {"status": "not_available", "files": [], "changed_file_count": 0}
    result = {"schema_version": "pre-d-system-changes-1.0", "project_id": after["project_id"],
              "baseline_run_id": before["run_id"], "current_run_id": after["run_id"],
              "baseline_report_sha256": before["report_sha256"], "current_report_sha256": after["report_sha256"],
              "changes": changes, "checks": comparisons, "source": source,
              "summary": {"regressions": sum(r["regression"] for r in comparisons),
                          "incomparable_checks": sum(not r["comparable"] for r in comparisons),
                          "changed_fields": len(changes), "changed_source_files": source["changed_file_count"]},
              "notice": "Changes link to these exact runs and evidence hashes. Numeric deltas use compatible verified evidence only. A delta alone is not statistical significance or proof of cause."}
    result["changes_sha256"] = sha256(result)
    return result


def attach_comparison(report: dict, baseline: dict) -> dict:
    comparison = compare_reports(baseline, report)
    report["changes"] = comparison
    # Keep the referenced current digest as the original execution report; seal the enriched report separately.
    report["execution_report_sha256"] = report["report_sha256"]
    report.pop("report_sha256")
    report["report_sha256"] = sha256(report)
    return comparison
