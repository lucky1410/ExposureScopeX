"""Conservative release comparisons; a changed test basis is not an improvement."""

from __future__ import annotations

from datetime import datetime
import math
import re
from typing import Any

from .runner import RunnerError, sha256


COMPARABLE_DIMENSIONS = {"classification", "confidence", "workflow_coverage", "decision_evidence"}
LOWER_IS_BETTER = {"confidence.expected_calibration_error", "confidence.correctness_brier_score"}


def validate_baseline(report: dict, application_id: str, now: datetime) -> None:
    from .release import GATE_FIELDS, VERDICTS, _timestamp

    if not isinstance(report, dict) or report.get("schema_version") not in ("pre-d-release-report-1.0", "pre-d-release-report-1.1"):
        raise RunnerError("Baseline must be a PRE-D release-review JSON report")
    app = report.get("application")
    if not isinstance(app, dict) or app.get("id") != application_id or not isinstance(app.get("version"), str):
        raise RunnerError("Baseline application does not match this release")
    issued = _timestamp(report.get("generated_at"))
    if issued is None or issued > now:
        raise RunnerError("Baseline must have a valid historical generation timestamp")
    if not isinstance(report.get("policy"), dict) or not isinstance(report.get("verdict"), str) or report["verdict"] not in VERDICTS:
        raise RunnerError("Baseline release policy or verdict is invalid")
    modules = report.get("modules")
    if not isinstance(modules, list) or not 1 <= len(modules) <= 1000:
        raise RunnerError("Baseline modules are invalid")
    ids: set[str] = set()
    suites: set[str] = set()
    for module in modules:
        if (not isinstance(module, dict) or not isinstance(module.get("id"), str)
                or module["id"] in ids or type(module.get("required")) is not bool
                or not isinstance(module.get("suites"), list) or len(module["suites"]) > 100):
            raise RunnerError("Baseline has invalid or duplicate modules")
        ids.add(module["id"])
        for suite in module["suites"]:
            if (not isinstance(suite, dict) or not isinstance(suite.get("id"), str)
                    or suite["id"] in suites or suite.get("kind") not in ("workflow", "decision")
                    or not isinstance(suite.get("gates"), list) or len(suite["gates"]) > 100):
                raise RunnerError("Baseline has invalid or duplicate suites")
            suites.add(suite["id"])
            signals: set[str] = set()
            for gate in suite["gates"]:
                if not isinstance(gate, dict) or not isinstance(gate.get("signal"), str) or gate["signal"].count(".") != 1:
                    raise RunnerError("Baseline contains an invalid metric gate")
                dimension, field = gate["signal"].split(".")
                if (field not in GATE_FIELDS.get(dimension, set()) or gate["signal"] in signals
                        or gate.get("operator") not in ("gte", "lte")
                        or gate.get("status") not in ("passed", "failed", "missing", "incomplete")
                        or not isinstance(gate.get("trust"), str)
                        or not _finite(gate.get("threshold"))):
                    raise RunnerError("Baseline contains an invalid or duplicate metric gate")
                signals.add(gate["signal"])
                if gate.get("observed") is not None and not _finite(gate["observed"]):
                    raise RunnerError("Baseline has a non-finite or malformed measurement")


def _finite(value: object) -> bool:
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def _basis_reason(before: dict, after: dict) -> str | None:
    if before.get("evidence_complete") is not True or after.get("evidence_complete") is not True:
        return "Both suites must have complete release evidence before their scores can be compared."
    for field in ("kind", "subject_id", "minimum_cases"):
        if before.get(field) is None or before.get(field) != after.get(field):
            return "Suite identity, kind, or minimum sample policy changed or is missing."
    for field in ("dataset_sha256", "protocol_sha256"):
        a, b = before.get("comparison_basis"), after.get("comparison_basis")
        if (not isinstance(a, dict) or not isinstance(b, dict)
                or any(not isinstance(x.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", x[field]) for x in (a, b))):
            return "Original dataset or evaluation-protocol fingerprint is missing; regenerate or rerun with fingerprint support."
        if a[field] != b[field]:
            return "Dataset content changed." if field == "dataset_sha256" else "Evaluation protocol changed."
    for suite in (before, after):
        requested, executed = suite.get("requested_cases"), suite.get("executed_cases")
        if (type(requested) is not int or type(executed) is not int or type(suite.get("minimum_cases")) is not int
                or requested != executed or executed < suite["minimum_cases"]):
            return "Both runs must fully execute the same pack and meet their sample minimum."
    if before["requested_cases"] != after["requested_cases"]:
        return "Executed sample sizes differ."
    if (any(not isinstance(suite.get("run_id"), str) or not suite["run_id"] for suite in (before, after))
            or before["run_id"] == after["run_id"]):
        return "Distinct source executions are required; regenerating or reusing a report is not a new run."
    if any(suite.get("report_sha256") is not None and not isinstance(suite["report_sha256"], str)
           for suite in (before, after)):
        return "Source report fingerprints are malformed."
    if before.get("report_sha256") and before["report_sha256"] == after.get("report_sha256"):
        return "The same source report was reused; this is not a new execution."
    return None


def _case_changes(before: dict, after: dict) -> dict:
    def outcomes(suite: dict) -> dict | None:
        rows = suite.get("case_outcomes")
        if not isinstance(rows, list) or len(rows) != suite.get("executed_cases"):
            return None
        result = {}
        for row in rows:
            if (not isinstance(row, dict) or not isinstance(row.get("case_id"), str)
                    or row["case_id"] in result or row.get("outcome") not in ("passed", "failed")):
                return None
            result[row["case_id"]] = row["outcome"]
        return result

    old, new = outcomes(before), outcomes(after)
    if old is None or new is None or old.keys() != new.keys():
        return {"status": "not_comparable", "regressed": [], "improved": [], "reason": "Complete matched case outcomes are unavailable."}
    return {"status": "compared", "regressed": sorted(k for k in old if old[k] == "passed" and new[k] == "failed"),
            "improved": sorted(k for k in old if old[k] == "failed" and new[k] == "passed")}


def _required_kinds(module: dict) -> list[str]:
    coverage = module.get("coverage", [])
    if not isinstance(coverage, list):
        return []
    return sorted(str(r.get("kind", "")) for r in coverage if isinstance(r, dict) and r.get("required", True))


def _comparison_row(
    manifest: dict, module_id: str, suite_id: str, signal: str,
    before_suite: dict, after_suite: dict,
    before_gate: dict | None, after_gate: dict | None,
) -> dict[str, Any]:
    reason = _basis_reason(before_suite, after_suite)
    if before_gate is None or after_gate is None:
        reason = "This check was added or removed."
    elif any(before_gate.get(key) != after_gate.get(key) for key in ("operator", "threshold", "severity")):
        reason = "The metric threshold, direction, or severity changed."
    elif signal.split(".")[0] not in COMPARABLE_DIMENSIONS:
        reason = "This metric needs an independently matched evidence/judge protocol before regression comparison is supported."
    elif any(
        gate.get("trust") != "verified" or gate.get("status") not in {"passed", "failed"}
        or not _finite(gate.get("observed")) or not 0 <= gate["observed"] <= 1
        for gate in (before_gate, after_gate)
    ):
        reason = "Both measurements must be complete, representative, verified, and numeric."
    row = {
        "module_id": module_id,
        "suite_id": suite_id,
        "signal": signal,
        "baseline": before_gate.get("observed") if before_gate else None,
        "candidate": after_gate.get("observed") if after_gate else None,
        "delta": None,
        "status": "not_comparable",
        "reason": reason,
    }
    if reason is None:
        delta = after_gate["observed"] - before_gate["observed"]
        change = -delta if signal in LOWER_IS_BETTER else delta
        tolerance = manifest["policy"]["regression_tolerance"]
        row.update(
            delta=round(delta, 10),
            status=(
                "unchanged" if abs(change) <= tolerance + 1e-10 else
                "regressed" if change < 0 else
                "improved"
            ),
        )
    return row


def compare_releases(manifest: dict, modules: list[dict], baseline: dict) -> tuple[dict, list[dict]]:
    findings: list[dict] = []
    scope_changes: list[dict] = []
    rows: list[dict] = []
    case_changes: list[dict] = []
    old_modules = {m["id"]: m for m in baseline["modules"]}
    new_modules = {m["id"]: m for m in modules}

    def changed(kind: str, module_id: str | None, detail: str, *, suite_id: str | None = None, review: bool = True) -> None:
        scope_changes.append({"kind": kind, "module_id": module_id, "suite_id": suite_id, "detail": detail})
        if review:
            # Removed modules/suites have no current anchor. Keep the location in text.
            findings.append({"code": "comparison_scope_changed", "why": detail,
                             "action": "Review and approve the scope or policy change; removing tests is not a demonstrated fix.",
                             "severity": "warning", "category": "comparison_scope",
                             "module_id": module_id if module_id in new_modules else None})

    if baseline["policy"] != manifest["policy"]:
        changed("policy_changed", None, "Release-level freshness or regression policy differs from the baseline.")
    for module_id in sorted(old_modules.keys() - new_modules.keys()):
        changed("module_removed", module_id, f"Module {module_id} was removed from the baseline inventory.")
    for module_id, module in new_modules.items():
        old = old_modules.get(module_id)
        if old is None:
            changed("module_added", module_id, f"Module {module_id} is new to this release review.", review=False)
            continue
        for key in ("required", "exclusion_reason", "depends_on", "coverage_basis"):
            if old.get(key) != module.get(key):
                changed("module_policy_changed", module_id, f"Module {module_id}: {key} differs from the baseline.")
        if _required_kinds(old) != _required_kinds(module):
            changed("coverage_requirements_changed", module_id, f"Module {module_id}: required test kinds changed.")
        if old.get("test_requirements_sha256") != module.get("test_requirements_sha256"):
            changed("test_objectives_changed", module_id, f"Module {module_id}: objective, persona, assertion, or case bindings changed or were not recorded in the baseline. This is not a demonstrated coverage improvement.")
        old_suites = {s["id"]: s for s in old["suites"]}
        new_suites = {s["id"]: s for s in module["suites"]}
        for suite_id in sorted(old_suites.keys() - new_suites.keys()):
            changed("suite_removed", module_id, f"Suite {suite_id} was removed from module {module_id}.", suite_id=suite_id)
        for suite_id, suite in new_suites.items():
            previous = old_suites.get(suite_id)
            if previous is None:
                changed("suite_added", module_id, f"Suite {suite_id} is new to module {module_id}.", suite_id=suite_id, review=False)
                continue
            reason = _basis_reason(previous, suite)
            old_gates = {g["signal"]: g for g in previous["gates"]}
            new_gates = {g["signal"]: g for g in suite["gates"]}
            if old_gates.keys() != new_gates.keys():
                changed("gates_changed", module_id, f"Suite {suite_id}: the set of release checks changed.", suite_id=suite_id)
            suite_rows = []
            for signal in sorted(old_gates.keys() | new_gates.keys()):
                a, b = old_gates.get(signal), new_gates.get(signal)
                row = _comparison_row(manifest, module_id, suite_id, signal, previous, suite, a, b)
                rows.append(row)
                suite_rows.append(row)
            comparable_outcomes = reason is None and any(r["status"] != "not_comparable" and r["signal"].split(".")[0] in {"classification", "workflow_coverage"} for r in suite_rows)
            cases = _case_changes(previous, suite) if comparable_outcomes else {"status": "not_comparable", "regressed": [], "improved": [], "reason": reason or "No comparable outcome metric."}
            case_changes.append({"module_id": module_id, "suite_id": suite_id, **cases})
            if not suite_rows or any(r["status"] == "not_comparable" for r in suite_rows):
                findings.append({"code": "comparison_unavailable", "module_id": module_id, "suite_id": suite_id,
                                 "why": f"Suite {suite_id} has release checks which cannot be compared like-for-like.",
                                 "action": "Review the comparison reasons. Rerun a matching baseline pack or explicitly review the changed evaluation scope; do not interpret this as product improvement.",
                                 "category": "comparison_evidence"})
            regressed = [r["signal"] for r in suite_rows if r["status"] == "regressed"]
            if regressed or cases["regressed"]:
                findings.append({"code": "release_regression", "module_id": module_id, "suite_id": suite_id,
                                 "why": ("Measured regressions: " + ", ".join(regressed) + "." if regressed else "Previously passing cases now fail despite aggregate scores staying within tolerance."),
                                 "action": "Inspect the case changes and source reports, investigate the application change, and rerun the same pack after the fix. This is an observed pack regression, not a proven code-level cause.",
                                 "severity": manifest["policy"]["regression_severity"], "category": "regression",
                                 "cases": cases["regressed"]})
    summary = {key: sum(r["status"] == key for r in rows) for key in ("regressed", "improved", "unchanged", "not_comparable")}
    summary.update(scope_changes=len(scope_changes), regressed_cases=sum(len(c["regressed"]) for c in case_changes), improved_cases=sum(len(c["improved"]) for c in case_changes))
    if not rows:
        findings.append({"code": "comparison_unavailable", "why": "No matching baseline release checks exist.",
                         "action": "Select a baseline for this application with matching suite IDs, datasets, and policies.", "category": "comparison_evidence"})
    return {"baseline_sha256": sha256(baseline), "baseline_version": baseline["application"]["version"],
            "candidate_version": manifest["application"]["version"], "baseline_verdict": baseline["verdict"],
            "baseline_generated_at": baseline["generated_at"], "summary": summary, "metrics": rows,
            "case_changes": case_changes, "scope_changes": scope_changes,
            "notice": "Deltas describe the matched local pack, not statistical significance or production-wide improvement. Advanced semantic/telemetry metrics remain in current release gates, but are not yet regression-compared."}, findings


def summarize_history(manifest: dict, modules: list[dict], history: list[dict]) -> dict[str, Any]:
    from .release import _timestamp

    unique: dict[str, dict] = {}
    for report in history:
        unique.setdefault(sha256(report), report)
    ordered = sorted(
        unique.values(),
        key=lambda item: _timestamp(item["generated_at"]),
    )
    rows: list[dict[str, Any]] = []
    summary = {"regressed": 0, "improved": 0, "unchanged": 0, "not_comparable": 0}
    if not ordered:
        return {
            "report_count": 0,
            "metrics": [],
            "summary": summary,
            "reports": [],
            "notice": "No historical release reports were supplied.",
        }

    module_maps = [{module["id"]: module for module in report["modules"]} for report in ordered]
    for module in modules:
        for suite in module["suites"]:
            current_gates = {gate["signal"]: gate for gate in suite["gates"]}
            for signal, current_gate in current_gates.items():
                points: list[dict[str, Any]] = []
                comparable: list[tuple[dict, dict[str, Any]]] = []
                seen_runs: set[str] = set()
                seen_reports: set[str] = set()
                for report, module_map in zip(ordered, module_maps, strict=True):
                    previous_module = module_map.get(module["id"])
                    if previous_module is None:
                        points.append({
                            "version": report["application"]["version"],
                            "generated_at": report["generated_at"],
                            "status": "not_comparable",
                            "reason": f"Module {module['id']} is absent from this historical review.",
                            "observed": None,
                        })
                        continue
                    previous_suite = next(
                        (item for item in previous_module.get("suites", []) if item.get("id") == suite["id"]),
                        None,
                    )
                    if previous_suite is None:
                        points.append({
                            "version": report["application"]["version"],
                            "generated_at": report["generated_at"],
                            "status": "not_comparable",
                            "reason": f"Suite {suite['id']} is absent from this historical review.",
                            "observed": None,
                        })
                        continue
                    previous_gates = {gate["signal"]: gate for gate in previous_suite.get("gates", [])}
                    row = _comparison_row(
                        manifest,
                        module["id"],
                        suite["id"],
                        signal,
                        previous_suite,
                        suite,
                        previous_gates.get(signal),
                        current_gate,
                    )
                    run_id = previous_suite.get("run_id")
                    report_hash = previous_suite.get("report_sha256")
                    if row["status"] != "not_comparable":
                        if run_id in seen_runs or (report_hash and report_hash in seen_reports):
                            row.update(status="not_comparable", reason="This historical source execution was already counted.")
                        else:
                            seen_runs.add(run_id)
                            if report_hash:
                                seen_reports.add(report_hash)
                    point = {
                        "version": report["application"]["version"],
                        "generated_at": report["generated_at"],
                        "status": row["status"],
                        "reason": row["reason"],
                        "observed": row["baseline"],
                    }
                    points.append(point)
                    if row["status"] != "not_comparable":
                        comparable.append((point, row))
                latest_point, latest_row = comparable[-1] if comparable else (None, None)
                if latest_row is None:
                    status = "not_comparable"
                    delta = None
                    latest_value = None
                    best_previous = None
                    worst_previous = None
                    reason = (
                        next((point["reason"] for point in reversed(points) if point["reason"]), None)
                        or "No comparable historical measurement is available."
                    )
                else:
                    status = latest_row["status"]
                    delta = latest_row["delta"]
                    latest_value = latest_row["baseline"]
                    comparable_values = [point["observed"] for point, _row in comparable]
                    if signal in LOWER_IS_BETTER:
                        best_previous = min(comparable_values)
                        worst_previous = max(comparable_values)
                    else:
                        best_previous = max(comparable_values)
                        worst_previous = min(comparable_values)
                    reason = latest_row["reason"]
                summary[status] += 1
                rows.append({
                    "module_id": module["id"],
                    "suite_id": suite["id"],
                    "signal": signal,
                    "current": current_gate.get("observed"),
                    "latest_previous": latest_value,
                    "latest_previous_version": latest_point["version"] if latest_point else None,
                    "latest_previous_generated_at": latest_point["generated_at"] if latest_point else None,
                    "best_previous": best_previous,
                    "worst_previous": worst_previous,
                    "comparable_history_count": len(comparable),
                    "status": status,
                    "delta_from_latest": delta,
                    "reason": reason,
                    "points": points,
                })
    return {
        "report_count": len(ordered),
        "reports": [
            {
                "version": report["application"]["version"],
                "generated_at": report["generated_at"],
                "verdict": report["verdict"],
                "sha256": sha256(report),
            }
            for report in ordered
        ],
        "summary": summary,
        "metrics": rows,
        "notice": (
            "History trends describe the supplied matched local packs over time. "
            "They are not a scheduled monitor, population estimate, or statistical significance claim."
        ),
    }
