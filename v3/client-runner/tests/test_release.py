"""Release recommendations must preserve failures, scope gaps, and provenance."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from esx_eval_runner.audit import verify_audit_log
from esx_eval_runner.cli import main
from esx_eval_runner.local_metrics import classification_metrics, confidence_metrics
from esx_eval_runner.release import MANIFEST_SCHEMA, build_release_report, default_gates, validate_manifest
from esx_eval_runner.release_html import render_release_report
from esx_eval_runner.runner import RunnerError, sha256


NOW = datetime(2026, 9, 19, 9, 0, tzinfo=timezone.utc)


def manifest() -> dict:
    return {
        "schema_version": MANIFEST_SCHEMA,
        "application": {"id": "sample-app", "version": "release-4", "inventory_complete": True},
        "modules": [{"id": "decisions", "owner": "Decision team", "suites": [{
            "id": "decision-pack", "kind": "decision", "subject_id": "decision-engine",
            "report": "decision.local-report.json",
        }]}],
    }


def local_report(*, version: str = "release-4", confidence: float | None = None) -> dict:
    expected = ["allow", "review"] * 10
    ids = [f"case-{i:03}" for i in range(20)]
    confidence_values = [confidence if confidence is not None else 0.90 + (i % 5) * 0.02 for i in range(20)]
    metrics = {
        "classification": classification_metrics(expected, expected, ids),
        "confidence": confidence_metrics(expected, expected, confidence_values, ids),
    }
    for value in metrics.values():
        value.update(trust_status="verified", representativeness="representative")
    return {
        "schema_version": "esx-local-evaluation-report-1.2", "status": "completed_locally",
        "package_id": "distinct-run", "subject": {"agent_id": "decision-engine", "subject_version": version},
        "run_provenance": {"project_key": "sample-app", "issued_at": NOW.isoformat()},
        "evaluation": {"required_dimensions": ["classification", "confidence"],
                       "comparison_basis": {"dataset_sha256": sha256({"fixture": "twenty-cases"}), "protocol_sha256": sha256({"fixture": "protocol"})},
                       "dataset_health": {"sample_size": 20, "unique_case_id_count": 20, "class_count": 2,
                                          "duplicate_input_count": 0, "majority_class_rate": 0.5}},
        "execution": {"adapter_type": "command_json_v1", "case_count": 20, "scored_case_count": 20, "blocked_case_count": 0},
        "metrics": metrics,
    }


def assess(plan: dict | None = None, report: dict | None = None) -> dict:
    source = local_report() if report is None else report
    return build_release_report(plan or manifest(), {"decision-pack": {"report": source, "report_sha256": sha256(source)}}, now=NOW)


def write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


class ReleasePolicyTests(unittest.TestCase):
    def test_complete_healthy_scope_can_ship_without_mutating_scores(self):
        source = local_report()
        original = deepcopy(source)
        result = assess(report=source)
        self.assertEqual(result["verdict"], "ship")
        self.assertEqual(source, original)
        self.assertEqual(result["summary"]["blockers"], 0)
        self.assertFalse(result["uploaded"])

    def test_perfect_accuracy_does_not_hide_poor_calibration(self):
        result = assess(report=local_report(confidence=0.498))
        self.assertEqual(result["verdict"], "do_not_ship")
        finding = next(f for f in result["findings"] if f["code"] == "threshold_failed")
        self.assertEqual(finding["category"], "confidence_calibration")
        self.assertEqual(finding["module_id"], "decisions")
        self.assertEqual(finding["owner"], "Decision team")
        self.assertIn("0.502", finding["why"])
        self.assertIn("held-out", finding["recommendation"])
        self.assertEqual(finding["root_cause_status"], "not_established")

    def test_untested_module_cannot_be_hidden_by_perfect_tested_module(self):
        plan = manifest()
        plan["modules"].append({"id": "integrations", "suites": []})
        result = assess(plan)
        self.assertEqual(result["verdict"], "insufficient_evidence")
        self.assertEqual(result["modules"][0]["verdict"], "ship")
        self.assertEqual(result["modules"][1]["verdict"], "insufficient_evidence")

    def test_explicit_exclusion_is_a_condition_and_never_executes(self):
        plan = manifest()
        plan["modules"].append({"id": "live-actions", "required": False, "exclusion_reason": "Live integration has no test tenant.", "suites": []})
        self.assertEqual(assess(plan)["verdict"], "ship_with_conditions")
        plan["modules"][-1]["suites"] = [deepcopy(plan["modules"][0]["suites"][0])]
        with self.assertRaisesRegex(RunnerError, "excluded modules"):
            validate_manifest(plan)

    def test_inventory_confirmation_is_required(self):
        plan = manifest()
        plan["application"]["inventory_complete"] = False
        self.assertEqual(assess(plan)["verdict"], "insufficient_evidence")

    def test_declared_perfect_metric_cannot_satisfy_release_gate(self):
        for dimension, field in (("groundedness", "grounded_claim_rate"), ("trajectory", "score"), ("cost_efficiency", "p95_latency_ms")):
            with self.subTest(dimension=dimension):
                plan, source = manifest(), local_report()
                suite = plan["modules"][0]["suites"][0]
                suite["gates"] = default_gates("decision") + [{"signal": f"{dimension}.{field}", "operator": "lte" if dimension == "cost_efficiency" else "gte", "threshold": 1}]
                source["evaluation"]["required_dimensions"].append(dimension)
                source["metrics"][dimension] = {"measurement_status": "measured", "trust_status": "declared", field: 0 if dimension == "cost_efficiency" else 1}
                result = assess(plan, source)
                self.assertEqual(result["verdict"], "insufficient_evidence")
                self.assertTrue(any(f["code"] == "metric_evidence_gap" for f in result["findings"]))

    def test_failure_wins_over_gap_but_gap_remains_visible(self):
        plan = manifest()
        plan["modules"].append({"id": "untested"})
        result = assess(plan, local_report(confidence=0.3))
        self.assertEqual(result["verdict"], "do_not_ship")
        self.assertGreater(result["summary"]["blockers"], 0)
        self.assertGreater(result["summary"]["evidence_gaps"], 0)

    def test_versions_projects_and_subjects_cannot_be_mixed(self):
        for section, field in (("subject", "subject_version"), ("subject", "agent_id"), ("run_provenance", "project_key")):
            with self.subTest(field=field):
                source = local_report()
                source[section][field] = "wrong"
                result = assess(report=source)
                self.assertEqual(result["verdict"], "insufficient_evidence")
                self.assertEqual(result["modules"][0]["suites"][0]["gates"], [])

    def test_old_missing_naive_and_future_timestamps_cannot_pass(self):
        for issued in (None, (NOW - timedelta(hours=25)).isoformat(), (NOW + timedelta(hours=2)).isoformat(), "2026-09-19T09:00:00"):
            with self.subTest(issued=issued):
                source = local_report()
                source["run_provenance"]["issued_at"] = issued
                self.assertEqual(assess(report=source)["verdict"], "insufficient_evidence")

    def test_duplicate_run_cannot_count_as_a_second_module(self):
        plan, source = manifest(), local_report()
        second = deepcopy(plan["modules"][0])
        second["id"] = "duplicate-module"
        second["suites"][0]["id"] = "other-pack"
        plan["modules"].append(second)
        result = build_release_report(plan, {"decision-pack": {"report": source}, "other-pack": {"report": source}}, now=NOW)
        self.assertEqual(result["verdict"], "insufficient_evidence")
        self.assertTrue(any(f["code"] == "duplicate_or_missing_run" for f in result["findings"]))

    def test_required_metric_without_threshold_is_explicit_gap(self):
        source = local_report()
        source["evaluation"]["required_dimensions"].append("security")
        self.assertTrue(any(f["code"] == "metric_policy_missing" for f in assess(report=source)["findings"]))

    def test_corrupt_counts_and_invalid_scores_never_pass(self):
        for value in (None, True, "1", -0.1, 1.1, float("inf"), float("nan")):
            with self.subTest(value=value):
                source = local_report()
                source["metrics"]["classification"]["accuracy"] = value
                result = build_release_report(manifest(), {"decision-pack": {"report": source}}, now=NOW)
                self.assertEqual(result["verdict"], "insufficient_evidence")
        source = local_report()
        source["execution"]["scored_case_count"] = 30
        self.assertEqual(assess(report=source)["verdict"], "insufficient_evidence")

    def test_minimum_cases_and_actual_metric_sample_must_match(self):
        source = local_report()
        source["metrics"]["classification"]["sample_size"] = 1
        self.assertTrue(any(f["code"] == "metric_sample_mismatch" for f in assess(report=source)["findings"]))
        plan = manifest()
        plan["modules"][0]["suites"][0]["minimum_cases"] = 50
        self.assertTrue(any(f["code"] == "too_few_cases" for f in assess(plan)["findings"]))

    def test_duplicate_and_imbalanced_data_remain_release_conditions(self):
        for field, value in (("duplicate_input_count", 18), ("majority_class_rate", 0.95)):
            with self.subTest(field=field):
                source = local_report()
                source["evaluation"]["dataset_health"][field] = value
                self.assertEqual(assess(report=source)["verdict"], "ship_with_conditions")
        source = local_report()
        source["evaluation"].pop("dataset_health")
        self.assertEqual(assess(report=source)["verdict"], "insufficient_evidence")

    def test_configured_warning_does_not_become_a_blocker(self):
        plan = manifest()
        gates = default_gates("decision")
        gates[-1]["severity"] = "warning"
        plan["modules"][0]["suites"][0]["gates"] = gates
        self.assertEqual(assess(plan, local_report(confidence=0.4))["verdict"], "ship_with_conditions")

    def test_threshold_boundary_is_inclusive(self):
        source = local_report()
        source["metrics"]["confidence"]["expected_calibration_error"] = 0.15
        self.assertEqual(assess(report=source)["verdict"], "ship")

    def test_blocked_sessions_are_coverage_gaps_and_failed_signals_are_reviewable(self):
        plan = manifest()
        suite = plan["modules"][0]["suites"][0]
        suite["kind"] = "workflow"
        source = local_report()
        source["execution"].update(adapter_type="browser_journey", case_count=2, scored_case_count=1, blocked_case_count=1)
        source["evaluation"]["required_dimensions"] = ["workflow_coverage"]
        source["metrics"] = {"workflow_coverage": {"measurement_status": "measured", "trust_status": "verified", "workflow_execution_rate": 0.5, "workflow_signal_match_rate": 1.0}}
        result = assess(plan, source)
        # A lower execution rate reflects the same setup gap, not a product defect.
        self.assertEqual(result["verdict"], "insufficient_evidence")
        self.assertTrue(any(f["code"] == "execution_blocked" for f in result["findings"]))
        source["execution"].update(scored_case_count=2, blocked_case_count=0, browser_case_diagnostics=[{"case_id": "settings", "outcome": "failed"}])
        source["metrics"]["workflow_coverage"].update(workflow_execution_rate=1.0, workflow_signal_match_rate=0.5)
        result = assess(plan, source)
        self.assertEqual(result["verdict"], "do_not_ship")
        finding = next(f for f in result["findings"] if f["code"] == "threshold_failed")
        self.assertIn("settings", finding["case_ids"])
        self.assertIn("assertion", finding["recommendation"])

    def test_partial_semantic_evidence_cannot_be_a_full_pass(self):
        plan, source = manifest(), local_report()
        plan["modules"][0]["suites"][0]["gates"] = default_gates("decision") + [{"signal": "hallucination.hallucinated_claim_rate", "operator": "lte", "threshold": 0}]
        source["metrics"]["hallucination"] = {"measurement_status": "measured", "trust_status": "verified", "verification_basis": "independent_local_semantic_judge", "hallucinated_claim_rate": 0, "response_count": 20, "assessed_response_count": 1}
        result = assess(plan, source)
        self.assertEqual(result["verdict"], "insufficient_evidence")
        self.assertTrue(any(f["code"] == "semantic_coverage_gap" for f in result["findings"]))
        self.assertTrue(any(f["code"] == "semantic_judge_review" for f in result["findings"]))

    def test_unsupported_and_boolean_thresholds_are_rejected(self):
        for signal, threshold in (("classification.accurracy", 0.95), ("confidence.expected_calibration_error", True), ("confidence.expected_calibration_error", float("nan"))):
            with self.subTest(signal=signal, threshold=threshold):
                plan = manifest()
                plan["modules"][0]["suites"][0]["gates"] = [{"signal": signal, "operator": "gte", "threshold": threshold}]
                with self.assertRaises(RunnerError):
                    validate_manifest(plan)
        plan = manifest()
        plan["modules"][0]["suites"][0]["minimun_cases"] = 200
        with self.assertRaisesRegex(RunnerError, "unknown fields"):
            validate_manifest(plan)

    def test_html_escapes_target_metadata_and_shows_fix_location(self):
        result = assess(report=local_report(confidence=0.3))
        result["modules"][0]["name"] = "<script>alert('test')</script>"
        page = render_release_report(result)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("confidence.expected_calibration_error", page)
        self.assertIn("Decision team", page)
        self.assertIn("Next action:", page)
        self.assertIn("Do not ship", page)
        self.assertIn("Nothing was uploaded", page)


class ReleaseCliTests(unittest.TestCase):
    def test_init_and_check_empty_scope_without_running_anything(self):
        with TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            root = Path(directory)
            path = root / "release.json"
            self.assertEqual(main(["release", "init", "--application-id", "sample-app", "--subject-version", "release-4", "--module", "decisions", "--module", "search", "--out", str(path)]), 0)
            self.assertEqual(main(["release", "check", "--manifest", str(path), "--out", str(root / "out.json"), "--require-ship"]), 2)
            result = json.loads((root / "out.json").read_text())
            self.assertEqual(result["summary"]["required_module_count"], 2)
            self.assertEqual(result["verdict"], "insufficient_evidence")
            self.assertEqual(verify_audit_log(root / "out.audit.jsonl")["status"], "valid")

    def test_default_check_never_calls_the_runner(self):
        plan = manifest()
        suite = plan["modules"][0]["suites"][0]
        suite["config"] = suite.pop("report")
        with TemporaryDirectory() as directory, redirect_stdout(io.StringIO()), patch("esx_eval_runner.cli.run_command") as run:
            root = Path(directory)
            write(root / "release.json", plan)
            self.assertEqual(main(["release", "check", "--manifest", str(root / "release.json"), "--out", str(root / "review.json")]), 0)
            run.assert_not_called()
            result = json.loads((root / "review.json").read_text())
            self.assertEqual(result["findings"][0]["code"], "run_not_requested")

    def test_existing_reports_are_hashed_and_reused_without_executing(self):
        source = local_report()
        source["run_provenance"]["issued_at"] = datetime.now(timezone.utc).isoformat()
        with TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            root = Path(directory)
            write(root / "release.json", manifest())
            write(root / "decision.local-report.json", source)
            self.assertEqual(main(["release", "check", "--manifest", str(root / "release.json"), "--out", str(root / "review.json"), "--require-ship"]), 0)
            report = json.loads((root / "review.json").read_text())
            self.assertEqual(report["modules"][0]["suites"][0]["report_sha256"], sha256(source))

    def test_output_cannot_overwrite_input(self):
        with TemporaryDirectory() as directory, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            root = Path(directory)
            path = root / "release.json"
            write(path, manifest())
            before = path.read_bytes()
            self.assertEqual(main(["release", "check", "--manifest", str(path), "--out", str(path)]), 1)
            self.assertEqual(path.read_bytes(), before)

    def test_multiple_real_local_adapter_runs_produce_one_release_review(self):
        with TemporaryDirectory() as directory, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            root = Path(directory)
            plan = manifest()
            first = plan["modules"][0]["suites"][0]
            first.pop("report")
            first["config"] = "healthy/plan.json"
            second = deepcopy(plan["modules"][0])
            second["id"] = "recommendations"
            second["suites"][0].update(id="poor-calibration", config="poor/plan.json")
            plan["modules"].append(second)
            for folder, confidence in (("healthy", None), ("poor", 0.498)):
                write(root / folder / "plan.json", adapter_config(confidence))
            write(root / "release.json", plan)
            cwd = Path.cwd()
            status = main(["release", "check", "--manifest", str(root / "release.json"), "--out", str(root / "out" / "release.json"), "--run", "--require-ship"])
            self.assertEqual(Path.cwd(), cwd)
            self.assertEqual(status, 2)
            result = json.loads((root / "out" / "release.json").read_text())
            self.assertEqual(result["verdict"], "do_not_ship")
            self.assertEqual(result["modules"][0]["verdict"], "ship")
            self.assertEqual(result["modules"][1]["verdict"], "do_not_ship")
            self.assertEqual(result["modules"][0]["suites"][0]["executed_cases"], 20)
            self.assertEqual(verify_audit_log(root / "out" / "release.audit.jsonl")["status"], "valid")

    def test_one_adapter_failure_does_not_discard_other_completed_results(self):
        with TemporaryDirectory() as directory, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            root = Path(directory)
            plan = manifest()
            first = plan["modules"][0]["suites"][0]
            first.pop("report")
            first["config"] = "broken.json"
            second = deepcopy(first)
            second.update(id="healthy", config="healthy.json")
            plan["modules"][0]["suites"].append(second)
            broken = adapter_config(None)
            broken["adapter"]["command"] = [sys.executable, "-c", "raise SystemExit(2)"]
            write(root / "broken.json", broken)
            write(root / "healthy.json", adapter_config(None))
            write(root / "release.json", plan)
            self.assertEqual(main(["release", "check", "--manifest", str(root / "release.json"), "--out", str(root / "review.json"), "--run"]), 0)
            result = json.loads((root / "review.json").read_text())
            self.assertEqual(result["verdict"], "insufficient_evidence")
            self.assertEqual(result["modules"][0]["suites"][1]["verdict"], "ship")


def adapter_config(confidence: float | None) -> dict:
    return {
        "schema_version": "esx-client-runner-config-1.0",
        "evaluation": {"name": "Synthetic release regression", "agent_id": "decision-engine", "subject_version": "release-4", "project_key": "sample-app", "dataset_version": "fixture-v1", "required_dimensions": ["classification", "confidence"]},
        "dataset": {"version": "fixture-v1", "cases": [
            {"case_id": f"case-{i:03}", "input": {"flagged": bool(i % 2), "example_index": i}, "expected_label": "review" if i % 2 else "allow"} for i in range(20)
        ]},
        "adapter": {"type": "command_json_v1", "command": [sys.executable, "-c",
            "import json,sys; r=json.load(sys.stdin); json.dump({'schema_version':'esx-client-adapter-response-1.0','results':[{'case_id':c['case_id'],'predicted_label':'review' if c['input']['flagged'] else 'allow','confidence':" + (str(confidence) if confidence is not None else "0.90+(i%5)*0.02") + "} for i,c in enumerate(r['cases'])]},sys.stdout)"], "timeout_seconds": 10},
    }


if __name__ == "__main__":
    unittest.main()
