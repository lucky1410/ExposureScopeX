"""Regression recommendations must not reward missing tests or changed evidence."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
from html.parser import HTMLParser
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import unquote

from esx_eval_runner.cli import main
from esx_eval_runner.confidence import NATIVE_CONFIDENCE, annotate_confidence
from esx_eval_runner.local_metrics import classification_metrics, confidence_metrics
from esx_eval_runner.release import build_release_report, default_gates, validate_manifest
from esx_eval_runner.release_html import render_release_report
from esx_eval_runner.runner import RunnerError, build_package, sha256
from test_release import NOW, adapter_config, assess, local_report, manifest, write


def baseline(confidence=None):
    plan = manifest()
    plan["application"]["version"] = "release-3"
    return build_release_report(plan, {"decision-pack": {"report": local_report(version="release-3", confidence=confidence)}}, now=NOW)


def compare(source=None, plan=None, previous=None):
    source = deepcopy(source or local_report())
    source["package_id"] = "candidate-run"
    return build_release_report(plan or manifest(), {"decision-pack": {"report": source, "report_sha256": sha256(source)}},
                                now=NOW, baseline=previous or baseline())


class CoverageRequirementsTests(unittest.TestCase):
    def test_decision_pack_cannot_satisfy_required_browser_coverage(self):
        plan = manifest()
        plan["modules"][0]["required_kinds"] = ["decision", "workflow"]
        result = assess(plan)
        self.assertEqual(result["verdict"], "insufficient_evidence")
        self.assertIn("required_kind_missing", [f["code"] for f in result["findings"]])
        self.assertEqual(result["modules"][0]["coverage"], [
            {"kind": "decision", "required": True, "planned_suites": 1, "executed_suites": 1, "status": "complete"},
            {"kind": "workflow", "required": True, "planned_suites": 0, "executed_suites": 0, "status": "missing"},
        ])

    def test_failed_metric_is_tested_coverage_not_missing_execution(self):
        result = assess(report=local_report(confidence=0.3))
        self.assertEqual(result["modules"][0]["coverage"][0]["status"], "complete")
        self.assertEqual(result["verdict"], "do_not_ship")

    def test_declared_evidence_remains_incomplete_coverage(self):
        source = local_report()
        source["metrics"]["confidence"]["trust_status"] = "declared"
        self.assertEqual(assess(report=source)["modules"][0]["coverage"][0]["status"], "incomplete")

    def test_legacy_scope_is_identified_without_silently_claiming_whole_module(self):
        result = assess()
        self.assertEqual(result["modules"][0]["coverage_basis"], "attached_plans_only")
        self.assertIn("Attached plans alone do not establish", render_release_report(result))

    def test_dependency_gaps_propagate_transitively(self):
        plan = manifest()
        plan["modules"][0]["depends_on"] = ["search"]
        plan["modules"] += [{"id": "search", "depends_on": ["external"]},
                            {"id": "external", "required": False, "exclusion_reason": "No test tenant"}]
        result = assess(plan)
        self.assertEqual(result["modules"][0]["verdict"], "insufficient_evidence")
        dependencies = [f for f in result["findings"] if f["code"] == "dependency_not_ready"]
        self.assertEqual(len(dependencies), 2)

    def test_bad_dependency_graphs_are_rejected(self):
        for dependencies in (["absent"], ["decisions"], ["other", "other"], "other", [None]):
            plan = manifest()
            plan["modules"][0]["depends_on"] = dependencies
            with self.subTest(dependencies=dependencies), self.assertRaises(RunnerError):
                validate_manifest(plan)
        plan = manifest()
        plan["modules"][0]["depends_on"] = ["other"]
        plan["modules"].append({"id": "other", "depends_on": ["decisions"]})
        with self.assertRaisesRegex(RunnerError, "cycle"):
            validate_manifest(plan)

    def test_invalid_kinds_and_regression_policy_are_rejected(self):
        for kinds in ([], ["decision", "decision"], ["security"], [None], [["decision"]], "decision"):
            plan = manifest()
            plan["modules"][0]["required_kinds"] = kinds
            with self.subTest(kinds=kinds), self.assertRaises(RunnerError):
                validate_manifest(plan)
        for policy in ({"regression_tolerance": True}, {"regression_tolerance": float("nan")}, {"regression_severity": "ignore"}):
            plan = manifest()
            plan["policy"] = policy
            with self.subTest(policy=policy), self.assertRaises(RunnerError):
                validate_manifest(plan)

    def test_normalization_is_idempotent(self):
        plan = manifest()
        plan["modules"][0]["required_kinds"] = ["workflow", "decision"]
        once = validate_manifest(plan)
        self.assertEqual(validate_manifest(once), once)


class ReleaseComparisonTests(unittest.TestCase):
    def test_same_pack_and_protocol_produce_unchanged_scores(self):
        result = compare()
        self.assertEqual(result["comparison"]["summary"]["unchanged"], 3)
        self.assertEqual(result["verdict"], "ship")
        self.assertEqual(result["comparison"]["case_changes"][0]["status"], "compared")

    def test_lower_ece_is_an_improvement_not_regression(self):
        result = compare(previous=baseline(0.498))
        row = next(r for r in result["comparison"]["metrics"] if r["signal"].startswith("confidence."))
        self.assertEqual(row["status"], "improved")
        self.assertAlmostEqual(row["delta"], -0.442)
        self.assertEqual(result["verdict"], "ship")

    def test_regression_within_absolute_gate_is_still_a_condition(self):
        source = local_report()
        source["metrics"]["confidence"]["expected_calibration_error"] = 0.08
        result = compare(source)
        self.assertEqual(result["verdict"], "ship_with_conditions")
        self.assertEqual(result["comparison"]["summary"]["regressed"], 1)

    def test_configured_regression_blocker_and_tolerance(self):
        source, plan = local_report(), manifest()
        source["metrics"]["confidence"]["expected_calibration_error"] = 0.08
        plan["policy"] = {"regression_severity": "blocker"}
        self.assertEqual(compare(source, plan)["verdict"], "do_not_ship")
        plan["policy"]["regression_tolerance"] = 0.02
        result = compare(source, plan)
        self.assertEqual(result["comparison"]["summary"]["regressed"], 0)
        self.assertTrue(any(c["kind"] == "policy_changed" for c in result["comparison"]["scope_changes"]))

    def test_dataset_and_protocol_changes_are_not_comparable(self):
        for key in ("dataset_sha256", "protocol_sha256"):
            source = local_report()
            source["evaluation"]["comparison_basis"][key] = sha256("changed")
            result = compare(source)
            self.assertEqual(result["comparison"]["summary"]["not_comparable"], 3)
            self.assertEqual(result["verdict"], "insufficient_evidence")
            self.assertTrue(all(r["delta"] is None for r in result["comparison"]["metrics"]))

    def test_older_missing_fingerprints_do_not_invent_comparability(self):
        previous = baseline()
        previous["schema_version"] = "pre-d-release-report-1.0"
        previous["modules"][0]["suites"][0].pop("comparison_basis")
        self.assertEqual(compare(previous=previous)["verdict"], "insufficient_evidence")

    def test_declared_or_non_numeric_scores_do_not_get_deltas(self):
        for trust, observed in (("declared", 1), ("verified", None)):
            previous = baseline()
            previous["modules"][0]["suites"][0]["gates"][0].update(trust=trust, observed=observed)
            result = compare(previous=previous)
            row = next(r for r in result["comparison"]["metrics"] if r["signal"] == "classification.accuracy")
            self.assertEqual(row["status"], "not_comparable")

    def test_changed_threshold_cannot_create_a_comparison_improvement(self):
        plan = manifest()
        plan["modules"][0]["suites"][0]["gates"] = default_gates("decision")
        plan["modules"][0]["suites"][0]["gates"][0]["threshold"] = 0.1
        self.assertEqual(compare(plan=plan)["comparison"]["summary"]["not_comparable"], 1)

    def test_removing_module_or_suite_is_not_a_fix(self):
        previous = baseline()
        previous["modules"].append({"id": "search", "required": True, "suites": []})
        duplicate = deepcopy(previous["modules"][0]["suites"][0])
        duplicate["id"] = "removed-pack"
        previous["modules"][0]["suites"].append(duplicate)
        result = compare(previous=previous)
        kinds = {c["kind"] for c in result["comparison"]["scope_changes"]}
        self.assertTrue({"module_removed", "suite_removed"} <= kinds)
        self.assertEqual(result["verdict"], "ship_with_conditions")

    def test_same_aggregate_scores_can_hide_case_regression(self):
        def with_error(index, version):
            source = local_report(version=version)
            rows = source["metrics"]["classification"]["case_results"]
            expected = [r["expected_label"] for r in rows]
            predicted = expected.copy()
            predicted[index] = "review"
            source["metrics"]["classification"] = classification_metrics(expected, predicted, [r["case_id"] for r in rows])
            source["metrics"]["confidence"] = annotate_confidence(confidence_metrics(expected, predicted, [0.9 + (i % 5) * 0.02 for i in range(20)], [r["case_id"] for r in rows]), NATIVE_CONFIDENCE)
            for m in source["metrics"].values():
                m["trust_status"] = "verified"
            return source
        plan = manifest()
        plan["application"]["version"] = "release-3"
        old = build_release_report(plan, {"decision-pack": {"report": with_error(2, "release-3")}}, now=NOW)
        result = compare(with_error(12, "release-4"), previous=old)
        self.assertEqual(result["comparison"]["summary"]["unchanged"], 3)
        change = result["comparison"]["case_changes"][0]
        self.assertEqual(change["regressed"], ["case-012"])
        self.assertEqual(change["improved"], ["case-002"])
        self.assertIn("release_regression", [f["code"] for f in result["findings"]])

    def test_case_rows_with_duplicate_ids_are_not_compared(self):
        previous = baseline()
        previous["modules"][0]["suites"][0]["case_outcomes"][0]["case_id"] = "case-001"
        self.assertEqual(compare(previous=previous)["comparison"]["case_changes"][0]["status"], "not_comparable")

    def test_reusing_same_execution_is_not_a_new_observation(self):
        previous = baseline()
        previous["modules"][0]["suites"][0]["run_id"] = "candidate-run"
        self.assertEqual(compare(previous=previous)["comparison"]["summary"]["not_comparable"], 3)

    def test_incomplete_baseline_cannot_supply_perfect_comparison(self):
        previous = baseline()
        previous["modules"][0]["suites"][0]["evidence_complete"] = False
        self.assertEqual(compare(previous=previous)["comparison"]["summary"]["not_comparable"], 3)

    def test_workflow_regression_preserves_failed_case_location(self):
        plan, source = manifest(), local_report()
        suite = plan["modules"][0]["suites"][0]
        suite.update(kind="workflow", minimum_cases=1)
        source["evaluation"]["required_dimensions"] = ["workflow_coverage"]
        source["execution"].update(adapter_type="browser_journey", case_count=2, scored_case_count=2, blocked_case_count=0,
                                   browser_case_diagnostics=[{"case_id": "home", "outcome": "passed"}, {"case_id": "settings", "outcome": "passed"}])
        source["metrics"] = {"workflow_coverage": {"measurement_status": "measured", "trust_status": "verified", "workflow_execution_rate": 1, "workflow_signal_match_rate": 1}}
        previous = assess(plan, source)
        source["metrics"]["workflow_coverage"]["workflow_signal_match_rate"] = 0.5
        source["execution"]["browser_case_diagnostics"][1]["outcome"] = "failed"
        result = compare(source, plan, previous)
        self.assertEqual(result["comparison"]["case_changes"][0]["regressed"], ["settings"])
        self.assertEqual(result["comparison"]["summary"]["regressed"], 1)

    def test_dependency_recommendation_accounts_for_regression_blockers(self):
        plan, source = manifest(), local_report()
        plan["modules"][0]["depends_on"] = ["engine"]
        engine = deepcopy(plan["modules"][0])
        engine.update(id="engine", depends_on=[])
        engine["suites"][0]["id"] = "engine-pack"
        plan["modules"].append(engine)
        plan["policy"] = {"regression_severity": "blocker"}
        old_engine = deepcopy(source)
        old_engine["package_id"] = "old-engine-run"
        previous = build_release_report(plan, {"decision-pack": {"report": source}, "engine-pack": {"report": old_engine}}, now=NOW)
        source["package_id"] = "new-decisions-run"
        new_engine = deepcopy(old_engine)
        new_engine["package_id"] = "new-engine-run"
        new_engine["metrics"]["confidence"]["expected_calibration_error"] = 0.08
        result = build_release_report(plan, {"decision-pack": {"report": source}, "engine-pack": {"report": new_engine}}, now=NOW, baseline=previous)
        self.assertEqual(result["modules"][0]["verdict"], "insufficient_evidence")
        self.assertEqual(result["modules"][1]["verdict"], "do_not_ship")

    def test_decision_dataset_fingerprints_bind_inputs_not_release_names(self):
        config = adapter_config(None)
        original = build_package(config)
        config["evaluation"]["subject_version"] = "release-5"
        renamed = build_package(config)
        self.assertEqual(original["evaluation"]["dataset_sha256"], renamed["evaluation"]["dataset_sha256"])
        self.assertEqual(original["evaluation"]["comparison_protocol_sha256"], renamed["evaluation"]["comparison_protocol_sha256"])
        config["dataset"]["cases"][0]["input"]["new_context"] = "not a report field"
        changed = build_package(config)
        self.assertNotEqual(original["evaluation"]["dataset_sha256"], changed["evaluation"]["dataset_sha256"])
        self.assertNotIn("not a report field", json.dumps(changed))

    def test_invalid_baselines_rejected_before_analysis(self):
        for change in ("app", "future", "gates", "nan", "duplicate", "status", "kind"):
            previous = baseline()
            if change == "app":
                previous["application"]["id"] = "other-app"
            elif change == "future":
                previous["generated_at"] = (NOW + timedelta(days=1)).isoformat()
            elif change == "gates":
                previous["modules"][0]["suites"][0]["gates"] = None
            elif change == "nan":
                previous["modules"][0]["suites"][0]["gates"][0]["observed"] = float("nan")
            elif change == "status":
                previous["modules"][0]["suites"][0]["gates"][0]["status"] = []
            elif change == "kind":
                previous["modules"][0]["suites"][0]["kind"] = []
            else:
                previous["modules"].append(deepcopy(previous["modules"][0]))
            with self.subTest(change=change), self.assertRaises(RunnerError):
                compare(previous=previous)

    def test_advanced_metrics_are_retained_but_not_falsely_trended(self):
        source, plan = local_report(), manifest()
        plan["modules"][0]["suites"][0]["gates"] = default_gates("decision") + [{"signal": "trajectory.score", "operator": "gte", "threshold": 0.9}]
        source["metrics"]["trajectory"] = {"measurement_status": "measured", "trust_status": "verified", "score": 1}
        previous = assess(plan, source)
        result = compare(source, plan, previous)
        row = next(r for r in result["comparison"]["metrics"] if r["signal"] == "trajectory.score")
        self.assertEqual(row["status"], "not_comparable")
        self.assertEqual(result["modules"][0]["suites"][0]["gates"][-1]["status"], "passed")

    def test_comparison_html_escapes_values_and_explains_scope(self):
        result = compare(previous=baseline(0.498))
        result["comparison"]["baseline_version"] = "<script>bad()</script>"
        page = render_release_report(result)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("What changed since the baseline", page)
        self.assertIn("not statistical significance", page)

    def test_history_summarizes_multi_run_trends_without_claiming_scheduling(self):
        older_plan = manifest()
        older_plan["application"]["version"] = "release-2"
        older_source = local_report(version="release-2", confidence=0.4)
        older_source["package_id"] = "history-run-1"
        older = build_release_report(
            older_plan,
            {"decision-pack": {"report": older_source}},
            now=NOW,
        )
        previous_source = local_report(version="release-3", confidence=0.498)
        previous_source["package_id"] = "history-run-2"
        previous_plan = manifest()
        previous_plan["application"]["version"] = "release-3"
        previous = build_release_report(
            previous_plan,
            {"decision-pack": {"report": previous_source}},
            now=NOW,
        )
        current_source = local_report()
        current_source["package_id"] = "candidate-run"
        current = build_release_report(
            manifest(),
            {"decision-pack": {"report": current_source, "report_sha256": sha256(current_source)}},
            now=NOW,
            history=[older, previous],
        )
        self.assertEqual(current["history"]["report_count"], 2)
        self.assertEqual(current["history"]["summary"]["improved"], 1)
        self.assertEqual(current["history"]["summary"]["unchanged"], 2)
        page = render_release_report(current)
        self.assertIn("Historical trend context", page)
        self.assertIn("not a scheduled monitor", page)


class ComparisonCliTests(unittest.TestCase):
    def test_public_fixture_executes_without_an_installed_runner_in_child_process(self):
        from examples.run_release_fixture import fixture

        with TemporaryDirectory() as directory, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            root = Path(directory)
            self.assertEqual(fixture(root, compare=True), 0)
            report = json.loads((root / "release-review.json").read_text())
            self.assertEqual(report["verdict"], "do_not_ship")
            self.assertEqual(report["comparison"]["summary"]["regressed"], 1)
            self.assertEqual(report["comparison"]["summary"]["unchanged"], 5)
            self.assertFalse(any(f["code"] == "suite_execution_failed" for f in report["findings"]))
            class Links(HTMLParser):
                def __init__(self):
                    super().__init__()
                    self.ids, self.links = set(), []

                def handle_starttag(self, tag, attrs):
                    attrs = dict(attrs)
                    if "id" in attrs:
                        self.ids.add(attrs["id"])
                    if tag == "a":
                        self.links.append(attrs.get("href", ""))

            page = Links()
            page.feed((root / "release-review.html").read_text(encoding="utf-8"))
            for link in page.links:
                if link.startswith("#"):
                    self.assertIn(link[1:], page.ids)
                else:
                    self.assertTrue(link.startswith("./"))
                    self.assertTrue((root / unquote(link)).is_file(), link)

    def test_report_regeneration_preserves_original_fingerprints(self):
        with TemporaryDirectory() as directory, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            root = Path(directory)
            package = build_package(adapter_config(None))
            for legacy in (False, True):
                if legacy:
                    package["evaluation"].pop("dataset_sha256")
                    package["evaluation"].pop("comparison_protocol_sha256")
                write(root / "package.json", package)
                self.assertEqual(main(["report", "--package", str(root / "package.json"), "--out", str(root / "regenerated.json")]), 0)
                report = json.loads((root / "regenerated.json").read_text())
                self.assertEqual(report["evaluation"]["comparison_basis"]["dataset_sha256"], package["evaluation"].get("dataset_sha256"))

    def test_bad_baseline_fails_without_running_any_adapter(self):
        with TemporaryDirectory() as directory, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), patch("esx_eval_runner.cli.run_command") as run:
            root = Path(directory)
            write(root / "manifest.json", manifest())
            write(root / "baseline.json", {"not": "a release report"})
            status = main(["release", "check", "--manifest", str(root / "manifest.json"), "--baseline", str(root / "baseline.json"), "--run", "--out", str(root / "out.json")])
            self.assertEqual(status, 1)
            run.assert_not_called()
            self.assertFalse((root / "out.json").exists())

    def test_baseline_cannot_be_overwritten(self):
        with TemporaryDirectory() as directory, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            root = Path(directory)
            previous = baseline()
            previous["generated_at"] = datetime.now(timezone.utc).isoformat()
            write(root / "manifest.json", manifest())
            write(root / "baseline.json", previous)
            original = (root / "baseline.json").read_bytes()
            self.assertEqual(main(["release", "check", "--manifest", str(root / "manifest.json"), "--baseline", str(root / "baseline.json"), "--out", str(root / "baseline.json")]), 1)
            self.assertEqual((root / "baseline.json").read_bytes(), original)

    def test_two_actual_adapter_versions_compare_locally(self):
        with TemporaryDirectory() as directory, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            root = Path(directory)
            plan = manifest()
            suite = plan["modules"][0]["suites"][0]
            suite["config"] = "adapter.json"
            suite.pop("report")
            for version, confidence, output in (("release-3", 0.498, "baseline"), ("release-4", None, "candidate")):
                config = adapter_config(confidence)
                config["evaluation"]["subject_version"] = version
                plan["application"]["version"] = version
                write(root / "adapter.json", config)
                write(root / "manifest.json", plan)
                args = ["release", "check", "--manifest", str(root / "manifest.json"), "--run", "--out", str(root / f"{output}.json")]
                if output == "candidate":
                    args += ["--baseline", str(root / "baseline.json"), "--require-ship"]
                self.assertEqual(main(args), 0)
            result = json.loads((root / "candidate.json").read_text())
            self.assertEqual(result["comparison"]["summary"]["improved"], 1)
            self.assertEqual(result["comparison"]["summary"]["not_comparable"], 0)
            self.assertEqual(result["verdict"], "ship")
            self.assertNotIn("example_index", json.dumps(result))

    def test_release_check_accepts_history_reports(self):
        with TemporaryDirectory() as directory, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            root = Path(directory)
            plan = manifest()
            suite = plan["modules"][0]["suites"][0]
            suite["config"] = "adapter.json"
            suite.pop("report")
            for version, confidence, output in (
                ("release-2", 0.4, "history-1"),
                ("release-3", 0.498, "history-2"),
                ("release-4", None, "candidate"),
            ):
                config = adapter_config(confidence)
                config["evaluation"]["subject_version"] = version
                plan["application"]["version"] = version
                write(root / "adapter.json", config)
                write(root / "manifest.json", plan)
                args = ["release", "check", "--manifest", str(root / "manifest.json"), "--run", "--out", str(root / f"{output}.json")]
                if output == "candidate":
                    args += [
                        "--history", str(root / "history-1.json"),
                        "--history", str(root / "history-2.json"),
                    ]
                self.assertEqual(main(args), 0)
            result = json.loads((root / "candidate.json").read_text())
            self.assertEqual(result["history"]["report_count"], 2)
            self.assertEqual(result["history"]["summary"]["improved"], 1)


if __name__ == "__main__":
    unittest.main()
