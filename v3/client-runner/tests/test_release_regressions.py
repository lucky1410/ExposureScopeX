"""Regression cases for coverage honesty, persisted metadata, and history order."""

from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
from datetime import timedelta
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from esx_eval_runner.cli import main
from esx_eval_runner.release import build_release_report, validate_manifest
from esx_eval_runner.release_coverage import plan_requirement_issues
from esx_eval_runner.release_execution import load_plan, workflow_signal_strength
from esx_eval_runner.release_html import render_release_report
from esx_eval_runner.runner import _browser_execution_summary
from test_release import NOW, adapter_config, assess, local_report, manifest, workflow_report, write


def workflow_manifest():
    plan = manifest()
    plan["modules"][0]["suites"][0].update(kind="workflow", subject_id="application-ui")
    return plan


def workflow_case(*steps, case_id="browser-000"):
    return {"case_id": case_id, "expected_label": "pass", "input": {"journey": list(steps)}}


def review_workflow(source=None, metadata=None):
    return build_release_report(
        workflow_manifest(), {"decision-pack": {"report": source or workflow_report()}},
        now=NOW, plan_metadata=metadata,
    )


class PopulationRegressionTests(unittest.TestCase):
    def test_partial_class_population_survives_manifest_reload(self):
        plan = manifest()
        plan["modules"][0]["suites"][0]["population"] = {
            "available_case_count": 100, "class_counts": {"allow": 40, "review": 30},
        }
        normalized = validate_manifest(plan)
        self.assertEqual(validate_manifest(normalized), normalized)
        result = assess(normalized)
        self.assertEqual(result["modules"][0]["suites"][0]["population_coverage"]["unclassified_case_count"], 30)

    def test_inconsistent_population_does_not_display_more_than_full_coverage(self):
        for population in (
            {"available_case_count": 10},
            {"available_case_count": 100, "class_counts": {"allow": 5, "review": 95}},
        ):
            with self.subTest(population=population):
                plan = manifest()
                plan["modules"][0]["suites"][0]["population"] = population
                result = assess(plan)
                coverage = result["modules"][0]["suites"][0]["population_coverage"]
                self.assertEqual(coverage["status"], "inconsistent_population")
                self.assertIsNone(coverage["sample_fraction"])
                self.assertIn("population_context_inconsistent", {a["code"] for a in result["advisories"]})
                self.assertIn("inconsistent", render_release_report(result).lower())


class CoverageRegressionTests(unittest.TestCase):
    def test_blocked_suites_keep_their_dimension_and_population_inventory(self):
        result = build_release_report(manifest(), {}, now=NOW, plan_metadata={
            "decision-pack": {"required_dimensions": ["classification", "confidence"]},
        })
        suite = result["modules"][0]["suites"][0]
        dimensions = {item["dimension"]: item for item in suite["dimension_coverage"]}
        self.assertEqual(dimensions["classification"]["measurement_status"], "not_measured")
        self.assertEqual(dimensions["decision_evidence"]["policy_status"], "not_requested")
        self.assertEqual(result["population_coverage"]["missing_population_suite_count"], 1)
        self.assertIn("baseline_dimension_unexercised", {a["code"] for a in result["advisories"]})

    def test_unavailable_plan_does_not_invent_which_dimensions_were_requested(self):
        result = build_release_report(manifest(), {}, now=NOW)
        dimensions = {item["dimension"]: item for item in result["modules"][0]["suites"][0]["dimension_coverage"]}
        self.assertEqual(dimensions["decision_evidence"]["policy_status"], "request_unknown")

    def test_partial_execution_is_blocked_in_review_scope(self):
        result = review_workflow(workflow_report(executed=1, blocked=1))
        self.assertEqual(result["modules"][0]["review_status"], "blocked")

    def test_one_executed_suite_does_not_hide_another_missing_suite_of_same_kind(self):
        plan = manifest()
        second = deepcopy(plan["modules"][0]["suites"][0])
        second.update(id="missing-pack", report="missing.json")
        plan["modules"][0]["suites"].append(second)
        self.assertEqual(assess(plan)["modules"][0]["review_status"], "blocked")

    def test_manual_evaluated_note_does_not_claim_pre_d_execution(self):
        plan = manifest()
        plan["modules"].append({"id": "manual", "suites": [], "review_methods": [{
            "id": "external-review", "label": "External test review", "status": "evaluated",
            "summary": "Reviewed an external test result.",
        }]})
        result = assess(plan)
        self.assertEqual(result["modules"][1]["review_status"], "inspected")
        self.assertEqual(result["review_scope"]["evaluated"], 1)

    def test_malformed_classification_is_a_gap_instead_of_an_exception(self):
        for malformed in (None, [], "unavailable"):
            with self.subTest(malformed=malformed):
                source = local_report()
                source["metrics"]["classification"] = malformed
                result = assess(report=source)
                self.assertEqual(result["verdict"], "insufficient_evidence")


class WorkflowSignalRegressionTests(unittest.TestCase):
    def test_text_wait_is_accepted_by_both_plan_and_objective_validation(self):
        case = workflow_case({"type": "goto", "path": "/"}, {"type": "wait_for_text", "value": "Ready"})
        config = adapter_config(None)
        config["evaluation"].update(required_dimensions=["workflow_coverage"])
        config["adapter"] = {"type": "browser_journey", "base_url": "http://127.0.0.1:3000"}
        config["dataset"]["cases"] = [case]
        with TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            write(path, config)
            load_plan(path, {"id": "sample-app", "version": "release-4"})
        module = {"id": "ui", "test_requirements": [{"id": "visible", "kind": "workflow", "bindings": [{
            "suite_id": "ui-pack", "case_ids": [case["case_id"]],
        }]}]}
        self.assertEqual(plan_requirement_issues(module, {"ui-pack": [case]}), [])

    def test_hidden_or_attached_elements_do_not_prove_visible_content(self):
        for kind in ("wait_for_selector", "expect_visible"):
            for state in ("attached", "hidden", "detached"):
                with self.subTest(kind=kind, state=state):
                    summary = workflow_signal_strength([workflow_case({"type": kind, "selector": "#spinner", "state": state})])
                    self.assertEqual(summary["content_signal_count"], 0)
                    self.assertEqual(summary["cases"][0]["signal_strength"], "element_state_only")

    def test_content_before_later_navigation_does_not_prove_destination_content(self):
        summary = workflow_signal_strength([workflow_case(
            {"type": "expect_text", "value": "Login"},
            {"type": "goto", "path": "/dashboard"},
            {"type": "assert_path", "path": "/dashboard"},
        )])
        self.assertEqual(summary["content_signal_count"], 0)
        self.assertEqual(summary["route_signal_only_count"], 1)

    def test_navigation_alone_is_not_mislabeled_as_a_route_assertion(self):
        summary = workflow_signal_strength([workflow_case({"type": "goto", "path": "/"})])
        self.assertEqual(summary["route_signal_only_count"], 0)
        self.assertEqual(summary["cases"][0]["signal_strength"], "no_explicit_signal")

    def test_title_only_case_is_warned_about_in_a_mixed_strength_suite(self):
        cases = [workflow_case({"type": "assert_title", "value": "Application"}),
                 workflow_case({"type": "expect_text", "value": "Settings"}, case_id="browser-001")]
        result = review_workflow(metadata={"decision-pack": {"workflow_signal_strength": workflow_signal_strength(cases)}})
        self.assertIn("workflow_title_only_signal", {a["code"] for a in result["advisories"]})

    def test_plan_assertions_are_not_described_as_executed_on_blocked_cases(self):
        cases = [workflow_case({"type": "assert_path", "path": "/"}, case_id="blocked-000")]
        result = review_workflow(workflow_report(executed=0, blocked=1), {
            "decision-pack": {"workflow_signal_strength": workflow_signal_strength(cases)},
        })
        self.assertNotIn("1 executed workflow case(s)", render_release_report(result))

    def test_signal_metadata_survives_report_reuse_without_exposing_page_content(self):
        cases = [workflow_case({"type": "expect_text", "value": "SECRET_PAGE_TEXT"},
                               {"type": "goto", "path": "/private-route"},
                               {"type": "assert_path", "path": "/private-route"})]
        response = {"browser_diagnostics": [{"case_id": "browser-000", "coverage_scope": "pre_auth",
                    "outcome": "passed", "session_status": "not_requested", "steps": []}]}
        execution = _browser_execution_summary(response, cases)
        self.assertIn("workflow_signal_strength", execution)
        self.assertNotIn("SECRET_PAGE_TEXT", str(execution))
        self.assertNotIn("/private-route", str(execution))
        source = workflow_report(executed=1)
        source["execution"].update(execution)
        result = review_workflow(source)
        self.assertIn("workflow_route_only_signal", {a["code"] for a in result["advisories"]})

    def test_legacy_report_explicitly_discloses_unknown_assertion_strength(self):
        result = review_workflow()
        self.assertIn("workflow_signal_unknown", {a["code"] for a in result["advisories"]})

    def test_mocked_browser_run_preserves_advisory_through_cli_report_reuse(self):
        config = adapter_config(None)
        config["evaluation"].update(agent_id="application-ui", required_dimensions=["workflow_coverage"])
        config["adapter"] = {"type": "browser_journey", "base_url": "http://127.0.0.1:3000"}
        config["dataset"]["cases"] = [workflow_case({"type": "goto", "path": "/"}, {"type": "assert_path", "path": "/"})]
        response = {
            "results": [{"case_id": "browser-000", "predicted_label": "pass"}],
            "browser_diagnostics": [{"case_id": "browser-000", "coverage_scope": "pre_auth", "outcome": "passed",
                                     "session_status": "not_required", "steps": [{"action": "assert_path", "status": "passed"}]}],
        }
        with TemporaryDirectory() as directory, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            root = Path(directory)
            write(root / "plan.json", config)
            with patch("esx_eval_runner.browser.invoke_browser_journeys", return_value=(response, 12, "a" * 64, "b" * 64)):
                self.assertEqual(main(["run", "--config", str(root / "plan.json"), "--out", str(root / "run.json")]), 0)
            plan = workflow_manifest()
            plan["modules"][0]["suites"][0]["report"] = "run.local-report.json"
            write(root / "release.json", plan)
            self.assertEqual(main(["release", "check", "--manifest", str(root / "release.json"), "--out", str(root / "review.json")]), 0)
            result = json.loads((root / "review.json").read_text(encoding="utf-8"))
            self.assertEqual(result["execution_review"]["reused_report_count"], 1)
            self.assertIn("workflow_route_only_signal", {a["code"] for a in result["advisories"]})
            self.assertIn("planned workflow case(s)", (root / "review.html").read_text(encoding="utf-8"))


class HistoryRegressionTests(unittest.TestCase):
    def history_report(self, version, run_id, confidence, timestamp):
        plan = manifest()
        plan["application"]["version"] = version
        source = local_report(version=version, confidence=confidence)
        source["package_id"] = run_id
        result = build_release_report(plan, {"decision-pack": {"report": source}}, now=NOW)
        result["generated_at"] = timestamp
        return result

    def test_history_uses_actual_timestamp_order_across_timezones(self):
        older = self.history_report("old", "old-run", 0.4, "2026-09-18T20:00:00+12:00")
        newer = self.history_report("new", "new-run", 0.7, "2026-09-18T12:00:00+00:00")
        current = build_release_report(manifest(), {"decision-pack": {"report": local_report()}},
                                       now=NOW, history=[newer, older])
        row = next(r for r in current["history"]["metrics"] if r["signal"] == "confidence.expected_calibration_error")
        self.assertEqual(row["latest_previous_version"], "new")
        self.assertAlmostEqual(row["latest_previous"], 0.3)

    def test_regenerated_history_reports_do_not_count_same_execution_twice(self):
        original = self.history_report("previous", "same-run", 0.7, (NOW - timedelta(hours=2)).isoformat())
        regenerated = deepcopy(original)
        regenerated["generated_at"] = (NOW - timedelta(hours=1)).isoformat()
        current = build_release_report(manifest(), {"decision-pack": {"report": local_report()}},
                                       now=NOW, history=[original, regenerated])
        self.assertTrue(all(r["comparable_history_count"] == 1 for r in current["history"]["metrics"]))

    def test_malformed_history_identifiers_are_not_comparable(self):
        for field in ("run_id", "report_sha256"):
            with self.subTest(field=field):
                previous = self.history_report("previous", "previous-run", 0.7, NOW.isoformat())
                previous["modules"][0]["suites"][0][field] = ["invalid"]
                result = build_release_report(manifest(), {"decision-pack": {"report": local_report()}}, now=NOW, history=[previous])
                self.assertTrue(all(row["status"] == "not_comparable" for row in result["history"]["metrics"]))


if __name__ == "__main__":
    unittest.main()
