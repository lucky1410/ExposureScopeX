"""Application breadth is demonstrated by bound outcomes, never module counts."""

from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from esx_eval_runner.release import build_release_report, default_gates, validate_manifest
from esx_eval_runner.release_coverage import draft_requirements, evaluate_requirements, plan_requirement_issues
from esx_eval_runner.release_execution import load_plan, preflight_all_modules
from esx_eval_runner.release_html import render_release_report
from esx_eval_runner.runner import RunnerError
from test_release import NOW, adapter_config, assess, local_report, manifest, write
from test_release_execution import attach, call, initialize


def objective(**extra):
    return {"id": "correct-decision", "kind": "decision", "category": "happy_path",
            "description": "Match the reviewed expected decision.", "bindings": [{"suite_id": "decision-pack",
            "case_ids": ["case-000"], "assertion": "Returned label matches the reviewed dataset label."}], **extra}


def scoped_manifest():
    plan = manifest()
    plan["modules"][0].update(required_kinds=["decision"], test_requirements=[objective()])
    return plan


class RequirementTests(unittest.TestCase):
    def test_generated_scope_is_unbound_not_fake_test_coverage(self):
        rows = draft_requirements(["decision", "workflow"], ["analyst", "read-only"], ["knowledge"])
        self.assertEqual(len(rows), 12)
        self.assertTrue(all(r["bindings"] == [] for r in rows))
        self.assertEqual(len({r["id"] for r in rows}), 12)
        self.assertEqual({r["persona"] for r in rows if "persona" in r}, {"analyst", "read-only"})

    def test_requirement_validation_is_idempotent_and_does_not_mutate(self):
        source = scoped_manifest()
        old = deepcopy(source)
        normalized = validate_manifest(source)
        self.assertEqual(normalized, validate_manifest(normalized))
        self.assertEqual(source, old)

    def test_invalid_scope_or_binding_is_rejected(self):
        for change in ({"kind": "anything"}, {"category": "unknown"}, {"persona": "analyst"},
                       {"dependency": "unlisted"}, {"category": "integration"}, {"bindings": "bad"},
                       {"bindings": [{"suite_id": "missing-suite", "case_ids": ["case-000"], "assertion": "test"}]},
                       {"bindings": [{"suite_id": "decision-pack", "case_ids": ["case-000", "case-000"], "assertion": "test"}]},
                       {"bindings": [{"suite_id": "decision-pack", "case_ids": ["case-000"], "assertion": ""}]},
                       {"bindings": [{"suite_id": "decision-pack", "case_ids": ["\n"], "assertion": "test"}]}):
            with self.subTest(change=change):
                plan = scoped_manifest()
                plan["modules"][0]["test_requirements"][0].update(change)
                with self.assertRaises(RunnerError):
                    validate_manifest(plan)

    def test_complete_matching_case_satisfies_objective(self):
        result = assess(scoped_manifest())
        self.assertEqual(result["verdict"], "ship")
        self.assertEqual(result["test_coverage"]["passed"], 1)
        self.assertEqual(result["modules"][0]["test_requirements"][0]["basis"], "reviewer_mapped_case_outcomes")

    def test_missing_objective_binding_cannot_pass(self):
        plan = scoped_manifest()
        plan["modules"][0]["test_requirements"][0]["bindings"] = []
        result = assess(plan)
        self.assertEqual(result["verdict"], "insufficient_evidence")
        self.assertEqual(result["test_coverage"]["missing"], 1)

    def test_selected_failure_is_not_hidden_by_passing_aggregate(self):
        source = local_report()
        source["metrics"]["classification"]["case_results"][0]["correct"] = False
        result = assess(scoped_manifest(), source)
        self.assertEqual(result["verdict"], "do_not_ship")
        self.assertEqual(result["test_coverage"]["failed"], 1)
        self.assertIn("requirement_failed", [f["code"] for f in result["findings"]])

    def test_partial_duplicate_or_unknown_case_ledger_cannot_pass(self):
        for modification in ("partial", "duplicate", "wrong-id", "invalid"):
            with self.subTest(modification=modification):
                source = local_report()
                rows = source["metrics"]["classification"]["case_results"]
                if modification == "partial":
                    rows.pop()
                elif modification == "duplicate":
                    rows[-1]["case_id"] = rows[0]["case_id"]
                elif modification == "invalid":
                    rows[-1]["correct"] = "true"
                else:
                    rows[0]["case_id"] = "unknown"
                result = assess(scoped_manifest(), source)
                self.assertEqual(result["test_coverage"]["missing"], 1)
                self.assertEqual(result["verdict"], "insufficient_evidence")

    def test_workflow_persona_and_blocked_status_are_checked(self):
        module = {"test_requirements": [objective(kind="workflow", persona="analyst")]}
        for outcome, persona, expected in (("passed", "analyst", "passed"), ("failed", "analyst", "failed"),
                                           ("blocked", "analyst", "incomplete"), ("passed", "admin", "missing")):
            with self.subTest(outcome=outcome, persona=persona):
                suites = [{"id": "decision-pack", "requested_cases": 1, "executed_cases": 0 if outcome == "blocked" else 1,
                           "case_outcomes": [{"case_id": "case-000", "outcome": outcome, "persona": persona}]}]
                self.assertEqual(evaluate_requirements(module, suites)[0]["status"], expected)

    def test_declared_dependency_is_not_integration_evidence(self):
        plan = scoped_manifest()
        plan["modules"].append({"id": "knowledge", "suites": []})
        plan["modules"][0]["depends_on"] = ["knowledge"]
        result = assess(plan)
        self.assertEqual(result["modules"][0]["dependency_coverage"][0]["status"], "declared_only")
        self.assertIn("dependency_path_untested", [f["code"] for f in result["findings"]])
        self.assertIn("declared only", render_release_report(result))

    def test_integration_binding_is_labelled_as_mapped_cases_not_observed_topology(self):
        plan = scoped_manifest()
        plan["modules"].append({"id": "knowledge", "suites": []})
        plan["modules"][0]["depends_on"] = ["knowledge"]
        plan["modules"][0]["test_requirements"][0].update(category="integration", dependency="knowledge")
        result = assess(plan)
        self.assertEqual(result["modules"][0]["dependency_coverage"][0]["status"], "mapped_cases_passed")
        self.assertEqual(result["verdict"], "insufficient_evidence")  # dependency itself remains untested

    def test_html_escapes_reviewed_assertions_and_exposes_depth(self):
        plan = scoped_manifest()
        plan["modules"][0]["test_requirements"][0]["bindings"][0]["assertion"] = "<script>alert(1)</script>"
        page = render_release_report(assess(plan))
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("1 / 1 declared test objectives passed", page)
        self.assertIn("reviewer-mapped", page)

    def test_custom_thresholds_are_visible(self):
        plan = scoped_manifest()
        gates = default_gates("decision")
        gates[0]["threshold"] = 0.7
        plan["modules"][0]["suites"][0]["gates"] = gates
        result = assess(plan)
        self.assertFalse(result["modules"][0]["suites"][0]["policy_disclosure"]["matches_defaults"])
        page = render_release_report(result)
        self.assertIn("Custom release thresholds", page)
        self.assertIn("gte 0.7", page)
        self.assertIn("gte 0.95", page)

    def test_single_class_observed_failures_remain_blocking_without_promoting_trust(self):
        source = local_report()
        metric = source["metrics"]["classification"]
        metric.update(measurement_status="not_measurable", trust_status="missing")
        for row in metric["case_results"]:
            row["correct"] = False
        source["evaluation"]["dataset_health"]["class_count"] = 1
        original = deepcopy(source)
        result = assess(manifest(), source)
        self.assertEqual(result["verdict"], "do_not_ship")
        suite = result["modules"][0]["suites"][0]
        self.assertEqual(suite["decision_observation"]["incorrect_cases"], 20)
        self.assertEqual(suite["gates"][0]["status"], "missing")
        self.assertEqual(source, original)
        self.assertIn("0 correct / 20 incorrect", render_release_report(result))

    def test_changed_objectives_are_not_silent_regression_improvement(self):
        baseline = assess(scoped_manifest())
        plan = scoped_manifest()
        plan["modules"][0]["test_requirements"][0]["bindings"][0]["case_ids"] = ["case-001"]
        source = local_report()
        source["package_id"] = "new-run"
        result = build_release_report(plan, {"decision-pack": {"report": source}}, now=NOW, baseline=baseline)
        self.assertIn("test_objectives_changed", [c["kind"] for c in result["comparison"]["scope_changes"]])


class AuthoringTests(unittest.TestCase):
    def test_scope_bind_and_run_end_to_end_without_editing_manifest(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = initialize(root)
            config = attach(root)
            self.assertEqual(call("release", "scope", "--manifest", str(path), "--module", "decisions", "--profile", "decision", "--replace"), 0)
            self.assertEqual(call("release", "preflight", "--manifest", str(path), "--out", str(root / "pre.json")), 2)
            data = json.loads(config.read_text())
            ids = [c["case_id"] for c in data["dataset"]["cases"]]
            for name, selected in (("happy-path", ids[::2]), ("negative-path", ids[1::2]), ("boundary", ids[-2:])):
                args = ["release", "bind", "--manifest", str(path), "--module", "decisions", "--requirement", "decision-" + name,
                        "--suite-id", "decisions-pack", "--assertion", "Compare returned labels with the synthetic fixture's reviewed expectations."]
                for case in selected:
                    args += ["--case-id", case]
                self.assertEqual(call(*args), 0)
            self.assertEqual(call("release", "run", "--manifest", str(path), "--out", str(root / "review.json"), "--require-ship"), 0)
            report = json.loads((root / "review.json").read_text())
            self.assertEqual(report["test_coverage"]["passed"], 3)
            self.assertTrue(report["execution_review"]["all_test_objectives_passed"])

    def test_unconfirmed_test_depth_blocks_all_module_run(self):
        with TemporaryDirectory() as directory, patch("esx_eval_runner.cli.run_command") as run:
            root = Path(directory)
            path = initialize(root)
            attach(root)
            data = json.loads(path.read_text())
            data["modules"][0].pop("test_requirements")
            write(path, data)
            self.assertEqual(call("release", "run", "--manifest", str(path), "--out", str(root / "review.json")), 2)
            run.assert_not_called()
            report = json.loads((root / "review.json").read_text())
            self.assertFalse(report["execution_review"]["test_requirements_confirmed"])

    def test_invalid_binding_and_unapproved_replace_preserve_manifest(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = initialize(root)
            attach(root)
            original = path.read_bytes()
            self.assertEqual(call("release", "scope", "--manifest", str(path), "--module", "decisions", "--profile", "mixed"), 1)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(call("release", "bind", "--manifest", str(path), "--module", "decisions", "--requirement", "decision-correctness",
                                  "--suite-id", "decisions-pack", "--case-id", "nonexistent", "--assertion", "Review outcome.", "--replace"), 1)
            self.assertEqual(path.read_bytes(), original)

    def test_navigation_alone_is_rejected_before_target_calls(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = adapter_config(None)
            config["adapter"] = {"type": "browser_journey", "base_url": "http://127.0.0.1:3000"}
            config["evaluation"]["required_dimensions"] = ["workflow_coverage"]
            config["dataset"]["cases"] = [{"case_id": "open-page", "expected_label": "pass", "input": {"journey": [{"type": "goto", "path": "/"}]}}]
            write(root / "plan.json", config)
            with self.assertRaisesRegex(RunnerError, "explicit"):
                load_plan(root / "plan.json", {"id": "sample-app", "version": "release-4"})

    def test_wrong_persona_is_a_preflight_issue(self):
        module = {"id": "workspace", "test_requirements": [objective(kind="workflow", persona="analyst")]}
        issues = plan_requirement_issues(module, {"decision-pack": [{"case_id": "case-000", "persona": "admin"}]})
        self.assertEqual(issues[0]["code"], "requirement_persona_mismatch")
