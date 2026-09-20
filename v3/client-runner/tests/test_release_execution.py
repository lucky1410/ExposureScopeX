"""Whole-inventory execution is fresh, explicit, and never a partial success."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from esx_eval_runner.audit import verify_audit_log
from esx_eval_runner.cli import main
from esx_eval_runner.release import validate_manifest
from esx_eval_runner.release_execution import preflight_all_modules
from esx_eval_runner.runner import RunnerError, sha256
from test_release import adapter_config, local_report, manifest, write


def call(*args):
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        return main(list(args))


def initialize(root, modules=("decisions",), *, complete=True, version="release-4"):
    args = ["release", "init", "--application-id", "sample-app", "--subject-version", version,
            "--out", str(root / "release.json")]
    for module in modules:
        args += ["--module", module]
    if complete:
        args += ["--inventory-complete"]
    assert call(*args) == 0
    return root / "release.json"


def attach(root, module="decisions", *, confidence=None, version="release-4", suite=None, replace=False):
    suite = suite or module + "-pack"
    config = adapter_config(confidence)
    config["evaluation"].update(agent_id=module, subject_version=version)
    path = root / module / "plan.json"
    write(path, config)
    args = ["release", "attach", "--manifest", str(root / "release.json"), "--module", module,
            "--suite-id", suite, "--config", str(path), "--read-only"]
    assert call(*args, *(["--replace"] if replace else [])) == 0
    plan = json.loads((root / "release.json").read_text())
    selected = next(m for m in plan["modules"] if m["id"] == module)
    if not selected.get("test_requirements"):
        selected["test_requirements"] = [{"id": "decision-correctness", "kind": "decision", "category": "happy_path",
            "description": "Match the synthetic fixture's reviewed labels.", "bindings": [{"suite_id": suite,
            "case_ids": [c["case_id"] for c in config["dataset"]["cases"]], "assertion": "Compare every returned label with its fixture label."}]}]
        write(root / "release.json", plan)
    return path


class WholeInventoryTests(unittest.TestCase):
    def test_fifteen_modules_all_execute_fresh_then_compare_an_actual_rerun(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            names = [f"module-{i:02d}" for i in range(15)]
            path = initialize(root, names)
            for name in names:
                attach(root, name)
            self.assertEqual(call("release", "preflight", "--manifest", str(path), "--out", str(root / "preflight.json")), 0)
            preflight = json.loads((root / "preflight.json").read_text())
            self.assertEqual(preflight["ready_module_count"], 15)
            self.assertEqual(preflight["planned_case_count"], 300)
            self.assertFalse(preflight["target_calls_made"])
            for name in ("baseline", "candidate"):
                args = ["release", "run", "--manifest", str(path), "--out", str(root / f"{name}.json"), "--require-ship"]
                if name == "candidate":
                    args += ["--baseline", str(root / "baseline.json")]
                self.assertEqual(call(*args), 0)
            result = json.loads((root / "candidate.json").read_text())
            execution = result["execution_review"]
            self.assertTrue(execution["all_modules_executed"])
            self.assertEqual(execution["suite_attempt_count"], 15)
            self.assertEqual(execution["modules_fully_executed_here"], 15)
            self.assertEqual(execution["reused_report_count"], 0)
            self.assertEqual(execution["not_fully_executed_module_ids"], [])
            self.assertTrue(execution["baseline_comparison_performed"])
            self.assertEqual(result["comparison"]["summary"]["unchanged"], 45)
            run_ids = [s["run_id"] for m in result["modules"] for s in m["suites"]]
            self.assertEqual(len(set(run_ids)), 15)
            self.assertEqual(verify_audit_log(root / "candidate.audit.jsonl")["status"], "valid")
            page = (root / "candidate.html").read_text(encoding="utf-8")
            self.assertIn("15 of 15 modules fully executed", page)
            self.assertIn("Existing reports reused: 0", page)

    def test_missing_seventh_module_prevents_any_partial_run(self):
        with TemporaryDirectory() as directory, patch("esx_eval_runner.cli.run_command") as run:
            root = Path(directory)
            path = initialize(root, [f"module-{i}" for i in range(7)])
            for i in range(6):
                attach(root, f"module-{i}")
            self.assertEqual(call("release", "run", "--manifest", str(path), "--out", str(root / "review.json")), 2)
            run.assert_not_called()
            report = json.loads((root / "review.json").read_text())
            execution = report["execution_review"]
            self.assertEqual(execution["suite_attempt_count"], 0)
            self.assertFalse(execution["all_modules_executed"])
            self.assertIn("module_has_no_plans", [i["code"] for i in execution["preflight"]["issues"]])
            self.assertIn("Preflight blocked: no suites were started", (root / "review.html").read_text(encoding="utf-8"))

    def test_excluded_module_cannot_be_called_whole_application(self):
        with TemporaryDirectory() as directory, patch("esx_eval_runner.cli.run_command") as run:
            root = Path(directory)
            path = initialize(root)
            attach(root)
            plan = json.loads(path.read_text())
            plan["modules"].append({"id": "external-actions", "required": False, "exclusion_reason": "No isolated tenant"})
            write(path, plan)
            self.assertEqual(call("release", "run", "--manifest", str(path), "--out", str(root / "review.json")), 2)
            run.assert_not_called()

    def test_preflight_requires_complete_inventory_and_both_declared_test_kinds(self):
        with TemporaryDirectory() as directory, patch("esx_eval_runner.cli.run_command") as run:
            root = Path(directory)
            path = initialize(root, complete=False)
            config = attach(root)
            self.assertEqual(call("release", "attach", "--manifest", str(path), "--module", "decisions", "--suite-id", "decisions-pack", "--config", str(config), "--read-only", "--replace", "--require-kind", "workflow"), 0)
            self.assertEqual(call("release", "preflight", "--manifest", str(path), "--out", str(root / "preflight.json")), 2)
            codes = {i["code"] for i in json.loads((root / "preflight.json").read_text())["issues"]}
            self.assertTrue({"inventory_unconfirmed", "required_kind_missing"} <= codes)
            run.assert_not_called()

    def test_preflight_reports_non_blocking_coverage_advisories(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = initialize(root)
            attach(root)
            self.assertEqual(call("release", "preflight", "--manifest", str(path), "--out", str(root / "preflight.json")), 0)
            preflight = json.loads((root / "preflight.json").read_text())
            self.assertEqual(preflight["status"], "ready")
            self.assertEqual(
                {item["code"] for item in preflight["advisories"]},
                {"baseline_dimension_unexercised", "population_context_missing"},
            )

    def test_existing_report_is_not_fresh_execution(self):
        with TemporaryDirectory() as directory, patch("esx_eval_runner.cli.run_command") as run:
            root = Path(directory)
            plan = manifest()
            plan["modules"][0]["required_kinds"] = ["decision"]
            write(root / "release.json", plan)
            source = local_report()
            source["run_provenance"]["issued_at"] = datetime.now(timezone.utc).isoformat()
            write(root / "decision.local-report.json", source)
            for command, expected_status in (("run", 2), ("check", 0)):
                self.assertEqual(call("release", command, "--manifest", str(root / "release.json"), "--out", str(root / f"{command}.json")), expected_status)
            run.assert_not_called()
            report = json.loads((root / "check.json").read_text())
            execution = report["execution_review"]
            self.assertEqual(execution["modules_with_execution_evidence"], 1)
            self.assertEqual(execution["modules_fully_executed_here"], 0)
            self.assertEqual(execution["reused_report_count"], 1)
            self.assertFalse(execution["all_modules_executed"])

    def test_changed_plan_needs_new_execution_approval(self):
        with TemporaryDirectory() as directory, patch("esx_eval_runner.cli.run_command") as run:
            root = Path(directory)
            path = initialize(root)
            config_path = attach(root)
            config = json.loads(config_path.read_text())
            config["adapter"]["command"][-1] += "\n# changed adapter invocation"
            write(config_path, config)
            self.assertEqual(call("release", "run", "--manifest", str(path), "--out", str(root / "review.json")), 2)
            run.assert_not_called()
            issues = json.loads((root / "review.json").read_text())["execution_review"]["preflight"]["issues"]
            self.assertIn("execution_not_approved", [i["code"] for i in issues])

    def test_later_invalid_plan_prevents_earlier_adapter_call(self):
        with TemporaryDirectory() as directory, patch("esx_eval_runner.cli.run_command") as run:
            root = Path(directory)
            path = initialize(root, ["first", "last"])
            attach(root, "first")
            last = attach(root, "last")
            write(last, {"invalid": True})
            self.assertEqual(call("release", "run", "--manifest", str(path), "--out", str(root / "review.json")), 2)
            run.assert_not_called()

    def test_failure_does_not_skip_remaining_modules_or_claim_complete(self):
        from esx_eval_runner.cli import run_command as real_run

        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = initialize(root, ["broken", "healthy"])
            attach(root, "broken")
            attach(root, "healthy")

            def dispatch(args):
                if Path(args.config).parent.name == "broken":
                    raise RunnerError("Synthetic transport failure")
                return real_run(args)

            with patch("esx_eval_runner.cli.run_command", side_effect=dispatch) as run:
                self.assertEqual(call("release", "run", "--manifest", str(path), "--out", str(root / "review.json")), 2)
                self.assertEqual(run.call_count, 2)
            report = json.loads((root / "review.json").read_text())
            self.assertEqual(report["execution_review"]["modules_fully_executed_here"], 1)
            self.assertEqual(report["execution_review"]["not_fully_executed_module_ids"], ["broken"])
            self.assertEqual(report["modules"][1]["verdict"], "ship")

    def test_fully_executed_does_not_mean_passed_quality_gates(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = initialize(root)
            attach(root, confidence=0.498)
            self.assertEqual(call("release", "run", "--manifest", str(path), "--out", str(root / "review.json"), "--require-ship"), 2)
            report = json.loads((root / "review.json").read_text())
            self.assertTrue(report["execution_review"]["all_modules_executed"])
            self.assertEqual(report["verdict"], "do_not_ship")

    def test_mixed_module_dispatches_both_browser_and_decision_plans(self):
        from esx_eval_runner.cli import run_command as real_run

        for blocked in (False, True):
            with self.subTest(blocked=blocked), TemporaryDirectory() as directory:
                root = Path(directory)
                path = initialize(root)
                attach(root)
                config = adapter_config(None)
                config["evaluation"].update(agent_id="application-ui", required_dimensions=["workflow_coverage"])
                config["adapter"] = {"type": "browser_journey", "base_url": "http://127.0.0.1:3000"}
                config["dataset"]["cases"] = [{"case_id": "dashboard", "expected_label": "pass", "input": {
                    "journey": [{"type": "goto", "path": "/dashboard"}, {"type": "expect_text", "value": "Dashboard", "exact": True}]}}]
                browser_path = root / "browser" / "plan.json"
                write(browser_path, config)
                self.assertEqual(call("release", "attach", "--manifest", str(path), "--module", "decisions", "--suite-id", "browser-pack", "--config", str(browser_path), "--read-only"), 0)
                plan = json.loads(path.read_text())
                plan["modules"][0]["test_requirements"].append({"id": "visible-dashboard", "kind": "workflow", "category": "happy_path",
                    "description": "Show the dashboard heading.", "persona": "default", "bindings": [{"suite_id": "browser-pack",
                    "case_ids": ["dashboard"], "assertion": "Dashboard text is visible after navigation."}]})
                write(path, plan)

                def dispatch(args):
                    if Path(args.config) != browser_path:
                        return real_run(args)
                    self.assertEqual(Path.cwd(), browser_path.parent)
                    self.assertFalse(args.sign)
                    # This is an orchestration contract fixture, not browser acceptance testing.
                    source = local_report()
                    source["package_id"] = "synthetic-browser-run"
                    source["subject"]["agent_id"] = "application-ui"
                    source["run_provenance"].update(issued_at=datetime.now(timezone.utc).isoformat(), config_sha256=sha256(config))
                    source["evaluation"]["required_dimensions"] = ["workflow_coverage"]
                    source["execution"] = {"adapter_type": "browser_journey", "case_count": 1,
                                           "scored_case_count": 0 if blocked else 1, "blocked_case_count": 1 if blocked else 0,
                                           "browser_case_diagnostics": [{"case_id": "dashboard", "persona": "default", "outcome": "blocked" if blocked else "passed"}]}
                    source["metrics"] = {"workflow_coverage": {"measurement_status": "measured", "trust_status": "verified",
                                                               "workflow_execution_rate": 0 if blocked else 1, "workflow_signal_match_rate": 1}}
                    write(Path(args.out).with_name("evaluation.local-report.json"), source)

                with patch("esx_eval_runner.cli.run_command", side_effect=dispatch) as run:
                    self.assertEqual(call("release", "run", "--manifest", str(path), "--out", str(root / "review.json")), 2 if blocked else 0)
                    self.assertEqual(run.call_count, 2)
                result = json.loads((root / "review.json").read_text())
                self.assertEqual(result["execution_review"]["all_modules_executed"], not blocked)
                self.assertEqual({s["kind"] for s in result["modules"][0]["suites"]}, {"workflow", "decision"})

    def test_changed_plan_after_preflight_never_executes_that_plan(self):
        from esx_eval_runner.cli import run_command as real_run

        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = initialize(root, ["first", "second"])
            attach(root, "first")
            second = attach(root, "second")

            def dispatch(args):
                result = real_run(args)
                config = json.loads(second.read_text())
                config["evaluation"]["name"] = "changed after preflight"
                write(second, config)
                return result

            with patch("esx_eval_runner.cli.run_command", side_effect=dispatch) as run:
                self.assertEqual(call("release", "run", "--manifest", str(path), "--out", str(root / "review.json")), 2)
                self.assertEqual(run.call_count, 1)
            execution = json.loads((root / "review.json").read_text())["execution_review"]
            self.assertEqual(execution["not_fully_executed_module_ids"], ["second"])
            self.assertEqual(execution["suite_attempt_count"], 1)

    def test_missing_output_is_a_failed_run_in_audit_not_a_completed_suite(self):
        with TemporaryDirectory() as directory, patch("esx_eval_runner.cli.run_command"):
            root = Path(directory)
            path = initialize(root)
            attach(root)
            self.assertEqual(call("release", "run", "--manifest", str(path), "--out", str(root / "review.json")), 2)
            events = (root / "review.audit.jsonl").read_text()
            self.assertIn("release_suite_failed", events)
            self.assertNotIn("release_suite_completed", events)

    def test_partial_check_never_certifies_unconfirmed_inventory_as_all_modules(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = initialize(root, complete=False)
            attach(root)
            self.assertEqual(call("release", "check", "--run", "--manifest", str(path), "--out", str(root / "review.json")), 0)
            execution = json.loads((root / "review.json").read_text())["execution_review"]
            self.assertEqual(execution["modules_fully_executed_here"], 1)
            self.assertFalse(execution["inventory_confirmed"])
            self.assertFalse(execution["all_modules_executed"])

    def test_attach_validates_identity_and_preserves_existing_manifest_on_error(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = initialize(root)
            original = path.read_bytes()
            config = adapter_config(None)
            config["evaluation"]["project_key"] = "other-app"
            write(root / "config.json", config)
            args = ["release", "attach", "--manifest", str(path), "--module", "decisions", "--suite-id", "pack", "--config", str(root / "config.json"), "--read-only"]
            self.assertEqual(call(*args), 1)
            self.assertEqual(path.read_bytes(), original)

    def test_isolated_write_approval_requires_description(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = initialize(root)
            write(root / "config.json", adapter_config(None))
            args = ["release", "attach", "--manifest", str(path), "--module", "decisions", "--suite-id", "pack", "--config", str(root / "config.json"), "--isolated-writes"]
            original = path.read_bytes()
            self.assertEqual(call(*args), 1)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(call(*args, "--isolation-note", "Disposable database; external writes disabled at the test environment"), 0)
            self.assertEqual(call("release", "preflight", "--manifest", str(path), "--out", str(root / "preflight.json")), 2)
            issues = json.loads((root / "preflight.json").read_text())["issues"]
            self.assertEqual({i["code"] for i in issues}, {"test_objectives_unconfirmed"})

    def test_replacement_is_explicit_and_preserves_thresholds(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = initialize(root)
            config = attach(root)
            plan = json.loads(path.read_text())
            plan["modules"][0]["suites"][0]["gates"][0]["threshold"] = 0.99
            write(path, plan)
            args = ["release", "attach", "--manifest", str(path), "--module", "decisions", "--suite-id", "decisions-pack", "--config", str(config), "--read-only"]
            original = path.read_bytes()
            self.assertEqual(call(*args), 1)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(call(*args, "--replace"), 0)
            self.assertEqual(json.loads(path.read_text())["modules"][0]["suites"][0]["gates"][0]["threshold"], 0.99)

    def test_duplicate_plan_file_and_duplicate_content_cannot_inflate_modules(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = initialize(root, ["first", "second"])
            config = attach(root, "first")
            args = ["release", "attach", "--manifest", str(path), "--module", "second", "--suite-id", "second-pack", "--config", str(config), "--read-only"]
            self.assertEqual(call(*args), 1)
            write(root / "copy.json", json.loads(config.read_text()))
            plan = json.loads(path.read_text())
            plan["modules"][1]["required_kinds"] = ["decision"]
            copied = deepcopy(plan["modules"][0]["suites"][0])
            copied.update(id="second-pack", config="copy.json")
            plan["modules"][1]["suites"] = [copied]
            preflight, _, _ = preflight_all_modules(validate_manifest(plan), path)
            self.assertIn("duplicate_plan", [i["code"] for i in preflight["issues"]])

    def test_preflight_output_cannot_overwrite_a_plan(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = initialize(root)
            config = attach(root)
            before = config.read_bytes()
            self.assertEqual(call("release", "preflight", "--manifest", str(path), "--out", str(config)), 1)
            self.assertEqual(config.read_bytes(), before)

    def test_execution_policy_normalizes_idempotently_and_rejects_bad_hash(self):
        plan = manifest()
        suite = plan["modules"][0]["suites"][0]
        suite["execution_policy"] = {"mode": "read_only", "config_sha256": "not-a-hash"}
        with self.assertRaises(RunnerError):
            validate_manifest(plan)
        suite["execution_policy"]["config_sha256"] = sha256("config")
        normalized = validate_manifest(plan)
        self.assertEqual(validate_manifest(normalized), normalized)


if __name__ == "__main__":
    unittest.main()
