"""Real local adapter runs distinguish numeric arithmetic from probabilities."""

from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from esx_eval_runner.cli import main
from esx_eval_runner.confidence import NATIVE_CONFIDENCE, confidence_provenance
from esx_eval_runner.evidence_requirements import inspect_evidence_preflight
from esx_eval_runner.local_metrics import calculate_local_metrics
from esx_eval_runner.release import build_release_report, default_gates, validate_manifest
from esx_eval_runner.runner import RunnerError, build_package
from esx_eval_runner.setup import _pred_local_setup_html, create_guided_plan
from esx_eval_runner.system_history import signals
from test_release import adapter_config, assess, local_report, manifest
from test_system_evaluation import decision_config


class ConfidenceProvenanceTests(unittest.TestCase):
    def config(self, origin=None):
        config = adapter_config(.7)
        if origin is None:
            config["evaluation"].pop("confidence_provenance", None)
        else:
            config["evaluation"]["confidence_provenance"] = origin
        return config

    def run_cli(self, root, config):
        path = root / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            code = main(["run", "--config", str(path), "--out", str(root / "result.json"), "--summary-only"])
        self.assertEqual(code, 0, output.getvalue())
        report = json.loads((root / "result.local-report.json").read_text(encoding="utf-8"))
        page = (root / "result.local-report.html").read_text(encoding="utf-8")
        return report, page, output.getvalue()

    def test_invalid_provenance_rejected_before_target_call(self):
        invalid = [True, [], {"kind": "invented"}, {"kind": []},
                   {"kind": "native_probability"}, {"kind": "native_probability", "meaning": "positive_class"},
                   {"kind": "unknown", "mapping": {}}, {"kind": "adapter_mapped"},
                   {"kind": "adapter_mapped", "mapping": {"medium": True}},
                   {"kind": "adapter_mapped", "mapping": {"medium": float("nan")}},
                   {"kind": "adapter_mapped", "mapping": {"medium": 2}},
                   {"kind": "adapter_mapped", "mapping": {"bad\nlabel": .7}}]
        for origin in invalid:
            with self.subTest(origin=origin), patch("esx_eval_runner.runner._invoke_command_adapter") as invoke:
                with self.assertRaises(RunnerError):
                    build_package(self.config(origin))
                invoke.assert_not_called()

    def test_omitted_provenance_preserves_math_but_not_calibration_trust(self):
        metrics = calculate_local_metrics(build_package(self.config()))
        self.assertEqual(metrics["classification"]["trust_status"], "verified")
        confidence = metrics["confidence"]
        self.assertEqual(confidence["correctness_brier_score"], .09)
        self.assertEqual(confidence["expected_calibration_error"], .3)
        self.assertEqual(confidence["calculation_status"], "verified_locally")
        self.assertEqual(confidence["trust_status"], "declared")
        self.assertFalse(confidence["calibration_eligible"])

    def test_mapped_categories_are_diagnostic_and_mapping_is_retained(self):
        origin = {"kind": "adapter_mapped", "mapping": {"medium": .7, "low": .4}}
        original = deepcopy(origin)
        metric = calculate_local_metrics(build_package(self.config(origin)))["confidence"]
        self.assertEqual(metric["trust_status"], "declared")
        self.assertEqual(metric["confidence_provenance"]["mapping"], origin["mapping"])
        self.assertEqual(metric["calculation_status"], "verified_locally")
        self.assertEqual(origin, original)

    def test_returned_values_must_match_reviewed_mapping(self):
        with self.assertRaisesRegex(RunnerError, "reviewed adapter mapping"):
            build_package(self.config({"kind": "adapter_mapped", "mapping": {"high": .9}}))

    def test_native_semantics_are_explicit_not_inferred_from_numbers(self):
        metric = calculate_local_metrics(build_package(self.config(NATIVE_CONFIDENCE)))["confidence"]
        self.assertEqual(metric["trust_status"], "verified")
        self.assertTrue(metric["calibration_eligible"])
        self.assertEqual(metric["provenance_basis"], "evaluator_configuration")
        self.assertIn("not the application's", metric["interpretation"])

    def test_origin_and_mapping_changes_invalidate_comparison_protocol(self):
        origins = [None, NATIVE_CONFIDENCE,
                   {"kind": "adapter_mapped", "mapping": {"medium": .7}},
                   {"kind": "adapter_mapped", "mapping": {"medium": .7, "low": .4}}]
        hashes = {build_package(self.config(origin))["evaluation"]["comparison_protocol_sha256"] for origin in origins}
        self.assertEqual(len(hashes), 4)

    def test_classification_only_cli_report_has_headline_without_confidence(self):
        config = self.config()
        config["evaluation"]["required_dimensions"] = ["classification"]
        config["adapter"]["command"][-1] = config["adapter"]["command"][-1].replace(",\'confidence\':0.7", "")
        with TemporaryDirectory() as directory:
            report, page, _ = self.run_cli(Path(directory), config)
        self.assertIn("Decision correctness", page)
        self.assertIn("20/20", page)
        self.assertNotIn("DECISION EVIDENCE INCOMPLETE", page)
        self.assertNotIn("CONFIDENCE PROVENANCE WARNING", page)
        self.assertEqual(report["metrics"]["classification"]["accuracy"], 1)

    def test_mapped_cli_report_warns_before_details_without_native_calibration_claim(self):
        origin = {"kind": "adapter_mapped", "mapping": {"medium": .7}}
        with TemporaryDirectory() as directory:
            report, page, stdout = self.run_cli(Path(directory), self.config(origin))
        self.assertIn("CONFIDENCE PROVENANCE WARNING", page)
        self.assertIn("DIAGNOSTIC ONLY", page)
        self.assertNotIn("CALIBRATION OBSERVED", page)
        self.assertNotIn("Confidence is unreliable on this pack", page)
        self.assertIn("not native application probability calibration", stdout)
        self.assertEqual(report["evaluation"]["confidence_provenance"]["kind"], "adapter_mapped")

    def test_release_rejects_legacy_verified_flag_without_probability_provenance(self):
        report = local_report()
        report["metrics"]["confidence"].pop("confidence_provenance")
        result = assess(report=report)
        self.assertEqual(result["verdict"], "insufficient_evidence")
        self.assertTrue(any("Native probability semantics" in row["why"] for row in result["findings"]))

    def test_classification_only_release_can_pass_and_wrong_labels_still_fail(self):
        plan = manifest()
        plan["modules"][0]["suites"][0]["gates"] = default_gates("decision", ["classification"])
        report = local_report()
        report["evaluation"]["required_dimensions"] = ["classification"]
        report["metrics"].pop("confidence")
        self.assertEqual(assess(plan, report)["verdict"], "ship")
        report["metrics"]["classification"]["accuracy"] = 0
        self.assertEqual(assess(plan, report)["verdict"], "do_not_ship")

    def test_semantic_and_abstention_gates_do_not_require_classification(self):
        for signal in ("groundedness.grounded_claim_rate", "decision_evidence.correct_abstention_rate"):
            plan = manifest()
            plan["modules"][0]["suites"][0]["gates"] = [{"signal": signal, "operator": "gte", "threshold": .9}]
            self.assertEqual(validate_manifest(plan)["modules"][0]["suites"][0]["gates"][0]["signal"], signal)

    def test_workflow_cannot_masquerade_as_decision_gate(self):
        plan = manifest()
        plan["modules"][0]["suites"][0]["gates"] = default_gates("workflow")
        with self.assertRaisesRegex(RunnerError, "cannot substitute workflow"):
            validate_manifest(plan)

    def test_preflight_distinguishes_classification_readiness_from_calibration(self):
        result = inspect_evidence_preflight(self.config())
        entries = {row["metric"]: row for row in result["metrics"]}
        self.assertEqual(entries["classification"]["status"], "ready_to_collect")
        self.assertEqual(entries["confidence"]["status"], "evidence_incomplete")

    def test_setup_retains_reviewed_origin_and_rejects_bad_mapping(self):
        with TemporaryDirectory() as directory:
            values = {"directory": str(Path(directory) / "plan"), "agent_id": "app", "subject_version": "candidate",
                      "project_key": "app", "url": "http://127.0.0.1:9900/eval", "connection_type": "http",
                      "profile": "smoke", "confirm_plan": True, "confidence_provenance": dict(NATIVE_CONFIDENCE)}
            _, config = create_guided_plan(values)
            self.assertEqual(config["evaluation"]["confidence_provenance"], NATIVE_CONFIDENCE)
            values["directory"] = str(Path(directory) / "invalid")
            values["confidence_provenance"] = {"kind": "adapter_mapped", "mapping": {"low": -1}}
            with self.assertRaises(ValueError):
                create_guided_plan(values)
            self.assertFalse(Path(values["directory"]).exists())
        page = _pred_local_setup_html("token", None)
        self.assertIn('id="confidence_origin"', page)
        self.assertIn('id="confidence_mapping"', page)

    def test_release_attach_selects_label_only_gates_and_preserves_reviewed_policy(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = self.config()
            config["evaluation"]["required_dimensions"] = ["classification"]
            config_path = root / "plan.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            plan = manifest()
            plan["modules"][0]["suites"] = []
            path = root / "release.json"
            path.write_text(json.dumps(plan), encoding="utf-8")
            args = ["release", "attach", "--manifest", str(path), "--module", "decisions", "--suite-id", "labels", "--config", str(config_path), "--read-only"]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 0)
            attached = json.loads(path.read_text(encoding="utf-8"))
            gates = attached["modules"][0]["suites"][0]["gates"]
            self.assertEqual({g["signal"].split(".")[0] for g in gates}, {"classification"})
            gates[0]["threshold"] = .99
            path.write_text(json.dumps(attached), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(args + ["--replace"]), 0)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["modules"][0]["suites"][0]["gates"], gates)

    def test_system_history_does_not_rehabilitate_old_verified_confidence(self):
        report = local_report()
        native = signals({"status": "passed", "metrics": report["metrics"]})
        self.assertIn("confidence.expected_calibration_error", native)
        report["metrics"]["confidence"].pop("confidence_provenance")
        unknown = signals({"status": "passed", "metrics": report["metrics"]})
        self.assertNotIn("confidence.expected_calibration_error", unknown)
        self.assertIn("classification.accuracy", unknown)

    def test_evidence_only_release_runs_without_labels_or_confidence(self):
        config = decision_config(["decision_evidence"], labels=False)
        with TemporaryDirectory() as directory:
            report, page, _ = self.run_cli(Path(directory), config)
        health = report["evaluation"]["dataset_health"]
        self.assertEqual(health["sample_size"], 2)
        self.assertEqual(health["labelled_case_count"], 0)
        self.assertIsNone(health["majority_class_rate"])
        self.assertIn("Task-specific evaluation", page)
        plan = manifest()
        plan["application"]["version"] = "candidate"
        suite = plan["modules"][0]["suites"][0]
        suite.update(subject_id="sample-engine", minimum_cases=2,
                     gates=[{"signal": "decision_evidence.correct_abstention_rate", "operator": "gte", "threshold": 1.0}])
        result = build_release_report(plan, {"decision-pack": {"report": report}})
        self.assertEqual(result["verdict"], "ship_with_conditions")
        self.assertNotIn("dataset_health_missing", {row["code"] for row in result["findings"]})


if __name__ == "__main__":
    unittest.main()
