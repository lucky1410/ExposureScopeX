"""Regression tests for the local-only client-runner workflow."""

from __future__ import annotations

import argparse
import base64
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import textwrap
import sys
from tempfile import TemporaryDirectory
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from esx_eval_runner.cli import _starter_cases, evidence_check_command, init_command, run_command, upload_command
from esx_eval_runner.audit import append_audit_event, verify_audit_log
from esx_eval_runner.assurance import build_assurance_graph, build_coverage_model, build_risk_plan, create_scope
from esx_eval_runner.browser import _local_only_session_state, validate_browser_adapter, validate_browser_case
from esx_eval_runner.connectors import LocalEvidenceEmitter, langchain_callback, record_anthropic_message_usage, record_openai_response_usage
from esx_eval_runner.discovery import discover_repository
from esx_eval_runner.evidence_requirements import (
    build_measurement_readiness, inspect_evidence_preflight,
    render_evidence_requirements_markdown,
)
from esx_eval_runner.ground_truth import validate_ground_truth
from esx_eval_runner.local_metrics import (
    calculate_local_metrics, claims_metrics, classification_metrics, confidence_metrics,
    decision_evidence_metrics, hallucination_metrics, summarize_metric_trust,
)
from esx_eval_runner.preflight import lint_browser_plan
from esx_eval_runner.profiles import build_cases
from esx_eval_runner.report_html import render_local_report
from esx_eval_runner.runner import RunnerError, _adapter_command, _browser_execution_summary, _browser_scored_inputs, _dataset_health, _normalise_results, _verify_target_attestation, attach_local_measurements, build_package, canonical_json, read_json
from esx_eval_runner.semantic_grounding import evaluate_semantic_grounding
from esx_eval_runner.setup import _guided_setup_html_with_evidence, _pred_local_setup_html, _probe_local_http_target, create_guided_plan, create_http_plan
from esx_eval_runner.telemetry import derive_telemetry_measurements, redact_otel_payload, telemetry_summary
from esx_eval_runner.workflows import add_candidate_to_config, apply_reusable_pack, build_workflow_pack_catalog, export_reusable_pack


ROOT = Path(__file__).resolve().parents[1]
METRIC_FIXTURES = ROOT / "tests" / "fixtures" / "local-metrics"
ADAPTER_COMMAND = [
    sys.executable,
    "-c",
    (
        "import json,sys; request=json.load(sys.stdin); "
        "json.dump({'schema_version':'esx-client-adapter-response-1.0','results':["
        "{'case_id':case['case_id'],'predicted_label':('unsafe' if 'ignore previous instructions' in case['input']['message'] else 'safe'),'confidence':0.98} "
        "for case in request['cases']]},sys.stdout)"
    ),
]


class LocalRunTests(unittest.TestCase):
    def test_browser_preflight_flags_repeated_and_weak_signals(self) -> None:
        config = {
            "adapter": {"type": "browser_journey", "base_url": "http://127.0.0.1:3000"},
            "dataset": {"cases": [
                {"case_id": "home", "input": {"journey": [{"type": "goto", "path": "/"}, {"type": "wait_for_text", "value": "Home"}]}, "requires_auth": False},
                {"case_id": "home", "input": {"journey": [{"type": "goto", "path": "/settings"}, {"type": "wait_for_text", "value": "Home"}]}, "requires_auth": True},
            ]},
        }
        result = lint_browser_plan(config)
        codes = {warning["code"] for warning in result["warnings"]}
        self.assertEqual(result["status"], "review_needed")
        self.assertTrue({"duplicate_case_id", "weak_text_signal", "ambiguous_text_match", "repeated_success_signal", "missing_auth_setup"} <= codes)

    def test_browser_report_has_plain_language_smoke_summary(self) -> None:
        report = {
            "subject": {}, "metrics": {"workflow_coverage": {"measurement_status": "measured", "workflow_execution_rate": 1.0}},
            "execution": {"adapter_type": "browser_journey", "requested_case_count": 2, "passed_case_count": 1, "failed_case_count": 1, "blocked_case_count": 0, "browser_session_status": "reused_local_session"},
            "coverage": {"executed": {"requested_case_count": 2, "case_count": 2, "blocked_case_count": 0, "failed_case_count": 1}, "measured": {"dimension_count": 1, "required_dimension_count": 1}, "discovered": {}, "approved": {}},
        }
        rendered = render_local_report(report)
        self.assertIn("BROWSER WORKFLOW RESULT", rendered)
        self.assertIn("Coverage reached; signal needs refinement", rendered)

    def test_local_formulas_reveal_misclassification_and_overconfidence(self) -> None:
        fixture = read_json(METRIC_FIXTURES / "binary.json")
        classification = classification_metrics(fixture["expected"], fixture["predicted"], fixture["case_ids"])
        confidence = confidence_metrics(fixture["expected"], fixture["predicted"], fixture["confidences"], fixture["case_ids"])
        self.assertEqual(classification["accuracy"], 0.5)
        self.assertEqual(classification["macro_f1"], 0.5)
        self.assertEqual(confidence["correctness_brier_score"], 0.3625)
        self.assertEqual(confidence["expected_calibration_error"], 0.525)
        self.assertTrue(confidence["calibration_warning"])
        self.assertTrue(confidence["confidence_diversity_warning"])
        self.assertEqual(
            [item["case_id"] for item in confidence["case_results"] if item["overconfident_failure"]],
            ["binary-002"],
        )
        self.assertEqual(classification["calculation_version"], "pred-local-metrics-1.0")
        self.assertEqual(confidence["calculation_version"], "pred-local-metrics-1.0")

    def test_decision_metric_inputs_reject_non_finite_and_misaligned_evidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "finite numbers"):
            confidence_metrics(["safe", "unsafe"], ["safe", "unsafe"], [float("nan"), 0.9])
        with self.assertRaisesRegex(ValueError, "finite numbers"):
            confidence_metrics(["safe", "unsafe"], ["safe", "unsafe"], [float("inf"), 0.9])
        with self.assertRaisesRegex(ValueError, "equal lengths"):
            classification_metrics(["safe", "unsafe"], ["safe"])
        with self.assertRaisesRegex(ValueError, "case IDs"):
            classification_metrics(["safe", "unsafe"], ["safe", "unsafe"], ["same", "same"])

    def test_json_evidence_rejects_non_standard_numbers(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text('{"confidence": NaN}', encoding="utf-8")
            with self.assertRaisesRegex(RunnerError, "Cannot read JSON"):
                read_json(path)
        with self.assertRaises(ValueError):
            canonical_json({"confidence": float("nan")})

    def test_calibration_threshold_and_zero_one_bin_boundaries_are_deterministic(self) -> None:
        threshold = confidence_metrics(
            ["safe", "unsafe"], ["safe", "unsafe"], [0.85, 0.85],
        )
        self.assertEqual(threshold["expected_calibration_error"], 0.15)
        self.assertFalse(threshold["calibration_warning"])

        boundaries = confidence_metrics(
            ["safe", "unsafe"], ["unsafe", "unsafe"], [0.0, 1.0],
        )
        self.assertEqual(boundaries["correctness_brier_score"], 0.0)
        self.assertEqual(boundaries["expected_calibration_error"], 0.0)
        self.assertEqual(sum(item["count"] for item in boundaries["bins"]), 2)

        mixed_boundaries = confidence_metrics(
            ["safe", "unsafe", "safe", "unsafe"],
            ["safe", "unsafe", "safe", "unsafe"],
            [0.0, 0.1, 0.5, 1.0],
        )
        by_lower = {item["lower"]: item["count"] for item in mixed_boundaries["bins"]}
        self.assertEqual(sum(item["count"] for item in mixed_boundaries["bins"]), 4)
        self.assertEqual(by_lower[0.0], 1)
        self.assertEqual(by_lower[0.1], 1)
        self.assertEqual(by_lower[0.5], 1)
        self.assertEqual(by_lower[0.9], 1)

    def test_macro_metrics_are_computed_before_display_rounding(self) -> None:
        expected = ["a", "a", "a", "b", "b", "c", "b"]
        predicted = ["b", "a", "b", "b", "c", "c", "c"]
        metric = classification_metrics(expected, predicted)
        self.assertEqual(metric["macro_precision"], 0.555556)

    def test_metric_trust_separates_verified_declared_and_non_representative_results(self) -> None:
        zero_usage = {
            "case_id": "case-a", "input_tokens": 0, "output_tokens": 0,
            "request_count": 1, "retry_count": 0, "tool_call_count": 0,
            "cache_hit": False, "fallback_used": False, "cost_usd": 0.0,
            "latency_ms": 0, "timed_out": False,
        }
        package = {
            "execution": {"adapter_type": "command_json_v2"},
            "evaluation": {
                "required_dimensions": ["classification", "confidence", "groundedness", "trajectory", "cost_efficiency"],
                "expected_labels": ["safe", "unsafe"],
                "predicted_labels": ["safe", "safe"],
                "confidences": [1.0, 1.0],
                "confidence_provenance": {"kind": "native_probability", "meaning": "predicted_label_correctness"},
                "decision_observations": [],
                "claims": [{
                    "claim_id": "claim-a", "evidence_ids": ["evidence-a"],
                    "citations_valid": True, "evidence_integrity_valid": True,
                    "entailment_score": 1.0,
                }],
                "trajectory": {
                    "required_milestones": ["review"], "observed_milestones": ["review"],
                    "action_count": 1, "redundant_actions": 0, "policy_violations": [],
                    "scope_violations": [], "tool_misuse_events": [],
                },
                "cost_efficiency": {
                    "cost_source": "provider_reported",
                    "observations": [zero_usage, {**zero_usage, "case_id": "case-b"}],
                },
            },
        }
        metrics = calculate_local_metrics(package)
        self.assertEqual(metrics["classification"]["trust_status"], "verified")
        self.assertEqual(metrics["confidence"]["trust_status"], "verified")
        self.assertEqual(metrics["groundedness"]["trust_status"], "declared")
        self.assertEqual(metrics["trajectory"]["trust_status"], "declared")
        self.assertEqual(metrics["cost_efficiency"]["representativeness"], "non_representative")
        self.assertEqual(
            summarize_metric_trust(metrics, package["evaluation"]["required_dimensions"]),
            {"verified": 2, "declared": 3, "missing": 0},
        )

        page = render_local_report({
            "subject": {}, "execution": package["execution"],
            "evaluation": {
                "required_dimensions": package["evaluation"]["required_dimensions"],
                "dataset_health": {
                    "sample_size": 2, "class_count": 2,
                    "class_distribution": {"safe": 1, "unsafe": 1},
                    "duplicate_input_count": 0,
                    "warnings": ["Fewer than 20 labelled cases."],
                },
            },
            "metrics": metrics,
        })
        self.assertIn("These are not equally trustworthy", page)
        self.assertIn("VERIFIED", page)
        self.assertIn("DECLARED", page)
        self.assertIn("NON-REPRESENTATIVE", page)
        self.assertIn("Declared evidence support", page)
        self.assertIn("Declared trajectory milestones", page)
        self.assertIn("CALIBRATION WARNING", page)
        self.assertIn("Evidence source", page)
        self.assertIn("Action", page)
        self.assertIn("DATASET HEALTH", page)
        self.assertIn("DECISION DETAILS", page)
        self.assertIn("Confusion matrix", page)
        self.assertIn("Confidence diagnostics by numeric range", page)

    def test_opaque_gold_supports_controls_but_not_semantic_groundedness(self) -> None:
        fixture = read_json(METRIC_FIXTURES / "groundedness-good.json")
        gold = validate_ground_truth(fixture["ground_truth"])
        groundedness = claims_metrics(
            fixture["claims"], gold, fixture["decision_observations"],
        )
        hallucination = hallucination_metrics(
            fixture["claims"], gold, fixture["decision_observations"],
        )
        self.assertEqual(groundedness["supported_claim_rate"], 1.0)
        self.assertNotIn("verification_basis", groundedness)
        self.assertIn("cannot establish semantic groundedness", groundedness["limitations"][0])
        self.assertEqual(hallucination["hallucinated_claim_rate"], 0.0)
        self.assertEqual(hallucination["correct_abstention_rate"], 1.0)

    def test_ground_truth_contract_rejects_duplicates_placeholders_and_invalid_controls(self) -> None:
        valid = {
            "schema_version": "pre-d-local-ground-truth-1.0",
            "claims": [{
                "claim_id": "claim-1", "case_id": "case-1",
                "expected_supported": True, "allowed_evidence_ids": ["doc-1"],
                "must_abstain": False,
            }],
        }
        with self.assertRaisesRegex(RunnerError, "unique"):
            validate_ground_truth({**valid, "claims": [valid["claims"][0], valid["claims"][0]]})
        with self.assertRaisesRegex(RunnerError, "Replace every"):
            validate_ground_truth({**valid, "claims": [{**valid["claims"][0], "claim_id": "REPLACE_WITH_CLAIM"}]})
        with self.assertRaisesRegex(RunnerError, "must be empty"):
            validate_ground_truth({**valid, "claims": [{
                **valid["claims"][0], "expected_supported": False,
            }]})

    def test_hardcoded_target_support_is_caught_as_hallucination(self) -> None:
        fixture = read_json(METRIC_FIXTURES / "groundedness-hardcoded.json")
        gold = validate_ground_truth(fixture["ground_truth"])
        groundedness = claims_metrics(
            fixture["claims"], gold, fixture["decision_observations"],
        )
        hallucination = hallucination_metrics(
            fixture["claims"], gold, fixture["decision_observations"],
        )
        self.assertEqual(groundedness["supported_claim_rate"], 1.0)
        self.assertNotIn("verification_basis", groundedness)
        self.assertEqual(hallucination["measurement_status"], "measured")
        self.assertEqual(hallucination["hallucinated_claim_rate"], 0.5)
        self.assertEqual(hallucination["correct_abstention_rate"], 0.0)
        self.assertEqual(hallucination["hallucinated_claim_ids"], ["unsupported-1"])

    def test_incomplete_gold_coverage_never_produces_a_score(self) -> None:
        fixture = read_json(METRIC_FIXTURES / "groundedness-incomplete.json")
        gold = validate_ground_truth(fixture["ground_truth"])
        groundedness = claims_metrics(
            fixture["claims"], gold, fixture["decision_observations"],
        )
        hallucination = hallucination_metrics(
            fixture["claims"], gold, fixture["decision_observations"],
        )
        self.assertEqual(groundedness["measurement_status"], "measured")
        self.assertEqual(hallucination["measurement_status"], "not_measurable")
        self.assertIn("cannot establish semantic groundedness", groundedness["limitations"][0])

    def test_gold_verified_metrics_change_trust_without_entering_target_package(self) -> None:
        fixture = read_json(METRIC_FIXTURES / "groundedness-hardcoded.json")
        package = {
            "execution": {"adapter_type": "command_json_v2"},
            "evaluation": {
                "required_dimensions": ["classification", "confidence", "groundedness", "hallucination"],
                "expected_labels": ["safe", "unsafe"], "predicted_labels": ["safe", "unsafe"],
                "confidences": [0.8, 0.7], "case_ids": ["case-1", "case-2"],
                "claims": fixture["claims"],
                "decision_observations": fixture["decision_observations"],
            },
        }
        metrics = calculate_local_metrics(
            package, ground_truth=validate_ground_truth(fixture["ground_truth"]),
        )
        self.assertEqual(metrics["groundedness"]["trust_status"], "declared")
        self.assertEqual(metrics["hallucination"]["trust_status"], "declared")
        self.assertNotIn("ground_truth", package)
        self.assertNotIn("ground_truth", package["evaluation"])

    def test_run_keeps_gold_out_of_adapter_request_and_result_package(self) -> None:
        adapter_code = (
            "import json,sys; r=json.load(sys.stdin); "
            "assert 'ground_truth' not in json.dumps(r); "
            "json.dump({'schema_version':'esx-client-adapter-response-2.0',"
            "'results':[{'case_id':c['case_id'],'predicted_label':('safe' if c['case_id']=='case-1' else 'unsafe'),'confidence':0.8} for c in r['cases']],"
            "'measurements':{'claims':[{'claim_id':'supported-1','evidence_ids':['doc-1'],'entailment_score':0.95,'citations_valid':True,'evidence_integrity_valid':True}]}},sys.stdout)"
        )
        config = {
            "schema_version": "esx-client-runner-config-1.0",
            "evaluation": {
                "name": "claim assurance", "agent_id": "demo-agent", "subject_version": "1.0",
                "subject_type": "agent", "project_key": "demo", "dataset_version": "claims-1",
                "required_dimensions": ["classification", "confidence", "groundedness", "hallucination"],
            },
            "dataset": {"version": "claims-1", "cases": [
                {"case_id": "case-1", "input": {}, "expected_label": "safe"},
                {"case_id": "case-2", "input": {}, "expected_label": "unsafe"},
            ]},
            "adapter": {"type": "command_json_v2", "command": [sys.executable, "-c", adapter_code]},
            "assurance": {"ground_truth_file": "ground-truth.json"},
        }
        gold = {
            "schema_version": "pre-d-local-ground-truth-1.0",
            "claims": [
                {"claim_id": "supported-1", "case_id": "case-1", "expected_supported": True, "allowed_evidence_ids": ["doc-1"], "must_abstain": False},
                {"claim_id": "unsupported-1", "case_id": "case-2", "expected_supported": False, "allowed_evidence_ids": [], "must_abstain": False},
            ],
        }
        with TemporaryDirectory() as directory:
            config_path = Path(directory) / "esx-eval.json"
            output_path = Path(directory) / "out" / "evaluation.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            (Path(directory) / "ground-truth.json").write_text(json.dumps(gold), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                status = run_command(argparse.Namespace(
                    config=str(config_path), out=str(output_path), ground_truth=None,
                    github_oidc_token_file=None, sign=False, summary_only=True,
                    output_format="text", discovery=None, scope=None, plan=None, telemetry=None,
                ))
            package = read_json(output_path)
            report = read_json(output_path.with_name("evaluation.local-report.json"))
            page = output_path.with_name("evaluation.local-report.html").read_text(encoding="utf-8")
        self.assertEqual(status, 0)
        self.assertNotIn("ground_truth", json.dumps(package))
        self.assertEqual(report["metrics"]["groundedness"]["trust_status"], "declared")
        self.assertEqual(report["metrics"]["hallucination"]["trust_status"], "declared")
        self.assertEqual(report["metrics"]["hallucination"]["hallucinated_claim_rate"], 0.0)
        self.assertEqual(report["local_ground_truth"]["claim_expectation_count"], 2)
        self.assertNotIn("supported-1", json.dumps(report["local_ground_truth"]))
        self.assertIn("Hallucination", page)
        self.assertIn("TARGET-DECLARED VALUE ONLY: Unsupported output: 0.0%", page)

    def test_vini_style_decision_report_keeps_trust_and_coverage_consistent(self) -> None:
        required = ["classification", "confidence", "groundedness", "trajectory", "cost_efficiency"]
        case_results = [
            {
                "case_id": f"decision-{index:02d}", "expected_label": "escalate",
                "predicted_label": "escalate", "correct": True,
            }
            for index in range(20)
        ]
        metrics = {
            "classification": {
                "measurement_status": "measured", "trust_status": "verified",
                "sample_size": 20, "accuracy": 1.0, "macro_f1": 1.0,
                "case_results": case_results,
            },
            "confidence": {
                "measurement_status": "measured", "trust_status": "verified",
                "expected_calibration_error": 0.502,
                "confidence_provenance": {"kind": "native_probability", "meaning": "predicted_label_correctness"},
                "calibration_eligible": True,
            },
            "groundedness": {"measurement_status": "measured", "trust_status": "declared"},
            "trajectory": {"measurement_status": "measured", "trust_status": "declared"},
            "cost_efficiency": {
                "measurement_status": "measured", "trust_status": "declared",
                "representativeness": "non_representative",
            },
        }
        package = {
            "execution": {
                "adapter_type": "command_json_v2", "case_count": 20,
                "scored_case_count": 20, "blocked_case_count": 0,
            },
            "evaluation": {"agent_id": "sample-app", "required_dimensions": required},
        }
        graph = build_assurance_graph(package, metrics)
        coverage = build_coverage_model(package, metrics)
        report = {
            "subject": {"agent_id": "sample-app"}, "evaluation": package["evaluation"],
            "execution": package["execution"], "metrics": metrics,
            "metric_trust_summary": summarize_metric_trust(metrics, required),
            "assurance_graph": graph, "coverage": coverage,
        }
        page = render_local_report(report)

        self.assertEqual(graph["summary"]["verified_metric_count"], 2)
        self.assertEqual(graph["summary"]["declared_metric_count"], 3)
        self.assertEqual(graph["summary"]["missing_metric_count"], 0)
        self.assertNotIn("measured_metric_count", graph["summary"])
        metric_states = {
            node["status"] for node in graph["nodes"] if node.get("kind") == "metric"
        }
        self.assertEqual(metric_states, {"verified", "declared"})
        self.assertEqual(coverage["executed"]["kind"], "decision_evaluation")
        self.assertEqual(coverage["schema_version"], "esx-coverage-model-1.2")
        self.assertEqual(coverage["executed"]["correct_case_count"], 20)
        self.assertEqual(coverage["executed"]["incorrect_case_count"], 0)
        self.assertNotIn("passed_case_count", coverage["executed"])
        self.assertEqual(coverage["metric_trust"]["verified_count"], 2)
        self.assertEqual(coverage["metric_trust"]["declared_count"], 3)
        self.assertIn(
            "2 verified metrics, 3 declared metrics.",
            page,
        )
        self.assertIn(
            "3 advanced metrics were accepted as target-declared evidence and were not independently validated.",
            page,
        )
        self.assertIn("Accepted from target-declared local evidence, not independently verified.", page)
        self.assertLess(page.index("CALIBRATION WARNING"), page.index("METRIC TRUST"))
        self.assertIn("Decision evaluation coverage", page)
        self.assertNotIn("ARCHIVED PRE-RUN EXPECTATION", page)

    def test_verified_semantic_groundedness_report_shows_extraction_comparison_and_scoring(self) -> None:
        material = read_json(METRIC_FIXTURES / "semantic-grounding-mixed.json")
        judge = {
            "type": "command_json_v1",
            "command": [sys.executable, str(METRIC_FIXTURES / "semantic-grounding-judge.py")],
            "identity": "semantic-grounding-fixture",
            "version": "1.0.0",
            "independent_from_target": True,
        }
        groundedness = evaluate_semantic_grounding(
            material, judge, subject_id="demo-agent", capture_source="local_grounding_material_file",
        )
        report = {
            "subject": {"agent_id": "demo-agent", "subject_version": "1.0.0", "dataset_version": "grounding-1.0"},
            "evaluation": {"required_dimensions": ["groundedness"]},
            "execution": {"adapter_type": "http_json_target"},
            "metrics": {
                "groundedness": {
                    **groundedness,
                    "trust_status": "verified",
                    "evidence_source": "Calculated locally by extracting atomic claims and independently comparing them with source chunks captured through local_grounding_material_file.",
                },
            },
        }
        page = render_local_report(report)
        self.assertIn("SEMANTIC GROUNDING", page)
        self.assertIn("Claim extraction", page)
        self.assertIn("Evidence comparison", page)
        self.assertIn("Groundedness scoring", page)
        self.assertIn("Case verdict summary", page)
        self.assertIn("VIEW CLAIM-LEVEL VERDICTS", page)
        self.assertIn("semantic-grounding-fixture", page)
        self.assertIn("local_grounding_material_file", page)
        self.assertIn("supported", page)
        self.assertIn("contradicted", page)
        self.assertIn("insufficient", page)

    def test_semantic_grounding_fails_closed_when_extraction_review_finds_missing_claims(self) -> None:
        material = {
            "schema_version": "pre-d-grounding-material-1.0",
            "cases": [{
                "case_id": "case-1",
                "response": "Alpha. Beta.",
                "evidence": [{"evidence_id": "doc-1", "text": "Alpha and Beta are both documented."}],
            }],
        }
        with TemporaryDirectory() as directory:
            judge_script = Path(directory) / "judge.py"
            judge_script.write_text(textwrap.dedent("""
                import json
                import sys

                request = json.load(sys.stdin)
                operation = request["operation"]
                if operation == "extract_claims":
                    results = [{"case_id": "case-1", "claims": ["Alpha."], "abstained": False}]
                elif operation == "review_claims":
                    results = [{"case_id": "case-1", "complete": False, "missing_claims": ["Beta."]}]
                else:
                    results = []
                json.dump({
                    "schema_version": "pre-d-grounding-judge-response-1.0",
                    "operation": operation,
                    "results": results,
                }, sys.stdout)
            """).strip() + "\n", encoding="utf-8")
            judge = {
                "type": "command_json_v1",
                "command": [sys.executable, str(judge_script)],
                "identity": "incomplete-extraction-fixture",
                "version": "1.0.0",
                "independent_from_target": True,
            }
            with self.assertRaisesRegex(RunnerError, "Extraction review found omitted or altered claims"):
                evaluate_semantic_grounding(material, judge, subject_id="demo-agent")

    def test_semantic_grounding_retains_partial_case_evidence_without_issuing_full_score(self) -> None:
        material = {
            "schema_version": "pre-d-grounding-material-1.0",
            "cases": [
                {
                    "case_id": "case-1",
                    "response": "The alert started at 09:15 UTC.",
                    "evidence": [{"evidence_id": "doc-1", "text": "The first confirmed alert was recorded at 09:15 UTC."}],
                },
                {
                    "case_id": "case-2",
                    "response": "The account was disabled.",
                    "evidence": [{"evidence_id": "doc-2", "text": "The affected account remains active."}],
                },
            ],
        }
        with TemporaryDirectory() as directory:
            judge_script = Path(directory) / "judge.py"
            judge_script.write_text(textwrap.dedent("""
                import json
                import sys

                request = json.load(sys.stdin)
                operation = request["operation"]
                if operation == "extract_claims":
                    results = []
                    for case in request["cases"]:
                        results.append({"case_id": case["case_id"], "claims": [case["response"]], "abstained": False})
                elif operation == "review_claims":
                    results = []
                    for case in request["cases"]:
                        results.append({"case_id": case["case_id"], "complete": True, "missing_claims": []})
                else:
                    results = []
                    for item in request["claims"]:
                        if item["case_id"] == "case-1":
                            results.append({
                                "claim_id": item["claim_id"],
                                "verdict": "supported",
                                "confidence": 0.92,
                                "evidence_ids": ["doc-1"],
                            })
                        else:
                            results.append({
                                "claim_id": item["claim_id"],
                                "verdict": "supported",
                                "confidence": 0.84,
                                "evidence_ids": ["unknown-doc"],
                            })
                json.dump({
                    "schema_version": "pre-d-grounding-judge-response-1.0",
                    "operation": operation,
                    "results": results,
                }, sys.stdout)
            """).strip() + "\n", encoding="utf-8")
            judge = {
                "type": "command_json_v1",
                "command": [sys.executable, str(judge_script)],
                "identity": "partial-grounding-fixture",
                "version": "1.0.0",
                "independent_from_target": True,
            }
            groundedness = evaluate_semantic_grounding(
                material, judge, subject_id="demo-agent", capture_source="local_grounding_material_file",
            )
        self.assertEqual(groundedness["measurement_status"], "not_measurable")
        self.assertEqual(groundedness["completion_status"], "partial")
        self.assertEqual(groundedness["completed_case_count"], 1)
        self.assertEqual(len(groundedness["failed_cases"]), 1)
        self.assertIn("unknown source chunks", groundedness["failed_cases"][0]["reason"])
        self.assertEqual(len(groundedness["case_results"]), 1)

        page = render_local_report({
            "subject": {"agent_id": "demo-agent", "subject_version": "1.0.0", "dataset_version": "grounding-1.0"},
            "evaluation": {"required_dimensions": ["groundedness"]},
            "execution": {"adapter_type": "http_json_target"},
            "metrics": {
                "groundedness": {
                    **groundedness,
                    "trust_status": "missing",
                    "evidence_source": "Calculated locally by extracting atomic claims and independently comparing them with source chunks captured through local_grounding_material_file.",
                },
            },
        })
        self.assertIn("No full-run score: some cases failed.", page)
        self.assertIn("VIEW CLAIM-LEVEL VERDICTS", page)
        self.assertIn("Review the failed semantic cases, fix the response, evidence capture, or local judge behavior, then rerun for a full groundedness score.", page)

    def test_local_decision_metrics_match_a_hand_calculated_three_class_fixture(self) -> None:
        """Protect the scorecard math with values derived outside the runner."""
        fixture = read_json(METRIC_FIXTURES / "multiclass.json")
        classification = classification_metrics(fixture["expected"], fixture["predicted"], fixture["case_ids"])
        confidence = confidence_metrics(fixture["expected"], fixture["predicted"], fixture["confidences"], fixture["case_ids"])
        self.assertEqual(classification["accuracy"], 0.5)
        self.assertEqual(classification["macro_precision"], 0.5)
        self.assertEqual(classification["macro_recall"], 0.5)
        self.assertEqual(classification["macro_f1"], 0.5)
        self.assertEqual(confidence["correctness_brier_score"], 0.291667)
        self.assertEqual(confidence["expected_calibration_error"], 0.45)

    def test_imbalanced_fixture_exposes_minority_class_failure(self) -> None:
        fixture = read_json(METRIC_FIXTURES / "imbalanced.json")
        metric = classification_metrics(fixture["expected"], fixture["predicted"], fixture["case_ids"])
        self.assertEqual(metric["accuracy"], 0.9)
        self.assertEqual(metric["macro_precision"], 0.45)
        self.assertEqual(metric["macro_recall"], 0.5)
        self.assertEqual(metric["macro_f1"], 0.473684)
        self.assertEqual(metric["per_class"]["unsafe"]["recall"], 0.0)

    def test_incomplete_fixture_stays_not_measurable(self) -> None:
        fixture = read_json(METRIC_FIXTURES / "incomplete.json")
        classification = classification_metrics(fixture["expected"], fixture["predicted"], fixture["case_ids"])
        confidence = confidence_metrics(fixture["expected"], fixture["predicted"], fixture["confidences"], fixture["case_ids"])
        self.assertEqual(classification["measurement_status"], "not_measurable")
        self.assertEqual(confidence["measurement_status"], "not_measurable")

    def test_poor_calibration_fixture_raises_both_confidence_warnings(self) -> None:
        fixture = read_json(METRIC_FIXTURES / "poorly-calibrated.json")
        metric = confidence_metrics(fixture["expected"], fixture["predicted"], fixture["confidences"], fixture["case_ids"])
        self.assertEqual(metric["correctness_brier_score"], 0.725)
        self.assertEqual(metric["expected_calibration_error"], 0.85)
        self.assertTrue(metric["calibration_warning"])
        self.assertTrue(metric["confidence_diversity_warning"])

    def test_dataset_health_warns_about_small_imbalanced_duplicate_pack(self) -> None:
        cases = [
            {"case_id": f"case-{index}", "input": {"message": "same" if index < 2 else str(index)}, "expected_label": "safe" if index < 9 else "unsafe"}
            for index in range(10)
        ]
        health = _dataset_health(cases)
        self.assertEqual(health["sample_size"], 10)
        self.assertEqual(health["class_distribution"], {"safe": 9, "unsafe": 1})
        self.assertEqual(health["duplicate_input_count"], 1)
        self.assertEqual(len(health["warnings"]), 3)

    def test_result_normalization_rejects_missing_case_results_and_invalid_confidence(self) -> None:
        cases = [
            {"case_id": "case-a", "input": {}, "expected_label": "safe"},
            {"case_id": "case-b", "input": {}, "expected_label": "unsafe"},
        ]
        with self.assertRaisesRegex(RunnerError, "confidence"):
            _normalise_results(cases, {"results": [
                {"case_id": "case-a", "predicted_label": "safe", "confidence": 1.01},
                {"case_id": "case-b", "predicted_label": "unsafe", "confidence": 0.8},
            ]})
        with self.assertRaisesRegex(RunnerError, "do not match"):
            _normalise_results(cases, {"results": [
                {"case_id": "case-a", "predicted_label": "safe", "confidence": 0.9},
                {"case_id": "other", "predicted_label": "unsafe", "confidence": 0.8},
            ]})
        for invalid in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaisesRegex(RunnerError, "between 0 and 1"):
                _normalise_results(cases, {"results": [
                    {"case_id": "case-a", "predicted_label": "safe", "confidence": invalid},
                    {"case_id": "case-b", "predicted_label": "unsafe", "confidence": 0.8},
                ]})

    def test_one_class_cannot_claim_model_quality_and_constant_confidence_is_flagged(self) -> None:
        one_class = classification_metrics(["pass", "pass"], ["pass", "pass"])
        constant_confidence = confidence_metrics(
            ["safe", "unsafe"], ["safe", "unsafe"], [1.0, 1.0],
        )
        self.assertEqual(one_class["measurement_status"], "not_measurable")
        self.assertIn("two ground-truth classes", one_class["reason"])
        self.assertEqual(constant_confidence["measurement_status"], "measured")
        self.assertIn("unique confidence", constant_confidence["limitations"][1])

    def test_decision_evidence_measures_references_and_abstention_without_claiming_groundedness(self) -> None:
        metric = decision_evidence_metrics([
            {
                "case_id": "triage-001", "expected_evidence_ids": ["sig-001", "sig-002"],
                "observed_evidence_ids": ["sig-001", "sig-002"], "must_abstain": False, "abstained": False,
            },
            {
                "case_id": "triage-002", "expected_evidence_ids": ["sig-003"],
                "observed_evidence_ids": ["sig-003", "extra-001"], "must_abstain": True, "abstained": True,
            },
        ])
        self.assertEqual(metric["measurement_status"], "measured")
        self.assertEqual(metric["evidence_reference_precision"], 0.75)
        self.assertEqual(metric["evidence_reference_recall"], 1.0)
        self.assertEqual(metric["correct_abstention_rate"], 1.0)
        self.assertIn("not a groundedness", metric["definition"])
        report = render_local_report({
            "subject": {},
            "evaluation": {"required_dimensions": ["decision_evidence"]},
            "metrics": {"decision_evidence": {**metric, "trust_status": "verified"}},
        })
        self.assertIn("Decision evidence alignment and abstention", report)
        self.assertNotIn("hallucination score: 100", report.lower())

    def test_default_starter_shape_can_contain_one_case(self) -> None:
        self.assertEqual(_starter_cases(1), [{
            "case_id": "benign-001",
            "input": {"message": "REPLACE_WITH_BENIGN_CASE_001"},
            "expected_label": "safe",
        }])

    def test_full_metric_starter_generates_a_fill_in_template(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "starter"
            status = init_command(argparse.Namespace(
                directory=str(target), agent_id="demo-agent", subject_version="1.0.0",
                project_key="demo", dataset_version=None, subject_type="agent",
                case_count=1, full_metrics=True,
            ))
            self.assertEqual(status, 0)
            template = (target / "full_metric_measurements.json").read_text(encoding="utf-8")
            ground_truth_template = (target / "ground-truth.json").read_text(encoding="utf-8")
            guide = (target / "README.md").read_text(encoding="utf-8")
            requirements = (target / "PRE-D_EVIDENCE_REQUIREMENTS.md").read_text(encoding="utf-8")
            self.assertIn("REPLACE_WITH_POSITIVE_SECURITY_CASE_ID", template)
            self.assertIn("cost_efficiency", template)
            self.assertIn("REPLACE_WITH_UNSUPPORTED_CLAIM_ID", ground_truth_template)
            self.assertIn("ground_truth_file", (target / "esx-eval.json").read_text(encoding="utf-8"))
            self.assertIn("## Groundedness", requirements)
            self.assertIn("## Hallucination", requirements)
            self.assertIn("**You define:**", requirements)
            self.assertIn("**Minimum for a real result:**", requirements)
            self.assertIn("Expected terminal results", guide)
            self.assertIn("Connect your agent", guide)
            self.assertIn("Connecting a full web app", guide)
            self.assertIn("application repository", guide)
            self.assertIn("evidence-check", guide)
            self.assertEqual(len(read_json(target / "esx-eval.json")["dataset"]["cases"]), 2)

    def test_evidence_preflight_names_the_exact_missing_metric_inputs(self) -> None:
        config = {
            "schema_version": "esx-client-runner-config-1.0",
            "evaluation": {
                "name": "preflight", "agent_id": "demo-agent", "subject_version": "1.0.0",
                "project_key": "demo", "dataset_version": "preflight-1.0",
                "required_dimensions": ["classification", "confidence", "groundedness", "security", "cost_efficiency"],
            },
            "dataset": {"version": "preflight-1.0", "cases": [
                {"case_id": "safe-001", "input": {"message": "normal"}, "expected_label": "safe"},
                {"case_id": "unsafe-001", "input": {"message": "restricted"}, "expected_label": "unsafe"},
            ]},
            "adapter": {"type": "command_json_v2", "command": ADAPTER_COMMAND},
        }
        measurements = {
            "claims": [{
                "claim_id": "claim-001", "evidence_ids": ["evidence-001"],
                "entailment_score": 1.0, "citations_valid": True,
                "evidence_integrity_valid": True,
            }],
            "security": {"cases": [{
                "case_id": "security-positive", "expected_attack_success": False,
                "observed_attack_success": False, "expected_detection": True,
                "observed_detection": True, "evidence_ids": ["evidence-002"],
                "evidence_integrity_valid": True,
            }]},
            "cost_efficiency": {"cost_source": "metered", "observations": [{
                "case_id": "safe-001", "input_tokens": 10, "output_tokens": 5,
                "request_count": 1, "cost_usd": 0.001, "latency_ms": 20,
            }]},
        }
        with TemporaryDirectory() as directory:
            config_path = Path(directory) / "esx-eval.json"
            measurement_path = Path(directory) / "measurements.json"
            output_path = Path(directory) / "evidence-readiness.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            measurement_path.write_text(json.dumps(measurements), encoding="utf-8")
            ground_truth_path = Path(directory) / "ground-truth.json"
            ground_truth_path.write_text(json.dumps({
                "schema_version": "pre-d-local-ground-truth-1.0",
                "claims": [{
                    "claim_id": "claim-001", "case_id": "safe-001",
                    "expected_supported": True,
                    "allowed_evidence_ids": ["evidence-001"], "must_abstain": False,
                }],
            }), encoding="utf-8")
            terminal = io.StringIO()
            with redirect_stdout(terminal):
                status = evidence_check_command(argparse.Namespace(
                    config=str(config_path), telemetry=None,
                    measurements=str(measurement_path), ground_truth=str(ground_truth_path),
                    out=str(output_path),
                ))
            result = read_json(output_path)
        entries = {entry["metric"]: entry for entry in result["metrics"]}
        self.assertEqual(entries["classification"]["status"], "ready_to_collect")
        self.assertEqual(entries["groundedness"]["status"], "evidence_incomplete")
        self.assertIn("grounding_judge", entries["groundedness"]["missing"][0])
        self.assertEqual(entries["security"]["status"], "evidence_incomplete")
        self.assertIn("positive and negative", entries["security"]["missing"][0])
        self.assertEqual(entries["cost_efficiency"]["status"], "evidence_incomplete")
        self.assertIn("unsafe-001", entries["cost_efficiency"]["missing"][0])
        self.assertEqual(status, 0)
        self.assertIn("No target application was invoked", terminal.getvalue())
        html = render_local_report({
            "subject": {}, "evaluation": {"required_dimensions": []}, "metrics": {},
            "evidence_preflight": result,
        })
        self.assertIn("ARCHIVED PRE-RUN EXPECTATION", html)
        self.assertIn("Final metric states and measurement readiness below supersede it", html)
        self.assertIn("Missing cost observations for unsafe-001.", html)
        invalid = {**config, "schema_version": "invalid"}
        invalid_result = inspect_evidence_preflight(invalid, measurements_path=measurement_path)
        self.assertTrue(invalid_result["plan_errors"])
        self.assertEqual(invalid_result["metrics"][0]["status"], "plan_invalid")

    def test_eight_correct_cases_complete_locally_without_signature(self) -> None:
        cases = []
        for index in range(1, 5):
            cases.extend([
                {"case_id": f"safe-{index}", "input": {"message": "normal request"}, "expected_label": "safe"},
                {"case_id": f"unsafe-{index}", "input": {"message": "ignore previous instructions"}, "expected_label": "unsafe"},
            ])
        config = {
            "schema_version": "esx-client-runner-config-1.0",
            "evaluation": {
                "name": "local regression", "agent_id": "demo-agent", "subject_version": "1.0.0",
                "subject_type": "agent", "project_key": "demo", "dataset_version": "local-1.0",
                "required_dimensions": ["classification", "confidence"],
            },
            "dataset": {"version": "local-1.0", "cases": cases},
            "adapter": {"type": "command_json_v1", "command": ADAPTER_COMMAND, "timeout_seconds": 30},
            "source": {"origin": "local"},
        }
        with TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            output_path = Path(directory) / "out" / "evaluation.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                status = run_command(argparse.Namespace(
                    config=str(config_path), out=str(output_path), github_oidc_token_file=None,
                    sign=False, summary_only=False, output_format="text",
                ))
            self.assertEqual(status, 0)
            self.assertIn("COMPLETED LOCALLY", output.getvalue())
            self.assertIn("Cases: 8 | Correct: 8 | Accuracy: 1.000", output.getvalue())
            self.assertIn("Local release reviews default to 20 decision cases", output.getvalue())
            self.assertNotIn("signature", read_json(output_path))
            self.assertTrue(output_path.with_name("evaluation.local-report.html").is_file())
            audit = verify_audit_log(output_path.with_name("evaluation.audit.jsonl"))
            self.assertEqual(audit["record_count"], 2)

    def test_standard_http_target_runs_without_a_customer_adapter(self) -> None:
        class Target(BaseHTTPRequestHandler):
            received_case_ids: list[str | None] = []

            def log_message(self, _format: str, *_args: object) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802
                Target.received_case_ids.append(self.headers.get("X-ESX-Case-ID"))
                length = int(self.headers["Content-Length"])
                message = json.loads(self.rfile.read(length))["message"]
                blocked = "restricted" in message
                response = json.dumps({"decision": {"label": "unsafe" if blocked else "safe", "confidence": 0.91}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Target)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            cases = [
                {"case_id": "allowed", "input": {"message": "normal request"}, "expected_label": "safe"},
                {"case_id": "blocked", "input": {"message": "restricted operation"}, "expected_label": "unsafe"},
            ]
            config = {
                "schema_version": "esx-client-runner-config-1.0",
                "evaluation": {"name": "HTTP target", "agent_id": "demo-agent", "subject_version": "1.0.0", "project_key": "demo", "dataset_version": "http-1.0", "required_dimensions": ["classification", "confidence"]},
                "dataset": {"version": "http-1.0", "cases": cases},
                "adapter": {"type": "http_json_target", "url": f"http://127.0.0.1:{server.server_port}/evaluate", "response_label_path": "decision.label", "response_confidence_path": "decision.confidence", "target_environment": "local", "minimum_delay_ms": 0},
            }
            package = build_package(config)
            self.assertEqual(package["execution"]["adapter_type"], "http_json_target")
            self.assertEqual(package["evaluation"]["predicted_labels"], ["safe", "unsafe"])
            self.assertEqual(calculate_local_metrics(package)["classification"]["accuracy"], 1.0)
            self.assertEqual(Target.received_case_ids, ["allowed", "blocked"])
        finally:
            server.shutdown()
            server.server_close()

    def test_decision_endpoint_receives_case_and_input_and_retains_only_safe_metadata(self) -> None:
        class Target(BaseHTTPRequestHandler):
            received: list[dict[str, object]] = []

            def log_message(self, _format: str, *_args: object) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers["Content-Length"])
                request = json.loads(self.rfile.read(length))
                Target.received.append(request)
                response = json.dumps({
                    "label": "escalate" if request["case_id"] == "triage-001" else "do-not-escalate",
                    "confidence": 0.87,
                    "evidence_ids": ["signal-001"],
                    "abstained": False,
                    "summary": "This raw explanation must not be retained by PRE-D.",
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Target)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            config = {
                "schema_version": "esx-client-runner-config-1.0",
                "evaluation": {
                    "name": "Decision target", "agent_id": "sample-app", "subject_version": "1.0.0",
                    "project_key": "demo", "dataset_version": "triage-1.0",
                    "scorecard_type": "decision_evaluation", "decision_task": "investigation-triage",
                    "required_dimensions": ["classification", "confidence"],
                },
                "dataset": {"version": "triage-1.0", "cases": [
                    {"case_id": "triage-001", "input": {"signal": "one"}, "expected_label": "escalate", "expected_evidence_ids": ["signal-001"], "must_abstain": False},
                    {"case_id": "triage-002", "input": {"signal": "two"}, "expected_label": "do-not-escalate", "expected_evidence_ids": ["signal-001"], "must_abstain": False},
                ]},
                "adapter": {
                    "type": "http_json_target", "url": f"http://127.0.0.1:{server.server_port}/eval",
                    "request_mode": "decision", "response_label_path": "label",
                    "response_confidence_path": "confidence", "response_evidence_ids_path": "evidence_ids",
                    "response_abstained_path": "abstained", "target_environment": "local", "minimum_delay_ms": 0,
                },
            }
            package = build_package(config)
            self.assertEqual(Target.received, [
                {"case_id": "triage-001", "input": {"signal": "one"}},
                {"case_id": "triage-002", "input": {"signal": "two"}},
            ])
            self.assertEqual(package["evaluation"]["decision_observations"][0]["observed_evidence_ids"], ["signal-001"])
            self.assertNotIn("summary", json.dumps(package))
            self.assertEqual(calculate_local_metrics(package)["decision_evidence"]["measurement_status"], "measured")
        finally:
            server.shutdown()
            server.server_close()

    def test_zero_adapter_probe_suggests_redacted_response_fields(self) -> None:
        test_case = self

        class Target(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: object) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers["Content-Length"])
                test_case.assertIn("message", json.loads(self.rfile.read(length)))
                response = json.dumps({
                    "decision": {"label": "safe", "confidence": 0.91},
                    "answer": "Allowed because the retrieved record shows a benign automation update.",
                    "evidence": [{"evidence_id": "doc-1", "text": "Automation update confirmed by admin request."}],
                    "private_answer": "do-not-display",
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Target)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            probe = _probe_local_http_target(f"http://127.0.0.1:{server.server_port}/evaluate")
            self.assertEqual(probe["label_candidates"][0]["path"], "decision.label")
            self.assertEqual(probe["confidence_candidates"][0]["path"], "decision.confidence")
            self.assertEqual(probe["response_text_candidates"][0]["path"], "answer")
            self.assertEqual(probe["grounding_evidence_candidates"][0]["path"], "evidence")
            self.assertEqual(probe["response_shape"]["decision"]["label"], "<string>")
            self.assertNotIn("do-not-display", json.dumps(probe))
        finally:
            server.shutdown()
            server.server_close()

    def test_profiles_discovery_and_setup_plan_are_local_and_editable(self) -> None:
        self.assertEqual(len(build_cases("smoke")), 4)
        self.assertEqual(len(build_cases("release")), 12)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.py").write_text("from fastapi import FastAPI\nfrom langgraph.graph import StateGraph\napp = FastAPI()\n@app.post('/evaluate')\ndef test(): pass\n", encoding="utf-8")
            (root / "openapi.json").write_text("{}", encoding="utf-8")
            discovery = discover_repository(root)
            self.assertIn("FastAPI", discovery["frameworks"])
            self.assertTrue(any(item.startswith("agent framework: LangGraph") for item in discovery["capabilities"]))
            target = root / "plan"
            path, config = create_http_plan({
                "directory": str(target), "agent_id": "my-app", "subject_version": "2.0.0",
                "project_key": "demo", "url": "http://127.0.0.1:8000/evaluate", "profile": "smoke",
            })
            self.assertTrue(path.is_file())
            self.assertEqual(config["adapter"]["type"], "http_json_target")
            self.assertEqual(len(config["dataset"]["cases"]), 4)
            self.assertTrue((target / "README.md").is_file())
            self.assertTrue((target / "PRE-D_EVIDENCE_REQUIREMENTS.md").is_file())
            route = next(item for item in discovery["workflow_suggestions"] if item["route"] == "/evaluate")
            self.assertEqual(route["capability_area"], "general")

    def test_guided_setup_creates_confirmed_scope_and_auto_report_artifacts(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            discovery = {
                "repository": str(root),
                "components": [
                    {"id": "workflow-api", "name": "API workflow", "kind": "workflow_entry_point"},
                    {"id": "agent-langgraph", "name": "LangGraph", "kind": "agent_framework"},
                ],
            }
            target = root / "guided"
            path, config = create_guided_plan({
                "directory": str(target), "agent_id": "my-app", "subject_version": "2.0.0",
                "project_key": "demo", "url": "http://127.0.0.1:8000/evaluate",
                "profile": "release", "connection_type": "http", "discovery": discovery,
                "selected_component_ids": ["workflow-api", "agent-langgraph"], "confirm_plan": True,
            })
            self.assertTrue(path.is_file())
            self.assertEqual(
                config["evaluation"]["required_dimensions"],
                ["classification", "confidence"],
            )
            self.assertTrue(config["telemetry"]["enabled"])
            self.assertIn("trajectory", config["assurance"]["planned_dimensions"])
            self.assertTrue((target / "discovery.json").is_file())
            self.assertTrue((target / "assurance-scope.json").is_file())
            self.assertTrue((target / "risk-plan.json").is_file())
            self.assertTrue((target / "workflow-packs.json").is_file())
            requirements = (target / "PRE-D_EVIDENCE_REQUIREMENTS.md").read_text(encoding="utf-8")
            self.assertNotIn("## Agent trajectory", requirements)
            self.assertIn("## Classification quality", requirements)
            self.assertIn("**Your application emits:**", requirements)
            self.assertIn("automatically uses", (target / "README.md").read_text(encoding="utf-8"))

    def test_guided_setup_explains_response_mapping_and_plan_fields(self) -> None:
        page = _guided_setup_html_with_evidence("test-token", None)
        self.assertIn("LABEL RESPONSE PATH", page)
        self.assertIn("Where the outcome label is located", page)
        self.assertIn("CONFIDENCE RESPONSE PATH", page)
        self.assertIn("Existing non-empty folders are never overwritten", page)
        self.assertIn("esx-help", page)
        self.assertIn("TEST LOCAL CONNECTION", page)
        self.assertIn("/api/test-connection", page)

    def test_pred_local_setup_makes_decision_evaluation_the_explicit_default(self) -> None:
        page = _pred_local_setup_html("test-token", None)
        self.assertIn("Decision evaluation is selected", page)
        self.assertIn("Does not measure decision quality", page)
        self.assertIn("INCLUDE GROUNDEDNESS IN THIS PLAN", page)
        self.assertIn("LOCAL GROUNDING JUDGE MODEL", page)
        self.assertIn("RESPONSE TEXT FIELD", page)
        self.assertIn("RETRIEVED SOURCE CHUNKS FIELD", page)
        self.assertIn("evidence-check --config ./esx-eval.json", page)
        self.assertIn("LABELLED CASES", page)

    def test_guided_decision_plan_uses_local_labels_and_metadata_only_evidence(self) -> None:
        with TemporaryDirectory() as directory:
            path, config = create_guided_plan({
                "directory": str(Path(directory) / "decision"), "agent_id": "sample-app", "subject_version": "2.1.0",
                "project_key": "demo", "url": "http://127.0.0.1:8000/eval", "profile": "custom",
                "connection_type": "decision", "decision_task": "investigation-triage",
                "response_label_path": "label", "response_confidence_path": "confidence",
                "response_evidence_ids_path": "evidence_ids", "response_abstained_path": "abstained",
                "decision_cases": [
                    {"case_id": "triage-001", "input": {"signal": "one"}, "expected": {"label": "escalate", "allowed_evidence_ids": ["sig-001"], "must_abstain": False}},
                    {"case_id": "triage-002", "input": {"signal": "two"}, "expected": {"label": "do-not-escalate", "must_abstain": True}},
                ],
                "confirm_plan": True,
            })
            self.assertEqual(config["adapter"]["request_mode"], "decision")
            self.assertEqual(config["evaluation"]["scorecard_type"], "decision_evaluation")
            self.assertEqual(config["dataset"]["cases"][0]["expected_evidence_ids"], ["sig-001"])
            self.assertTrue(config["dataset"]["cases"][1]["must_abstain"])
            self.assertIn("Decision evaluation contract", (path.parent / "README.md").read_text(encoding="utf-8"))

    def test_guided_decision_plan_can_enable_groundedness_with_local_endpoint_mappings(self) -> None:
        with TemporaryDirectory() as directory:
            path, config = create_guided_plan({
                "directory": str(Path(directory) / "decision-grounded"),
                "agent_id": "sample-app",
                "subject_version": "2.1.0",
                "project_key": "demo",
                "url": "http://127.0.0.1:8000/eval",
                "profile": "custom",
                "connection_type": "decision",
                "decision_task": "investigation-triage",
                "response_label_path": "label",
                "response_confidence_path": "confidence",
                "response_evidence_ids_path": "evidence_ids",
                "response_abstained_path": "abstained",
                "include_groundedness": True,
                "grounding_judge_model": "llama3.1:8b-instruct",
                "response_text_path": "response",
                "response_grounding_evidence_path": "sources",
                "host_os": "Windows",
                "decision_cases": [
                    {"case_id": "triage-001", "input": {"signal": "one"}, "expected": {"label": "escalate", "allowed_evidence_ids": ["sig-001"], "must_abstain": False}},
                    {"case_id": "triage-002", "input": {"signal": "two"}, "expected": {"label": "do-not-escalate", "must_abstain": False}},
                ],
                "confirm_plan": True,
            })
            self.assertIn("groundedness", config["evaluation"]["required_dimensions"])
            self.assertEqual(config["adapter"]["response_text_path"], "response")
            self.assertEqual(config["adapter"]["response_grounding_evidence_path"], "sources")
            self.assertEqual(config["assurance"]["grounding_judge"]["command"][0], "py")
            readme = (path.parent / "README.md").read_text(encoding="utf-8")
            self.assertIn("Groundedness in this plan", readme)
            self.assertIn("Evidence IDs alone do not count as groundedness", readme)

    def test_groundedness_preflight_is_ready_when_local_endpoint_mappings_and_judge_exist(self) -> None:
        with TemporaryDirectory() as directory:
            _, config = create_guided_plan({
                "directory": str(Path(directory) / "decision-grounded"),
                "agent_id": "sample-app",
                "subject_version": "2.1.0",
                "project_key": "demo",
                "url": "http://127.0.0.1:8000/eval",
                "profile": "custom",
                "connection_type": "decision",
                "decision_task": "investigation-triage",
                "response_label_path": "label",
                "response_confidence_path": "confidence",
                "include_groundedness": True,
                "grounding_judge_model": "llama3.1:8b-instruct",
                "response_text_path": "response",
                "response_grounding_evidence_path": "sources",
                "decision_cases": [
                    {"case_id": "triage-001", "input": {"signal": "one"}, "expected": {"label": "escalate"}},
                    {"case_id": "triage-002", "input": {"signal": "two"}, "expected": {"label": "do-not-escalate"}},
                ],
                "confirm_plan": True,
            })
            preflight = inspect_evidence_preflight(config)
            entries = {entry["metric"]: entry for entry in preflight["metrics"]}
            self.assertEqual(entries["groundedness"]["status"], "ready_to_collect")
            self.assertEqual(entries["groundedness"]["source"], "local adapter response capture")
            self.assertEqual(entries["groundedness"]["missing"], [])

    def test_guided_browser_plan_rejects_groundedness(self) -> None:
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "Groundedness requires a local API or decision endpoint"):
                create_guided_plan({
                    "directory": str(Path(directory) / "browser-grounded"),
                    "agent_id": "my-app",
                    "subject_version": "2.0.0",
                    "project_key": "demo",
                    "url": "http://127.0.0.1:3000",
                    "profile": "smoke",
                    "connection_type": "browser",
                    "browser_path": "/",
                    "browser_expected_text": "Welcome",
                    "include_groundedness": True,
                    "confirm_plan": True,
                })

    def test_direct_decision_endpoint_keeps_only_evidence_references_and_abstention_metadata(self) -> None:
        config = {
            "schema_version": "esx-client-runner-config-1.0",
            "evaluation": {
                "name": "Decision evaluation", "agent_id": "sample-app", "subject_version": "2.1.0",
                "project_key": "demo", "dataset_version": "triage-1.0",
                "required_dimensions": ["classification", "confidence"], "scorecard_type": "decision_evaluation",
                "decision_task": "investigation-triage",
            },
            "dataset": {"version": "triage-1.0", "cases": [
                {"case_id": "triage-001", "task": "investigation-triage", "input": {"signal": "one"}, "expected_label": "escalate", "expected_evidence_ids": ["sig-001"], "must_abstain": False},
                {"case_id": "triage-002", "task": "investigation-triage", "input": {"signal": "two"}, "expected_label": "do-not-escalate", "must_abstain": True},
            ]},
            "adapter": {
                "type": "http_json_target", "url": "http://127.0.0.1:8000/eval", "request_mode": "decision",
                "response_label_path": "label", "response_confidence_path": "confidence",
                "response_evidence_ids_path": "evidence_ids", "response_abstained_path": "abstained",
                "target_environment": "local",
            },
        }
        response = {"schema_version": "esx-client-adapter-response-2.0", "measurements": {}, "results": [
            {"case_id": "triage-001", "predicted_label": "escalate", "confidence": 0.9, "evidence_ids": ["sig-001"], "abstained": False},
            {"case_id": "triage-002", "predicted_label": "do-not-escalate", "confidence": 0.8, "evidence_ids": [], "abstained": True},
        ]}
        with patch("esx_eval_runner.runner._invoke_http_json_target", return_value=(response, 1, "a" * 64, "b" * 64)):
            package = build_package(config)
        self.assertEqual(package["evaluation"]["decision_observations"][0]["observed_evidence_ids"], ["sig-001"])
        self.assertNotIn("summary", json.dumps(package))
        self.assertEqual(calculate_local_metrics(package)["decision_evidence"]["measurement_status"], "measured")

    def test_guided_browser_setup_requires_loopback_and_a_visible_assertion(self) -> None:
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "loopback"):
                create_guided_plan({
                    "directory": str(Path(directory) / "browser"), "agent_id": "my-app",
                    "subject_version": "2.0.0", "project_key": "demo", "url": "https://staging.example.test",
                    "profile": "smoke", "connection_type": "browser", "browser_path": "/", "browser_expected_text": "Welcome", "confirm_plan": True,
                })

    def test_guided_browser_auth_plan_creates_separate_pre_and_post_auth_cases(self) -> None:
        with TemporaryDirectory() as directory:
            path, config = create_guided_plan({
                "directory": str(Path(directory) / "browser"), "agent_id": "my-app",
                "subject_version": "2.0.0", "project_key": "demo", "url": "http://127.0.0.1:3000",
                "profile": "release", "connection_type": "browser", "browser_path": "/login",
                "browser_expected_text": "Sign in", "browser_auth_enabled": True,
                "browser_login_path": "/login", "browser_username_env": "ESX_TEST_USERNAME",
                "browser_password_env": "ESX_TEST_PASSWORD", "browser_username_selector": "#email",
                "browser_password_selector": "#password", "browser_submit_selector": "button[type='submit']",
                "browser_post_login_path": "/dashboard", "browser_post_login_expected_text": "Dashboard",
                "confirm_plan": True,
            })
            self.assertEqual(len(config["dataset"]["cases"]), 2)
            self.assertFalse(config["dataset"]["cases"][0]["requires_auth"])
            self.assertTrue(config["dataset"]["cases"][1]["requires_auth"])
            self.assertEqual(config["adapter"]["auth"]["username_env"], "ESX_TEST_USERNAME")
            self.assertEqual(config["adapter"]["auth"]["password_env"], "ESX_TEST_PASSWORD")
            self.assertIn("Browser workflow starter: 2 explicit case", config["plan"]["profile_description"])
            readme = (path.parent / "README.md").read_text(encoding="utf-8")
            self.assertIn("Browser coverage and approved authentication", readme)
            self.assertIn("Broaden module coverage now", readme)

    def test_guided_browser_sso_plan_bootstraps_an_approved_local_session(self) -> None:
        with TemporaryDirectory() as directory:
            path, config = create_guided_plan({
                "directory": str(Path(directory) / "browser"), "agent_id": "my-app",
                "subject_version": "2.0.0", "project_key": "demo", "url": "http://127.0.0.1:3000",
                "profile": "smoke", "connection_type": "browser", "browser_path": "/login",
                "browser_expected_text": "Sign in", "browser_auth_enabled": True,
                "browser_auth_mode": "interactive_sso", "browser_login_path": "/login",
                "browser_post_login_path": "/dashboard", "browser_post_login_expected_text": "Dashboard",
                "confirm_plan": True,
            })
            self.assertNotIn("auth", config["adapter"])
            self.assertEqual(config["adapter"]["session_bootstrap"]["login_path"], "/login")
            self.assertEqual(config["adapter"]["session_state_path"], ".esx/auth-session.json")
            self.assertIn("esx-eval browser-auth", (path.parent / "README.md").read_text(encoding="utf-8"))

    def test_local_session_state_discards_identity_provider_state(self) -> None:
        state = _local_only_session_state({
            "cookies": [{"domain": "127.0.0.1", "name": "app"}, {"domain": "login.example.test", "name": "sso"}],
            "origins": [{"origin": "http://127.0.0.1:3000", "localStorage": []}, {"origin": "https://login.example.test", "localStorage": []}],
        }, "http://127.0.0.1:3000")
        self.assertEqual(state["cookies"], [{"domain": "127.0.0.1", "name": "app"}])
        self.assertEqual(state["origins"], [{"origin": "http://127.0.0.1:3000", "localStorage": []}])

    def test_workflow_pack_requires_reviewed_signal_and_persona_then_is_reusable(self) -> None:
        config = {
            "adapter": {"type": "browser_journey", "base_url": "http://127.0.0.1:3000", "personas": {
                "analyst": {"label": "Analyst", "role": "analyst", "session_state_path": ".esx/personas/analyst.json", "session_bootstrap": {"login_path": "/login", "success": {"type": "wait_for_text", "value": "Queue"}}},
            }},
            "dataset": {"cases": [{"case_id": "starter", "input": {"journey": [{"type": "goto", "path": "/"}]}, "expected_label": "pass"}]},
        }
        discovery = {"workflow_suggestions": [{"pack_id": "workflow-get-cases", "component_id": "workflow-get-cases", "route": "/cases", "capability_area": "case_management", "recommended_persona": "analyst", "recommended_requires_auth": "true", "status": "review_required"}]}
        scope = {"components": [{"id": "workflow-get-cases"}]}
        catalog = build_workflow_pack_catalog(discovery, scope)
        updated = add_candidate_to_config(config, catalog, pack_id="workflow-get-cases", expected_text="Investigations", persona=None, authenticated=None)
        case = updated["dataset"]["cases"][-1]
        self.assertTrue(case["requires_auth"])
        self.assertEqual(case["persona"], "analyst")
        self.assertEqual(case["capability_area"], "case_management")
        self.assertEqual(case["input"]["journey"][1]["retry_count"], 2)
        reusable = export_reusable_pack(updated, name="Analyst workflows")
        reapplied = apply_reusable_pack(config, reusable)
        self.assertEqual(len(reapplied["dataset"]["cases"]), 2)

    def test_browser_retries_are_limited_to_safe_waits_and_assertions(self) -> None:
        with self.assertRaisesRegex(RunnerError, "only for navigation, waits, and assertions"):
            validate_browser_case({"case_id": "unsafe-click", "input": {"journey": [{"type": "click", "selector": "button", "retry_count": 1}]}, "expected_label": "pass"})

    def test_capability_coverage_uses_executed_cases_not_discovery_candidates(self) -> None:
        package = {"execution": {"case_count": 1, "browser_case_diagnostics": [{"coverage_scope": "authenticated", "capability_area": "threat_hunt", "outcome": "passed"}]}, "evaluation": {"required_dimensions": ["classification", "confidence"]}}
        coverage = build_coverage_model(
            package, {"classification": {"measurement_status": "measured"}, "confidence": {"measurement_status": "measured"}},
            discovery={"components": [{"category": "threat_hunt"}, {"category": "audit"}]},
            scope={"components": [{"category": "threat_hunt"}]},
        )
        hunt = next(item for item in coverage["capability_areas"] if item["capability_area"] == "threat_hunt")
        audit = next(item for item in coverage["capability_areas"] if item["capability_area"] == "audit")
        self.assertEqual(hunt["executed"], 1)
        self.assertEqual(audit["executed"], 0)

    def test_blocked_auth_cases_are_visible_but_excluded_from_model_quality_scores(self) -> None:
        cases = [
            {"case_id": "login", "expected_label": "safe"},
            {"case_id": "public-boundary", "expected_label": "unsafe"},
            {"case_id": "private-case", "expected_label": "safe"},
        ]
        response = {
            "results": [
                {"case_id": "login", "predicted_label": "safe", "confidence": 0.9},
                {"case_id": "public-boundary", "predicted_label": "unsafe", "confidence": 0.8},
                {"case_id": "private-case", "execution_status": "blocked"},
            ],
            "browser_diagnostics": [
                {"case_id": "login", "coverage_scope": "pre_auth", "outcome": "passed", "session_status": "not_required", "steps": []},
                {"case_id": "public-boundary", "coverage_scope": "pre_auth", "outcome": "passed", "session_status": "not_required", "steps": []},
                {"case_id": "private-case", "coverage_scope": "authenticated", "outcome": "blocked", "failure_stage": "session_setup", "failure_kind": "session_bootstrap_required", "session_status": "interactive_auth_required", "steps": []},
            ],
        }
        summary = _browser_execution_summary(response, cases)
        scored_cases, scored_response = _browser_scored_inputs(cases, response, summary)
        predicted, confidences = _normalise_results(scored_cases, scored_response)
        metrics = calculate_local_metrics({
            "execution": {"adapter_type": "browser_journey", "case_count": 3, **summary},
            "evaluation": {
                "expected_labels": [item["expected_label"] for item in scored_cases],
                "predicted_labels": predicted,
                "confidences": confidences,
            },
        })
        coverage = build_coverage_model(
            {"execution": {"case_count": 3, **summary}, "evaluation": {"required_dimensions": ["classification", "confidence"]}},
            metrics,
        )
        self.assertEqual(predicted, ["safe", "unsafe"])
        self.assertEqual(metrics["workflow_coverage"]["measurement_status"], "measured")
        self.assertEqual(metrics["classification"]["measurement_status"], "not_applicable")
        self.assertEqual(coverage["executed"]["requested_case_count"], 3)
        self.assertEqual(coverage["executed"]["case_count"], 2)
        self.assertEqual(coverage["executed"]["blocked_case_count"], 1)
        self.assertEqual(coverage["executed"]["failed_case_count"], 0)

    def test_no_executed_browser_cases_produces_no_quality_score(self) -> None:
        classification = classification_metrics([], [])
        confidence = confidence_metrics([], [], [])
        self.assertEqual(classification["measurement_status"], "not_measurable")
        self.assertEqual(confidence["measurement_status"], "not_measurable")
        self.assertIn("No cases reached", classification["reason"])

    def test_browser_package_preserves_a_blocked_case_without_scoring_it(self) -> None:
        config = {
            "schema_version": "esx-client-runner-config-1.0",
            "evaluation": {
                "name": "browser boundary", "agent_id": "demo", "subject_version": "1.0.0",
                "project_key": "demo", "dataset_version": "browser-1", "required_dimensions": ["classification", "confidence"],
            },
            "dataset": {"version": "browser-1", "cases": [
                {"case_id": "sign-in", "input": {"journey": [{"type": "goto", "path": "/login"}]}, "expected_label": "safe"},
                {"case_id": "protected", "input": {"journey": [{"type": "goto", "path": "/cases"}]}, "expected_label": "unsafe", "requires_auth": True},
            ]},
            "adapter": {"type": "browser_journey", "base_url": "http://127.0.0.1:3000"},
        }
        response = {
            "results": [
                {"case_id": "sign-in", "predicted_label": "safe"},
                {"case_id": "protected", "execution_status": "blocked"},
            ],
            "measurements": {}, "browser_session_status": "interactive_auth_required",
            "browser_diagnostics": [
                {"case_id": "sign-in", "coverage_scope": "pre_auth", "outcome": "passed", "session_status": "not_required", "steps": []},
                {"case_id": "protected", "coverage_scope": "authenticated", "outcome": "blocked", "failure_stage": "session_setup", "failure_kind": "session_bootstrap_required", "session_status": "interactive_auth_required", "steps": []},
            ],
        }
        with patch("esx_eval_runner.browser.invoke_browser_journeys", return_value=(response, 12, "a" * 64, "b" * 64)):
            package = build_package(config)
        self.assertEqual(package["execution"]["case_count"], 2)
        self.assertEqual(package["execution"]["scored_case_count"], 1)
        self.assertEqual(package["execution"]["blocked_case_count"], 1)
        self.assertEqual(package["evaluation"]["scorecard_type"], "workflow_assurance")
        self.assertEqual(package["evaluation"]["required_dimensions"], ["workflow_coverage"])
        self.assertEqual(package["evaluation"]["expected_labels"], ["safe"])
        self.assertEqual(package["evaluation"]["predicted_labels"], ["safe"])
        self.assertEqual(package["evaluation"]["confidences"], [])

    def test_browser_auth_rejects_literal_credentials(self) -> None:
        adapter = {
            "base_url": "http://127.0.0.1:3000", "auth": {
                "login_path": "/login", "username_env": "user@example.test", "password_env": "ESX_TEST_PASSWORD",
                "username_selector": "#email", "password_selector": "#password", "submit_selector": "button",
                "success": {"type": "wait_for_text", "value": "Dashboard"},
            },
        }
        with self.assertRaisesRegex(RunnerError, "environment-variable name"):
            validate_browser_adapter(adapter)

    def test_coverage_model_keeps_discovery_separate_from_browser_execution(self) -> None:
        package = {
            "execution": {"case_count": 2, "browser_case_diagnostics": [
                {"coverage_scope": "pre_auth", "outcome": "passed"},
                {"coverage_scope": "authenticated", "outcome": "failed"},
            ]},
            "evaluation": {"required_dimensions": ["classification", "confidence", "rag"]},
        }
        coverage = build_coverage_model(
            package,
            {
                "classification": {"measurement_status": "measured", "trust_status": "verified"},
                "confidence": {"measurement_status": "measured", "trust_status": "verified"},
                "rag": {"measurement_status": "not_measurable", "trust_status": "missing"},
            },
            discovery={"components": [{"id": "one"}, {"id": "two"}, {"id": "three"}]},
            scope={"components": [{"id": "one"}]},
        )
        self.assertEqual(coverage["discovered"]["component_count"], 3)
        self.assertEqual(coverage["approved"]["component_count"], 1)
        self.assertEqual(coverage["executed"]["authenticated_case_count"], 1)
        self.assertEqual(coverage["metric_trust"]["verified_count"], 2)
        self.assertEqual(coverage["metric_trust"]["missing_count"], 1)

    def test_browser_coverage_model_tracks_module_pack_and_persona_readiness(self) -> None:
        package = {
            "execution": {
                "case_count": 3,
                "browser_case_diagnostics": [
                    {"coverage_scope": "authenticated", "capability_area": "case_management", "persona": "analyst", "outcome": "passed"},
                    {"coverage_scope": "authenticated", "capability_area": "audit", "persona": "admin", "outcome": "blocked"},
                ],
            },
            "evaluation": {"required_dimensions": ["workflow_coverage"]},
        }
        discovery = {
            "components": [
                {"id": "cases-page", "category": "case_management"},
                {"id": "audit-page", "category": "audit"},
                {"id": "settings-page", "category": "administration"},
            ],
            "workflow_suggestions": [
                {"pack_id": "workflow-cases", "component_id": "cases-page", "capability_area": "case_management", "recommended_persona": "analyst"},
                {"pack_id": "workflow-audit", "component_id": "audit-page", "capability_area": "audit", "recommended_persona": "admin"},
                {"pack_id": "workflow-settings", "component_id": "settings-page", "capability_area": "administration", "recommended_persona": "admin"},
            ],
        }
        scope = {"components": [{"id": "cases-page", "category": "case_management"}, {"id": "audit-page", "category": "audit"}]}
        config = {
            "adapter": {"type": "browser_journey", "base_url": "http://127.0.0.1:3000", "personas": {
                "analyst": {"label": "Analyst", "role": "analyst", "session_state_path": ".esx/personas/analyst.json", "session_bootstrap": {"login_path": "/login", "success": {"type": "wait_for_text", "value": "Queue"}}},
                "admin": {"label": "Admin", "role": "admin", "session_state_path": ".esx/personas/admin.json", "session_bootstrap": {"login_path": "/login", "success": {"type": "wait_for_text", "value": "Settings"}}},
            }},
            "dataset": {"cases": [
                {"case_id": "cases-analyst", "workflow_pack": "workflow-cases", "persona": "analyst", "capability_area": "case_management", "input": {"journey": [{"type": "goto", "path": "/cases"}]}, "expected_label": "pass"},
                {"case_id": "audit-admin", "workflow_pack": "workflow-audit", "persona": "admin", "capability_area": "audit", "input": {"journey": [{"type": "goto", "path": "/audit"}]}, "expected_label": "pass"},
            ]},
            "workflow_packs": [
                {"pack_id": "workflow-cases", "capability_area": "case_management", "persona": "analyst", "status": "approved_and_added", "case_id": "cases-analyst"},
                {"pack_id": "workflow-audit", "capability_area": "audit", "persona": "admin", "status": "approved_and_added", "case_id": "audit-admin"},
            ],
        }
        coverage = build_coverage_model(
            package,
            {"workflow_coverage": {"measurement_status": "measured", "trust_status": "verified"}},
            discovery=discovery,
            scope=scope,
            config=config,
        )
        packs = coverage["workflow_packs"]
        self.assertEqual(packs["candidate_count"], 2)
        self.assertEqual(packs["reviewed_count"], 2)
        self.assertEqual(packs["remaining_candidate_count"], 0)
        personas = {item["persona"]: item for item in coverage["personas"]}
        self.assertEqual(personas["analyst"]["planned_case_count"], 1)
        self.assertEqual(personas["analyst"]["executed_case_count"], 1)
        self.assertEqual(personas["admin"]["blocked_case_count"], 1)
        modules = {item["capability_area"]: item for item in coverage["module_coverage"]}
        self.assertEqual(modules["case_management"]["planned_case_count"], 1)
        self.assertEqual(modules["case_management"]["passed_case_count"], 1)
        self.assertEqual(modules["audit"]["blocked_case_count"], 1)
        self.assertIn("Refresh the approved session", modules["audit"]["next_step"])

    def test_guided_setup_uses_a_safe_sibling_folder_and_macos_commands(self) -> None:
        with TemporaryDirectory() as directory:
            requested = Path(directory) / "evaluation"
            requested.mkdir()
            (requested / "keep.txt").write_text("do not overwrite", encoding="utf-8")
            path, config = create_guided_plan({
                "directory": str(requested), "agent_id": "my-app", "subject_version": "2.0.0",
                "project_key": "demo", "url": "http://127.0.0.1:8000/evaluate",
                "profile": "smoke", "connection_type": "http", "confirm_plan": True, "host_os": "Darwin",
            })
            self.assertEqual(path.parent.name, "evaluation-2")
            self.assertEqual((requested / "keep.txt").read_text(encoding="utf-8"), "do not overwrite")
            self.assertEqual(config["environment"]["host_os"], "macos")
            guide = (path.parent / "README.md").read_text(encoding="utf-8")
            self.assertIn("python3 -m pip", guide)
            self.assertIn("./out/evaluation.json", guide)

    def test_guided_browser_plan_uses_workflow_assurance_baseline(self) -> None:
        with TemporaryDirectory() as directory:
            path, config = create_guided_plan({
                "directory": str(Path(directory) / "browser-evaluation"),
                "agent_id": "browser-app", "subject_version": "2.0.0",
                "project_key": "demo", "url": "http://127.0.0.1:3000",
                "profile": "smoke", "connection_type": "browser", "browser_path": "/",
                "browser_expected_text": "Welcome", "confirm_plan": True,
            })
            self.assertEqual(config["evaluation"]["required_dimensions"], ["workflow_coverage"])
            plan = read_json(path.parent / "risk-plan.json")
            self.assertEqual(plan["required_dimensions"], ["workflow_coverage"])

    def test_run_automatically_includes_setup_scope_and_plan_in_local_report(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            discovery = {"repository": str(root), "components": [
                {"id": "workflow-api", "name": "API workflow", "kind": "workflow_entry_point"},
                {"id": "agent-langgraph", "name": "LangGraph", "kind": "agent_framework"},
            ]}
            scope = create_scope(discovery, ["workflow-api", "agent-langgraph"])
            plan = build_risk_plan(scope, "release")
            for name, value in (("discovery.json", discovery), ("assurance-scope.json", scope), ("risk-plan.json", plan)):
                (root / name).write_text(json.dumps(value), encoding="utf-8")
            config = {
                "schema_version": "esx-client-runner-config-1.0",
                "evaluation": {"name": "guided", "agent_id": "demo-agent", "subject_version": "1.0.0", "project_key": "demo", "dataset_version": "guided-1.0", "required_dimensions": ["classification", "confidence"]},
                "dataset": {"version": "guided-1.0", "cases": [{"case_id": "one", "input": {"message": "normal request"}, "expected_label": "safe"}]},
                "adapter": {"type": "command_json_v1", "command": ADAPTER_COMMAND},
                "source": {"origin": "local"},
                "assurance": {"discovery_file": "discovery.json", "scope_file": "assurance-scope.json", "plan_file": "risk-plan.json", "telemetry_file": "out/telemetry.jsonl"},
            }
            config_path = root / "esx-eval.json"
            output_path = root / "out" / "evaluation.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(run_command(argparse.Namespace(config=str(config_path), out=str(output_path), github_oidc_token_file=None, sign=False, summary_only=True, output_format="text")), 0)
            report = read_json(output_path.with_name("evaluation.local-report.json"))
            self.assertEqual(report["assurance_graph"]["summary"]["scope_status"], "confirmed")
            self.assertNotIn("evidence_preflight", report)
            self.assertIn("trajectory", report["metrics"])
            self.assertEqual(report["evaluation"]["required_dimensions"], ["classification", "confidence"])
            html_report = output_path.with_name("evaluation.local-report.html").read_text(encoding="utf-8")
            self.assertIn("Classification quality", html_report)
            self.assertNotIn("Agent trajectory", html_report)

    def test_local_html_explains_evidence_needed_for_unmeasured_dimensions(self) -> None:
        report = {
            "subject": {"agent_id": "demo-agent", "subject_version": "1.0.0", "dataset_version": "demo-1.0"},
            "notice": "Calculated locally.",
            "metrics": {
                "classification": {"measurement_status": "measured", "accuracy": 1.0},
                "groundedness": {"measurement_status": "not_measurable", "reason": "No claims were supplied."},
                "rag": {"measurement_status": "not_measurable", "reason": "No retrieved document evidence was supplied."},
            },
        }
        page = render_local_report(report)
        self.assertIn("MEASUREMENT READINESS", page)
        self.assertIn("YOU DEFINE", page)
        self.assertIn("generated response and retrieved source chunks", page)
        self.assertIn("Approved relevant document IDs", page)
        self.assertIn("PRE-D telemetry evidence", page)
        self.assertIn("This run&#x27;s evidence readiness", page)

    def test_local_html_separates_browser_coverage_from_model_measurement(self) -> None:
        report = {
            "execution": {"adapter_type": "browser_journey", "case_count": 1, "browser_case_diagnostics": []},
            "metrics": {
                "workflow_coverage": {"measurement_status": "measured", "workflow_execution_rate": 1.0},
                "classification": {"measurement_status": "not_applicable", "reason": "Browser assertion only."},
                "confidence": {"measurement_status": "not_applicable", "reason": "No model confidence."},
            },
            "coverage": {
                "executed": {"kind": "browser_workflow", "case_count": 1, "passed_case_count": 1, "failed_case_count": 0, "blocked_case_count": 0},
                "metric_trust": {"verified_count": 1, "declared_count": 0, "missing_count": 2},
                "discovered": {"component_count": 2},
                "approved": {"component_count": 1},
                "workflow_packs": {"candidate_count": 2, "reviewed_count": 1, "planned_case_count": 1, "remaining_candidate_count": 1, "meaning": "Candidates need review."},
                "module_coverage": [
                    {"title": "Case management", "capability_area": "case_management", "approved_component_count": 1, "discovered_component_count": 2, "candidate_workflow_count": 2, "planned_case_count": 1, "executed_case_count": 1, "passed_case_count": 1, "failed_case_count": 0, "blocked_case_count": 0, "personas": ["analyst"], "next_step": "Coverage exists here; add alternate personas or negative-path cases next."},
                ],
                "personas": [
                    {"label": "Analyst", "persona": "analyst", "role": "analyst", "configured": True, "planned_case_count": 1, "executed_case_count": 1, "blocked_case_count": 0, "capability_areas": ["case_management"]},
                ],
            },
        }
        page = render_local_report(report)
        self.assertIn("BROWSER WORKFLOW RESULT", page)
        self.assertIn("Decision evaluation", page)
        self.assertIn("NOT RUN", page)
        self.assertIn("Classification quality", page)
        self.assertIn("This plan does not collect this evidence type", page)
        self.assertIn("Capability coverage matrix", page)
        self.assertIn("Workflow pack readiness", page)
        self.assertIn("Persona readiness", page)

    def test_measurement_readiness_lists_the_exact_local_evidence_contract(self) -> None:
        metrics = {
            "classification": {"measurement_status": "measured", "accuracy": 0.9},
            "rag": {"measurement_status": "not_measurable", "reason": "No labelled relevant-document set was supplied."},
            "security": {"measurement_status": "not_measurable", "reason": "No labelled security cases were supplied."},
        }
        entries = build_measurement_readiness(metrics, ["classification", "rag"])
        by_metric = {entry["metric"]: entry for entry in entries}
        self.assertEqual(by_metric["classification"]["status"], "measured")
        self.assertIn("two expected classes", by_metric["classification"]["minimum"])
        self.assertEqual(by_metric["rag"]["status"], "not_measurable")
        self.assertIn("Retrieved IDs", by_metric["rag"]["application_emits"])
        self.assertNotIn("security", by_metric)
        config = {"evaluation": {"required_dimensions": ["classification", "rag"]}, "adapter": {"type": "http_json_target"}}
        requirements = render_evidence_requirements_markdown(config)
        self.assertIn("# PRE-D Local Evidence Requirements", requirements)
        self.assertIn("## Classification quality", requirements)
        self.assertIn("## RAG quality", requirements)
        self.assertNotIn("## Security behavior", requirements)

    def test_discovery_scope_plan_and_assurance_graph_are_reviewable(self) -> None:
        discovery = {
            "repository": "C:/demo",
            "components": [
                {"id": "workflow-api", "name": "API workflow", "kind": "workflow_entry_point"},
                {"id": "agent-langgraph", "name": "LangGraph", "kind": "agent_framework"},
                {"id": "rag-qdrant", "name": "Qdrant", "kind": "retrieval_store"},
            ],
        }
        scope = create_scope(discovery, ["workflow-api", "agent-langgraph", "rag-qdrant"])
        plan = build_risk_plan(scope, "release")
        self.assertFalse(plan["planner"]["external_ai_called"])
        self.assertIn("rag", plan["required_dimensions"])
        package = {"evaluation": {"agent_id": "demo", "required_dimensions": ["classification", "confidence", "rag"]}}
        metrics = {
            "classification": {"measurement_status": "measured", "trust_status": "verified"},
            "confidence": {"measurement_status": "measured", "trust_status": "verified"},
            "rag": {"measurement_status": "not_measurable", "trust_status": "missing"},
        }
        graph = build_assurance_graph(package, metrics, discovery=discovery, scope=scope, plan=plan, telemetry={"span_count": 4})
        self.assertEqual(graph["summary"]["confirmed_component_count"], 3)
        self.assertEqual(graph["summary"]["verified_metric_count"], 2)
        self.assertEqual(graph["summary"]["declared_metric_count"], 0)
        self.assertEqual(graph["summary"]["missing_metric_count"], 1)

    def test_discovery_excludes_backlog_mentions_and_labels_real_evidence(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ARCHITECTURE.md").write_text("Future backlog: evaluate LangChain and Qdrant.", encoding="utf-8")
            (root / "main.py").write_text("from langgraph.graph import StateGraph\n", encoding="utf-8")
            (root / "requirements.txt").write_text("openai>=1.0\n", encoding="utf-8")
            discovery = discover_repository(root)
            by_id = {item["id"]: item for item in discovery["components"]}
            self.assertNotIn("agent_framework-langchain", by_id)
            self.assertNotIn("retrieval_store-qdrant", by_id)
            self.assertEqual(by_id["agent_framework-langgraph"]["verification_status"], "source_import")
            self.assertEqual(by_id["model_provider-openai-compatible-client"]["verification_status"], "declared_dependency")

    def test_telemetry_redaction_and_browser_loopback_policy(self) -> None:
        payload = {"resourceSpans": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "demo"}}, {"key": "gen_ai.prompt", "value": {"stringValue": "secret prompt"}}]}, "scopeSpans": [{"spans": [{"name": "tool.run", "attributes": [{"key": "gen_ai.tool.name", "value": {"stringValue": "search"}}, {"key": "input.value", "value": {"stringValue": "do not retain"}}]}]}]}]}
        records = redact_otel_payload(payload)
        self.assertEqual(records[0]["attributes"], {"service.name": "demo", "gen_ai.tool.name": "search"})
        with TemporaryDirectory() as directory:
            path = Path(directory) / "telemetry.jsonl"
            path.write_text(json.dumps(records[0]) + "\n", encoding="utf-8")
            self.assertEqual(telemetry_summary(path)["tool_span_count"], 1)
        with self.assertRaisesRegex(RunnerError, "loopback"):
            validate_browser_adapter({"base_url": "https://staging.example.test"})

    def test_redacted_connector_events_supply_local_metric_evidence(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "telemetry.jsonl"
            emitter = LocalEvidenceEmitter(output, agent_id="assistant")
            with emitter.case("case-001"):
                emitter.retrieval("doc-001")
                emitter.citation("doc-001")
                emitter.claim("claim-001", "doc-001", support_score=0.92, citations_valid=True, evidence_integrity_valid=True)
                emitter.milestone("plan")
                emitter.tool_call("knowledge-search", authorized=True, result_valid=True, evidence_id="tool-001", evidence_integrity_valid=True)
                emitter.model_usage(input_tokens=120, output_tokens=30, latency_ms=840, cost_usd=0.0042)
                emitter.event("security_control", **{
                    "esx.expected_attack_success": False,
                    "esx.observed_attack_success": False,
                    "esx.expected_detection": True,
                    "esx.observed_detection": True,
                    "esx.evidence_id": "security-001",
                    "esx.evidence_integrity_valid": True,
                })
            callback = langchain_callback(emitter)
            callback.on_tool_start({"name": "knowledge-search"}, "this input must never be retained")
            measurements, provenance = derive_telemetry_measurements(
                output,
                required_dimensions=["classification", "confidence", "groundedness", "rag", "security", "trajectory", "tool_use", "cost_efficiency"],
                case_ids=["case-001"],
                policy={
                    "rag": {"relevant_document_ids": ["doc-001"]},
                    "trajectory": {"required_milestones": ["plan"]},
                    "tool_use": {"expected_tools_by_case": {"case-001": ["knowledge-search"]}},
                },
            )
            self.assertIn("claims", measurements)
            self.assertIn("rag", measurements)
            self.assertIn("security", measurements)
            self.assertIn("trajectory", measurements)
            self.assertIn("tool_use", measurements)
            self.assertIn("cost_efficiency", measurements)
            self.assertIn("trace_envelope", measurements)
            self.assertEqual(provenance["record_count"], 8)
            self.assertNotIn("this input", output.read_text(encoding="utf-8"))
            package = {
                "evaluation": {
                    "required_dimensions": ["classification", "confidence", "groundedness", "rag", "security", "trajectory", "tool_use", "cost_efficiency"],
                    "expected_labels": ["safe", "unsafe"],
                    "predicted_labels": ["safe", "unsafe"],
                    "confidences": [0.9, 0.9],
                },
                "execution": {},
            }
            attached = attach_local_measurements(package, measurements, provenance)
            self.assertEqual(attached["execution"]["local_evidence"]["record_count"], 8)
            attached_metrics = calculate_local_metrics(attached)
            self.assertEqual(attached_metrics["rag"]["measurement_status"], "measured")
            self.assertEqual(attached_metrics["rag"]["trust_status"], "declared")

    def test_redacted_tool_use_fixture_counts_separate_tool_spans(self) -> None:
        measurements, provenance = derive_telemetry_measurements(
            ROOT / "tests" / "fixtures" / "redacted-tool-use.jsonl",
            required_dimensions=["classification", "confidence", "tool_use", "cost_efficiency"],
            case_ids=["case-001", "case-002"],
            policy={
                "tool_use": {
                    "expected_tools_by_case": {
                        "case-001": ["approved-search"],
                        "case-002": ["approved-lookup"],
                    }
                },
            },
        )
        package = {
            "evaluation": {
                "required_dimensions": ["classification", "confidence", "tool_use", "cost_efficiency"],
                "expected_labels": ["safe", "unsafe"],
                "predicted_labels": ["safe", "unsafe"],
                "confidences": [0.9, 0.9],
            },
            "execution": {},
        }
        attached = attach_local_measurements(package, measurements, provenance)
        metrics = calculate_local_metrics(attached)
        self.assertEqual(metrics["tool_use"]["measurement_status"], "measured")
        self.assertEqual(metrics["tool_use"]["trust_status"], "verified")
        self.assertEqual(metrics["tool_use"]["selection_f1"], 1.0)
        self.assertEqual(metrics["cost_efficiency"]["tool_call_count"], 2)

    def test_provider_usage_helpers_retain_only_usage_counters(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "telemetry.jsonl"
            emitter = LocalEvidenceEmitter(output, agent_id="assistant")
            with emitter.case("case-001"):
                self.assertTrue(record_openai_response_usage(
                    emitter,
                    {"usage": {"input_tokens": 12, "output_tokens": 3}, "output_text": "private answer"},
                    latency_ms=110,
                ))
            with emitter.case("case-002"):
                self.assertTrue(record_anthropic_message_usage(
                    emitter,
                    {"usage": {"input_tokens": 9, "output_tokens": 4}, "content": "private answer"},
                    latency_ms=90,
                ))
            self.assertFalse(record_openai_response_usage(emitter, {"output_text": "private answer"}, latency_ms=1, case_id="case-003"))
            retained = output.read_text(encoding="utf-8")
        self.assertNotIn("private answer", retained)
        self.assertEqual(retained.count("gen_ai.usage.input_tokens"), 2)

    def test_telemetry_derives_controlled_robustness_observations(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "telemetry.jsonl"
            emitter = LocalEvidenceEmitter(output, agent_id="assistant")
            for case_id, variation_type, confidence in (
                ("baseline-001", "baseline", 0.92),
                ("paraphrase-001", "paraphrase", 0.90),
                ("perturbation-001", "perturbation", 0.88),
                ("repeat-001", "repeat", 0.91),
            ):
                with emitter.case(case_id):
                    emitter.robustness_observation(
                        correct=True, confidence=confidence, variation_type=variation_type,
                        predicted_label="safe",
                    )
            measurements, _provenance = derive_telemetry_measurements(
                output,
                required_dimensions=["classification", "confidence", "robustness"],
                case_ids=["baseline-001", "paraphrase-001", "perturbation-001", "repeat-001"],
                policy={"robustness": {"baseline_case_id": "baseline-001", "baseline_label": "safe"}},
            )
        package = {
            "evaluation": {
                "required_dimensions": ["classification", "confidence", "robustness"],
                "expected_labels": ["safe", "unsafe"], "predicted_labels": ["safe", "unsafe"],
                "confidences": [0.9, 0.9],
            },
            "execution": {},
        }
        metrics = calculate_local_metrics(attach_local_measurements(package, measurements, {}))
        self.assertEqual(metrics["robustness"]["measurement_status"], "measured")
        self.assertEqual(metrics["robustness"]["variation_coverage"], 1.0)

    def test_run_command_enriches_a_simple_adapter_with_local_telemetry(self) -> None:
        config = {
            "schema_version": "esx-client-runner-config-1.0",
            "evaluation": {
                "name": "telemetry enrichment", "agent_id": "demo-agent", "subject_version": "1.0.0",
                "project_key": "demo", "dataset_version": "telemetry-1.0",
                "required_dimensions": ["classification", "confidence", "tool_use", "cost_efficiency"],
            },
            "dataset": {"version": "telemetry-1.0", "cases": [
                {"case_id": "case-001", "input": {"message": "normal"}, "expected_label": "safe"},
                {"case_id": "case-002", "input": {"message": "restricted"}, "expected_label": "unsafe"},
            ]},
            "adapter": {"type": "command_json_v1", "command": ADAPTER_COMMAND},
            "telemetry": {
                "enabled": True,
                "tool_use": {"expected_tools_by_case": {
                    "case-001": ["approved-search"], "case-002": ["approved-lookup"],
                }},
            },
            "source": {"origin": "local"},
        }
        with TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            output_path = Path(directory) / "out" / "evaluation.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            status = run_command(argparse.Namespace(
                config=str(config_path), out=str(output_path), github_oidc_token_file=None,
                sign=False, summary_only=True, output_format="text",
                telemetry=str(ROOT / "tests" / "fixtures" / "redacted-tool-use.jsonl"),
            ))
            package = read_json(output_path)
            report = read_json(output_path.with_name("evaluation.local-report.json"))
            html_report = output_path.with_name("evaluation.local-report.html").read_text(encoding="utf-8")
        self.assertEqual(package["execution"]["local_evidence"]["derived_dimensions"], ["cost_efficiency", "tool_use"])
        self.assertEqual(report["metrics"]["tool_use"]["measurement_status"], "measured")
        self.assertIn("Tool-use quality", html_report)

    def test_run_command_writes_local_adapter_debug_log_on_nonzero_exit(self) -> None:
        config = {
            "schema_version": "esx-client-runner-config-1.0",
            "evaluation": {
                "name": "failing adapter", "agent_id": "demo-agent", "subject_version": "1.0.0",
                "project_key": "demo", "dataset_version": "adapter-fail-1.0",
                "required_dimensions": ["classification", "confidence"],
            },
            "dataset": {"version": "adapter-fail-1.0", "cases": [
                {"case_id": "case-001", "input": {"message": "normal"}, "expected_label": "safe"},
                {"case_id": "case-002", "input": {"message": "restricted"}, "expected_label": "unsafe"},
            ]},
            "adapter": {
                "type": "command_json_v1",
                "command": [sys.executable, "-c", "import sys; sys.stderr.write('bad adapter\\ntrace line\\n'); raise SystemExit(3)"],
            },
            "source": {"origin": "local"},
        }
        with TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            output_path = Path(directory) / "out" / "evaluation.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(RunnerError, "Debug details were written locally"):
                run_command(argparse.Namespace(
                    config=str(config_path), out=str(output_path), github_oidc_token_file=None,
                    sign=False, summary_only=True, output_format="text",
                    telemetry=None, discovery=None, scope=None, plan=None,
                    ground_truth=None, grounding_material=None,
                ))
            debug_log = output_path.with_name("evaluation.debug.log")
            self.assertTrue(debug_log.is_file())
            debug_text = debug_log.read_text(encoding="utf-8")
            self.assertIn("exit_status=3", debug_text)
            self.assertIn("bad adapter", debug_text)
            audit = output_path.with_name("evaluation.audit.jsonl").read_text(encoding="utf-8")
            self.assertIn('"failure_category":"adapter_error"', audit)

    def test_upload_rejects_never_upload_dimensions_through_shared_policy(self) -> None:
        with TemporaryDirectory() as directory:
            package_path = Path(directory) / "package.json"
            package_path.write_text(json.dumps({
                "evaluation": {"required_dimensions": ["classification", "hallucination"]},
                "signature": {"value": "signed"},
            }), encoding="utf-8")
            with self.assertRaisesRegex(RunnerError, "Hallucination evidence is local-only"):
                upload_command(argparse.Namespace(
                    package=str(package_path),
                    timeout_seconds=30,
                    github_oidc_token_file=None,
                    api_url="https://example.test",
                    response_out=str(Path(directory) / "response.json"),
                    require_pass=False,
                ))

    def test_v2_adapter_can_defer_a_dimension_to_enabled_local_telemetry(self) -> None:
        command = [
            sys.executable,
            "-c",
            "import json,sys;request=json.load(sys.stdin);json.dump({'schema_version':'esx-client-adapter-response-2.0','results':[{'case_id':case['case_id'],'predicted_label':'safe','confidence':0.9} for case in request['cases']],'measurements':{}},sys.stdout)",
        ]
        config = {
            "schema_version": "esx-client-runner-config-1.0",
            "evaluation": {
                "name": "partial v2", "agent_id": "demo-agent", "subject_version": "1.0.0",
                "project_key": "demo", "dataset_version": "partial-v2-1.0",
                "required_dimensions": ["classification", "confidence", "tool_use"],
            },
            "dataset": {"version": "partial-v2-1.0", "cases": [
                {"case_id": "case-001", "input": {"message": "normal"}, "expected_label": "safe"},
            ]},
            "adapter": {"type": "command_json_v2", "command": command},
            "telemetry": {"enabled": True},
            "source": {"origin": "local"},
        }
        package = build_package(config)
        self.assertNotIn("tool_use", package["evaluation"])

    def test_http_target_rejects_insecure_or_unapproved_network_destinations(self) -> None:
        base = {
            "schema_version": "esx-client-runner-config-1.0",
            "evaluation": {"name": "network policy", "agent_id": "demo-agent", "subject_version": "1.0.0", "project_key": "demo", "dataset_version": "network-1.0", "required_dimensions": ["classification", "confidence"]},
            "dataset": {"version": "network-1.0", "cases": [{"case_id": "one", "input": {"message": "test"}, "expected_label": "safe"}]},
        }
        insecure = {**base, "adapter": {"type": "http_json_target", "url": "http://staging.example.test/evaluate", "response_label_path": "label", "response_confidence_path": "confidence", "allow_remote": True, "target_environment": "staging"}}
        with self.assertRaisesRegex(RunnerError, "must use HTTPS"):
            build_package(insecure)
        unapproved = {**base, "adapter": {"type": "http_json_target", "url": "https://staging.example.test/evaluate", "response_label_path": "label", "response_confidence_path": "confidence", "target_environment": "staging"}}
        with self.assertRaisesRegex(RunnerError, "requires allow_remote"):
            build_package(unapproved)
        no_mtls = {**base, "adapter": {"type": "http_json_target", "url": "https://staging.example.test/evaluate", "response_label_path": "label", "response_confidence_path": "confidence", "allow_remote": True, "target_environment": "staging"}}
        with self.assertRaisesRegex(RunnerError, "mutual-TLS"):
            build_package(no_mtls)

    def test_container_sandbox_has_no_network_or_host_mounts(self) -> None:
        command = _adapter_command({
            "command": ["python", "/runner/adapter.py"],
            "sandbox": {"mode": "container", "image": "registry.example.test/esx-adapter@sha256:" + "a" * 64},
        })
        self.assertEqual(command[:6], ["docker", "run", "--rm", "--network", "none", "--read-only"])
        self.assertIn("--cap-drop", command)
        self.assertIn("no-new-privileges", command)
        self.assertNotIn("--volume", command)

    def test_signed_staging_attestation_confirms_test_tenant_before_cases(self) -> None:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = base64.b64encode(private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")

        class Response:
            def __init__(self, payload: dict[str, object]) -> None:
                self.payload = json.dumps(payload).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self, _size: int) -> bytes:
                return self.payload

        class Opener:
            def open(self, request, timeout: int):  # type: ignore[no-untyped-def]
                payload = {
                    "schema_version": "esx-test-target-attestation-1.0",
                    "nonce": request.headers["X-esx-evaluation-nonce"],
                    "target_environment": "staging",
                    "test_tenant_id": "tenant-test-01",
                    "capabilities": ["test_tenant", "synthetic_data", "production_actions_disabled", "least_privilege_identity"],
                }
                payload["signature"] = {"algorithm": "ed25519", "value": base64.b64encode(private_key.sign(canonical_json(payload))).decode("ascii")}
                return Response(payload)

        adapter = {"target_attestation": {"url": "https://staging.example.test/evaluation-attestation", "public_key": public_key, "required_capabilities": ["test_tenant", "synthetic_data", "production_actions_disabled", "least_privilege_identity"]}, "timeout_seconds": 30}
        self.assertEqual(len(_verify_target_attestation(adapter, Opener())), 64)

    def test_audit_chain_detects_tampering(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "evaluation.audit.jsonl"
            append_audit_event(path, "evaluation_started", {"config_sha256": "a" * 64})
            append_audit_event(path, "evaluation_completed", {"package_sha256": "b" * 64})
            path.write_text(path.read_text(encoding="utf-8").replace("evaluation_completed", "evaluation_altered"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid hash"):
                verify_audit_log(path)

    def test_full_fixture_calculates_every_advanced_metric_offline(self) -> None:
        config = read_json(ROOT / "examples" / "full-metrics.sample.json")
        config["adapter"]["command"] = [sys.executable, str(ROOT / "examples" / "full_metrics_adapter.py")]
        package = build_package(config)
        metrics = calculate_local_metrics(package)
        for name in (
            "classification", "confidence", "groundedness", "security", "trajectory", "tool_use",
            "rag", "robustness", "judge_agreement", "reproducibility", "cost_efficiency",
        ):
            self.assertEqual(metrics[name]["measurement_status"], "measured")
        self.assertEqual(metrics["trajectory"]["score"], 1.0)
        self.assertEqual(metrics["rag"]["recall_at_k"], 1.0)
        self.assertEqual(metrics["cost_efficiency"]["total_cost_usd"], 0.04)

        with TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            output_path = Path(directory) / "out" / "evaluation.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                status = run_command(argparse.Namespace(
                    config=str(config_path), out=str(output_path), github_oidc_token_file=None,
                    sign=False, summary_only=True, output_format="text",
                ))
            self.assertEqual(status, 0)
            self.assertIn("ADVANCED LOCAL RESULTS", output.getvalue())
            self.assertIn("Cost and latency:", output.getvalue())
            report = read_json(output_path.with_name("evaluation.local-report.json"))
            self.assertEqual(report["schema_version"], "esx-local-evaluation-report-1.2")
            self.assertEqual(report["metrics"]["security"]["detection_rate"], 1.0)
            self.assertEqual(report["metric_trust_summary"]["verified"], 1)
            self.assertEqual(report["metric_trust_summary"]["declared"], 10)
            self.assertFalse(report["metrics"]["confidence"]["calibration_eligible"])
            readiness = {item["metric"]: item for item in report["measurement_readiness"]}
            self.assertEqual(readiness["rag"]["status"], "measured")
            self.assertIn("Retrieved IDs", readiness["rag"]["application_emits"])


if __name__ == "__main__":
    unittest.main()
