from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

from esx_eval_runner.cli import run_command
from esx_eval_runner.ground_truth import validate_ground_truth
from esx_eval_runner.local_metrics import calculate_local_metrics, claims_metrics
from esx_eval_runner.ollama_grounding_judge import _loopback_url
from esx_eval_runner.report_html import render_local_report
from esx_eval_runner.runner import RunnerError, _validate_config, build_package, read_json
from esx_eval_runner.semantic_grounding import (
    evaluate_semantic_grounding, read_grounding_material, validate_grounding_material,
)


ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures" / "local-metrics"
JUDGE_COMMAND = [sys.executable, str(FIXTURES / "semantic-grounding-judge.py")]


def judge_config(command: list[str] | None = None) -> dict[str, object]:
    return {
        "type": "command_json_v1",
        "command": command or JUDGE_COMMAND,
        "identity": "fixture-semantic-judge",
        "version": "1.0.0",
        "independent_from_target": True,
    }


class SemanticGroundingTests(unittest.TestCase):
    def test_ollama_bridge_is_loopback_only(self) -> None:
        self.assertEqual(
            _loopback_url("http://127.0.0.1:11434/api/chat"),
            "http://127.0.0.1:11434/api/chat",
        )
        with self.assertRaisesRegex(ValueError, "loopback"):
            _loopback_url("http://ollama.example.test:11434/api/chat")

    def test_claim_extraction_comparison_and_scoring_are_separate_and_complete(self) -> None:
        material = read_grounding_material(FIXTURES / "semantic-grounding-mixed.json", case_ids={"case-1"})
        metric = evaluate_semantic_grounding(
            material, judge_config(), target_command=[sys.executable, "target.py"],
            subject_id="vini",
        )
        self.assertEqual(metric["verification_basis"], "independent_local_semantic_judge")
        self.assertEqual(metric["claim_count"], 3)
        self.assertEqual(metric["supported_claim_count"], 1)
        self.assertEqual(metric["contradicted_claim_count"], 1)
        self.assertEqual(metric["insufficient_evidence_claim_count"], 1)
        self.assertAlmostEqual(metric["grounded_claim_rate"], 1 / 3, places=6)
        self.assertAlmostEqual(metric["contradiction_rate"], 1 / 3, places=6)
        self.assertAlmostEqual(metric["insufficient_evidence_rate"], 1 / 3, places=6)
        self.assertNotIn("semantic_coverage_rate", metric)
        self.assertEqual(metric["compared_extracted_claim_rate"], 1.0)
        self.assertEqual(metric["extraction_review_status"], "model_reviewed")
        serialized = json.dumps(metric)
        self.assertNotIn("incident began", serialized)
        self.assertNotIn("account remains active", serialized)

    def test_semantic_result_is_verified_and_rendered_without_raw_content(self) -> None:
        material = read_grounding_material(FIXTURES / "semantic-grounding-mixed.json")
        grounding = evaluate_semantic_grounding(material, judge_config(), subject_id="vini")
        package = {
            "evaluation": {
                "required_dimensions": ["classification", "confidence", "groundedness"],
                "expected_labels": ["safe", "unsafe"], "predicted_labels": ["safe", "unsafe"],
                "confidences": [0.8, 0.7], "case_ids": ["case-1", "case-2"],
            },
            "execution": {"adapter_type": "command_json_v2"},
        }
        metrics = calculate_local_metrics(package, semantic_grounding=grounding)
        self.assertEqual(metrics["groundedness"]["trust_status"], "verified")
        page = render_local_report({
            "subject": {"agent_id": "vini"},
            "evaluation": {"required_dimensions": ["groundedness"]},
            "metrics": metrics,
        })
        self.assertIn("Claim-level evidence comparison", page)
        self.assertIn("Contradicted 33.3%", page)
        self.assertNotIn("incident began", page)
        self.assertNotIn("account remains active", page)

    def test_target_declared_claim_ids_never_become_verified_groundedness(self) -> None:
        claims = [{
            "claim_id": "claim-1", "evidence_ids": ["doc-1"], "entailment_score": 1.0,
            "citations_valid": True, "evidence_integrity_valid": True,
        }]
        gold = validate_ground_truth({
            "schema_version": "pre-d-local-ground-truth-1.0",
            "claims": [{
                "claim_id": "claim-1", "case_id": "case-1", "expected_supported": True,
                "allowed_evidence_ids": ["doc-1"], "must_abstain": False,
            }],
        })
        metric = claims_metrics(claims, gold)
        self.assertNotIn("verification_basis", metric)
        self.assertIn("cannot establish semantic groundedness", metric["limitations"][0])

    def test_judge_must_be_independent_from_target(self) -> None:
        material = read_grounding_material(FIXTURES / "semantic-grounding-mixed.json")
        with self.assertRaisesRegex(RunnerError, "independent from the target"):
            evaluate_semantic_grounding(material, judge_config(JUDGE_COMMAND), target_command=JUDGE_COMMAND)

    def test_material_requires_complete_case_coverage_and_real_source_text(self) -> None:
        material = json.loads((FIXTURES / "semantic-grounding-mixed.json").read_text(encoding="utf-8"))
        with self.assertRaisesRegex(RunnerError, "cover every evaluated case"):
            validate_grounding_material(material, case_ids={"case-1", "case-2"})
        material["cases"][0]["evidence"][0]["text"] = ""
        with self.assertRaisesRegex(RunnerError, "must be non-empty text"):
            validate_grounding_material(material)
        with self.assertRaisesRegex(RunnerError, "Replace every"):
            validate_grounding_material({
                "schema_version": "pre-d-grounding-material-1.0",
                "cases": [{
                    "case_id": "case-1", "response": "REPLACE_WITH_RESPONSE",
                    "evidence": [{"evidence_id": "doc-1", "text": "source"}],
                }],
            })

    def test_incomplete_or_unknown_comparison_results_fail_closed(self) -> None:
        material = read_grounding_material(FIXTURES / "semantic-grounding-mixed.json")
        incomplete_code = (
            "import json,sys; r=json.load(sys.stdin); op=r['operation']; "
            "results=([{'case_id':c['case_id'],'complete':True,'missing_claims':[]} for c in r['cases']] if op=='review_claims' else [{'case_id':c['case_id'],'claims':['A claim.']} for c in r.get('cases',[])] if op=='extract_claims' else []); "
            "json.dump({'schema_version':'pre-d-grounding-judge-response-1.0','operation':op,'results':results},sys.stdout)"
        )
        with self.assertRaisesRegex(RunnerError, "omitted extracted claims"):
            evaluate_semantic_grounding(
                material, judge_config([sys.executable, "-c", incomplete_code]), subject_id="vini",
            )
        unknown_code = (
            "import json,sys; r=json.load(sys.stdin); op=r['operation']; "
            "results=[{'case_id':c['case_id'],'complete':True,'missing_claims':[]} for c in r['cases']] if op=='review_claims' else [{'case_id':c['case_id'],'claims':['A claim.']} for c in r.get('cases',[])] if op=='extract_claims' else "
            "[{'claim_id':c['claim_id'],'verdict':'supported','confidence':0.9,'evidence_ids':['unknown-doc']} for c in r['claims']]; "
            "json.dump({'schema_version':'pre-d-grounding-judge-response-1.0','operation':op,'results':results},sys.stdout)"
        )
        with self.assertRaisesRegex(RunnerError, "unknown source chunks"):
            evaluate_semantic_grounding(
                material, judge_config([sys.executable, "-c", unknown_code]), subject_id="vini",
            )

    def test_http_grounding_capture_requires_both_response_paths(self) -> None:
        config = {
            "schema_version": "esx-client-runner-config-1.0",
            "evaluation": {
                "name": "grounding", "agent_id": "vini", "subject_version": "1.0",
                "project_key": "demo", "dataset_version": "g-1",
                "required_dimensions": ["classification", "confidence", "groundedness", "hallucination"],
            },
            "dataset": {"version": "g-1", "cases": [
                {"case_id": "case-1", "input": {}, "expected_label": "safe"},
                {"case_id": "case-2", "input": {}, "expected_label": "unsafe"},
            ]},
            "adapter": {
                "type": "http_json_target", "url": "http://127.0.0.1:9999/eval",
                "target_environment": "local", "request_mode": "decision",
                "response_label_path": "result.label", "response_confidence_path": "result.confidence",
                "response_text_path": "result.response", "response_grounding_evidence_path": "result.evidence",
            },
        }
        _validate_config(config)
        del config["adapter"]["response_grounding_evidence_path"]
        with self.assertRaisesRegex(RunnerError, "must be supplied together"):
            _validate_config(config)

    def test_adapter_material_is_captured_in_memory_and_excluded_from_package(self) -> None:
        material = json.loads((FIXTURES / "semantic-grounding-mixed.json").read_text(encoding="utf-8"))
        adapter_code = (
            "import json,sys; r=json.load(sys.stdin); "
            f"m={material!r}; "
            "json.dump({'schema_version':'esx-client-adapter-response-2.0',"
            "'results':[{'case_id':c['case_id'],'predicted_label':'safe','confidence':0.8} for c in r['cases']],"
            "'measurements':{},'grounding_material':m},sys.stdout)"
        )
        config = {
            "schema_version": "esx-client-runner-config-1.0",
            "evaluation": {
                "name": "grounding", "agent_id": "vini", "subject_version": "1.0",
                "project_key": "demo", "dataset_version": "g-1",
                "required_dimensions": ["classification", "confidence", "groundedness"],
            },
            "dataset": {"version": "g-1", "cases": [
                {"case_id": "case-1", "input": {}, "expected_label": "safe"},
            ]},
            "adapter": {"type": "command_json_v2", "command": [sys.executable, "-c", adapter_code]},
        }
        local_artifacts: dict[str, object] = {}
        package = build_package(config, local_artifacts=local_artifacts)
        self.assertIn("grounding_material", local_artifacts)
        serialized = json.dumps(package)
        self.assertNotIn("incident began", serialized)
        self.assertNotIn("account remains active", serialized)
        self.assertNotIn("grounding_material", serialized)

    def test_run_automatically_scores_adapter_grounding_material(self) -> None:
        material = json.loads((FIXTURES / "semantic-grounding-mixed.json").read_text(encoding="utf-8"))
        adapter_code = (
            "import json,sys; r=json.load(sys.stdin); "
            f"m={material!r}; "
            "json.dump({'schema_version':'esx-client-adapter-response-2.0',"
            "'results':[{'case_id':c['case_id'],'predicted_label':'safe','confidence':0.8} for c in r['cases']],"
            "'measurements':{},'grounding_material':m},sys.stdout)"
        )
        config = {
            "schema_version": "esx-client-runner-config-1.0",
            "evaluation": {
                "name": "grounding", "agent_id": "vini", "subject_version": "1.0",
                "project_key": "demo", "dataset_version": "g-1",
                "required_dimensions": ["classification", "confidence", "groundedness", "hallucination"],
            },
            "dataset": {"version": "g-1", "cases": [
                {"case_id": "case-1", "input": {}, "expected_label": "safe"},
            ]},
            "adapter": {"type": "command_json_v2", "command": [sys.executable, "-c", adapter_code]},
            "assurance": {"grounding_judge": judge_config()},
        }
        with TemporaryDirectory() as directory:
            config_path = Path(directory) / "esx-eval.json"
            output_path = Path(directory) / "out" / "evaluation.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                status = run_command(argparse.Namespace(
                    config=str(config_path), out=str(output_path), ground_truth=None,
                    grounding_material=None, github_oidc_token_file=None, sign=False,
                    summary_only=True, output_format="text", discovery=None, scope=None,
                    plan=None, telemetry=None,
                ))
            package = read_json(output_path)
            report = read_json(output_path.with_name("evaluation.local-report.json"))
            page = output_path.with_name("evaluation.local-report.html").read_text(encoding="utf-8")
        self.assertEqual(status, 0)
        self.assertEqual(report["metrics"]["groundedness"]["trust_status"], "verified")
        self.assertEqual(report["metrics"]["hallucination"]["trust_status"], "verified")
        self.assertAlmostEqual(report["metrics"]["hallucination"]["unsupported_claim_rate"], 2 / 3, places=6)
        self.assertAlmostEqual(report["metrics"]["groundedness"]["grounded_claim_rate"], 1 / 3, places=6)
        self.assertIn("Claim-level evidence comparison", page)
        for output in (json.dumps(package), json.dumps(report), page):
            self.assertNotIn("incident began", output)
            self.assertNotIn("account remains active", output)


if __name__ == "__main__":
    unittest.main()
