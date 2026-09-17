from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from esx_eval_runner.cli import _read_saved_semantic_result, report_command, run_command
from esx_eval_runner.local_metrics import calculate_local_metrics
from esx_eval_runner.report_html import render_local_report
from esx_eval_runner.runner import RunnerError, build_package, sha256
from esx_eval_runner.semantic_grounding import _invoke_judge, _validate_judge, evaluate_semantic_grounding


FIXTURES = Path(__file__).parent / "fixtures" / "local-metrics"
JUDGE = {
    "type": "command_json_v1", "identity": "fixture-judge", "version": "1",
    "independent_from_target": True,
    "command": [sys.executable, str(FIXTURES / "semantic-grounding-judge.py")],
}


def material(count=1):
    return {"schema_version": "pre-d-grounding-material-1.0", "cases": [
        {"case_id": f"case-{i}", "response": "The incident began at 09:15. The account was disabled.",
         "evidence": [{"evidence_id": "timeline-1", "text": "The incident began at 09:15."},
                      {"evidence_id": "identity-1", "text": "The account remains active."}]}
        for i in range(count)
    ]}


def config():
    source = material()
    code = (
        "import json,sys; r=json.load(sys.stdin); "
        "json.dump({'schema_version':'esx-client-adapter-response-2.0',"
        "'results':[{'case_id':c['case_id'],'predicted_label':'safe','confidence':0.9} for c in r['cases']],"
        "'measurements':{},'grounding_material':" + repr(source) + "},sys.stdout)"
    )
    return {
        "schema_version": "esx-client-runner-config-1.0",
        "evaluation": {"name": "review", "agent_id": "app", "subject_version": "1", "project_key": "demo",
                       "dataset_version": "1", "required_dimensions": ["classification", "confidence", "groundedness", "hallucination"]},
        "dataset": {"version": "1", "cases": [{"case_id": "case-0", "input": {}, "expected_label": "safe"}]},
        "adapter": {"type": "command_json_v2", "command": [sys.executable, "-c", code]},
        "assurance": {"grounding_judge": JUDGE},
    }


def judge_result(judge, operation, payload):
    if operation == "extract_claims":
        return {"results": [{"case_id": c["case_id"], "claims": ["The incident began at 09:15.", "The account was disabled."], "abstained": False} for c in payload["cases"]]}
    if operation == "review_claims":
        return {"results": [{"case_id": c["case_id"], "complete": True, "missing_claims": []} for c in payload["cases"]]}
    return {"results": [{"claim_id": c["claim_id"], "verdict": "supported" if "09:15" in c["claim"] else "contradicted", "confidence": 0.9,
                         "evidence_ids": ["timeline-1"] if "09:15" in c["claim"] else ["identity-1"]} for c in payload["claims"]]}


class SemanticHardeningTests(unittest.TestCase):
    def test_review_detects_omitted_claim_without_reporting_perfect_coverage(self):
        def omitted(judge, operation, payload):
            result = judge_result(judge, operation, payload)
            if operation == "extract_claims":
                result["results"][0]["claims"].pop()
            if operation == "review_claims":
                result["results"][0].update(complete=False, missing_claims=["The account was disabled."])
            return result
        with patch("esx_eval_runner.semantic_grounding._invoke_judge", side_effect=omitted):
            with self.assertRaisesRegex(RunnerError, "omitted or altered"):
                evaluate_semantic_grounding(material(), JUDGE)

    def test_review_is_required_even_when_extraction_returns_no_claims(self):
        def empty(judge, operation, payload):
            if operation == "extract_claims":
                return {"results": [{"case_id": "case-0", "claims": [], "abstained": True}]}
            raise RunnerError("review operation unsupported")
        with patch("esx_eval_runner.semantic_grounding._invoke_judge", side_effect=empty):
            with self.assertRaisesRegex(RunnerError, "review operation unsupported"):
                evaluate_semantic_grounding(material(), JUDGE)

    def test_malformed_verdicts_are_controlled_validation_errors(self):
        for invalid in ([], {}, None, True, 42):
            with self.subTest(verdict=invalid):
                def malformed(judge, operation, payload):
                    result = judge_result(judge, operation, payload)
                    if operation == "compare_evidence":
                        result["results"][0]["verdict"] = invalid
                    return result
                with patch("esx_eval_runner.semantic_grounding._invoke_judge", side_effect=malformed):
                    with self.assertRaisesRegex(RunnerError, "verdict must be"):
                        evaluate_semantic_grounding(material(), JUDGE)

    def test_completed_claims_survive_failed_case_without_full_run_scores(self):
        def failure(judge, operation, payload):
            if operation == "compare_evidence" and payload["claims"][0]["case_id"] == "case-1" and "disabled" in payload["claims"][0]["claim"]:
                raise RunnerError("Local grounding judge timed out during compare_evidence")
            return judge_result(judge, operation, payload)
        with patch("esx_eval_runner.semantic_grounding._invoke_judge", side_effect=failure):
            result = evaluate_semantic_grounding(material(2), JUDGE)
        self.assertEqual(result["completion_status"], "partial")
        self.assertEqual(result["completed_case_count"], 1)
        self.assertEqual(len(result["case_results"]), 2)
        self.assertEqual(len(result["partial_claim_results"]), 1)
        self.assertIsNone(result["grounded_claim_rate"])
        metrics = calculate_local_metrics({"evaluation": {"expected_labels": ["safe", "safe"], "predicted_labels": ["safe", "safe"], "confidences": [.9, .9], "case_ids": ["case-0", "case-1"]}}, semantic_grounding=result)
        self.assertEqual(metrics["groundedness"]["trust_status"], "missing")
        self.assertEqual(metrics["hallucination"]["trust_status"], "missing")
        page = render_local_report({"evaluation": {"required_dimensions": ["groundedness", "hallucination"]}, "metrics": metrics})
        self.assertIn("No full-run score", page)
        self.assertIn("timed out", page)
        self.assertNotIn("The account was disabled", page)

    def test_each_case_and_claim_has_an_independent_timeout(self):
        # Every operation fits in one second, but the entire run does not.
        code = (
            "import json,sys,time; r=json.load(sys.stdin); op=r['operation']; time.sleep(0.35); "
            "results=([{'case_id':c['case_id'],'claims':['A.','B.'],'abstained':False} for c in r['cases']] if op=='extract_claims' else "
            "[{'case_id':c['case_id'],'complete':True,'missing_claims':[]} for c in r['cases']] if op=='review_claims' else "
            "[{'claim_id':c['claim_id'],'verdict':'insufficient','confidence':0.9,'evidence_ids':[]} for c in r['claims']]); "
            "assert len(results)==1; json.dump({'schema_version':'pre-d-grounding-judge-response-1.0','operation':op,'results':results},sys.stdout)"
        )
        result = evaluate_semantic_grounding(material(2), {**JUDGE, "command": [sys.executable, "-c", code], "timeout_seconds": 1})
        self.assertEqual(result["completion_status"], "complete")
        self.assertEqual(result["claim_count"], 4)

    def test_stdout_and_stderr_limits_stop_noisy_judge_before_timeout(self):
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                code = f"import sys,time; sys.{stream}.write('x'*1000000); sys.{stream}.flush(); time.sleep(10)"
                judge = _validate_judge({**JUDGE, "command": [sys.executable, "-c", code], "timeout_seconds": 5, "max_response_bytes": 1024})
                started = time.monotonic()
                with self.assertRaisesRegex(RunnerError, stream + " limit"):
                    _invoke_judge(judge, "extract_claims", {"cases": []})
                self.assertLess(time.monotonic() - started, 4)

    def test_large_stdin_and_early_output_do_not_deadlock(self):
        code = "import sys,time; sys.stdout.write('x'*100000); sys.stdout.flush(); sys.stdin.read(); time.sleep(10)"
        judge = _validate_judge({**JUDGE, "command": [sys.executable, "-c", code], "timeout_seconds": 5, "max_response_bytes": 1024})
        with self.assertRaisesRegex(RunnerError, "stdout limit"):
            _invoke_judge(judge, "extract_claims", {"cases": [{"response": "a" * 1_000_000}]})

    def test_valid_output_at_limit_and_invalid_json(self):
        envelope = json.dumps({"schema_version": "pre-d-grounding-judge-response-1.0", "operation": "extract_claims", "results": []})
        code = "import sys; sys.stdin.read(); sys.stdout.write(" + repr(envelope) + ")"
        judge = _validate_judge({**JUDGE, "command": [sys.executable, "-c", code], "max_response_bytes": len(envelope)})
        self.assertEqual(_invoke_judge(judge, "extract_claims", {"cases": []})["results"], [])
        judge["command"] = [sys.executable, "-c", "print('not json')"]
        with self.assertRaisesRegex(RunnerError, "invalid JSON"):
            _invoke_judge(judge, "extract_claims", {"cases": []})

    def test_http_capture_runs_both_metrics_without_telemetry(self):
        cfg = config()
        cfg["adapter"] = {
            "type": "http_json_target", "url": "http://127.0.0.1:9999/eval", "target_environment": "local", "request_mode": "decision",
            "response_label_path": "label", "response_confidence_path": "confidence", "response_text_path": "response", "response_grounding_evidence_path": "evidence",
        }
        payload = {"label": "safe", "confidence": 0.9, **{k: v for k, v in material()["cases"][0].items() if k != "case_id"}}
        with patch("esx_eval_runner.runner._http_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = json.dumps(payload).encode()
            artifacts = {}
            package = build_package(cfg, local_artifacts=artifacts)
        result = evaluate_semantic_grounding(artifacts["grounding_material"], JUDGE)
        metrics = calculate_local_metrics(package, semantic_grounding=result)
        self.assertEqual(metrics["hallucination"]["trust_status"], "verified")
        self.assertEqual(metrics["groundedness"]["grounded_claim_rate"], 0.5)

    def test_report_regeneration_reuses_results_without_config_or_judge(self):
        with TemporaryDirectory() as directory:
            path = Path(directory)
            config_path = path / "config.json"
            config_path.write_text(json.dumps(config()), encoding="utf-8")
            package_path = path / "evaluation.json"
            with redirect_stdout(io.StringIO()):
                run_command(argparse.Namespace(config=str(config_path), out=str(package_path), ground_truth=None, grounding_material=None,
                           github_oidc_token_file=None, sign=False, summary_only=True, output_format="json", discovery=None, scope=None, plan=None, telemetry=None))
            original = json.loads((path / "evaluation.local-report.json").read_text())
            saved = (path / "evaluation.semantic-results.json").read_text()
            self.assertNotIn("The account was disabled", saved)
            self.assertNotIn("The account remains active", saved)
            with patch("esx_eval_runner.cli._semantic_grounding_result", side_effect=AssertionError("Must not rerun judge")), redirect_stdout(io.StringIO()):
                report_command(argparse.Namespace(package=str(package_path), out=str(path / "regenerated.json"), config=None,
                               discovery=None, scope=None, plan=None, telemetry=None, ground_truth=None, grounding_material=None))
            regenerated = json.loads((path / "regenerated.json").read_text())
            for name in ("groundedness", "hallucination"):
                self.assertEqual(original["metrics"][name], regenerated["metrics"][name])
            package = json.loads(package_path.read_text())
            with self.assertRaisesRegex(RunnerError, "do not match"):
                _read_saved_semantic_result(package_path, {**package, "package_id": "different-run"})
            envelope = json.loads(saved)
            envelope["result"]["grounded_claim_rate"] = 1
            (path / "evaluation.semantic-results.json").write_text(json.dumps(envelope))
            with self.assertRaisesRegex(RunnerError, "integrity check"):
                _read_saved_semantic_result(package_path, package)


if __name__ == "__main__":
    unittest.main()
