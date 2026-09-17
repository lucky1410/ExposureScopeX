from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

from esx_eval_runner.local_metrics import calculate_local_metrics
from esx_eval_runner.report_html import render_local_report
from esx_eval_runner.runner import RunnerError
from esx_eval_runner.semantic_grounding import evaluate_semantic_grounding


FIXTURES = Path(__file__).parent / "fixtures" / "local-metrics"
JUDGE = {
    "type": "command_json_v1",
    "command": [sys.executable, str(FIXTURES / "semantic-grounding-judge.py")],
    "identity": "fixture-judge", "version": "1", "independent_from_target": True,
}


class SemanticHallucinationTests(unittest.TestCase):
    def score(self, cases, observations=(), confidence=None, judge=None):
        grounding = evaluate_semantic_grounding({
            "schema_version": "pre-d-grounding-material-1.0", "cases": cases,
        }, judge or JUDGE)
        count = len(cases)
        metrics = calculate_local_metrics({"evaluation": {
            "expected_labels": ["safe"] * count, "predicted_labels": ["safe"] * count,
            "confidences": confidence or [0.9] * count,
            "case_ids": [case["case_id"] for case in cases],
            "decision_observations": list(observations),
        }}, semantic_grounding=grounding)
        return metrics

    def test_mixed_claims_reuse_verdicts_and_distinguish_contradictions(self):
        material = json.loads((FIXTURES / "semantic-grounding-mixed.json").read_text())
        metrics = self.score(material["cases"])
        metric = metrics["hallucination"]
        self.assertEqual(metric["trust_status"], "verified")
        self.assertAlmostEqual(metric["unsupported_claim_rate"], 2 / 3, places=6)
        self.assertEqual(metric["contradicted_claim_count"], 1)
        self.assertEqual(metric["insufficient_evidence_claim_count"], 1)
        self.assertEqual(metric["hallucination_free_response_rate"], 0)
        self.assertEqual(metric["unsupported_confident_answer_rate"], 1)
        self.assertIsNone(metric["correct_abstention_rate"])
        self.assertIsNone(metric["false_answer_rate"])
        page = render_local_report({"metrics": metrics, "evaluation": {"required_dimensions": ["hallucination"]}})
        self.assertIn("Unsupported claims 66.7%", page)
        self.assertNotIn("incident began", page)

    def test_abstention_and_false_answer_with_empty_sources(self):
        metrics = self.score([
            {"case_id": "abstain", "response": "I cannot answer from the available evidence.", "evidence": []},
            {"case_id": "answer", "response": "The incident was caused by malware.", "evidence": []},
            {"case_id": "empty", "response": "Hello!", "evidence": []},
        ], [{"case_id": "abstain", "must_abstain": True}, {"case_id": "answer", "must_abstain": True}], [0.2, 0.5, 0.9])
        metric = metrics["hallucination"]
        self.assertEqual(metric["unsupported_claim_rate"], 1)
        self.assertEqual(metric["correct_abstention_rate"], 0.5)
        self.assertEqual(metric["false_answer_rate"], 0.5)
        self.assertEqual(metric["hallucination_free_response_rate"], 0.5)
        self.assertEqual(metric["assessed_response_count"], 2)
        self.assertAlmostEqual(metric["response_assessment_coverage"], 2 / 3, places=6)
        # The judge's 0.93 confidence must never become application confidence.
        self.assertIsNone(metric["unsupported_confident_answer_rate"])

    def test_all_abstentions_have_no_claim_denominator(self):
        metrics = self.score([
            {"case_id": "abstain", "response": "I cannot answer from the available evidence.", "evidence": []},
        ], [{"case_id": "abstain", "must_abstain": True}])
        metric = metrics["hallucination"]
        self.assertIsNone(metric["unsupported_claim_rate"])
        self.assertEqual(metric["correct_abstention_rate"], 1)
        self.assertEqual(metrics["groundedness"]["trust_status"], "missing")
        page = render_local_report({"metrics": metrics, "evaluation": {"required_dimensions": ["groundedness", "hallucination"]}})
        self.assertIn("N/A (no factual claims)", page)

    def test_non_factual_response_does_not_get_perfect_score(self):
        metric = self.score([{"case_id": "empty", "response": "Hello!", "evidence": []}])["hallucination"]
        self.assertEqual(metric["trust_status"], "missing")
        self.assertIsNone(metric["hallucination_free_response_rate"])

    def test_supported_response(self):
        metric = self.score([{
            "case_id": "supported", "response": "The incident began at 09:15.",
            "evidence": [{"evidence_id": "timeline-1", "text": "The incident began at 09:15."}],
        }])["hallucination"]
        self.assertEqual(metric["unsupported_claim_rate"], 0)
        self.assertEqual(metric["hallucination_free_response_rate"], 1)

    def test_bad_judge_abstention_fails_closed(self):
        code = (
            "import json,sys; r=json.load(sys.stdin); "
            "json.dump({'schema_version':'pre-d-grounding-judge-response-1.0',"
            "'operation':r['operation'],'results':[{'case_id':'c','claims':[], 'abstained':'yes'}]},sys.stdout)"
        )
        with self.assertRaisesRegex(RunnerError, "abstained must be boolean"):
            self.score([{"case_id": "c", "response": "Hello!", "evidence": []}], judge={**JUDGE, "command": [sys.executable, "-c", code]})

    def test_old_judge_cannot_supply_abstention_score(self):
        code = (
            "import json,sys; r=json.load(sys.stdin); "
            "json.dump({'schema_version':'pre-d-grounding-judge-response-1.0',"
            "'operation':r['operation'],'results':[{'case_id':'c','complete':True,'missing_claims':[]}] if r['operation']=='review_claims' else [{'case_id':'c','claims':[]}]},sys.stdout)"
        )
        metric = self.score([{"case_id": "c", "response": "Hello!", "evidence": []}],
                            [{"case_id": "c", "must_abstain": True, "abstained": True}],
                            judge={**JUDGE, "command": [sys.executable, "-c", code]})["hallucination"]
        self.assertIsNone(metric["correct_abstention_rate"])
        self.assertEqual(metric["trust_status"], "missing")


if __name__ == "__main__":
    unittest.main()
