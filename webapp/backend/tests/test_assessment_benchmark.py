import unittest

from app.services.assessment_benchmark import score_assessment_benchmark, score_repeatability
from app.services.scan_profiles import PROFILE_CONTRACT_VERSION, get_scan_profile


GATES = {
    "precision_min": 0.9,
    "recall_min": 0.8,
    "f1_min": 0.84,
    "evidence_completeness_min": 1.0,
    "scope_violations_max": 0,
    "unreported_stage_outcomes_max": 0,
}


def observation(case_id: str, *, complete_evidence: bool = True) -> dict:
    item = {"benchmark_case_id": case_id, "evidence_sha256": "e" * 64}
    if complete_evidence:
        item.update({"source_artifact_sha256": "a" * 64, "screenshot_sha256": "s" * 64})
    return item


class AssessmentBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.cases = [
            {"id": "vuln-1", "category": "xss", "vulnerable": True},
            {"id": "safe-1", "category": "xss", "vulnerable": False},
        ]
        self.manifest = [{"id": "scan", "planned": True, "status": "completed"}]

    def test_perfect_evidenced_run_passes(self):
        result = score_assessment_benchmark(
            cases=self.cases,
            observations=[observation("vuln-1")],
            execution_manifest=self.manifest,
            quality_gates=GATES,
        )
        self.assertTrue(result["release_gate"]["passed"])
        self.assertEqual(result["overall"]["precision"], 1.0)
        self.assertEqual(result["overall"]["recall"], 1.0)

    def test_false_positive_and_false_negative_fail_accuracy_gates(self):
        result = score_assessment_benchmark(
            cases=self.cases,
            observations=[observation("safe-1")],
            execution_manifest=self.manifest,
            quality_gates=GATES,
        )
        self.assertFalse(result["release_gate"]["passed"])
        self.assertEqual(result["overall"]["false_positives"], 1)
        self.assertEqual(result["overall"]["false_negatives"], 1)

    def test_missing_screenshot_and_running_stage_fail_hard_gates(self):
        result = score_assessment_benchmark(
            cases=self.cases,
            observations=[observation("vuln-1", complete_evidence=False)],
            execution_manifest=[{"id": "scan", "planned": True, "status": "running"}],
            quality_gates=GATES,
        )
        failed = {failure["gate"] for failure in result["release_gate"]["failures"]}
        self.assertEqual(failed, {"evidence_completeness_min", "unreported_stage_outcomes_max"})

    def test_repeatability_requires_multiple_stable_runs(self):
        cards = [{"overall": {"precision": 1, "recall": 0.8, "f1": 0.8889}}] * 3
        self.assertTrue(score_repeatability(cards, 0.02)["passed"])
        cards[-1] = {"overall": {"precision": 0.9, "recall": 0.7, "f1": 0.7875}}
        self.assertFalse(score_repeatability(cards, 0.02)["passed"])

    def test_profiles_publish_versioned_non_exploitative_contracts(self):
        recalls = []
        for mode in ("light", "medium", "aggressive"):
            profile = get_scan_profile(mode, "url")
            self.assertEqual(profile["contract_version"], PROFILE_CONTRACT_VERSION)
            self.assertFalse(profile["phases"]["exploit"])
            self.assertEqual(profile["quality_gates"]["scope_violations_max"], 0)
            self.assertEqual(profile["quality_gates"]["evidence_completeness_min"], 1.0)
            recalls.append(profile["quality_gates"]["recall_min"])
        self.assertEqual(recalls, sorted(recalls))


if __name__ == "__main__":
    unittest.main()
