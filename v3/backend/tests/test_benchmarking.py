import unittest
from pathlib import Path

from app.benchmarking import (
    BenchmarkObservation,
    GroundTruthCase,
    benchmark_thresholds,
    measured_quality_gate,
    score_vulnerability_benchmark,
)
from app.methodology import PROFILE_COVERAGE, profile_contract, validate_profile_monotonicity
from app.benchmark_manifest import (
    benchmark_release_eligibility,
    load_benchmark_manifest,
    map_observation_key,
)


class VulnerabilityBenchmarkTests(unittest.TestCase):
    def truth(self) -> list[GroundTruthCase]:
        return [
            GroundTruthCase("WEB-SQLI-001", True, frozenset({"medium", "aggressive"}), frozenset({"request", "response"})),
            GroundTruthCase("WEB-XSS-001", True, frozenset({"medium", "aggressive"}), frozenset({"request", "browser_capture"})),
            GroundTruthCase("WEB-HEADER-001", True, frozenset({"light", "medium", "aggressive"}), frozenset({"response"})),
            GroundTruthCase("NEG-SQLI-001", False, frozenset({"medium", "aggressive"}), frozenset({"request", "response"})),
        ]

    def test_scores_detection_metrics_and_evidence_separately(self) -> None:
        result = score_vulnerability_benchmark(
            dataset_version="fixture-1.0.0",
            profile="medium",
            truth_cases=self.truth(),
            observations=[
                BenchmarkObservation("obs-1", "WEB-SQLI-001", frozenset({"request", "response"})),
                BenchmarkObservation("obs-2", "WEB-SQLI-001", frozenset({"request", "response"})),
                BenchmarkObservation("obs-3", "WEB-XSS-001", frozenset({"request"})),
                BenchmarkObservation("obs-4", "NEG-SQLI-001", frozenset({"request", "response"})),
                BenchmarkObservation("obs-5", None, frozenset({"response"})),
            ],
        )
        self.assertEqual(result["confusion"], {"tp": 2, "fp": 2, "fn": 1, "tn": 0})
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["recall"], 0.666667)
        self.assertEqual(result["f1"], 0.571429)
        self.assertEqual(result["duplicate_observation_count"], 1)
        self.assertEqual(result["evidence_failure_case_ids"], ["WEB-XSS-001"])
        self.assertEqual(result["evidence_completeness"], 0.5)
        self.assertFalse(result["quality_gate"]["eligible"])

    def test_profile_applicability_changes_the_denominator(self) -> None:
        result = score_vulnerability_benchmark(
            dataset_version="fixture-1.0.0",
            profile="light",
            truth_cases=self.truth(),
            observations=[BenchmarkObservation("obs-1", "WEB-HEADER-001", frozenset({"response"}))],
        )
        self.assertEqual(result["sample_size"], 1)
        self.assertEqual(result["recall"], 1.0)
        self.assertIsNone(result["accuracy"])

    def test_rejects_unlabelled_profile(self) -> None:
        with self.assertRaises(ValueError):
            score_vulnerability_benchmark(
                dataset_version="fixture-1.0.0",
                profile="unknown",
                truth_cases=self.truth(),
                observations=[],
            )

    def test_requires_versioned_dataset(self) -> None:
        with self.assertRaises(ValueError):
            score_vulnerability_benchmark(
                dataset_version="",
                profile="light",
                truth_cases=self.truth(),
                observations=[],
            )

    def test_profile_coverage_is_complete_and_monotonic(self) -> None:
        validate_profile_monotonicity()
        families = set(PROFILE_COVERAGE["light"])
        self.assertEqual(families, set(PROFILE_COVERAGE["medium"]))
        self.assertEqual(families, set(PROFILE_COVERAGE["aggressive"]))
        for family in families:
            self.assertLessEqual(PROFILE_COVERAGE["light"][family], PROFILE_COVERAGE["medium"][family])
            self.assertLessEqual(PROFILE_COVERAGE["medium"][family], PROFILE_COVERAGE["aggressive"][family])
        self.assertEqual(profile_contract("medium")["methodology_version"], "1.0.0-draft")

    def test_dvwa_manifest_is_loadable_but_not_release_eligible_until_pinned(self) -> None:
        manifest_path = Path(__file__).parents[2] / "benchmarks" / "dvwa" / "manifest.json"
        payload, cases = load_benchmark_manifest(manifest_path, variant="low", profile="medium")
        applicable = [case for case in cases if "medium" in case.applicable_profiles]
        self.assertGreaterEqual(len(applicable), 10)
        eligibility = benchmark_release_eligibility(payload)
        self.assertFalse(eligibility["eligible"])
        self.assertFalse(eligibility["checks"]["immutable_image"])
        self.assertFalse(eligibility["checks"]["immutable_source"])

    def test_structured_observation_key_maps_without_using_finding_title(self) -> None:
        manifest_path = Path(__file__).parents[2] / "benchmarks" / "dvwa" / "manifest.json"
        payload, _ = load_benchmark_manifest(manifest_path, variant="low", profile="light")
        mapped = map_observation_key(
            payload,
            key="http.header.absent:content-security-policy",
            variant="low",
            profile="light",
        )
        self.assertEqual(mapped, "DVWA-CONFIG-CSP-001")
        self.assertEqual(map_observation_key(
            payload,
            key="nuclei.template:phpinfo-files",
            variant="low",
            profile="light",
        ), "DVWA-DISC-PHPINFO-001")
        self.assertIsNone(map_observation_key(
            payload,
            key="nuclei.template:unmapped-template",
            variant="low",
            profile="light",
        ))

    def test_dvwa_light_manifest_has_an_explicit_negative_control(self) -> None:
        manifest_path = Path(__file__).parents[2] / "benchmarks" / "dvwa" / "manifest.json"
        _, cases = load_benchmark_manifest(manifest_path, variant="low", profile="light")
        light_cases = [case for case in cases if "light" in case.applicable_profiles]
        self.assertTrue(any(not case.expected_positive for case in light_cases))

    def test_profile_thresholds_and_quality_gate_are_explicit(self) -> None:
        self.assertEqual(benchmark_thresholds("light")["recall"], 0.80)
        gate = measured_quality_gate({
            "profile": "light",
            "precision": 0.97,
            "recall": 0.81,
            "evidence_completeness": 1.0,
        })
        self.assertTrue(gate["eligible"])
        self.assertIsNone(gate["reason"])
        with self.assertRaises(ValueError):
            benchmark_thresholds("unknown")


if __name__ == "__main__":
    unittest.main()
