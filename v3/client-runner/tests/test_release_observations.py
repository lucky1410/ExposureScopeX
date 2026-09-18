"""Case observations preserve limited scope; policy comparisons disclose changes."""

from copy import deepcopy
import math
import unittest
from unittest.mock import patch

from esx_eval_runner.local_metrics import classification_metrics
from esx_eval_runner.release import default_gates
from esx_eval_runner.release_observations import decision_observation, policy_disclosure


def decision_report(outcomes=(False, False), class_count=2):
    return {
        "evaluation": {"dataset_health": {"class_count": class_count}},
        "metrics": {"classification": {
            "sample_size": len(outcomes),
            "case_results": [
                {"case_id": f"case-{index}", "correct": correct}
                for index, correct in enumerate(outcomes)
            ],
        }},
    }


class DecisionObservationTests(unittest.TestCase):
    def test_single_class_all_wrong_is_observed_even_without_aggregate_status_or_trust(self):
        metric = classification_metrics(["allow"] * 3, ["deny"] * 3, ["a", "b", "c"])
        self.assertEqual(metric["measurement_status"], "not_measurable")
        for status, trust in (("not_measurable", "missing"), ("not_measurable", None), (None, None)):
            with self.subTest(status=status, trust=trust):
                report = decision_report((False,) * 3, class_count=1)
                report["metrics"]["classification"] = deepcopy(metric)
                classification = report["metrics"]["classification"]
                if status is None:
                    classification.pop("measurement_status")
                if trust is not None:
                    classification["trust_status"] = trust
                before = deepcopy(report)
                observed = decision_observation(report, 3)
                self.assertEqual(observed["sample_size"], 3)
                self.assertEqual(observed["correct_cases"], 0)
                self.assertEqual(observed["incorrect_cases"], 3)
                self.assertEqual(observed["accuracy"], 0.0)
                self.assertEqual(observed["case_ids"], ["a", "b", "c"])
                self.assertEqual(observed["class_count"], 1)
                self.assertIn("Only one expected class", observed["scope_caveat"])
                self.assertIn("does not establish", observed["scope_caveat"])
                self.assertIn("all-class", observed["scope_caveat"])
                self.assertNotIn("trust_status", observed)
                self.assertNotIn("measurement_status", observed)
                self.assertNotIn("macro_f1", observed)
                self.assertEqual(report, before)

    def test_multiclass_counts_and_accuracy_are_derived_from_rows(self):
        report = decision_report((True, False, True), class_count=2)
        report["metrics"]["classification"] = classification_metrics(
            ["allow", "deny", "allow"], ["allow", "allow", "allow"], ["a", "b", "c"],
        )
        report["metrics"]["classification"].update(accuracy=1.0, macro_f1=1.0, trust_status="verified")
        observed = decision_observation(report, 3)
        self.assertEqual(observed["correct_cases"], 2)
        self.assertEqual(observed["incorrect_cases"], 1)
        self.assertEqual(observed["accuracy"], 2 / 3)
        self.assertEqual(observed["case_ids"], ["b"])
        self.assertEqual(observed["class_count"], 2)
        self.assertIn("only these scored cases", observed["scope_caveat"])

    def test_all_correct_single_class_does_not_invent_errors_or_broad_validation(self):
        observed = decision_observation(decision_report((True, True), class_count=1), 2)
        self.assertEqual(observed["correct_cases"], 2)
        self.assertEqual(observed["incorrect_cases"], 0)
        self.assertEqual(observed["accuracy"], 1.0)
        self.assertEqual(observed["case_ids"], [])
        self.assertIn("does not establish", observed["scope_caveat"])

    def test_aggregate_scores_labels_and_other_dimensions_cannot_substitute_for_rows(self):
        report = decision_report()
        report["metrics"]["classification"] = {
            "sample_size": 2, "accuracy": 0.0, "macro_f1": 0.0,
            "measurement_status": "measured", "trust_status": "verified",
            "confusion_matrix": {"allow": {"deny": 2}},
        }
        report["metrics"]["confidence"] = decision_report()["metrics"]["classification"]
        self.assertIsNone(decision_observation(report, 2))
        report["metrics"]["classification"]["case_results"] = [
            {"case_id": "a", "expected_label": "allow", "predicted_label": "deny"},
            {"case_id": "b", "expected_label": "allow", "predicted_label": "deny"},
        ]
        self.assertIsNone(decision_observation(report, 2))

    def test_invalid_report_and_metric_containers_return_none(self):
        shapes = (None, True, 2, "bad", [], {})
        for shape in shapes:
            for report in (shape, {"metrics": shape}, {"metrics": {"classification": shape}}):
                with self.subTest(report=report):
                    self.assertIsNone(decision_observation(report, 2))

    def test_scored_must_be_a_positive_integer(self):
        for scored in (None, False, True, 0, -1, 1.0, "1", [], {}, float("nan"), float("inf"), 10**400):
            with self.subTest(scored=scored):
                self.assertIsNone(decision_observation(decision_report((False,), 1), scored))

    def test_sample_size_must_be_present_an_integer_and_equal_scored(self):
        report = decision_report((False,), 1)
        for sample in (None, False, True, 0, -1, 2, 1.0, "1", [], {}, float("nan"), float("inf")):
            with self.subTest(sample=sample):
                report["metrics"]["classification"]["sample_size"] = sample
                self.assertIsNone(decision_observation(report, 1))
        report["metrics"]["classification"].pop("sample_size")
        self.assertIsNone(decision_observation(report, 1))

    def test_case_results_must_be_a_complete_list(self):
        report = decision_report()
        valid = report["metrics"]["classification"]["case_results"]
        for rows in (None, True, 2, "bad", {}, tuple(valid), [], valid[:1], valid + [{"case_id": "extra", "correct": False}]):
            with self.subTest(rows=rows):
                report["metrics"]["classification"]["case_results"] = rows
                self.assertIsNone(decision_observation(report, 2))

    def test_malformed_rows_are_not_filtered_into_an_observation(self):
        for row in (None, True, 0, "bad", [], {}, {"case_id": "bad"}, {"correct": False}):
            with self.subTest(row=row):
                report = decision_report()
                report["metrics"]["classification"]["case_results"][1] = row
                self.assertIsNone(decision_observation(report, 2))

    def test_correct_requires_a_boolean_not_truthiness(self):
        for correct in (None, 0, 1, 0.0, "false", "true", [], {}):
            with self.subTest(correct=correct):
                self.assertIsNone(decision_observation(decision_report((False, correct)), 2))

    def test_case_ids_must_be_nonblank_strings(self):
        for case_id in (None, False, 1, "", "  ", "a\nb", [], {}):
            with self.subTest(case_id=case_id):
                report = decision_report()
                report["metrics"]["classification"]["case_results"][1]["case_id"] = case_id
                self.assertIsNone(decision_observation(report, 2))

    def test_duplicate_ids_reject_both_matching_and_conflicting_outcomes(self):
        for correct in (True, False):
            with self.subTest(correct=correct):
                report = decision_report((False, correct))
                report["metrics"]["classification"]["case_results"][1]["case_id"] = "case-0"
                self.assertIsNone(decision_observation(report, 2))

    def test_zero_cases_do_not_become_zero_percent_correctness(self):
        self.assertIsNone(decision_observation(decision_report((), 0), 0))

    def test_invalid_optional_class_counts_are_omitted(self):
        for count in (None, False, True, 0, -1, 3, 2.0, "2", [], {}, float("inf")):
            with self.subTest(count=count):
                observed = decision_observation(decision_report(class_count=count), 2)
                self.assertEqual(observed["accuracy"], 0.0)
                self.assertNotIn("class_count", observed)

    def test_missing_or_malformed_dataset_health_does_not_hide_valid_case_rows(self):
        for shape in (None, True, 2, "bad", [], {}):
            for evaluation in (shape, {"dataset_health": shape}):
                with self.subTest(evaluation=evaluation):
                    report = decision_report()
                    report["evaluation"] = evaluation
                    observed = decision_observation(report, 2)
                    self.assertEqual(observed["incorrect_cases"], 2)
                    self.assertNotIn("class_count", observed)
        report.pop("evaluation")
        self.assertNotIn("class_count", decision_observation(report, 2))

    def test_observation_does_not_mutate_or_alias_source_rows(self):
        report = decision_report((False, True, False))
        report["metrics"]["classification"].update(trust_status="declared", representativeness="non_representative")
        before = deepcopy(report)
        observed = decision_observation(report, 3)
        self.assertEqual(observed["case_ids"], ["case-0", "case-2"])
        observed["case_ids"].append("unrelated")
        self.assertEqual(report, before)


class PolicyDisclosureTests(unittest.TestCase):
    def test_defaults_match_for_both_kinds(self):
        for kind in ("decision", "workflow"):
            with self.subTest(kind=kind):
                result = policy_disclosure(kind, default_gates(kind))
                self.assertEqual(result["kind"], kind)
                self.assertTrue(result["matches_defaults"])
                self.assertEqual(result["changes"], [])
                self.assertIn("starting points", result["notice"])
                self.assertIn("not universal release standards", result["notice"])

    def test_gate_order_default_severity_and_result_metadata_do_not_change_policy(self):
        gates = list(reversed(default_gates("decision")))
        for gate in gates:
            gate.pop("severity")
            gate.update(observed=0, status="failed", trust="missing")
        before = deepcopy(gates)
        self.assertTrue(policy_disclosure("decision", gates)["matches_defaults"])
        self.assertEqual(gates, before)

    def test_integer_and_float_threshold_equality_is_not_a_change(self):
        gates = default_gates("workflow")
        for gate in gates:
            gate["threshold"] = 1
        self.assertTrue(policy_disclosure("workflow", gates)["matches_defaults"])

    def test_any_actual_threshold_change_is_disclosed_without_risk_cutoffs(self):
        baseline = default_gates("decision")
        for index, threshold in ((0, 0.5), (0, 1.0), (2, 0.0), (2, 1.0), (0, math.nextafter(0.95, 0.0))):
            with self.subTest(index=index, threshold=threshold):
                gates = deepcopy(baseline)
                gates[index]["threshold"] = threshold
                result = policy_disclosure("decision", gates)
                self.assertFalse(result["matches_defaults"])
                self.assertEqual(result["changes"], [{
                    "signal": gates[index]["signal"], "change": "modified",
                    "baseline": baseline[index], "selected": gates[index],
                }])
                self.assertNotIn("risk", result)
                self.assertNotIn("verdict", result)

    def test_severity_weakening_is_disclosed_even_when_thresholds_equal(self):
        gates = default_gates("decision")
        baseline = deepcopy(gates[0])
        gates[0]["severity"] = "warning"
        result = policy_disclosure("decision", gates)
        self.assertFalse(result["matches_defaults"])
        self.assertEqual(result["changes"], [{
            "signal": gates[0]["signal"], "change": "modified",
            "baseline": baseline, "selected": gates[0],
        }])

    def test_operator_change_is_disclosed(self):
        gates = default_gates("decision")
        gates[0]["operator"] = "lte"
        change = policy_disclosure("decision", gates)["changes"][0]
        self.assertEqual(change["baseline"]["operator"], "gte")
        self.assertEqual(change["selected"]["operator"], "lte")

    def test_custom_policy_discloses_omitted_and_added_gates_with_full_details(self):
        baseline = default_gates("decision")
        custom = {"signal": "confidence.correctness_brier_score", "operator": "lte", "threshold": 0.42, "severity": "warning"}
        gates = [baseline[0], baseline[2], custom]
        result = policy_disclosure("decision", gates)
        self.assertFalse(result["matches_defaults"])
        self.assertEqual(result["changes"], [
            {"signal": baseline[1]["signal"], "change": "missing", "baseline": baseline[1], "selected": None},
            {"signal": custom["signal"], "change": "added", "baseline": None, "selected": custom},
        ])

    def test_empty_selection_discloses_every_missing_default(self):
        result = policy_disclosure("workflow", [])
        self.assertFalse(result["matches_defaults"])
        self.assertEqual(len(result["changes"]), 2)
        for change in result["changes"]:
            self.assertEqual(change["change"], "missing")
            self.assertEqual(change["baseline"]["severity"], "blocker")
            self.assertIsNone(change["selected"])

    def test_policy_results_do_not_alias_inputs_or_default_gate_objects(self):
        baseline = default_gates("decision")
        original = deepcopy(baseline)
        gates = deepcopy(baseline)
        gates[0]["severity"] = "warning"
        before = deepcopy(gates)
        with patch("esx_eval_runner.release.default_gates", return_value=baseline) as defaults:
            result = policy_disclosure("decision", gates)
            defaults.assert_called_once_with("decision")
        result["changes"][0]["baseline"]["threshold"] = 0
        result["changes"][0]["selected"]["severity"] = "blocker"
        self.assertEqual(baseline, original)
        self.assertEqual(gates, before)

    def test_current_default_gate_policy_is_the_baseline(self):
        baseline = default_gates("decision")
        baseline[0]["threshold"] = 0.87
        with patch("esx_eval_runner.release.default_gates", return_value=baseline):
            self.assertTrue(policy_disclosure("decision", deepcopy(baseline))["matches_defaults"])

    def test_invalid_kinds_and_gate_containers_raise_value_error(self):
        for kind in (None, True, "", "other", [], {}):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                policy_disclosure(kind, [])
        for gates in (None, True, 1, "bad", {}, tuple(default_gates("decision")), [None], [[]]):
            with self.subTest(gates=gates), self.assertRaises(ValueError):
                policy_disclosure("decision", gates)

    def test_malformed_normalized_gate_fields_raise_value_error(self):
        invalid = {
            "signal": (None, True, "", "classification", "unknown.field", [], {}),
            "operator": (None, True, "eq", [], {}),
            "severity": (None, True, "info", [], {}),
            "threshold": (None, True, False, "1", -1, 1.1, [], {}, float("nan"), float("inf"), 10**400),
        }
        for field, values in invalid.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    gates = default_gates("decision")
                    gates[0][field] = value
                    policy_disclosure("decision", gates)
        for field in ("signal", "operator", "threshold"):
            with self.subTest(missing=field), self.assertRaises(ValueError):
                gates = default_gates("decision")
                gates[0].pop(field)
                policy_disclosure("decision", gates)

    def test_boolean_threshold_does_not_equal_one(self):
        gates = default_gates("workflow")
        gates[0]["threshold"] = True
        with self.assertRaises(ValueError):
            policy_disclosure("workflow", gates)

    def test_duplicate_gate_signals_cannot_mask_policy_changes(self):
        for severity in ("blocker", "warning"):
            with self.subTest(severity=severity), self.assertRaises(ValueError):
                gates = default_gates("decision")
                gates.append({**gates[0], "severity": severity})
                policy_disclosure("decision", gates)

    def test_unbounded_cost_threshold_is_disclosed_without_a_new_risk_standard(self):
        gate = {"signal": "cost_efficiency.p95_latency_ms", "operator": "lte", "threshold": 2500, "severity": "warning"}
        result = policy_disclosure("decision", default_gates("decision") + [gate])
        self.assertEqual(result["changes"], [{
            "signal": gate["signal"], "change": "added", "baseline": None, "selected": gate,
        }])


if __name__ == "__main__":
    unittest.main()
