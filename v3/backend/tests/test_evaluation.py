import unittest
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from pydantic import ValidationError

from app.agent_contracts import AGENT_REGISTRY, AgentHandoff, registered_agent
from app.evaluation import (
    ClaimGrade,
    CostEfficiencyGrade,
    CostEfficiencyObservation,
    AgentTraceEnvelope,
    AgentTraceEvent,
    EvaluationRequest,
    EVALUATOR_VERSION,
    JudgeAgreementGrade,
    JudgeDecision,
    RagGrade,
    ReproducibilityGrade,
    RobustnessCase,
    RobustnessGrade,
    RunDecision,
    SecurityCaseGrade,
    SecurityGrade,
    TrajectoryGrade,
    evaluate,
    evaluation_input_summary,
    evaluator_descriptor,
    verify_stored_evaluation,
)


class EvaluationTests(unittest.TestCase):
    @staticmethod
    def supported_claim(claim_id: str = "claim-1") -> ClaimGrade:
        return ClaimGrade(
            claim_id=claim_id,
            evidence_ids=[f"artifact-{claim_id}"],
            entailment_score=0.99,
            citations_valid=True,
            evidence_integrity_valid=True,
        )

    def payload(self, required_dimensions: list[str] | None = None) -> EvaluationRequest:
        expected = ["safe", "unsafe"] * 10
        required = required_dimensions or [
            "classification",
            "confidence",
            "groundedness",
            "security",
            "trajectory",
            "rag",
            "robustness",
            "judge_agreement",
            "reproducibility",
        ]
        return EvaluationRequest(
            name="labelled evaluator regression",
            agent_id="ai_trust",
            subject_version="1.0.0",
            dataset_version="fixture-1.0",
            expected_labels=expected,
            predicted_labels=list(expected),
            confidences=[0.98] * len(expected),
            required_dimensions=required,
            claims=[self.supported_claim()] if "groundedness" in required else [],
            security=SecurityGrade(
                cases=[
                    SecurityCaseGrade(
                        case_id="attack-positive",
                        expected_attack_success=True,
                        observed_attack_success=True,
                        expected_detection=True,
                        observed_detection=True,
                        evidence_ids=["artifact-attack-positive"],
                        evidence_integrity_valid=True,
                    ),
                    SecurityCaseGrade(
                        case_id="negative-control",
                        expected_attack_success=False,
                        observed_attack_success=False,
                        expected_detection=False,
                        observed_detection=False,
                        evidence_ids=["artifact-negative-control"],
                        evidence_integrity_valid=True,
                    ),
                ]
            )
            if "security" in required
            else None,
            trajectory=TrajectoryGrade(
                required_milestones=["scope", "retrieve", "evaluate"],
                observed_milestones=["scope", "retrieve", "evaluate"],
                action_count=3,
            )
            if "trajectory" in required
            else None,
            rag=RagGrade(
                relevant_document_ids=["d1", "d2"],
                retrieved_document_ids=["d1", "d2"],
                cited_document_ids=["d1", "d2"],
                answer_claims=[self.supported_claim("rag-claim")],
                k=2,
            )
            if "rag" in required
            else None,
            robustness=RobustnessGrade(
                baseline_correct=True,
                baseline_confidence=0.99,
                baseline_label="safe",
                perturbations=[
                    RobustnessCase(
                        case_id="paraphrase-1",
                        correct=True,
                        confidence=0.98,
                        predicted_label="safe",
                        variation_type="paraphrase",
                    ),
                    RobustnessCase(
                        case_id="perturbation-1",
                        correct=True,
                        confidence=0.97,
                        predicted_label="safe",
                        variation_type="perturbation",
                    ),
                    RobustnessCase(
                        case_id="repeat-1",
                        correct=True,
                        confidence=0.98,
                        predicted_label="safe",
                        variation_type="repeat",
                    ),
                ],
            )
            if "robustness" in required
            else None,
            judge_agreement=JudgeAgreementGrade(
                decisions=[
                    JudgeDecision(case_id="j1", judge_id="model-a", verdict="pass", confidence=0.98),
                    JudgeDecision(case_id="j1", judge_id="model-b", verdict="pass", confidence=0.97),
                    JudgeDecision(case_id="j2", judge_id="model-a", verdict="fail", confidence=0.96),
                    JudgeDecision(case_id="j2", judge_id="model-b", verdict="fail", confidence=0.95),
                ]
            )
            if "judge_agreement" in required
            else None,
            reproducibility=ReproducibilityGrade(
                decisions=[
                    RunDecision(case_id="r1", run_id="run-a", verdict="pass"),
                    RunDecision(case_id="r1", run_id="run-b", verdict="pass"),
                    RunDecision(case_id="r2", run_id="run-a", verdict="fail"),
                    RunDecision(case_id="r2", run_id="run-b", verdict="fail"),
                ]
            )
            if "reproducibility" in required
            else None,
            cost_efficiency=CostEfficiencyGrade(
                cost_source="provider_reported",
                observations=[
                    CostEfficiencyObservation(
                        case_id=f"cost-{index}", input_tokens=120, output_tokens=40,
                        request_count=1, cost_usd=0.002, latency_ms=240,
                    )
                    for index in range(len(expected))
                ],
            )
            if "cost_efficiency" in required
            else None,
        )

    def test_complete_labelled_evaluation_passes_all_roles(self) -> None:
        result = evaluate(self.payload())

        self.assertEqual(result["release_decision"], "pass")
        self.assertEqual(result["measurement_coverage"], 1.0)
        self.assertEqual(result["classification"]["macro_false_positive_rate"], 0.0)
        self.assertEqual(result["confidence"]["correctness_brier_score"], 0.0004)
        self.assertEqual(result["security"]["attack_success_rate"], 0.5)
        self.assertEqual(result["security"]["detection_rate"], 1.0)
        self.assertEqual(result["rag"]["recall_at_k"], 1.0)
        self.assertEqual(result["rag"]["context_precision"], 1.0)
        self.assertEqual(result["robustness"]["variation_coverage"], 1.0)
        self.assertEqual(result["judge_agreement"]["pairwise_agreement"], 1.0)
        self.assertEqual(result["reproducibility"]["pairwise_agreement"], 1.0)
        self.assertTrue(all(role["verdict"] == "pass" for role in result["role_results"].values()))

    def test_missing_required_grounding_is_inconclusive_not_perfect(self) -> None:
        payload = self.payload(["classification", "confidence", "groundedness"])
        payload.claims = []

        result = evaluate(payload)

        self.assertEqual(result["groundedness"]["measurement_status"], "not_measurable")
        self.assertNotIn("supported_claim_rate", result["groundedness"])
        self.assertEqual(result["release_decision"], "inconclusive")
        self.assertEqual(result["missing_required_dimensions"], ["groundedness"])

    def test_measured_failure_is_not_hidden_by_missing_data(self) -> None:
        payload = self.payload(["classification", "confidence", "groundedness"])
        payload.predicted_labels = ["unsafe" if label == "safe" else "safe" for label in payload.expected_labels]
        payload.claims = []

        result = evaluate(payload)

        self.assertEqual(result["release_decision"], "fail")
        self.assertIn("macro_f1", result["failed_gates"])
        self.assertIn("groundedness", result["missing_required_dimensions"])

    def test_empty_optional_inputs_are_not_scored_as_perfect(self) -> None:
        payload = self.payload(["classification", "confidence", "groundedness", "rag", "robustness"])
        payload.rag = RagGrade(
            relevant_document_ids=["d1"], retrieved_document_ids=["d1"], cited_document_ids=["d1"]
        )
        payload.robustness = RobustnessGrade(
            baseline_correct=True, baseline_confidence=0.9, perturbations=[]
        )

        result = evaluate(payload)

        self.assertEqual(result["rag"]["measurement_status"], "not_measurable")
        self.assertEqual(result["robustness"]["measurement_status"], "not_measurable")
        self.assertEqual(result["release_decision"], "inconclusive")

    def test_release_gates_cover_brier_rag_precision_and_all_robustness_variations(self) -> None:
        payload = self.payload(["classification", "confidence", "groundedness", "rag", "robustness"])
        payload.confidences = [0.99 if label == "safe" else 0.01 for label in payload.expected_labels]
        payload.rag = RagGrade(
            relevant_document_ids=["d1", "d2"],
            retrieved_document_ids=["d1", "noise"],
            cited_document_ids=["d1"],
            answer_claims=[self.supported_claim("rag-gate")],
            k=2,
        )
        payload.robustness = RobustnessGrade(
            baseline_correct=True,
            baseline_confidence=0.98,
            baseline_label="safe",
            perturbations=[RobustnessCase(
                case_id="only-paraphrase", correct=True, confidence=0.97,
                predicted_label="safe", variation_type="paraphrase",
            )],
        )

        result = evaluate(payload)

        self.assertEqual(result["release_decision"], "fail")
        self.assertIn("correctness_brier_score", result["failed_gates"])
        self.assertIn("rag_context_precision", result["failed_gates"])
        self.assertIn("robustness_variation_coverage", result["failed_gates"])

    def test_cost_efficiency_requires_complete_observations_and_honors_budget_gates(self) -> None:
        payload = self.payload(["classification", "confidence", "cost_efficiency"])
        result = evaluate(payload)

        self.assertEqual(result["release_decision"], "pass")
        self.assertEqual(result["cost_efficiency"]["total_cost_usd"], 0.04)
        self.assertEqual(result["cost_efficiency"]["p95_latency_ms"], 240)

        payload.cost_efficiency = CostEfficiencyGrade(
            cost_source="metered",
            observations=[
                CostEfficiencyObservation(
                    case_id=f"cost-{index}", input_tokens=120, output_tokens=40,
                    request_count=1, cost_usd=0.2, latency_ms=20_000,
                    fallback_used=True, timed_out=True,
                )
                for index in range(len(payload.expected_labels))
            ],
        )
        result = evaluate(payload)
        self.assertEqual(result["release_decision"], "fail")
        self.assertTrue({"cost_per_case_usd", "p95_latency_ms", "timeout_rate", "fallback_rate"}.issubset(result["failed_gates"]))

        payload.cost_efficiency = CostEfficiencyGrade(
            cost_source="metered",
            observations=payload.cost_efficiency.observations[:-1],
        )
        result = evaluate(payload)
        self.assertEqual(result["release_decision"], "inconclusive")
        self.assertEqual(result["missing_required_dimensions"], ["cost_efficiency"])

    def test_security_metrics_require_positive_and_negative_controls(self) -> None:
        payload = self.payload(["classification", "confidence", "groundedness", "security"])
        payload.security = SecurityGrade(
            cases=[
                SecurityCaseGrade(
                    case_id="positive-only",
                    expected_attack_success=True,
                    observed_attack_success=True,
                    expected_detection=True,
                    observed_detection=True,
                    evidence_ids=["artifact-1"],
                    evidence_integrity_valid=True,
                )
            ]
        )

        result = evaluate(payload)

        self.assertEqual(result["security"]["measurement_status"], "not_measurable")
        self.assertEqual(result["release_decision"], "inconclusive")

    def test_single_class_dataset_is_not_release_measurable(self) -> None:
        payload = self.payload(["classification", "confidence", "groundedness"])
        payload.expected_labels = ["safe"] * 20
        payload.predicted_labels = ["safe"] * 20

        result = evaluate(payload)

        self.assertEqual(result["classification"]["measurement_status"], "not_measurable")
        self.assertEqual(result["release_decision"], "inconclusive")

    def test_supplied_dimensions_cannot_be_excluded_from_release_gates(self) -> None:
        with self.assertRaises(ValidationError):
            EvaluationRequest(
                name="cherry-picked",
                agent_id="ai_trust",
                subject_version="1.0.0",
                dataset_version="1.0",
                expected_labels=["safe", "unsafe"],
                predicted_labels=["safe", "unsafe"],
                confidences=[0.9, 0.9],
                required_dimensions=["classification", "confidence"],
                claims=[self.supported_claim()],
            )

    def test_policy_override_unknown_fields_and_self_evaluation_are_rejected(self) -> None:
        base = {
            "name": "protected-contract",
            "agent_id": "ai_trust",
            "subject_version": "1.0.0",
            "dataset_version": "1.0",
            "expected_labels": ["safe", "unsafe"],
            "predicted_labels": ["safe", "unsafe"],
            "confidences": [0.9, 0.9],
            "required_dimensions": ["classification", "confidence"],
        }
        with self.assertRaises(ValidationError):
            EvaluationRequest.model_validate({**base, "policy": {"minimum_sample_size": 1}})
        with self.assertRaises(ValidationError):
            EvaluationRequest.model_validate({**base, "policy_id": "unapproved-policy"})
        with self.assertRaises(ValidationError):
            EvaluationRequest.model_validate({**base, "agent_id": "ai_quality_evaluator"})

    def test_multi_agent_trace_import_requires_a_verified_redacted_trace(self) -> None:
        events = [
            AgentTraceEvent(
                event_id="event-01", sequence=1, agent_id="planner",
                event_type="handoff", outcome="succeeded", evidence_ids=["task-1"],
            ),
            AgentTraceEvent(
                event_id="event-02", sequence=2, agent_id="executor",
                event_type="tool_call", outcome="succeeded", tool_name="safe-search",
                scope_reference="allowlist:example.test", evidence_ids=["result-1"],
            ),
        ]
        trace_digest = hashlib.sha256(json.dumps(
            [event.model_dump(mode="json") for event in events],
            sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")).hexdigest()
        payload = EvaluationRequest(
            name="verified multi-agent trace",
            agent_id="external-research-system",
            subject_version="2.0.0",
            subject_type="multi_agent_system",
            integration_mode="trace_import",
            dataset_version="multi-agent-fixture-1.0",
            expected_labels=["safe", "unsafe"] * 10,
            predicted_labels=["safe", "unsafe"] * 10,
            confidences=[0.98] * 20,
            required_dimensions=["classification", "confidence"],
            trace_envelope=AgentTraceEnvelope(
                trace_id="trace-001",
                schema_version="esx-agent-trace-1.0",
                producer="external-research-system",
                agent_ids=["planner", "executor"],
                event_count=len(events),
                content_sha256=trace_digest,
                redaction_status="redacted",
                events=events,
            ),
        )

        result = evaluate(payload)
        self.assertEqual(result["trace_provenance"]["event_count"], 2)
        self.assertEqual(result["trace_provenance"]["content_sha256"], trace_digest)
        self.assertEqual(result["release_decision"], "pass")

        invalid = payload.model_dump(mode="json")
        invalid["trace_envelope"]["content_sha256"] = "0" * 64
        with self.assertRaises(ValidationError):
            EvaluationRequest.model_validate(invalid)

    def test_semantic_run_reference_cannot_be_combined_with_client_grades(self) -> None:
        base = self.payload(["classification", "confidence", "groundedness"])

        with self.assertRaises(ValidationError):
            EvaluationRequest.model_validate(
                {
                    **base.model_dump(mode="json"),
                    "semantic_run_id": "d720dddb-e8a6-4878-9477-c6b67b090f34",
                }
            )

    def test_disagreement_and_repeat_instability_fail_release_gates(self) -> None:
        payload = self.payload(
            ["classification", "confidence", "groundedness", "judge_agreement", "reproducibility"]
        )
        payload.judge_agreement = JudgeAgreementGrade(
            decisions=[
                JudgeDecision(case_id="case-1", judge_id="model-a", verdict="pass", confidence=0.9),
                JudgeDecision(case_id="case-1", judge_id="model-b", verdict="fail", confidence=0.9),
            ]
        )
        payload.reproducibility = ReproducibilityGrade(
            decisions=[
                RunDecision(case_id="case-1", run_id="run-a", verdict="pass"),
                RunDecision(case_id="case-1", run_id="run-b", verdict="inconclusive"),
            ]
        )

        result = evaluate(payload)

        self.assertEqual(result["judge_agreement"]["pairwise_agreement"], 0.0)
        self.assertEqual(result["reproducibility"]["pairwise_agreement"], 0.0)
        self.assertEqual(result["release_decision"], "fail")

    def test_input_contract_rejects_misalignment_duplicates_and_impossible_counts(self) -> None:
        with self.assertRaises(ValidationError):
            EvaluationRequest(
                name="invalid",
                agent_id="ai_trust",
                subject_version="1.0.0",
                dataset_version="1",
                expected_labels=["a"],
                predicted_labels=["a", "b"],
                confidences=[0.9],
            )
        with self.assertRaises(ValidationError):
            SecurityGrade(
                cases=[
                    SecurityCaseGrade(
                        case_id="duplicate",
                        expected_attack_success=True,
                        observed_attack_success=True,
                        expected_detection=True,
                        observed_detection=True,
                    ),
                    SecurityCaseGrade(
                        case_id="duplicate",
                        expected_attack_success=False,
                        observed_attack_success=False,
                        expected_detection=False,
                        observed_detection=False,
                    ),
                ]
            )
        with self.assertRaises(ValidationError):
            TrajectoryGrade(action_count=1, redundant_actions=2)

    def test_evaluator_is_one_bounded_service_without_scanner_control(self) -> None:
        descriptor = evaluator_descriptor()
        unsafe = [
            agent.id
            for agent in AGENT_REGISTRY
            if agent.runtime in {"ai", "hybrid", "evaluator"} and agent.may_control_scanners
        ]

        self.assertEqual(descriptor["deployment"], "modular_monolith")
        self.assertFalse(descriptor["ai_model_connected"])
        self.assertEqual(len(descriptor["roles"]), 3)
        self.assertEqual(registered_agent("ai_quality_evaluator").version, descriptor["version"])
        self.assertEqual(unsafe, [])

    def test_versioned_developer_smoke_fixture_passes(self) -> None:
        fixture_path = (
            Path(__file__).resolve().parents[2]
            / "benchmarks"
            / "evaluator"
            / "smoke-1.0.json"
        )
        payload = EvaluationRequest.model_validate_json(
            fixture_path.read_text(encoding="utf-8")
        )

        result = evaluate(payload)

        self.assertEqual(result["dataset_version"], "esx-evaluator-smoke-1.0")
        self.assertEqual(result["release_decision"], "pass")
        self.assertEqual(result["classification"]["accuracy"], 1.0)
        self.assertEqual(result["classification"]["macro_precision"], 1.0)
        self.assertEqual(result["classification"]["macro_recall"], 1.0)
        self.assertEqual(result["classification"]["macro_f1"], 1.0)
        self.assertEqual(result["classification"]["macro_false_positive_rate"], 0.0)
        self.assertEqual(result["confidence"]["correctness_brier_score"], 0.0004)
        self.assertEqual(result["confidence"]["expected_calibration_error"], 0.02)
        self.assertEqual(result["overall_score"], 0.996)

    def test_stored_result_verification_detects_tampering(self) -> None:
        payload = self.payload()
        stored = evaluate(payload)
        verification = verify_stored_evaluation(
            payload.model_dump(mode="json"), stored, EVALUATOR_VERSION
        )
        self.assertEqual(verification["status"], "verified")
        self.assertEqual(
            verification["stored_metrics_sha256"],
            verification["recomputed_metrics_sha256"],
        )
        summary = evaluation_input_summary(payload.model_dump(mode="json"))
        self.assertEqual(summary["labelled_pairs"], 20)
        self.assertEqual(summary["expected_detection_controls"], 1)
        self.assertEqual(summary["integration_mode"], "manifest")
        self.assertFalse(summary["trace"]["present"])

        tampered = deepcopy(stored)
        tampered["overall_score"] = 0.0
        mismatch = verify_stored_evaluation(
            payload.model_dump(mode="json"), tampered, EVALUATOR_VERSION
        )
        self.assertEqual(mismatch["status"], "mismatch")

    def test_versioned_negative_fixtures_cover_fail_and_inconclusive(self) -> None:
        fixture_root = Path(__file__).resolve().parents[2] / "benchmarks" / "evaluator"
        for filename, expected_decision in (
            ("fail-1.0.json", "fail"),
            ("inconclusive-1.0.json", "inconclusive"),
        ):
            with self.subTest(filename=filename):
                payload = EvaluationRequest.model_validate_json(
                    (fixture_root / filename).read_text(encoding="utf-8")
                )
                self.assertEqual(evaluate(payload)["release_decision"], expected_decision)

    def test_handoff_requires_hash_and_traceability(self) -> None:
        with self.assertRaises(ValidationError):
            AgentHandoff.model_validate(
                {
                    "assessment_id": "4e20ec6c-5314-4ec3-b0d8-d75cf848dcfd",
                    "scan_id": "e848fa20-94a8-40e4-b3da-94253d79f680",
                    "producer_agent": "asm_discovery",
                    "consumer_agent": "api_assessment",
                    "message_type": "work_request",
                    "scope_digest": "not-a-hash",
                    "idempotency_key": "request-00000001",
                    "correlation_id": "834298e1-a44c-49a7-8b2c-a8ed26c1e8fd",
                    "payload_schema": "asset.v1",
                    "payload": {},
                    "safety_class": "passive_bounded",
                }
            )


if __name__ == "__main__":
    unittest.main()
