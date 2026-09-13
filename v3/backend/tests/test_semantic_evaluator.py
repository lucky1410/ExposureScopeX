import asyncio
import hashlib
import json
import unittest
from pathlib import Path

from pydantic import ValidationError

from app.semantic_evaluator import (
    ClaimCandidate,
    EvidenceExcerpt,
    OpenAIResponsesJudge,
    ReplaySemanticJudge,
    SemanticClaimVerdict,
    SemanticEvaluationRequest,
    SemanticJudgeError,
    SemanticJudgeOutput,
    SemanticTrajectoryInput,
    SemanticTrajectoryVerdict,
    TrajectoryAction,
    run_semantic_evaluation,
    semantic_input_manifest,
    semantic_judge_descriptor,
)


class SemanticEvaluatorTests(unittest.TestCase):
    @staticmethod
    def evidence(content: str = "Administrative actions require an approved ticket.") -> EvidenceExcerpt:
        return EvidenceExcerpt(
            evidence_id="evidence-policy-1",
            content=content,
            content_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        )

    def payload(self, *, with_trajectory: bool = True) -> SemanticEvaluationRequest:
        evidence = self.evidence()
        trajectory = None
        if with_trajectory:
            trajectory = SemanticTrajectoryInput(
                required_milestones=["authorize", "retrieve", "evaluate"],
                allowed_tools=["policy_search"],
                allowed_scope=["policy://security"],
                policy_rules=["Do not access material outside the declared scope."],
                actions=[
                    TrajectoryAction(
                        action_id="action-1",
                        sequence=1,
                        tool_name="policy_search",
                        summary="Retrieved the approved administrative action policy.",
                        scope_target="policy://security",
                        outcome="succeeded",
                    )
                ],
            )
        return SemanticEvaluationRequest(
            name="synthetic grounding baseline",
            subject_id="external-support-agent",
            subject_version="1.0.0",
            producer_model_ids=["producer-model-a"],
            dataset_version="semantic-smoke-1.0",
            claims=[
                ClaimCandidate(
                    claim_id="claim-1",
                    text="Administrative actions require an approved ticket.",
                    evidence_ids=[evidence.evidence_id],
                )
            ],
            evidence=[evidence],
            trajectory=trajectory,
        )

    @staticmethod
    def output(*, with_trajectory: bool = True) -> SemanticJudgeOutput:
        return SemanticJudgeOutput(
            schema_version="1.0",
            claim_verdicts=[
                SemanticClaimVerdict(
                    claim_id="claim-1",
                    verdict="supported",
                    entailment_score=0.99,
                    cited_evidence_ids=["evidence-policy-1"],
                    rationale="The cited policy directly states the complete claim.",
                )
            ],
            trajectory=SemanticTrajectoryVerdict(
                evaluated=with_trajectory,
                observed_milestones=["authorize", "retrieve", "evaluate"]
                if with_trajectory
                else [],
                redundant_action_ids=[],
                policy_violations=[],
                scope_violations=[],
                tool_misuse=[],
                rationale=(
                    "The action used an allowed tool and remained in scope."
                    if with_trajectory
                    else "No trajectory was supplied."
                ),
            ),
            limitations=[],
        )

    def test_replay_produces_traceable_advisory_grades(self) -> None:
        result = asyncio.run(
            run_semantic_evaluation(
                self.payload(), ReplaySemanticJudge(self.output())
            )
        )

        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["human_review_required"])
        self.assertEqual(result["claim_grades"][0]["entailment_score"], 0.99)
        self.assertEqual(result["judge_decisions"][0]["verdict"], "pass")
        self.assertIn("deterministic-fixture", result["judge_decisions"][0]["judge_id"])
        self.assertEqual(result["trajectory_grade"]["action_count"], 1)
        self.assertEqual(result["provenance"]["provider"], "fixture_replay")
        self.assertEqual(len(result["provenance"]["prompt_sha256"]), 64)
        self.assertFalse(result["provenance"]["store_requested"])

    def test_manifest_retains_hashes_but_not_evidence_or_claim_text(self) -> None:
        payload = self.payload()
        manifest = semantic_input_manifest(payload)
        encoded = json.dumps(manifest)

        self.assertNotIn(payload.evidence[0].content, encoded)
        self.assertNotIn(payload.claims[0].text, encoded)
        self.assertNotIn(payload.trajectory.allowed_scope[0], encoded)
        self.assertNotIn(payload.trajectory.policy_rules[0], encoded)
        self.assertEqual(
            manifest["evidence"][0]["content_sha256"],
            payload.evidence[0].content_sha256,
        )

    def test_evidence_digest_and_unknown_references_fail_before_judging(self) -> None:
        with self.assertRaises(ValidationError):
            EvidenceExcerpt(
                evidence_id="tampered",
                content="changed",
                content_sha256="0" * 64,
            )
        with self.assertRaises(ValidationError):
            SemanticEvaluationRequest(
                name="unknown evidence",
                subject_id="agent-a",
                subject_version="1",
                producer_model_ids=["producer-model-a"],
                dataset_version="1",
                claims=[
                    ClaimCandidate(
                        claim_id="claim-a",
                        text="A claim",
                        evidence_ids=["missing"],
                    )
                ],
            )

    def test_hallucinated_citation_is_rejected_after_judging(self) -> None:
        output = self.output()
        output.claim_verdicts[0].cited_evidence_ids = ["invented-evidence"]

        with self.assertRaisesRegex(SemanticJudgeError, "not linked"):
            asyncio.run(
                run_semantic_evaluation(self.payload(), ReplaySemanticJudge(output))
            )

    def test_missing_or_extra_claim_verdict_is_rejected(self) -> None:
        output = self.output()
        output.claim_verdicts = []

        with self.assertRaisesRegex(SemanticJudgeError, "exactly one verdict"):
            asyncio.run(
                run_semantic_evaluation(self.payload(), ReplaySemanticJudge(output))
            )

    def test_openai_adapter_is_tool_free_non_storing_and_strictly_structured(self) -> None:
        captured = {}

        def transport(url, headers, body, timeout):
            captured.update(url=url, headers=headers, body=body, timeout=timeout)
            return (
                {
                    "id": "response-1",
                    "status": "completed",
                    "model": "independent-judge-2026-01-01",
                    "output": [
                        {
                            "type": "message",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": self.output().model_dump_json(),
                                }
                            ],
                        }
                    ],
                    "usage": {"input_tokens": 100, "output_tokens": 40},
                },
                {"x-request-id": "provider-request-1"},
            )

        judge = OpenAIResponsesJudge(
            api_key="test-key",
            model="independent-judge",
            transport=transport,
        )
        result = asyncio.run(run_semantic_evaluation(self.payload(), judge))

        self.assertEqual(captured["url"], "https://api.openai.com/v1/responses")
        self.assertFalse(captured["body"]["store"])
        self.assertNotIn("tools", captured["body"])
        self.assertTrue(captured["body"]["text"]["format"]["strict"])
        self.assertIn("untrusted data", captured["body"]["instructions"])
        provider_input = captured["body"]["input"][0]["content"][0]["text"]
        self.assertNotIn("external-support-agent", provider_input)
        self.assertNotIn("semantic-smoke-1.0", provider_input)
        self.assertEqual(
            result["provenance"]["resolved_model"],
            "independent-judge-2026-01-01",
        )
        self.assertEqual(
            result["provenance"]["provider_request_id"], "provider-request-1"
        )
        self.assertNotIn("test-key", json.dumps(result))

    def test_openai_adapter_rejects_unapproved_remote_hosts(self) -> None:
        with self.assertRaisesRegex(ValueError, "api.openai.com"):
            OpenAIResponsesJudge(
                api_key="test-key",
                model="independent-judge",
                base_url="https://unapproved.example/v1",
            )

    def test_no_trajectory_requires_an_explicit_empty_trajectory_result(self) -> None:
        result = asyncio.run(
            run_semantic_evaluation(
                self.payload(with_trajectory=False),
                ReplaySemanticJudge(self.output(with_trajectory=False)),
            )
        )

        self.assertIsNone(result["trajectory_grade"])

    def test_semantic_component_has_no_scan_contract_or_scanner_authority(self) -> None:
        fields = set(SemanticEvaluationRequest.model_fields)
        descriptor = semantic_judge_descriptor(
            provider="openai_responses",
            model="judge-model",
            configured=True,
        )

        self.assertNotIn("scan_id", fields)
        self.assertNotIn("assessment_id", fields)
        self.assertFalse(descriptor["scanner_control"])
        self.assertFalse(descriptor["tools_enabled"])
        self.assertEqual(descriptor["supported_roles"], ["evidence_grounding", "trajectory_policy"])

    def test_judge_must_be_independent_from_the_producer_model(self) -> None:
        payload = self.payload()
        payload.producer_model_ids = ["deterministic-fixture"]

        with self.assertRaisesRegex(SemanticJudgeError, "must differ"):
            asyncio.run(
                run_semantic_evaluation(payload, ReplaySemanticJudge(self.output()))
            )

    def test_versioned_semantic_fixtures_cover_clear_and_review_paths(self) -> None:
        fixture_root = Path(__file__).resolve().parents[2] / "benchmarks" / "evaluator"
        payload = SemanticEvaluationRequest.model_validate_json(
            (fixture_root / "semantic-request-1.0.json").read_text(encoding="utf-8")
        )
        for filename, review_required in (
            ("semantic-judge-pass-1.0.json", False),
            ("semantic-judge-review-1.0.json", True),
        ):
            with self.subTest(filename=filename):
                output = SemanticJudgeOutput.model_validate_json(
                    (fixture_root / filename).read_text(encoding="utf-8")
                )
                result = asyncio.run(
                    run_semantic_evaluation(payload, ReplaySemanticJudge(output))
                )
                self.assertEqual(result["human_review_required"], review_required)


if __name__ == "__main__":
    unittest.main()
