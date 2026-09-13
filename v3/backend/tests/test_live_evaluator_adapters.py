import json
import unittest
from uuid import uuid4

from app.evaluation import evaluate
from app.live_evaluator_adapters import (
    AdapterInvocationError,
    LIVE_ADAPTER_RESPONSE_SCHEMA_VERSION,
    LiveAdapterCase,
    LiveAdapterEvaluationRequest,
    adapter_evaluation_payload,
    invoke_live_adapter,
    validate_adapter_endpoint_url,
)


def cases() -> list[LiveAdapterCase]:
    return [
        LiveAdapterCase(
            case_id=f"{label}-{index}",
            input={"message": f"non-persisted input {label} {index}", "private_marker": "not-stored"},
            expected_label=label,
        )
        for label in ("safe", "unsafe")
        for index in range(10)
    ]


def request() -> LiveAdapterEvaluationRequest:
    return LiveAdapterEvaluationRequest(
        name="Live adapter test",
        adapter_id=uuid4(),
        subject_id="external-classifier",
        subject_version="1.0.0",
        subject_type="model",
        project_key="default",
        dataset_version="external-live-1.0",
        cases=cases(),
    )


class LiveEvaluatorAdapterTests(unittest.TestCase):
    def test_endpoint_rejects_unencrypted_and_credential_bearing_urls(self):
        with self.assertRaises(ValueError):
            validate_adapter_endpoint_url("https://token@example.test/evaluate")
        with self.assertRaises(ValueError):
            validate_adapter_endpoint_url("https://example.test/evaluate?token=secret")
        with self.assertRaises(ValueError):
            validate_adapter_endpoint_url("http://example.test/evaluate")

    def test_adapter_response_must_cover_every_case_once(self):
        submitted = cases()

        def incomplete_transport(_, __, ___):
            body = {"schema_version": LIVE_ADAPTER_RESPONSE_SCHEMA_VERSION, "results": [{"case_id": submitted[0].case_id, "predicted_label": "safe", "confidence": 0.98}]}
            return 200, json.dumps(body).encode("utf-8")

        with self.assertRaises(AdapterInvocationError) as caught:
            invoke_live_adapter("http://localhost:9911/evaluate", "a" * 32, submitted, transport=incomplete_transport)
        self.assertEqual(caught.exception.code, "adapter_case_mismatch")

    def test_live_payload_persists_results_and_hashes_not_case_inputs(self):
        submitted = request()

        def valid_transport(_, __, body):
            self.assertEqual(body["schema_version"], "esx-live-evaluation-request-1.0")
            result = {
                "schema_version": LIVE_ADAPTER_RESPONSE_SCHEMA_VERSION,
                "results": [
                    {"case_id": item.case_id, "predicted_label": item.expected_label, "confidence": 0.98}
                    for item in submitted.cases
                ],
            }
            return 200, json.dumps(result).encode("utf-8")

        invocation = invoke_live_adapter("http://localhost:9911/evaluate", "a" * 32, submitted.cases, transport=valid_transport)
        payload = adapter_evaluation_payload(
            submitted,
            invocation,
            adapter_name="Customer gateway",
            adapter_url_sha256="a" * 64,
        )
        serialized = payload.model_dump_json()
        self.assertNotIn("private_marker", serialized)
        self.assertNotIn("non-persisted input", serialized)
        result = evaluate(payload)
        self.assertEqual(result["release_decision"], "pass")
        self.assertEqual(result["classification"]["macro_f1"], 1.0)
        self.assertEqual(result["confidence"]["expected_calibration_error"], 0.02)


if __name__ == "__main__":
    unittest.main()
