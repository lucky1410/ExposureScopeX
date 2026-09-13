import sys
import tempfile
import unittest
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from uuid import uuid4

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

CLIENT_RUNNER_ROOT = Path(__file__).resolve().parents[2] / "client-runner"
sys.path.insert(0, str(CLIENT_RUNNER_ROOT))

from app.client_evaluator_runs import (  # noqa: E402
    ClientRunError,
    ClientRunnerPackage,
    github_integration_claims_match,
    package_evaluation_request,
    verify_github_actions_oidc,
    verify_ed25519_package,
)
from app.evaluation import evaluate  # noqa: E402
from esx_eval_runner.runner import build_package, generate_keypair, read_json, sign_package  # noqa: E402


def unsigned_package() -> dict:
    labels = ["safe", "unsafe"] * 10
    return {
        "schema_version": "esx-client-evaluation-result-1.0",
        "package_id": str(uuid4()),
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "runner_version": "0.1.0",
        "execution": {
            "adapter_type": "command_json_v1",
            "case_count": len(labels),
            "duration_ms": 55,
            "request_sha256": "a" * 64,
            "response_sha256": "b" * 64,
        },
        "source": {"origin": "local", "repository": None, "commit_sha": None, "workflow_ref": None, "external_run_id": None},
        "evaluation": {
            "name": "Customer agent release gate",
            "agent_id": "customer-agent",
            "subject_version": "2026.09.12",
            "subject_type": "agent",
            "project_key": "default",
            "dataset_version": "customer-synthetic-1.0",
            "expected_labels": labels,
            "predicted_labels": labels,
            "confidences": [0.98] * len(labels),
            "required_dimensions": ["classification", "confidence"],
        },
    }


class ClientEvaluatorRunTests(unittest.TestCase):
    def test_signed_local_package_is_verified_and_does_not_contain_case_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            keys = generate_keypair(Path(directory) / "runner.key")
            signed = sign_package(
                unsigned_package(), identity_id=str(uuid4()), private_key_path=keys["private_key_path"]
            )
            package = ClientRunnerPackage.model_validate(signed)
            verify_ed25519_package(package, keys["public_key"])
            evaluation = package_evaluation_request(
                package,
                identity_type="ed25519",
                identity_id=package.signature.identity_id,
                identity_name="Developer workstation",
                identity_fingerprint=keys["key_fingerprint"],
            )

        serialized = evaluation.model_dump_json()
        self.assertNotIn("private_marker", serialized)
        self.assertNotIn("prompt", serialized)
        self.assertEqual(evaluate(evaluation)["release_decision"], "pass")
        self.assertEqual(evaluation.client_provenance.runner_version, "0.1.0")

    def test_tampered_package_signature_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            keys = generate_keypair(Path(directory) / "runner.key")
            signed = sign_package(
                unsigned_package(), identity_id=str(uuid4()), private_key_path=keys["private_key_path"]
            )
            signed["evaluation"]["predicted_labels"][0] = "unsafe"
            package = ClientRunnerPackage.model_validate(signed)
            with self.assertRaises(ClientRunError) as caught:
                verify_ed25519_package(package, keys["public_key"])
        self.assertEqual(caught.exception.code, "signature_invalid")

    def test_github_claims_are_bound_to_the_registered_repository_and_workflow(self) -> None:
        claims = {
            "repository": "customer/ai-platform",
            "workflow_ref": "customer/ai-platform/.github/workflows/esx-evaluate.yml@refs/heads/main",
            "sub": "repo:customer/ai-platform:pull_request",
        }
        integration = {
            "repository": "customer/ai-platform",
            "workflow_ref": "customer/ai-platform/.github/workflows/esx-evaluate.yml@refs/heads/main",
        }
        github_integration_claims_match(claims, integration)
        with self.assertRaises(ClientRunError):
            github_integration_claims_match({**claims, "repository": "attacker/ai-platform"}, integration)

    def test_github_oidc_signature_is_verified_against_jwks(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = key.public_key().public_numbers()
        encode = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
        header = encode(json.dumps({"alg": "RS256", "kid": "test-key"}, separators=(",", ":")).encode())
        claims = encode(json.dumps({
            "iss": "https://token.actions.githubusercontent.com",
            "aud": "exposurescopex-evaluator",
            "iat": int(time.time()) - 10,
            "exp": int(time.time()) + 120,
            "repository": "customer/ai-platform",
        }, separators=(",", ":")).encode())
        signed = f"{header}.{claims}".encode("ascii")
        signature = encode(key.sign(signed, padding.PKCS1v15(), hashes.SHA256()))
        jwks = {"keys": [{
            "kid": "test-key",
            "kty": "RSA",
            "n": encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        }]}
        verified = verify_github_actions_oidc(
            f"{header}.{claims}.{signature}", fetcher=lambda _: json.dumps(jwks).encode("utf-8")
        )
        self.assertEqual(verified["repository"], "customer/ai-platform")

    def test_v2_adapter_package_measures_every_supported_dimension(self) -> None:
        config = read_json(CLIENT_RUNNER_ROOT / "examples" / "full-metrics.sample.json")
        config["adapter"]["command"] = [
            sys.executable,
            str(CLIENT_RUNNER_ROOT / "examples" / "full_metrics_adapter.py"),
        ]
        package_data = build_package(config)
        package = ClientRunnerPackage.model_validate(package_data)
        evaluation = package_evaluation_request(
            package,
            identity_type="ed25519",
            identity_id=uuid4(),
            identity_name="Fixture client",
            identity_fingerprint="c" * 64,
        )
        metrics = evaluate(evaluation)

        self.assertEqual(package.schema_version, "esx-client-evaluation-result-1.1")
        self.assertEqual(
            set(evaluation.required_dimensions),
            {
                "classification", "confidence", "groundedness", "security", "trajectory",
                "rag", "robustness", "judge_agreement", "reproducibility", "cost_efficiency",
            },
        )
        self.assertEqual(metrics["release_decision"], "pass")
        self.assertEqual(metrics["measurement_coverage"], 1.0)
        self.assertTrue(all(
            metrics[dimension]["measurement_status"] == "measured"
            for dimension in (
                "classification", "confidence", "groundedness", "security", "trajectory",
                "rag", "robustness", "judge_agreement", "reproducibility", "cost_efficiency",
            )
        ))
        serialized = json.dumps(package_data)
        self.assertNotIn("Summarize approved policy", serialized)
        self.assertNotIn("Ignore previous instructions", serialized)

    def test_v2_package_rejects_raw_metric_text(self) -> None:
        config = read_json(CLIENT_RUNNER_ROOT / "examples" / "full-metrics.sample.json")
        config["adapter"]["command"] = [
            sys.executable,
            str(CLIENT_RUNNER_ROOT / "examples" / "full_metrics_adapter.py"),
        ]
        package_data = build_package(config)
        package_data["evaluation"]["trajectory"]["policy_violations"] = [
            "the full private user prompt was disclosed here"
        ]
        with self.assertRaises(ValueError) as caught:
            ClientRunnerPackage.model_validate(package_data)
        self.assertIn("opaque reference", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
