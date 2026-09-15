import unittest

from pydantic import ValidationError

from app.exposure_management import _combine_ownership, validate_integration_endpoint_url
from app.schemas import AssessmentCreate, IntegrationCreate


class ExposureManagementTests(unittest.TestCase):
    def test_passive_observation_never_overwrites_verified_or_excluded_ownership(self) -> None:
        self.assertEqual(_combine_ownership("verified", "candidate"), "verified")
        self.assertEqual(_combine_ownership("excluded", "client_declared"), "excluded")
        self.assertEqual(_combine_ownership("candidate", "client_declared"), "client_declared")

    def test_deep_lane_requires_a_validated_scope_and_non_light_profile(self) -> None:
        with self.assertRaises(ValidationError):
            AssessmentCreate(
                name="Deep test", target="https://example.test", mode="medium",
                service_tier="authorized_deep", authorization_confirmed=True,
            )
        with self.assertRaises(ValidationError):
            AssessmentCreate(
                name="Deep test", target="https://example.test", mode="light",
                service_tier="authorized_deep", authorization_confirmed=True,
            )

    def test_outbound_integration_requires_a_safe_url_and_secret(self) -> None:
        with self.assertRaises(ValidationError):
            IntegrationCreate(name="SIEM", integration_type="siem")
        with self.assertRaises(ValueError):
            validate_integration_endpoint_url("http://events.example.test/hook")
        self.assertEqual(
            validate_integration_endpoint_url("http://localhost:8999/hook"),
            "http://localhost:8999/hook",
        )

    def test_connector_configuration_cannot_store_plaintext_credentials(self) -> None:
        with self.assertRaises(ValidationError):
            IntegrationCreate(
                name="Webhook", integration_type="webhook", endpoint_url="https://events.example.test/hook",
                configuration={"api_token": "must-not-be-stored-here"},
            )


if __name__ == "__main__":
    unittest.main()
