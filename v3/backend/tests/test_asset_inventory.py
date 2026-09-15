import unittest

from app.asset_inventory import display_asset_status, target_for_discovered_hostname


class AssessmentAssetInventoryTests(unittest.TestCase):
    def test_discovered_hostname_uses_the_parent_origin_without_credentials_or_path(self) -> None:
        self.assertEqual(
            target_for_discovered_hostname("https://example.test:8443/path?token=secret", "api.example.test"),
            "https://api.example.test:8443",
        )

    def test_candidate_never_appears_as_an_approved_asset(self) -> None:
        self.assertEqual(display_asset_status("candidate", "not_assessed"), "needs ownership review")

    def test_unapproved_client_seed_discloses_its_authorization_gate(self) -> None:
        self.assertEqual(display_asset_status("client_declared", "not_assessed"), "authorization required")
        self.assertEqual(display_asset_status("approved", "approved_for_assessment"), "approved for assessment")


if __name__ == "__main__":
    unittest.main()
