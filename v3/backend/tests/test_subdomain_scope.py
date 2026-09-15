import unittest

from app.subdomain_scope import approved_discovered_subdomains, target_for_subdomain


class SubdomainScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = {
            "status": "completed",
            "subdomains": ["api.example.test", "status.example.test"],
        }

    def test_approval_accepts_only_discovered_descendants(self) -> None:
        selected = approved_discovered_subdomains(
            self.inventory, "https://example.test", ["API.example.test."],
        )
        self.assertEqual(selected, ["api.example.test"])

    def test_approval_rejects_uninventoried_or_outside_hosts(self) -> None:
        with self.assertRaisesRegex(ValueError, "not present"):
            approved_discovered_subdomains(self.inventory, "https://example.test", ["admin.example.test"])
        with self.assertRaisesRegex(ValueError, "not a descendant"):
            approved_discovered_subdomains(self.inventory, "https://example.test", ["api.outside.test"])

    def test_child_target_preserves_only_scheme_and_explicit_port(self) -> None:
        self.assertEqual(
            target_for_subdomain("https://example.test:8443/path?token=secret", "api.example.test"),
            "https://api.example.test:8443",
        )


if __name__ == "__main__":
    unittest.main()
