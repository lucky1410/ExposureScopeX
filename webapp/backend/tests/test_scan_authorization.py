import unittest

from app.services.scan_authorization import target_matches_scope


class ScanAuthorizationMatchingTests(unittest.TestCase):
    def test_domain_scope_covers_subdomains_and_urls(self):
        self.assertTrue(target_matches_scope("api.example.com", "domain", "example.com"))
        self.assertTrue(target_matches_scope("https://api.example.com/v1", "url", "example.com"))
        self.assertFalse(target_matches_scope("example.net", "domain", "example.com"))

    def test_wildcard_scope_excludes_apex(self):
        self.assertTrue(target_matches_scope("api.example.com", "domain", "*.example.com"))
        self.assertFalse(target_matches_scope("example.com", "domain", "*.example.com"))

    def test_network_scope_requires_containment(self):
        self.assertTrue(target_matches_scope("203.0.113.7", "ip", "203.0.113.0/24"))
        self.assertTrue(target_matches_scope("203.0.113.64/26", "cidr", "203.0.113.0/24"))
        self.assertFalse(target_matches_scope("203.0.114.7", "ip", "203.0.113.0/24"))

    def test_url_scope_honors_scheme_port_and_path(self):
        scope = "https://example.com:8443/api"
        self.assertTrue(target_matches_scope("https://example.com:8443/api/v1", "url", scope))
        self.assertFalse(target_matches_scope("http://example.com:8443/api/v1", "url", scope))
        self.assertFalse(target_matches_scope("https://example.com:8443/admin", "url", scope))


if __name__ == "__main__":
    unittest.main()
