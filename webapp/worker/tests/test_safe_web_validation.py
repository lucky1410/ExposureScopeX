import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from safe_web_validation import deduplicate_findings, passive_baseline_findings


class PassiveBaselineFindingTests(unittest.TestCase):
    def test_password_form_and_missing_headers_are_reported(self):
        findings = passive_baseline_findings(
            "http://dvwa.localhost/login.php",
            {"content-type": "text/html", "server": "Apache"},
            [],
            has_password_form=True,
        )

        self.assertEqual(len(findings), 4)
        self.assertIn("password-form-over-http", {item["template_id"] for item in findings})
        self.assertTrue(all(item["evidence"] for item in findings))

    def test_non_html_assets_do_not_create_page_findings(self):
        findings = passive_baseline_findings(
            "http://dvwa.localhost/dvwa/css/login.css",
            {"content-type": "text/css"},
            [],
            has_password_form=False,
        )

        self.assertEqual(findings, [])

    def test_secure_html_baseline_does_not_raise_header_findings(self):
        findings = passive_baseline_findings(
            "https://example.test/",
            {
                "content-type": "text/html",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "x-content-type-options": "nosniff",
                "strict-transport-security": "max-age=31536000",
            },
            [{"name": "session", "httpOnly": True, "secure": True}],
            has_password_form=False,
        )

        self.assertEqual(findings, [])

    def test_duplicate_cookie_observations_are_collapsed(self):
        cookie = [{"name": "PHPSESSID", "domain": "dvwa.localhost", "path": "/", "httpOnly": False}]
        first = passive_baseline_findings(
            "http://dvwa.localhost/login.php",
            {"content-type": "text/html", "content-security-policy": "default-src 'self'", "x-content-type-options": "nosniff", "x-frame-options": "DENY"},
            cookie,
            has_password_form=False,
        )
        second = passive_baseline_findings(
            "http://dvwa.localhost/index.php",
            {"content-type": "text/html", "content-security-policy": "default-src 'self'", "x-content-type-options": "nosniff", "x-frame-options": "DENY"},
            cookie,
            has_password_form=False,
        )

        self.assertEqual(len(deduplicate_findings(first + second)), 1)


if __name__ == "__main__":
    unittest.main()
