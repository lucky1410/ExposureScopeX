import unittest

from app.redaction import redact_object, redact_text


class RedactionTests(unittest.TestCase):
    def test_http_authentication_material_is_removed(self) -> None:
        result = redact_text("Authorization: Bearer token-123\nCookie: PHPSESSID=abc\nSet-Cookie: session=server-secret\npassword=hunter2")
        self.assertNotIn("token-123", result)
        self.assertNotIn("PHPSESSID=abc", result)
        self.assertNotIn("server-secret", result)
        self.assertNotIn("hunter2", result)
        self.assertEqual(result.count("[REDACTED]"), 4)

    def test_nested_nuclei_result_is_redacted(self) -> None:
        result = redact_object({"request": "GET / HTTP/1.1\nCookie: secret-cookie", "headers": {"Set-Cookie": "PHPSESSID=raw", "Content-Type": "text/html"}, "items": ["api_key=secret"]})
        self.assertNotIn("secret-cookie", result["request"])
        self.assertEqual(result["headers"]["Set-Cookie"], "[REDACTED]")
        self.assertEqual(result["headers"]["Content-Type"], "text/html")
        self.assertNotIn("secret", result["items"][0])


if __name__ == "__main__":
    unittest.main()
