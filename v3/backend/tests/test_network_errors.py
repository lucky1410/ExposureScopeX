import ssl
import unittest
from urllib.error import URLError

from app.network_errors import classify_target_connection_error


class NetworkErrorTests(unittest.TestCase):
    def test_sni_rejection_is_explained_without_a_tls_bypass(self) -> None:
        code, detail = classify_target_connection_error(
            URLError(ssl.SSLError("[SSL: TLSV1_UNRECOGNIZED_NAME] tlsv1 unrecognized name"))
        )
        self.assertEqual(code, "TARGET_TLS_SNI_REJECTED")
        self.assertIn("did not bypass", detail)

    def test_other_connection_error_stays_unreachable(self) -> None:
        code, detail = classify_target_connection_error(URLError("connection refused"))
        self.assertEqual(code, "TARGET_UNREACHABLE")
        self.assertEqual(detail, "connection refused")


if __name__ == "__main__":
    unittest.main()
