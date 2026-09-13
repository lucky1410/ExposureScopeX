import unittest

from app.light_adapters import (
    _has_primary_nonvisual_evidence,
    _screenshot_failure_blocks_finding,
)


class LightAdapterEvidencePolicyTests(unittest.TestCase):
    def test_request_response_evidence_is_self_sufficient(self) -> None:
        evidence = {
            "requires_screenshot": True,
            "request": "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\n\r\nok",
        }
        self.assertTrue(_has_primary_nonvisual_evidence(evidence, None))
        self.assertFalse(_screenshot_failure_blocks_finding(evidence, None))

    def test_structured_source_payload_counts_as_primary_evidence(self) -> None:
        evidence = {"requires_screenshot": True}
        payload = {
            "request": {"method": "GET", "url": "https://example.test/"},
            "status": 200,
            "headers": {"content-type": "text/html"},
        }
        self.assertTrue(_has_primary_nonvisual_evidence(evidence, payload))
        self.assertFalse(_screenshot_failure_blocks_finding(evidence, payload))

    def test_screenshot_only_claim_still_blocks_on_missing_image(self) -> None:
        evidence = {"requires_screenshot": True}
        self.assertFalse(_has_primary_nonvisual_evidence(evidence, None))
        self.assertTrue(_screenshot_failure_blocks_finding(evidence, None))

    def test_optional_contextual_screenshot_never_blocks(self) -> None:
        evidence = {"requires_screenshot": False, "screenshot_artifact_id": "artifact-1"}
        self.assertFalse(_screenshot_failure_blocks_finding(evidence, None))


if __name__ == "__main__":
    unittest.main()
