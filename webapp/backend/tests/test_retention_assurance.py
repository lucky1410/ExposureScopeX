import unittest
from dataclasses import dataclass
from unittest.mock import patch
from uuid import uuid4

from app.services.retention import make_confirmation_token, retention_preview, verify_confirmation_token


@dataclass
class Candidate:
    id: object
    size_bytes: int = 0
    file_size: int = 0


def candidates():
    return {
        "scan_days": 30,
        "report_days": 90,
        "scan_artifacts": [Candidate(uuid4(), size_bytes=1024)],
        "reports": [Candidate(uuid4(), file_size=2048)],
    }


class RetentionAssuranceTests(unittest.TestCase):
    def test_preview_totals_and_token_are_bound_to_exact_candidates(self):
        org_id = uuid4()
        selected = candidates()
        preview = retention_preview(org_id, selected)
        self.assertEqual(preview["reclaimable_bytes"], 3072)
        self.assertTrue(verify_confirmation_token(preview["confirmation_token"], org_id, selected))

        changed = {**selected, "reports": []}
        self.assertFalse(verify_confirmation_token(preview["confirmation_token"], org_id, changed))
        self.assertFalse(verify_confirmation_token(preview["confirmation_token"], uuid4(), selected))

    def test_tampered_and_expired_tokens_are_rejected(self):
        org_id = uuid4()
        selected = candidates()
        token = make_confirmation_token(org_id, selected, issued_at=100)
        with patch("app.services.retention.time.time", return_value=100 + 901):
            self.assertFalse(verify_confirmation_token(token, org_id, selected))
        self.assertFalse(verify_confirmation_token(token + "0", org_id, selected))
        self.assertFalse(verify_confirmation_token("not-a-token", org_id, selected))


if __name__ == "__main__":
    unittest.main()
