import json
import unittest
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from uuid import UUID

from app.serialization import json_safe


class JsonSafeTests(unittest.TestCase):
    def test_database_values_are_converted_recursively(self):
        value = {
            "scan_id": UUID("1e4593a4-91bd-47d8-935b-402434dbab64"),
            "created_at": datetime(2026, 9, 11, 18, 30, tzinfo=timezone.utc),
            "confidence": Decimal("70.5"),
            "path": Path("artifacts/report.pdf"),
            "nested": (Decimal("2"),),
        }

        converted = json_safe(value)

        self.assertEqual(converted["scan_id"], "1e4593a4-91bd-47d8-935b-402434dbab64")
        self.assertEqual(converted["created_at"], "2026-09-11T18:30:00+00:00")
        self.assertEqual(converted["confidence"], 70.5)
        self.assertEqual(converted["path"], "artifacts/report.pdf")
        self.assertEqual(converted["nested"], [2])
        json.dumps(converted)

    def test_unknown_types_fail_closed(self):
        with self.assertRaisesRegex(TypeError, "not JSON serializable"):
            json_safe(object())

    def test_non_finite_decimals_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Non-finite"):
            json_safe(Decimal("NaN"))
