import unittest
from unittest.mock import AsyncMock, patch
from uuid import UUID

from app.runner import _report_lock_key, recover_missing_reports


class _RecoveryPool:
    def __init__(self, rows):
        self.rows = rows
        self.limit = None

    async def fetch(self, _query, limit):
        self.limit = limit
        return self.rows


class ReportRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_terminal_reports_are_finalized(self):
        row = {
            "scan_id": UUID("1e4593a4-91bd-47d8-935b-402434dbab64"),
            "assessment_id": UUID("1e4593a4-91bd-47d8-935b-402434dbab65"),
        }
        fake_pool = _RecoveryPool([row])
        finalize = AsyncMock(return_value=True)

        with patch("app.runner.pool", return_value=fake_pool), patch(
            "app.runner.finalize_if_terminal", finalize
        ):
            recovered = await recover_missing_reports(limit=4)

        self.assertEqual(recovered, 1)
        self.assertEqual(fake_pool.limit, 4)
        finalize.assert_awaited_once_with(row["scan_id"], row["assessment_id"])

    async def test_one_failed_recovery_does_not_block_the_next_scan(self):
        rows = [
            {"scan_id": UUID(int=1), "assessment_id": UUID(int=11)},
            {"scan_id": UUID(int=2), "assessment_id": UUID(int=12)},
        ]
        fake_pool = _RecoveryPool(rows)
        finalize = AsyncMock(side_effect=(RuntimeError("fixture failure"), True))

        with patch("app.runner.pool", return_value=fake_pool), patch(
            "app.runner.finalize_if_terminal", finalize
        ):
            recovered = await recover_missing_reports()

        self.assertEqual(recovered, 1)
        self.assertEqual(finalize.await_count, 2)

    def test_report_lock_key_is_stable_and_signed_64_bit(self):
        scan_id = UUID("1e4593a4-91bd-47d8-935b-402434dbab64")
        key = _report_lock_key(scan_id)

        self.assertEqual(key, _report_lock_key(scan_id))
        self.assertGreaterEqual(key, -(2**63))
        self.assertLess(key, 2**63)
