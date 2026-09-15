import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from pydantic import ValidationError

from app.schemas.operation_workspace import OperationTransitionRequest, OperationWorkspaceCreate
from app.services.operation_control import approval_readiness_issues, operation_execution_issue, target_status_for_transition


class OperationWorkspaceSchemaTests(unittest.TestCase):
    def test_tags_are_normalized_and_deduplicated(self):
        payload = OperationWorkspaceCreate(
            name="Q4 Adversary Exercise",
            codename="granite-owl",
            objective="Validate identity, cloud, and detection controls across the finance segment.",
            tags=[" Finance ", "finance", "IDENTITY", "", "Cloud "],
        )
        self.assertEqual(payload.tags, ["finance", "identity", "cloud"])

    def test_rejects_inverted_date_windows(self):
        start = datetime.now(timezone.utc)
        with self.assertRaises(ValidationError):
            OperationWorkspaceCreate(
                name="Q4 Adversary Exercise",
                objective="Validate identity, cloud, and detection controls across the finance segment.",
                planned_start_at=start,
                planned_end_at=start - timedelta(days=1),
            )

    def test_rejects_direct_creation_in_active_state(self):
        with self.assertRaises(ValidationError):
            OperationWorkspaceCreate(
                name="Q4 Adversary Exercise",
                objective="Validate identity, cloud, and detection controls across the finance segment.",
                status="active",
            )

    def test_approval_requires_scope_roe_and_window(self):
        operation = SimpleNamespace(
            status="planning",
            scope_summary=None,
            roe_summary="",
            planned_start_at=None,
            planned_end_at=None,
        )
        self.assertEqual(len(approval_readiness_issues(operation)), 3)
        with self.assertRaisesRegex(ValueError, "Scope summary"):
            target_status_for_transition(operation, "approve")

    def test_ready_operation_can_be_approved_and_activated_in_window(self):
        now = datetime.now(timezone.utc)
        operation = SimpleNamespace(
            status="planning",
            scope_summary="example.com and approved test identities",
            roe_summary="No denial of service; stop on production impact.",
            planned_start_at=now - timedelta(minutes=5),
            planned_end_at=now + timedelta(hours=1),
        )
        self.assertEqual(target_status_for_transition(operation, "approve", now), "approved")
        operation.status = "approved"
        operation.approved_by = "manager-id"
        operation.approved_at = now
        self.assertEqual(target_status_for_transition(operation, "activate", now), "active")

    def test_active_operation_blocks_scans_after_window(self):
        now = datetime.now(timezone.utc)
        operation = SimpleNamespace(
            status="active",
            approved_by="manager-id",
            approved_at=now - timedelta(hours=2),
            planned_start_at=now - timedelta(hours=2),
            planned_end_at=now - timedelta(minutes=1),
        )
        self.assertEqual(operation_execution_issue(operation, now), "Operation approval window has expired")

    def test_legacy_active_operation_without_approval_is_blocked(self):
        now = datetime.now(timezone.utc)
        operation = SimpleNamespace(
            status="active",
            approved_by=None,
            approved_at=None,
            planned_start_at=now - timedelta(minutes=1),
            planned_end_at=now + timedelta(hours=1),
        )
        self.assertEqual(operation_execution_issue(operation, now), "Operation does not have a recorded approval")

    def test_emergency_stop_requires_reason(self):
        with self.assertRaises(ValidationError):
            OperationTransitionRequest(action="emergency_stop")
        request = OperationTransitionRequest(action="emergency_stop", reason="Unexpected production impact")
        self.assertEqual(request.reason, "Unexpected production impact")


if __name__ == "__main__":
    unittest.main()
