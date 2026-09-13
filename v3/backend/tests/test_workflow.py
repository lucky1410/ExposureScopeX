import unittest

from app.workflow import (
    ALLOWED_TRANSITIONS,
    AssessmentState,
    can_transition,
    require_transition,
    validate_workflow,
)
from app.execution_control import blocks_downstream


class AssessmentWorkflowTests(unittest.TestCase):
    def test_scope_preflight_is_the_only_downstream_execution_barrier(self) -> None:
        self.assertTrue(blocks_downstream("scope_preflight", "failed"))
        self.assertTrue(blocks_downstream("scope_preflight", "timed_out"))
        self.assertFalse(blocks_downstream("scope_preflight", "succeeded"))
        self.assertFalse(blocks_downstream("authenticated_crawl", "failed"))

    def test_workflow_contract_is_complete(self) -> None:
        validate_workflow()
        self.assertEqual(set(ALLOWED_TRANSITIONS), set(AssessmentState))

    def test_normal_complete_path(self) -> None:
        path = [
            AssessmentState.DRAFT,
            AssessmentState.AWAITING_AUTHORIZATION,
            AssessmentState.PLANNED,
            AssessmentState.QUEUED,
            AssessmentState.RUNNING,
            AssessmentState.AWAITING_REVIEW,
            AssessmentState.FINALIZING,
            AssessmentState.COMPLETE,
        ]
        for current, target in zip(path, path[1:]):
            self.assertTrue(can_transition(current, target))

    def test_partial_result_still_reaches_retest(self) -> None:
        self.assertTrue(can_transition(AssessmentState.FINALIZING, AssessmentState.PARTIAL))
        self.assertTrue(can_transition(AssessmentState.PARTIAL, AssessmentState.RETEST))

    def test_invalid_shortcut_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            require_transition(AssessmentState.DRAFT, AssessmentState.COMPLETE)


if __name__ == "__main__":
    unittest.main()
