from __future__ import annotations

from enum import StrEnum


WORKFLOW_VERSION = "1.0.0-draft"


class AssessmentState(StrEnum):
    DRAFT = "draft"
    AWAITING_AUTHORIZATION = "awaiting_authorization"
    PLANNED = "planned"
    QUEUED = "queued"
    RUNNING = "running"
    AWAITING_REVIEW = "awaiting_review"
    FINALIZING = "finalizing"
    CANCELLING = "cancelling"
    BLOCKED = "blocked"
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETEST = "retest"
    CLOSED = "closed"


TERMINAL_STATES = frozenset({
    AssessmentState.BLOCKED,
    AssessmentState.COMPLETE,
    AssessmentState.PARTIAL,
    AssessmentState.FAILED,
    AssessmentState.CANCELLED,
    AssessmentState.CLOSED,
})

ALLOWED_TRANSITIONS = {
    AssessmentState.DRAFT: {AssessmentState.AWAITING_AUTHORIZATION},
    AssessmentState.AWAITING_AUTHORIZATION: {AssessmentState.PLANNED, AssessmentState.BLOCKED},
    AssessmentState.PLANNED: {AssessmentState.QUEUED},
    AssessmentState.QUEUED: {AssessmentState.RUNNING, AssessmentState.CANCELLING},
    AssessmentState.RUNNING: {AssessmentState.AWAITING_REVIEW, AssessmentState.FINALIZING, AssessmentState.CANCELLING},
    AssessmentState.AWAITING_REVIEW: {AssessmentState.FINALIZING, AssessmentState.PARTIAL},
    AssessmentState.FINALIZING: {AssessmentState.COMPLETE, AssessmentState.PARTIAL, AssessmentState.FAILED},
    AssessmentState.CANCELLING: {AssessmentState.CANCELLED},
    AssessmentState.COMPLETE: {AssessmentState.RETEST, AssessmentState.CLOSED},
    AssessmentState.PARTIAL: {AssessmentState.RETEST, AssessmentState.CLOSED},
    AssessmentState.FAILED: {AssessmentState.RETEST, AssessmentState.CLOSED},
    AssessmentState.RETEST: {AssessmentState.PLANNED, AssessmentState.CLOSED},
    AssessmentState.BLOCKED: set(),
    AssessmentState.CANCELLED: set(),
    AssessmentState.CLOSED: set(),
}


def can_transition(current: AssessmentState, target: AssessmentState) -> bool:
    return target in ALLOWED_TRANSITIONS[current]


def require_transition(current: AssessmentState, target: AssessmentState) -> None:
    if not can_transition(current, target):
        raise ValueError(f"invalid assessment transition: {current.value} -> {target.value}")


def validate_workflow() -> None:
    if set(ALLOWED_TRANSITIONS) != set(AssessmentState):
        raise ValueError("every assessment state must define its allowed transitions")
    for state, targets in ALLOWED_TRANSITIONS.items():
        if state in TERMINAL_STATES and targets and state not in {
            AssessmentState.COMPLETE,
            AssessmentState.PARTIAL,
            AssessmentState.FAILED,
        }:
            raise ValueError(f"terminal state {state.value!r} cannot have outgoing transitions")
        if not targets <= set(AssessmentState):
            raise ValueError(f"state {state.value!r} contains an unknown transition target")
