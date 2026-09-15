"""Rules for moving an operation through its controlled lifecycle."""

from datetime import datetime, timezone


TRANSITIONS = {
    "approve": ({"planning"}, "approved"),
    "activate": ({"approved"}, "active"),
    "resume": ({"paused"}, "active"),
    "pause": ({"active"}, "paused"),
    "complete": ({"active", "paused"}, "completed"),
    "emergency_stop": ({"approved", "active", "paused"}, "stopped"),
    "archive": ({"completed", "stopped"}, "archived"),
}


def approval_readiness_issues(operation) -> list[str]:
    issues: list[str] = []
    if not (operation.scope_summary or "").strip():
        issues.append("Scope summary is required")
    if not (operation.roe_summary or "").strip():
        issues.append("Rules of engagement are required")
    if operation.planned_start_at is None or operation.planned_end_at is None:
        issues.append("A planned start and end time are required")
    elif operation.planned_end_at <= operation.planned_start_at:
        issues.append("The operation end time must be after its start time")
    return issues


def operation_execution_issue(operation, now: datetime | None = None) -> str | None:
    now = now or datetime.now(timezone.utc)
    if operation.status != "active":
        return f"Operation is {operation.status}; scans require an active operation"
    if not getattr(operation, "approved_by", None) or not getattr(operation, "approved_at", None):
        return "Operation does not have a recorded approval"
    if operation.planned_start_at and now < operation.planned_start_at:
        return "Operation is outside its approved start time"
    if operation.planned_end_at and now > operation.planned_end_at:
        return "Operation approval window has expired"
    return None


def target_status_for_transition(operation, action: str, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    transition = TRANSITIONS.get(action)
    if transition is None:
        raise ValueError("Unsupported operation action")
    allowed_statuses, target_status = transition
    if operation.status not in allowed_statuses:
        raise ValueError(f"Cannot {action.replace('_', ' ')} an operation that is {operation.status}")
    if action == "approve":
        issues = approval_readiness_issues(operation)
        if issues:
            raise ValueError("; ".join(issues))
        if operation.planned_end_at <= now:
            raise ValueError("The approval window must end in the future")
    if action in {"activate", "resume"}:
        if not getattr(operation, "approved_by", None) or not getattr(operation, "approved_at", None):
            raise ValueError("Operation does not have a recorded approval")
        if operation.planned_start_at and now < operation.planned_start_at:
            raise ValueError("Operation is outside its approved start time")
        if operation.planned_end_at and now > operation.planned_end_at:
            raise ValueError("Operation approval window has expired")
    return target_status
