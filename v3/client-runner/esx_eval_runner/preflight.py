"""Local, non-invasive checks for browser workflow plans."""

from __future__ import annotations

from collections import Counter
from typing import Any


def lint_browser_plan(config: dict[str, Any]) -> dict[str, Any]:
    """Return actionable warnings without reaching the application."""
    adapter = config.get("adapter")
    dataset = config.get("dataset")
    if not isinstance(adapter, dict) or adapter.get("type") != "browser_journey":
        return {"status": "not_applicable", "warnings": [], "notice": "Preflight applies to browser_journey plans only."}
    cases = dataset.get("cases", []) if isinstance(dataset, dict) else []
    warnings: list[dict[str, str]] = []
    signals: list[tuple[str, str]] = []
    seen_ids: set[str] = set()
    for case in cases if isinstance(cases, list) else []:
        if not isinstance(case, dict):
            continue
        case_id = str(case.get("case_id", "unknown"))
        if case_id in seen_ids:
            warnings.append(_warning("duplicate_case_id", case_id, "Give each workflow case a unique ID so its evidence cannot be mixed with another case."))
        seen_ids.add(case_id)
        journey = case.get("input", {}).get("journey", []) if isinstance(case.get("input"), dict) else []
        if not isinstance(journey, list):
            continue
        proof_actions = []
        for action in journey:
            if not isinstance(action, dict):
                continue
            kind = action.get("type")
            if kind in {"wait_for_text", "expect_text"}:
                value = str(action.get("value", "")).strip()
                signals.append((case_id, value.lower()))
                proof_actions.append(action)
                if len(value) < 6:
                    warnings.append(_warning("weak_text_signal", case_id, "Use a distinctive visible phrase of at least six characters; short text is often repeated across unrelated pages."))
                if not action.get("exact", False):
                    warnings.append(_warning("ambiguous_text_match", case_id, "This text assertion is not exact. Prefer a unique text signal, an approved data-testid selector, or a role-based selector."))
            elif kind in {"wait_for_selector", "expect_visible", "assert_path", "assert_title"}:
                proof_actions.append(action)
        if not proof_actions:
            warnings.append(_warning("missing_success_signal", case_id, "Add a final wait or assertion that proves the approved workflow reached its intended state."))
        if case.get("requires_auth") and not (adapter.get("auth") or adapter.get("session_state_path") or adapter.get("session_bootstrap") or adapter.get("personas")):
            warnings.append(_warning("missing_auth_setup", case_id, "This protected case has no approved local login or session setup and will be blocked before workflow execution."))
    for signal, count in Counter(value for _, value in signals if value).items():
        if count > 1:
            for case_id, value in signals:
                if value == signal:
                    warnings.append(_warning("repeated_success_signal", case_id, "This success signal is used by multiple cases. Confirm it uniquely proves this workflow or replace it with a stronger selector."))
    return {
        "status": "review_needed" if warnings else "ready",
        "case_count": len(cases) if isinstance(cases, list) else 0,
        "warning_count": len(warnings),
        "warnings": warnings,
        "notice": "Warnings do not claim an application defect. Resolve them before relying on workflow signal-match results.",
    }


def _warning(code: str, case_id: str, message: str) -> dict[str, str]:
    return {"code": code, "case_id": case_id, "message": message}
