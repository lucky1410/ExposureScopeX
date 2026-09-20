"""Content-free descriptions of planned browser checks, separate from outcomes."""

from typing import Any


EXPLICIT_SIGNAL_STEPS = frozenset({
    "expect_text", "wait_for_text", "expect_visible", "wait_for_selector", "assert_title", "assert_path",
})
SIGNAL_STRENGTHS = (
    "content_signal", "title_signal_only", "route_signal_only", "element_state_only", "no_explicit_signal",
)
_STATE_CHANGING_STEPS = frozenset({"goto", "click", "press", "fill", "wait_for_url", "wait_for_navigation"})


def has_explicit_signal(journey: list[dict[str, Any]]) -> bool:
    return any(step.get("type") in EXPLICIT_SIGNAL_STEPS for step in journey)


def _summary(rows: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "basis": "planned_assertions",
        "case_count": len(rows),
        **{name + "_count": sum(row["signal_strength"] == name for row in rows) for name in SIGNAL_STRENGTHS},
        "cases": rows,
        "notice": (
            "These are planned checks after the last navigation or interaction, not execution results. "
            "A passed content check establishes the selected visible text or element only. "
            "Title, route, and hidden/detached/attached-element checks do not establish that the intended page content rendered. "
            "Review the case outcome separately; failed or blocked cases do not prove their planned checks passed."
        ),
    }


def workflow_signal_strength(cases: list[dict[str, Any]]) -> dict[str, Any]:
    rows = []
    for case in cases:
        signals = set()
        for step in case.get("input", {}).get("journey", []):
            kind = step.get("type")
            if kind in _STATE_CHANGING_STEPS:
                signals.clear()
            elif kind in {"expect_text", "wait_for_text"}:
                signals.add("content_signal")
            elif kind in {"expect_visible", "wait_for_selector"}:
                signals.add("content_signal" if step.get("state", "visible") == "visible" else "element_state_only")
            elif kind == "assert_title":
                signals.add("title_signal_only")
            elif kind == "assert_path":
                signals.add("route_signal_only")
        strength = next((name for name in SIGNAL_STRENGTHS if name in signals), "no_explicit_signal")
        rows.append({"case_id": case["case_id"], "signal_strength": strength})
    return _summary(rows)


def read_signal_summary(value: object) -> dict[str, Any] | None:
    """Recompute counts and keep only known fields from persisted summaries."""
    if not isinstance(value, dict) or not isinstance(value.get("cases"), list):
        return None
    rows = []
    seen = set()
    for row in value["cases"]:
        if (not isinstance(row, dict) or not isinstance(row.get("case_id"), str)
                or row["case_id"] in seen or row.get("signal_strength") not in SIGNAL_STRENGTHS):
            return None
        seen.add(row["case_id"])
        rows.append({"case_id": row["case_id"], "signal_strength": row["signal_strength"]})
    return _summary(rows)


def workflow_signal_advisories(summary: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for strength, code, description in (
        ("route_signal_only", "workflow_route_only_signal", "route-only assertions"),
        ("title_signal_only", "workflow_title_only_signal", "title-only assertions"),
        ("element_state_only", "workflow_element_state_signal", "element-state checks that do not require visible content"),
        ("no_explicit_signal", "workflow_final_signal_missing", "no explicit assertion after the last navigation or interaction"),
    ):
        ids = [row["case_id"] for row in summary["cases"] if row["signal_strength"] == strength]
        if ids:
            result.append({
                "code": code,
                "summary": f"{len(ids)} planned workflow case(s) have {description}.",
                "action": (
                    "Review the intended outcome. Where rendered content matters, add an explicit visible text or element "
                    "check after the final navigation or interaction. Keep deliberate absence checks for negative paths."
                ),
                "case_ids": ids,
            })
    return result
