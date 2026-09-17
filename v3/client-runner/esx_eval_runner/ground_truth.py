"""Validation for local-only groundedness and hallucination expectations."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from .runner import RunnerError, sha256


GROUND_TRUTH_SCHEMA_VERSION = "pre-d-local-ground-truth-1.0"
_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")


def _reference(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SAFE_REFERENCE.fullmatch(value):
        raise RunnerError(f"{field} must be a non-empty opaque ID no longer than 160 characters")
    return value


def _references(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise RunnerError(f"{field} must be an array of opaque IDs")
    output = [_reference(item, field) for item in value]
    if len(output) != len(set(output)):
        raise RunnerError(f"{field} must contain unique values")
    return output


def validate_ground_truth(value: object) -> dict[str, Any]:
    """Validate a content-free gold set that is never sent to the target."""
    if not isinstance(value, dict) or set(value) != {"schema_version", "claims"}:
        raise RunnerError("Ground-truth JSON must contain only schema_version and claims")
    if value.get("schema_version") != GROUND_TRUTH_SCHEMA_VERSION:
        raise RunnerError(f"Ground-truth schema_version must be {GROUND_TRUTH_SCHEMA_VERSION}")
    if "REPLACE_WITH_" in json.dumps(value, sort_keys=True):
        raise RunnerError("Replace every REPLACE_WITH_* value in the local ground-truth file")
    raw_claims = value.get("claims")
    if not isinstance(raw_claims, list) or not raw_claims or len(raw_claims) > 10_000:
        raise RunnerError("Ground-truth claims must contain between 1 and 10,000 expectations")
    claims: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_claims):
        field = f"ground_truth.claims[{index}]"
        if not isinstance(raw, dict):
            raise RunnerError(f"{field} must be an object")
        allowed_fields = {
            "claim_id", "case_id", "expected_supported", "allowed_evidence_ids", "must_abstain",
        }
        unknown = sorted(set(raw) - allowed_fields)
        if unknown:
            raise RunnerError(f"{field} has unsupported fields: " + ", ".join(unknown))
        if set(raw) - {"case_id", "must_abstain"} != {
            "claim_id", "expected_supported", "allowed_evidence_ids",
        }:
            raise RunnerError(
                f"{field} requires claim_id, expected_supported, and allowed_evidence_ids"
            )
        expected_supported = raw["expected_supported"]
        if not isinstance(expected_supported, bool):
            raise RunnerError(f"{field}.expected_supported must be a boolean")
        allowed_ids = _references(raw["allowed_evidence_ids"], f"{field}.allowed_evidence_ids")
        if expected_supported and not allowed_ids:
            raise RunnerError(f"{field}.allowed_evidence_ids cannot be empty for a supported claim")
        if not expected_supported and allowed_ids:
            raise RunnerError(f"{field}.allowed_evidence_ids must be empty for an unsupported claim")
        must_abstain = raw.get("must_abstain", False)
        if not isinstance(must_abstain, bool):
            raise RunnerError(f"{field}.must_abstain must be a boolean")
        if must_abstain and expected_supported:
            raise RunnerError(f"{field}.must_abstain cannot be true for a supported claim")
        case_id = raw.get("case_id")
        if must_abstain and case_id is None:
            raise RunnerError(f"{field}.case_id is required when must_abstain is true")
        claims.append({
            "claim_id": _reference(raw["claim_id"], f"{field}.claim_id"),
            "case_id": _reference(case_id, f"{field}.case_id") if case_id is not None else None,
            "expected_supported": expected_supported,
            "allowed_evidence_ids": allowed_ids,
            "must_abstain": must_abstain,
        })
    claim_ids = [item["claim_id"] for item in claims]
    if len(claim_ids) != len(set(claim_ids)):
        raise RunnerError("Ground-truth claim_id values must be unique")
    return {"schema_version": GROUND_TRUTH_SCHEMA_VERSION, "claims": claims}


def validate_ground_truth_case_ids(value: dict[str, Any], case_ids: set[str]) -> None:
    referenced = {
        item["case_id"] for item in value["claims"] if item.get("case_id") is not None
    }
    if unknown := sorted(referenced - case_ids):
        raise RunnerError("Ground-truth claims reference unknown dataset cases: " + ", ".join(unknown))


def read_ground_truth(path: str | Path) -> dict[str, Any]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"Cannot read local ground-truth JSON: {path}") from exc
    return validate_ground_truth(raw)


def ground_truth_summary(value: dict[str, Any]) -> dict[str, Any]:
    """Return only content-free provenance for the local report."""
    claims = value["claims"]
    return {
        "schema_version": value["schema_version"],
        "sha256": sha256(value),
        "claim_expectation_count": len(claims),
        "supported_control_count": sum(item["expected_supported"] for item in claims),
        "unsupported_control_count": sum(not item["expected_supported"] for item in claims),
        "abstention_control_count": sum(item["must_abstain"] for item in claims),
        "retention": "Local report stores this digest and counts only; the gold expectations are not sent to the target or added to the result package.",
    }
