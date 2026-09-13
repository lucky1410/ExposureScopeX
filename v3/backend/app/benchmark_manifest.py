from __future__ import annotations

import json
import re
from pathlib import Path

from .benchmarking import GroundTruthCase


SHA256_IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")


def load_benchmark_manifest(path: Path, *, variant: str, profile: str) -> tuple[dict, list[GroundTruthCase]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    required = {"schema_version", "dataset_id", "dataset_version", "status", "fixture", "cases"}
    missing = sorted(required - set(payload))
    if missing:
        raise ValueError(f"benchmark manifest is missing: {', '.join(missing)}")
    if variant not in payload["fixture"]["variants"]:
        raise ValueError(f"unknown fixture variant: {variant}")
    identifiers = [case["case_id"] for case in payload["cases"]]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("benchmark case IDs must be unique")

    cases = []
    for case in payload["cases"]:
        expected = case.get("expected_by_variant", {}).get(variant)
        if expected is None or case.get("policy_status") != "allowed":
            continue
        cases.append(
            GroundTruthCase(
                case_id=case["case_id"],
                expected_positive=bool(expected),
                applicable_profiles=frozenset(case["applicable_profiles"]),
                required_evidence_kinds=frozenset(case.get("required_evidence_kinds", [])),
            )
        )
    if not any(profile in case.applicable_profiles for case in cases):
        raise ValueError(f"manifest has no cases for profile {profile!r} and variant {variant!r}")
    return payload, cases


def benchmark_release_eligibility(payload: dict) -> dict:
    fixture = payload.get("fixture") or {}
    checks = {
        "approved_status": payload.get("status") == "approved",
        "immutable_image": bool(SHA256_IMAGE.fullmatch(str(fixture.get("image_digest") or ""))),
        "immutable_source": bool(GIT_REVISION.fullmatch(str(fixture.get("source_revision") or ""))),
        "versioned_dataset": bool(str(payload.get("dataset_version") or "").strip()),
    }
    return {
        "eligible": all(checks.values()),
        "checks": checks,
        "reason": None if all(checks.values()) else "Benchmark metrics are development-only until every release prerequisite passes.",
    }


def map_observation_key(payload: dict, *, key: str | None, variant: str, profile: str) -> str | None:
    if not key:
        return None
    matches = [
        case["case_id"]
        for case in payload["cases"]
        if key in case.get("observation_keys", [])
        and case.get("policy_status") == "allowed"
        and profile in case.get("applicable_profiles", [])
        and variant in case.get("expected_by_variant", {})
    ]
    if len(matches) > 1:
        raise ValueError(f"observation key {key!r} maps to multiple benchmark cases")
    return matches[0] if matches else None
