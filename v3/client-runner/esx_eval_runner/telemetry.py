"""Local redacting OpenTelemetry JSON collector for assurance evidence."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
from pathlib import Path
import re
import secrets
from typing import Any


_SAFE_ATTRIBUTE_KEYS = {
    "service.name", "gen_ai.operation.name", "gen_ai.usage.input_tokens",
    "gen_ai.usage.output_tokens", "gen_ai.response.model", "gen_ai.tool.name",
    "gen_ai.request.model", "error.type", "http.response.status_code",
    "esx.case_id", "esx.trace_id", "esx.agent_id", "esx.event_id",
    "esx.event_type", "esx.milestone", "esx.evidence_id", "esx.document_id",
    "esx.claim_id", "esx.claim_support_score", "esx.citation_valid",
    "esx.evidence_integrity_valid", "esx.expected_attack_success",
    "esx.observed_attack_success", "esx.expected_detection",
    "esx.observed_detection", "esx.correct", "esx.confidence",
    "esx.variation_type", "esx.predicted_label", "esx.judge_id", "esx.run_id", "esx.verdict",
    "esx.cost_usd", "esx.retry_count", "esx.cache_hit", "esx.fallback_used",
    "esx.timed_out", "esx.policy_violation", "esx.scope_violation",
    "esx.tool_misuse_event", "esx.tool_authorized", "esx.tool_result_valid",
}

_REFERENCE_KEYS = {
    "service.name", "gen_ai.operation.name", "gen_ai.response.model",
    "gen_ai.request.model", "gen_ai.tool.name", "error.type", "esx.case_id",
    "esx.trace_id", "esx.agent_id", "esx.event_id", "esx.event_type",
    "esx.milestone", "esx.evidence_id", "esx.document_id", "esx.claim_id",
    "esx.variation_type", "esx.predicted_label", "esx.judge_id", "esx.run_id", "esx.verdict",
    "esx.policy_violation", "esx.scope_violation", "esx.tool_misuse_event",
}
_BOOLEAN_KEYS = {
    "esx.citation_valid", "esx.evidence_integrity_valid", "esx.expected_attack_success",
    "esx.observed_attack_success", "esx.expected_detection", "esx.observed_detection",
    "esx.correct", "esx.cache_hit", "esx.fallback_used", "esx.timed_out",
    "esx.tool_authorized", "esx.tool_result_valid",
}
_INTEGER_KEYS = {
    "gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens", "http.response.status_code",
    "esx.retry_count",
}
_FLOAT_KEYS = {"esx.claim_support_score", "esx.confidence", "esx.cost_usd"}
_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
_TRACE_EVENT_TYPES = {
    "handoff", "model_request", "model_response", "tool_call", "tool_result",
    "policy_decision", "final_response", "error", "retrieval", "citation",
    "security_control", "robustness_observation", "judge_decision", "run_decision",
}


def _attributes(items: object) -> dict[str, object]:
    result: dict[str, object] = {}
    if not isinstance(items, list):
        return result
    for item in items:
        if not isinstance(item, dict) or item.get("key") not in _SAFE_ATTRIBUTE_KEYS:
            continue
        scalar = _otel_scalar(item.get("value"))
        safe_value = _safe_value(str(item["key"]), scalar)
        if safe_value is not None:
            result[str(item["key"])] = safe_value
    return result


def _otel_scalar(value: object) -> object | None:
    if not isinstance(value, dict):
        return None
    for key in ("stringValue", "boolValue", "intValue", "doubleValue"):
        candidate = value.get(key)
        if key == "intValue" and isinstance(candidate, str) and candidate.lstrip("-").isdigit():
            return int(candidate)
        if isinstance(candidate, (str, int, float, bool)):
            return candidate
    return None


def _safe_value(key: str, value: object | None) -> object | None:
    """Allow only bounded metadata values from the explicit telemetry contract."""
    if key in _REFERENCE_KEYS:
        return value if isinstance(value, str) and _SAFE_REFERENCE.fullmatch(value) else None
    if key in _BOOLEAN_KEYS:
        return value if isinstance(value, bool) else None
    if key in _INTEGER_KEYS:
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 10_000_000_000:
            return value
        return None
    if key in _FLOAT_KEYS:
        if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)) and 0 <= float(value) <= 10_000_000:
            return float(value)
    return None


def redact_otel_payload(payload: dict[str, Any]) -> list[dict[str, object]]:
    """Keep only allowlisted operational metadata, never prompts or outputs."""
    records: list[dict[str, object]] = []
    for resource_span in payload.get("resourceSpans", []):
        if not isinstance(resource_span, dict):
            continue
        resource = _attributes((resource_span.get("resource") or {}).get("attributes"))
        for scope_span in resource_span.get("scopeSpans", []):
            if not isinstance(scope_span, dict):
                continue
            for span in scope_span.get("spans", []):
                if not isinstance(span, dict):
                    continue
                name = str(span.get("name", "unnamed"))
                if not _SAFE_REFERENCE.fullmatch(name):
                    name = "unnamed"
                record = {
                    "schema_version": "esx-redacted-telemetry-record-1.0",
                    "name": name,
                    "attributes": {**resource, **_attributes(span.get("attributes"))},
                }
                duration_ms = _span_duration_ms(span)
                if duration_ms is not None:
                    record["duration_ms"] = duration_ms
                records.append(record)
    return records


def _span_duration_ms(span: dict[str, Any]) -> int | None:
    start, end = span.get("startTimeUnixNano"), span.get("endTimeUnixNano")
    if not isinstance(start, str) or not isinstance(end, str) or not start.isdigit() or not end.isdigit():
        return None
    elapsed = int(end) - int(start)
    if elapsed < 0 or elapsed > 86_400_000_000_000:
        return None
    return round(elapsed / 1_000_000)


def telemetry_summary(path: str | Path) -> dict[str, object]:
    span_count = tool_calls = retrievals = 0
    services: set[str] = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        try:
            span = json.loads(line)
        except json.JSONDecodeError:
            continue
        attributes = span.get("attributes", {}) if isinstance(span, dict) else {}
        if not isinstance(attributes, dict):
            continue
        if isinstance(attributes.get("service.name"), str):
            services.add(attributes["service.name"])
        name = str(span.get("name", "")).lower()
        tool_calls += int("tool" in name or "gen_ai.tool.name" in attributes)
        retrievals += int("retriev" in name or "vector" in name)
        span_count += 1
    return {"schema_version": "esx-redacted-telemetry-summary-1.0", "span_count": span_count, "service_count": len(services), "tool_span_count": tool_calls, "retrieval_span_count": retrievals}


def derive_telemetry_measurements(
    path: str | Path, *, required_dimensions: list[str], case_ids: list[str],
    policy: dict[str, Any] | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    """Derive only supported, redacted metric inputs from local telemetry.

    This intentionally returns partial data. A metric is attached only when the
    trace contains every fact its local formula requires; absent facts stay
    `not_measurable` rather than being guessed from a browser outcome.
    """
    records = _read_redacted_records(path)
    required = set(required_dimensions)
    allowed_cases = {case_id for case_id in case_ids if _SAFE_REFERENCE.fullmatch(case_id)}
    options = policy if isinstance(policy, dict) else {}
    measurements: dict[str, object] = {}
    claims = _claims_from_records(records)
    if "groundedness" in required and claims:
        measurements["claims"] = claims
    if "rag" in required:
        rag = _rag_from_records(records, claims, options)
        if rag is not None:
            measurements["rag"] = rag
    if "robustness" in required:
        robustness = _robustness_from_records(records, allowed_cases, options)
        if robustness is not None:
            measurements["robustness"] = robustness
    if "security" in required:
        security = _security_from_records(records)
        if security is not None:
            measurements["security"] = security
    if "trajectory" in required:
        trajectory = _trajectory_from_records(records, options)
        if trajectory is not None:
            measurements["trajectory"] = trajectory
    if "tool_use" in required:
        tool_use = _tool_use_from_records(records, allowed_cases, options)
        if tool_use is not None:
            measurements["tool_use"] = tool_use
    if "judge_agreement" in required:
        decisions = _decisions_from_records(records, event_type="judge_decision", actor_key="esx.judge_id", include_confidence=True)
        if decisions:
            measurements["judge_agreement"] = {"decisions": decisions}
    if "reproducibility" in required:
        decisions = _decisions_from_records(records, event_type="run_decision", actor_key="esx.run_id", include_confidence=False)
        if decisions:
            measurements["reproducibility"] = {"decisions": decisions}
    if "cost_efficiency" in required:
        cost = _cost_from_records(records, allowed_cases, options)
        if cost is not None:
            measurements["cost_efficiency"] = cost
    trace = _trace_from_records(records)
    if trace is not None:
        measurements["trace_envelope"] = trace
    provenance = {
        "schema_version": "esx-telemetry-derived-evidence-1.0",
        "record_count": len(records),
        "case_count": len(allowed_cases),
        "derived_dimensions": sorted(
            "groundedness" if key == "claims" else key
            for key in measurements if key != "trace_envelope"
        ),
        "trace_captured": trace is not None,
    }
    return measurements, provenance


def _read_redacted_records(path: str | Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return records
    for line in lines[:10_000]:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict) or not isinstance(record.get("attributes"), dict):
            continue
        attributes = {
            key: value for key, value in record["attributes"].items()
            if isinstance(key, str) and key in _SAFE_ATTRIBUTE_KEYS
            and _safe_value(key, value) is not None
        }
        name = record.get("name")
        if not isinstance(name, str) or not _SAFE_REFERENCE.fullmatch(name):
            continue
        clean: dict[str, object] = {"name": name, "attributes": attributes}
        duration = record.get("duration_ms")
        if isinstance(duration, int) and not isinstance(duration, bool) and 0 <= duration <= 86_400_000:
            clean["duration_ms"] = duration
        records.append(clean)
    return records


def _event_type(record: dict[str, object]) -> str | None:
    attributes = record["attributes"]
    if not isinstance(attributes, dict):
        return None
    value = attributes.get("esx.event_type")
    return value if isinstance(value, str) and value in _TRACE_EVENT_TYPES else None


def _references(options: object) -> list[str]:
    if not isinstance(options, list):
        return []
    return [item for item in options if isinstance(item, str) and _SAFE_REFERENCE.fullmatch(item)]


def _claims_from_records(records: list[dict[str, object]]) -> list[dict[str, object]]:
    claims: dict[str, dict[str, object]] = {}
    for record in records:
        attributes = record["attributes"]
        if not isinstance(attributes, dict):
            continue
        claim_id = attributes.get("esx.claim_id")
        evidence_id = attributes.get("esx.evidence_id")
        score = attributes.get("esx.claim_support_score")
        citations = attributes.get("esx.citation_valid")
        integrity = attributes.get("esx.evidence_integrity_valid")
        if not isinstance(claim_id, str) or not isinstance(evidence_id, str) or not isinstance(score, (int, float)):
            continue
        if not isinstance(citations, bool) or not isinstance(integrity, bool) or not 0 <= float(score) <= 1:
            continue
        current = claims.setdefault(claim_id, {
            "claim_id": claim_id, "evidence_ids": [], "entailment_score": float(score),
            "citations_valid": citations, "evidence_integrity_valid": integrity,
        })
        if evidence_id not in current["evidence_ids"]:
            current["evidence_ids"].append(evidence_id)
        current["entailment_score"] = min(float(current["entailment_score"]), float(score))
        current["citations_valid"] = bool(current["citations_valid"]) and citations
        current["evidence_integrity_valid"] = bool(current["evidence_integrity_valid"]) and integrity
    return [claims[claim_id] for claim_id in sorted(claims)]


def _rag_from_records(records: list[dict[str, object]], claims: list[dict[str, object]], options: dict[str, Any]) -> dict[str, object] | None:
    rag_options = options.get("rag", {})
    relevant = _references(rag_options.get("relevant_document_ids") if isinstance(rag_options, dict) else None)
    retrieved: list[str] = []
    cited: list[str] = []
    for record in records:
        attributes = record["attributes"]
        if not isinstance(attributes, dict):
            continue
        document_id = attributes.get("esx.document_id")
        if not isinstance(document_id, str):
            continue
        if _event_type(record) == "retrieval" and document_id not in retrieved:
            retrieved.append(document_id)
        if _event_type(record) == "citation" and document_id not in cited:
            cited.append(document_id)
    if not relevant or not claims:
        return None
    return {
        "relevant_document_ids": relevant,
        "retrieved_document_ids": retrieved,
        "cited_document_ids": cited,
        "answer_claims": claims,
        "k": max(1, len(retrieved)),
    }


def _robustness_from_records(
    records: list[dict[str, object]], case_ids: set[str], options: dict[str, Any],
) -> dict[str, object] | None:
    """Derive controlled variation outcomes without retaining their inputs."""
    robustness_options = options.get("robustness", {})
    baseline_case_id = robustness_options.get("baseline_case_id") if isinstance(robustness_options, dict) else None
    baseline_label = robustness_options.get("baseline_label") if isinstance(robustness_options, dict) else None
    if not isinstance(baseline_case_id, str) or baseline_case_id not in case_ids or not _SAFE_REFERENCE.fullmatch(baseline_case_id):
        return None
    if baseline_label is not None and (not isinstance(baseline_label, str) or not _SAFE_REFERENCE.fullmatch(baseline_label)):
        return None
    observations: dict[str, dict[str, object]] = {}
    for record in records:
        if _event_type(record) != "robustness_observation":
            continue
        attributes = record["attributes"]
        if not isinstance(attributes, dict):
            continue
        case_id = attributes.get("esx.case_id")
        correct = attributes.get("esx.correct")
        confidence = attributes.get("esx.confidence")
        variation_type = attributes.get("esx.variation_type")
        if (
            not isinstance(case_id, str) or case_id not in case_ids
            or not isinstance(correct, bool) or not isinstance(confidence, (int, float))
            or not isinstance(variation_type, str) or variation_type not in {"baseline", "paraphrase", "perturbation", "repeat"}
        ):
            continue
        observations[case_id] = {
            "correct": correct,
            "confidence": float(confidence),
            "predicted_label": attributes.get("esx.predicted_label"),
            "variation_type": variation_type,
        }
    baseline = observations.get(baseline_case_id)
    if not isinstance(baseline, dict) or baseline.get("variation_type") != "baseline":
        return None
    perturbations = []
    for case_id, observation in sorted(observations.items()):
        if case_id == baseline_case_id or observation["variation_type"] == "baseline":
            continue
        perturbation = {
            "case_id": case_id,
            "correct": observation["correct"],
            "confidence": observation["confidence"],
            "variation_type": observation["variation_type"],
        }
        if isinstance(observation["predicted_label"], str):
            perturbation["predicted_label"] = observation["predicted_label"]
        perturbations.append(perturbation)
    if not perturbations:
        return None
    return {
        "baseline_correct": baseline["correct"],
        "baseline_confidence": baseline["confidence"],
        "baseline_label": baseline_label,
        "perturbations": perturbations,
    }


def _security_from_records(records: list[dict[str, object]]) -> dict[str, object] | None:
    cases: dict[str, dict[str, object]] = {}
    required = ("esx.expected_attack_success", "esx.observed_attack_success", "esx.expected_detection", "esx.observed_detection")
    for record in records:
        if _event_type(record) != "security_control":
            continue
        attributes = record["attributes"]
        if not isinstance(attributes, dict):
            continue
        case_id = attributes.get("esx.case_id")
        if not isinstance(case_id, str) or not all(isinstance(attributes.get(key), bool) for key in required):
            continue
        evidence_id = attributes.get("esx.evidence_id")
        cases[case_id] = {
            "case_id": case_id,
            "expected_attack_success": attributes["esx.expected_attack_success"],
            "observed_attack_success": attributes["esx.observed_attack_success"],
            "expected_detection": attributes["esx.expected_detection"],
            "observed_detection": attributes["esx.observed_detection"],
            "evidence_ids": [evidence_id] if isinstance(evidence_id, str) else [],
            "evidence_integrity_valid": attributes.get("esx.evidence_integrity_valid"),
        }
    return {"cases": [cases[key] for key in sorted(cases)]} if cases else None


def _trajectory_from_records(records: list[dict[str, object]], options: dict[str, Any]) -> dict[str, object] | None:
    trajectory_options = options.get("trajectory", {})
    required = _references(trajectory_options.get("required_milestones") if isinstance(trajectory_options, dict) else None)
    events = [record for record in records if _event_type(record) is not None]
    if not required or not events:
        return None
    observed = []
    policy_violations = []
    scope_violations = []
    misuse_events = []
    for record in events:
        attributes = record["attributes"]
        if not isinstance(attributes, dict):
            continue
        milestone = attributes.get("esx.milestone")
        if isinstance(milestone, str) and milestone not in observed:
            observed.append(milestone)
        for key, target in (("esx.policy_violation", policy_violations), ("esx.scope_violation", scope_violations), ("esx.tool_misuse_event", misuse_events)):
            value = attributes.get(key)
            if isinstance(value, str) and value not in target:
                target.append(value)
    return {
        "required_milestones": required,
        "observed_milestones": observed,
        "action_count": len(events),
        "redundant_actions": 0,
        "policy_violations": policy_violations,
        "scope_violations": scope_violations,
        "tool_misuse_events": misuse_events,
    }


def _tool_use_from_records(
    records: list[dict[str, object]], case_ids: set[str], options: dict[str, Any],
) -> dict[str, object] | None:
    """Build tool-use observations only when labelled expectations are complete."""
    tool_options = options.get("tool_use", {})
    expected_by_case = tool_options.get("expected_tools_by_case", {}) if isinstance(tool_options, dict) else {}
    if not case_ids or not isinstance(expected_by_case, dict):
        return None
    expected: dict[str, list[str]] = {}
    for case_id in case_ids:
        tool_names = _references(expected_by_case.get(case_id))
        if not tool_names:
            return None
        expected[case_id] = tool_names
    groups: dict[str, dict[str, object]] = {
        case_id: {"observed": [], "controlled": [], "authorized": [], "result_valid": [], "evidence_ids": [], "integrity": []}
        for case_id in case_ids
    }
    for record in records:
        if _event_type(record) != "tool_call":
            continue
        attributes = record["attributes"]
        if not isinstance(attributes, dict):
            continue
        case_id = attributes.get("esx.case_id")
        tool_name = attributes.get("gen_ai.tool.name")
        authorized = attributes.get("esx.tool_authorized")
        result_valid = attributes.get("esx.tool_result_valid")
        # A framework callback outside an ESX case context is retained for the
        # trace but cannot be attributed to this labelled metric.
        if not isinstance(case_id, str) or case_id not in groups:
            continue
        if not isinstance(tool_name, str):
            return None
        group = groups[case_id]
        if tool_name not in group["observed"]:
            group["observed"].append(tool_name)
        if isinstance(authorized, bool) and isinstance(result_valid, bool):
            if tool_name not in group["controlled"]:
                group["controlled"].append(tool_name)
            group["authorized"].append(authorized)
            group["result_valid"].append(result_valid)
        evidence_id = attributes.get("esx.evidence_id")
        if isinstance(evidence_id, str) and evidence_id not in group["evidence_ids"]:
            group["evidence_ids"].append(evidence_id)
        integrity = attributes.get("esx.evidence_integrity_valid")
        if isinstance(integrity, bool):
            group["integrity"].append(integrity)
    output = []
    for case_id in sorted(case_ids):
        group = groups[case_id]
        observed = group["observed"]
        if any(tool_name not in group["controlled"] for tool_name in observed):
            return None
        # A missing required call is a selection failure, not a guessed control failure.
        output.append({
            "case_id": case_id,
            "expected_tool_names": expected[case_id],
            "observed_tool_names": observed,
            "authorized": all(group["authorized"]) if observed else True,
            "result_valid": all(group["result_valid"]) if observed else True,
            "evidence_ids": group["evidence_ids"],
            "evidence_integrity_valid": all(group["integrity"]) if group["integrity"] else None,
        })
    return {"cases": output}


def _decisions_from_records(records: list[dict[str, object]], *, event_type: str, actor_key: str, include_confidence: bool) -> list[dict[str, object]]:
    decisions: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for record in records:
        if _event_type(record) != event_type:
            continue
        attributes = record["attributes"]
        if not isinstance(attributes, dict):
            continue
        case_id, actor, verdict = attributes.get("esx.case_id"), attributes.get(actor_key), attributes.get("esx.verdict")
        if not isinstance(case_id, str) or not isinstance(actor, str) or verdict not in {"pass", "fail", "inconclusive"} or (case_id, actor) in seen:
            continue
        decision: dict[str, object] = {"case_id": case_id, actor_key.removeprefix("esx."): actor, "verdict": verdict}
        confidence = attributes.get("esx.confidence")
        if include_confidence:
            if not isinstance(confidence, (int, float)) or not 0 <= float(confidence) <= 1:
                continue
            decision["confidence"] = float(confidence)
        decisions.append(decision)
        seen.add((case_id, actor))
    return decisions


def _cost_from_records(records: list[dict[str, object]], case_ids: set[str], options: dict[str, Any]) -> dict[str, object] | None:
    if not case_ids:
        return None
    cost_options = options.get("cost_efficiency", {})
    cost_options = cost_options if isinstance(cost_options, dict) else {}
    input_rate = cost_options.get("input_cost_per_million_usd")
    output_rate = cost_options.get("output_cost_per_million_usd")
    groups: dict[str, dict[str, object]] = {}
    for record in records:
        attributes = record["attributes"]
        if not isinstance(attributes, dict):
            continue
        case_id = attributes.get("esx.case_id")
        if not isinstance(case_id, str) or case_id not in case_ids:
            continue
        group = groups.setdefault(case_id, {"input_tokens": 0, "output_tokens": 0, "request_count": 0, "retry_count": 0, "tool_call_count": 0, "cost_values": [], "latency_ms": 0, "cache_hit": False, "fallback_used": False, "timed_out": False, "usage_seen": False})
        if _event_type(record) == "tool_call" or "gen_ai.tool.name" in attributes:
            group["tool_call_count"] = int(group["tool_call_count"]) + 1
        has_usage = any(key in attributes for key in ("gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens", "esx.cost_usd"))
        if not has_usage:
            continue
        group["usage_seen"] = True
        group["input_tokens"] = int(group["input_tokens"]) + int(attributes.get("gen_ai.usage.input_tokens", 0))
        group["output_tokens"] = int(group["output_tokens"]) + int(attributes.get("gen_ai.usage.output_tokens", 0))
        group["request_count"] = int(group["request_count"]) + 1
        group["retry_count"] = int(group["retry_count"]) + int(attributes.get("esx.retry_count", 0))
        group["latency_ms"] = int(group["latency_ms"]) + int(record.get("duration_ms", 0))
        group["cache_hit"] = bool(group["cache_hit"]) or bool(attributes.get("esx.cache_hit", False))
        group["fallback_used"] = bool(group["fallback_used"]) or bool(attributes.get("esx.fallback_used", False))
        group["timed_out"] = bool(group["timed_out"]) or bool(attributes.get("esx.timed_out", False))
        if isinstance(attributes.get("esx.cost_usd"), (int, float)):
            group["cost_values"].append(float(attributes["esx.cost_usd"]))
    if set(groups) != case_ids or not all(group["usage_seen"] for group in groups.values()):
        return None
    provider_reported = all(group["cost_values"] for group in groups.values())
    metered = isinstance(input_rate, (int, float)) and isinstance(output_rate, (int, float)) and input_rate >= 0 and output_rate >= 0
    if not provider_reported and not metered:
        return None
    observations = []
    for case_id in sorted(groups):
        group = groups[case_id]
        cost = sum(group["cost_values"]) if provider_reported else (
            int(group["input_tokens"]) * float(input_rate) / 1_000_000 + int(group["output_tokens"]) * float(output_rate) / 1_000_000
        )
        observations.append({
            "case_id": case_id, "input_tokens": group["input_tokens"], "output_tokens": group["output_tokens"],
            "request_count": group["request_count"], "retry_count": group["retry_count"], "tool_call_count": group["tool_call_count"],
            "cache_hit": group["cache_hit"], "fallback_used": group["fallback_used"], "cost_usd": cost,
            "latency_ms": group["latency_ms"], "timed_out": group["timed_out"],
        })
    return {"cost_source": "provider_reported" if provider_reported else "metered", "observations": observations}


def _trace_from_records(records: list[dict[str, object]]) -> dict[str, object] | None:
    events = []
    agents: set[str] = set()
    for sequence, record in enumerate(records, start=1):
        event_type = _event_type(record)
        if event_type not in {"handoff", "model_request", "model_response", "tool_call", "tool_result", "policy_decision", "final_response", "error"}:
            continue
        attributes = record["attributes"]
        if not isinstance(attributes, dict):
            continue
        agent_id = attributes.get("esx.agent_id", "telemetry")
        if not isinstance(agent_id, str):
            continue
        agents.add(agent_id)
        event_id = attributes.get("esx.event_id", f"event-{sequence}")
        outcome = "failed" if event_type == "error" else "succeeded"
        evidence = attributes.get("esx.evidence_id")
        events.append({
            "event_id": event_id, "sequence": len(events) + 1, "agent_id": agent_id,
            "event_type": event_type, "outcome": outcome,
            "tool_name": attributes.get("gen_ai.tool.name"),
            "scope_reference": attributes.get("esx.case_id"),
            "evidence_ids": [evidence] if isinstance(evidence, str) else [],
        })
    if not events:
        return None
    return {
        "trace_id": "local-telemetry", "schema_version": "esx-redacted-trace-1.0",
        "producer": "otel-local-collector", "agent_ids": sorted(agents),
        "redaction_status": "redacted", "events": events,
    }


def serve_collector(output: str | Path) -> None:
    """Receive OTLP JSON on loopback and append redacted spans locally."""
    target = Path(output).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(24)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/v1/traces" or self.headers.get("X-ESX-Telemetry-Token") != token:
                self.send_error(403)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 1 <= length <= 1_048_576:
                    raise ValueError
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                records = redact_otel_payload(payload)
                with target.open("a", encoding="utf-8") as stream:
                    for record in records:
                        stream.write(json.dumps(record, separators=(",", ":")) + "\n")
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                self.send_error(400)
                return
            self.send_response(202)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    print(f"Local OTLP JSON collector: http://127.0.0.1:{server.server_port}/v1/traces")
    print(f"Set X-ESX-Telemetry-Token: {token}; redacted spans will be written to {target}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
