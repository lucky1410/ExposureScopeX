"""Privacy-preserving local instrumentation helpers for supported AI runtimes."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import json
from pathlib import Path
import re
from typing import Any, Iterator


_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
_EVENT_TYPES = {
    "handoff", "model_request", "model_response", "tool_call", "tool_result",
    "policy_decision", "final_response", "error", "retrieval", "citation",
    "security_control", "robustness_observation", "judge_decision", "run_decision",
}
_REFERENCE_ATTRIBUTES = {
    "esx.case_id", "esx.agent_id", "esx.event_id", "esx.event_type", "esx.milestone",
    "esx.evidence_id", "esx.document_id", "esx.claim_id", "esx.policy_violation",
    "esx.scope_violation", "esx.tool_misuse_event", "esx.variation_type", "esx.predicted_label", "esx.judge_id", "esx.run_id",
    "esx.verdict", "gen_ai.tool.name",
}
_BOOLEAN_ATTRIBUTES = {
    "esx.citation_valid", "esx.evidence_integrity_valid", "esx.expected_attack_success",
    "esx.observed_attack_success", "esx.expected_detection", "esx.observed_detection",
    "esx.correct", "esx.cache_hit", "esx.fallback_used", "esx.timed_out",
    "esx.tool_authorized", "esx.tool_result_valid",
}
_INTEGER_ATTRIBUTES = {
    "gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens", "esx.retry_count",
}
_SCORE_ATTRIBUTES = {"esx.claim_support_score", "esx.confidence"}
_CASE_ID: ContextVar[str | None] = ContextVar("esx_case_id", default=None)


def _reference(value: object, name: str) -> str:
    if not isinstance(value, str) or not _REFERENCE.fullmatch(value):
        raise ValueError(f"{name} must be an opaque identifier using letters, digits, '.', '_', ':', '/', or '-'")
    return value


def _score(value: object, name: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= float(value) <= 1:
        raise ValueError(f"{name} must be a number from 0 to 1")
    return float(value)


class LocalEvidenceEmitter:
    """Append compact, redacted events that the local collector can score.

    Event values intentionally accept only opaque identifiers, booleans, and
    numeric operational metadata. Callers cannot accidentally record prompts,
    answers, documents, tool arguments, credentials, or session data.
    """

    def __init__(self, output: str | Path, *, agent_id: str = "application") -> None:
        self.output = Path(output).resolve()
        self.agent_id = _reference(agent_id, "agent_id")

    @contextmanager
    def case(self, case_id: str) -> Iterator[None]:
        """Associate a group of local events with one opaque evaluation case."""
        token = _CASE_ID.set(_reference(case_id, "case_id"))
        try:
            yield
        finally:
            _CASE_ID.reset(token)

    def event(self, event_type: str, *, case_id: str | None = None, duration_ms: int | None = None, **attributes: object) -> None:
        if event_type not in _EVENT_TYPES:
            raise ValueError("Unsupported local evidence event type")
        resolved_case = case_id or _CASE_ID.get()
        values: dict[str, object] = {"esx.event_type": event_type, "esx.agent_id": self.agent_id}
        if resolved_case:
            values["esx.case_id"] = _reference(resolved_case, "case_id")
        for key, value in attributes.items():
            values[key] = _safe_attribute(key, value)
        record = {
            "schema_version": "esx-redacted-telemetry-record-1.0",
            "name": f"esx.{event_type}",
            "attributes": values,
        }
        if duration_ms is not None:
            record["duration_ms"] = _non_negative_integer(duration_ms, "duration_ms")
        self.output.parent.mkdir(parents=True, exist_ok=True)
        with self.output.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n")

    def retrieval(self, document_id: str, *, case_id: str | None = None) -> None:
        self.event("retrieval", case_id=case_id, **{"esx.document_id": _reference(document_id, "document_id")})

    def citation(self, document_id: str, *, case_id: str | None = None) -> None:
        self.event("citation", case_id=case_id, **{"esx.document_id": _reference(document_id, "document_id")})

    def claim(self, claim_id: str, evidence_id: str, *, support_score: float, citations_valid: bool, evidence_integrity_valid: bool, case_id: str | None = None) -> None:
        self.event("final_response", case_id=case_id, **{
            "esx.claim_id": _reference(claim_id, "claim_id"),
            "esx.evidence_id": _reference(evidence_id, "evidence_id"),
            "esx.claim_support_score": _score(support_score, "support_score"),
            "esx.citation_valid": _boolean(citations_valid, "citations_valid"),
            "esx.evidence_integrity_valid": _boolean(evidence_integrity_valid, "evidence_integrity_valid"),
        })

    def milestone(self, name: str, *, case_id: str | None = None) -> None:
        self.event("policy_decision", case_id=case_id, **{"esx.milestone": _reference(name, "milestone")})

    def tool_call(
        self, tool_name: str, *, case_id: str | None = None,
        authorized: bool | None = None, result_valid: bool | None = None,
        evidence_id: str | None = None, evidence_integrity_valid: bool | None = None,
    ) -> None:
        """Record a tool call; add labelled controls to enable tool-use scoring."""
        values: dict[str, object] = {"gen_ai.tool.name": _reference(tool_name, "tool_name")}
        optional_booleans = {
            "esx.tool_authorized": authorized,
            "esx.tool_result_valid": result_valid,
            "esx.evidence_integrity_valid": evidence_integrity_valid,
        }
        for key, value in optional_booleans.items():
            if value is not None:
                values[key] = _boolean(value, key)
        if evidence_id is not None:
            values["esx.evidence_id"] = _reference(evidence_id, "evidence_id")
        self.event("tool_call", case_id=case_id, **values)

    def model_usage(self, *, input_tokens: int, output_tokens: int, latency_ms: int, cost_usd: float | None = None, retry_count: int = 0, cache_hit: bool = False, fallback_used: bool = False, timed_out: bool = False, case_id: str | None = None) -> None:
        values: dict[str, object] = {
            "gen_ai.usage.input_tokens": _non_negative_integer(input_tokens, "input_tokens"),
            "gen_ai.usage.output_tokens": _non_negative_integer(output_tokens, "output_tokens"),
            "esx.retry_count": _non_negative_integer(retry_count, "retry_count"),
            "esx.cache_hit": _boolean(cache_hit, "cache_hit"),
            "esx.fallback_used": _boolean(fallback_used, "fallback_used"),
            "esx.timed_out": _boolean(timed_out, "timed_out"),
        }
        if cost_usd is not None:
            if not isinstance(cost_usd, (int, float)) or isinstance(cost_usd, bool) or float(cost_usd) < 0:
                raise ValueError("cost_usd must be a non-negative number")
            values["esx.cost_usd"] = float(cost_usd)
        self.event("model_request", case_id=case_id, duration_ms=latency_ms, **values)

    def robustness_observation(
        self, *, correct: bool, confidence: float, variation_type: str,
        case_id: str | None = None, predicted_label: str | None = None,
    ) -> None:
        """Record a labelled baseline or controlled variation outcome."""
        if variation_type not in {"baseline", "paraphrase", "perturbation", "repeat"}:
            raise ValueError("variation_type must be baseline, paraphrase, perturbation, or repeat")
        values: dict[str, object] = {
            "esx.correct": _boolean(correct, "correct"),
            "esx.confidence": _score(confidence, "confidence"),
            "esx.variation_type": variation_type,
        }
        if predicted_label is not None:
            values["esx.predicted_label"] = _reference(predicted_label, "predicted_label")
        self.event("robustness_observation", case_id=case_id, **values)


class LangChainTelemetryCallback:
    """Duck-typed callback for LangChain and LangGraph callback managers.

    It intentionally ignores prompts, outputs, documents, and tool arguments.
    Retriever documents are recorded only when their metadata supplies an
    opaque `esx_document_id` or `document_id`.
    """

    def __init__(self, emitter: LocalEvidenceEmitter) -> None:
        self.emitter = emitter

    def on_tool_start(self, serialized: object, _input_str: object, **_kwargs: object) -> None:
        if isinstance(serialized, dict):
            name = serialized.get("name")
            if isinstance(name, str) and _REFERENCE.fullmatch(name):
                self.emitter.tool_call(name)

    def on_retriever_end(self, documents: object, **_kwargs: object) -> None:
        if not isinstance(documents, list):
            return
        for document in documents:
            metadata = getattr(document, "metadata", None)
            if not isinstance(metadata, dict):
                continue
            identifier = metadata.get("esx_document_id", metadata.get("document_id"))
            if isinstance(identifier, str) and _REFERENCE.fullmatch(identifier):
                self.emitter.retrieval(identifier)


def langchain_callback(emitter: LocalEvidenceEmitter) -> LangChainTelemetryCallback:
    """Return a content-safe callback usable by LangChain and LangGraph."""
    return LangChainTelemetryCallback(emitter)


def record_openai_response_usage(
    emitter: LocalEvidenceEmitter, response: object, *, latency_ms: int,
    case_id: str | None = None, cost_usd: float | None = None,
) -> bool:
    """Record OpenAI-compatible response usage without retaining the response."""
    usage = _member(response, "usage")
    return _record_provider_usage(
        emitter, usage, latency_ms=latency_ms, case_id=case_id, cost_usd=cost_usd,
        input_names=("input_tokens", "prompt_tokens"),
        output_names=("output_tokens", "completion_tokens"),
    )


def record_anthropic_message_usage(
    emitter: LocalEvidenceEmitter, message: object, *, latency_ms: int,
    case_id: str | None = None, cost_usd: float | None = None,
) -> bool:
    """Record Anthropic-compatible message usage without retaining the message."""
    usage = _member(message, "usage")
    return _record_provider_usage(
        emitter, usage, latency_ms=latency_ms, case_id=case_id, cost_usd=cost_usd,
        input_names=("input_tokens",), output_names=("output_tokens",),
    )


def _member(value: object, name: str) -> object | None:
    if isinstance(value, dict):
        return value.get(name)
    return getattr(value, name, None)


def _record_provider_usage(
    emitter: LocalEvidenceEmitter, usage: object, *, latency_ms: int,
    case_id: str | None, cost_usd: float | None,
    input_names: tuple[str, ...], output_names: tuple[str, ...],
) -> bool:
    input_tokens = next((_member(usage, name) for name in input_names if isinstance(_member(usage, name), int)), None)
    output_tokens = next((_member(usage, name) for name in output_names if isinstance(_member(usage, name), int)), None)
    if input_tokens is None or output_tokens is None:
        return False
    emitter.model_usage(
        input_tokens=input_tokens, output_tokens=output_tokens, latency_ms=latency_ms,
        cost_usd=cost_usd, case_id=case_id,
    )
    return True


def _safe_attribute(key: str, value: object) -> object:
    if key in _REFERENCE_ATTRIBUTES:
        return _reference(value, key)
    if key in _BOOLEAN_ATTRIBUTES:
        return _boolean(value, key)
    if key in _INTEGER_ATTRIBUTES:
        return _non_negative_integer(value, key)
    if key in _SCORE_ATTRIBUTES:
        return _score(value, key)
    if key == "esx.cost_usd":
        return _non_negative_number(value, key)
    raise ValueError("Only explicitly approved local evidence metadata keys are allowed")


def _boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be true or false")
    return value


def _non_negative_integer(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _non_negative_number(value: object, name: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or float(value) < 0:
        raise ValueError(f"{name} must be a non-negative number")
    return float(value)
