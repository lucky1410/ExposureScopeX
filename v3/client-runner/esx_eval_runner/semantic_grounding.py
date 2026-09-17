"""Local semantic groundedness evaluation with content-safe report output."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import threading
import time
from typing import Any

from .runner import RunnerError, canonical_json, sha256


GROUNDING_MATERIAL_SCHEMA_VERSION = "pre-d-grounding-material-1.0"
JUDGE_REQUEST_SCHEMA_VERSION = "pre-d-grounding-judge-request-1.0"
JUDGE_RESPONSE_SCHEMA_VERSION = "pre-d-grounding-judge-response-1.0"
GROUNDING_CALCULATION_VERSION = "pred-semantic-grounding-1.2"
GROUNDING_RUBRIC_VERSION = "pred-grounding-rubric-1.2"
_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
_VERDICTS = {"supported", "contradicted", "insufficient"}
_MAX_CASES = 10_000
_MAX_TEXT_CHARS = 200_000
_MAX_EVIDENCE_PER_CASE = 1_000
_MAX_TOTAL_TEXT_CHARS = 10_000_000


def _strict_object(value: object, field: str, *, required: set[str], allowed: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RunnerError(f"{field} must be an object")
    if unknown := sorted(set(value) - allowed):
        raise RunnerError(f"{field} has unsupported fields: " + ", ".join(unknown))
    if missing := sorted(required - set(value)):
        raise RunnerError(f"{field} is missing fields: " + ", ".join(missing))
    return value


def _reference(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SAFE_REFERENCE.fullmatch(value):
        raise RunnerError(f"{field} must be an opaque reference no longer than 160 characters")
    return value


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT_CHARS:
        raise RunnerError(f"{field} must be non-empty text no longer than {_MAX_TEXT_CHARS:,} characters")
    return value


def validate_grounding_material(value: object, *, case_ids: set[str] | None = None) -> dict[str, Any]:
    """Validate raw local response and retrieval content used only by the judge."""
    if "REPLACE_WITH_" in json.dumps(value, sort_keys=True):
        raise RunnerError("Replace every REPLACE_WITH_* value in the local grounding material")
    root = _strict_object(
        value, "grounding_material", required={"schema_version", "cases"},
        allowed={"schema_version", "cases"},
    )
    if root["schema_version"] != GROUNDING_MATERIAL_SCHEMA_VERSION:
        raise RunnerError(
            f"grounding_material.schema_version must be {GROUNDING_MATERIAL_SCHEMA_VERSION}"
        )
    raw_cases = root["cases"]
    if not isinstance(raw_cases, list) or not raw_cases or len(raw_cases) > _MAX_CASES:
        raise RunnerError(f"grounding_material.cases must contain between 1 and {_MAX_CASES:,} cases")
    cases: list[dict[str, Any]] = []
    total_chars = 0
    for index, raw_case in enumerate(raw_cases):
        field = f"grounding_material.cases[{index}]"
        case = _strict_object(
            raw_case, field, required={"case_id", "response", "evidence"},
            allowed={"case_id", "response", "evidence"},
        )
        case_id = _reference(case["case_id"], f"{field}.case_id")
        response = _text(case["response"], f"{field}.response")
        evidence = case["evidence"]
        if not isinstance(evidence, list) or len(evidence) > _MAX_EVIDENCE_PER_CASE:
            raise RunnerError(
                f"{field}.evidence must contain between 0 and {_MAX_EVIDENCE_PER_CASE:,} source chunks"
            )
        chunks: list[dict[str, str]] = []
        for chunk_index, raw_chunk in enumerate(evidence):
            chunk_field = f"{field}.evidence[{chunk_index}]"
            chunk = _strict_object(
                raw_chunk, chunk_field, required={"evidence_id", "text"},
                allowed={"evidence_id", "text"},
            )
            chunks.append({
                "evidence_id": _reference(chunk["evidence_id"], f"{chunk_field}.evidence_id"),
                "text": _text(chunk["text"], f"{chunk_field}.text"),
            })
        if len({item["evidence_id"] for item in chunks}) != len(chunks):
            raise RunnerError(f"{field}.evidence evidence_id values must be unique")
        total_chars += len(response) + sum(len(item["text"]) for item in chunks)
        cases.append({"case_id": case_id, "response": response, "evidence": chunks})
    observed_ids = [item["case_id"] for item in cases]
    if len(set(observed_ids)) != len(observed_ids):
        raise RunnerError("grounding_material case_id values must be unique")
    if case_ids is not None and set(observed_ids) != case_ids:
        missing = sorted(case_ids - set(observed_ids))
        extra = sorted(set(observed_ids) - case_ids)
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unknown " + ", ".join(extra))
        raise RunnerError("Grounding material must cover every evaluated case: " + "; ".join(detail))
    if total_chars > _MAX_TOTAL_TEXT_CHARS:
        raise RunnerError(
            f"Grounding material exceeds the {_MAX_TOTAL_TEXT_CHARS:,}-character local safety limit"
        )
    return {"schema_version": GROUNDING_MATERIAL_SCHEMA_VERSION, "cases": cases}


def read_grounding_material(path: str | Path, *, case_ids: set[str] | None = None) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"Cannot read local grounding material JSON: {path}") from exc
    return validate_grounding_material(value, case_ids=case_ids)


def _validate_judge(judge: object, *, target_command: object = None, subject_id: str | None = None) -> dict[str, Any]:
    item = _strict_object(
        judge, "assurance.grounding_judge",
        required={"type", "command", "identity", "version", "independent_from_target"},
        allowed={
            "type", "command", "identity", "version", "independent_from_target",
            "timeout_seconds", "max_response_bytes",
        },
    )
    if item["type"] != "command_json_v1":
        raise RunnerError("assurance.grounding_judge.type must be command_json_v1")
    command = item["command"]
    if not isinstance(command, list) or not command or not all(isinstance(part, str) and part for part in command):
        raise RunnerError("assurance.grounding_judge.command must be a non-empty string array")
    if isinstance(target_command, list) and command == target_command:
        raise RunnerError("The grounding judge command must be independent from the target adapter command")
    identity = _reference(item["identity"], "assurance.grounding_judge.identity")
    version = _reference(item["version"], "assurance.grounding_judge.version")
    if subject_id and identity == subject_id:
        raise RunnerError("The grounding judge identity must differ from the evaluated subject identity")
    if item["independent_from_target"] is not True:
        raise RunnerError("assurance.grounding_judge.independent_from_target must be true")
    timeout = item.get("timeout_seconds", 120)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1 or timeout > 600:
        raise RunnerError("assurance.grounding_judge.timeout_seconds must be between 1 and 600")
    maximum = item.get("max_response_bytes", 5_242_880)
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1 or maximum > 10_485_760:
        raise RunnerError("assurance.grounding_judge.max_response_bytes must be between 1 and 10,485,760")
    return {
        "type": "command_json_v1", "command": command, "identity": identity,
        "version": version, "independent_from_target": True,
        "timeout_seconds": timeout, "max_response_bytes": maximum,
    }


def _bounded_command(judge: dict[str, Any], request: bytes, operation: str) -> bytes:
    """Drain both pipes concurrently, enforcing limits before buffering output."""
    try:
        process = subprocess.Popen(
            judge["command"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError as exc:
        raise RunnerError("Local grounding judge could not be started; check its executable and permissions") from exc
    output = bytearray()
    violations: list[str] = []
    exceeded = threading.Event()

    def drain(pipe: Any, limit: int, name: str) -> None:
        count = 0
        try:
            while chunk := pipe.read1(16_384):
                count += len(chunk)
                if count > limit:
                    violations.append(name)
                    exceeded.set()
                    return
                if name == "stdout":
                    output.extend(chunk)
        except OSError:
            violations.append(name + " read")
            exceeded.set()
        finally:
            pipe.close()

    def feed() -> None:
        try:
            process.stdin.write(request)
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            process.stdin.close()

    threads = [
        threading.Thread(target=drain, args=(process.stdout, judge["max_response_bytes"], "stdout"), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, 65_536, "stderr"), daemon=True),
        threading.Thread(target=feed, daemon=True),
    ]
    deadline = time.monotonic() + judge["timeout_seconds"]
    for thread in threads:
        thread.start()
    try:
        while True:
            if exceeded.is_set():
                raise RunnerError(f"Local grounding judge exceeded its {violations[0]} limit during {operation}")
            if process.poll() is not None and not any(thread.is_alive() for thread in threads):
                break
            if time.monotonic() >= deadline:
                raise RunnerError(f"Local grounding judge timed out during {operation}")
            exceeded.wait(0.01)
        if process.returncode != 0:
            raise RunnerError(f"Local grounding judge exited with status {process.returncode} during {operation}; stderr is omitted")
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        for thread in threads:
            thread.join(timeout=1)


def _invoke_judge(judge: dict[str, Any], operation: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = {
        "schema_version": JUDGE_REQUEST_SCHEMA_VERSION,
        "operation": operation,
        "rubric_version": GROUNDING_RUBRIC_VERSION,
        **payload,
    }
    output = _bounded_command(judge, canonical_json(request), operation)
    try:
        response = json.loads(output.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"Local grounding judge returned invalid JSON during {operation}") from exc
    root = _strict_object(
        response, "grounding_judge_response",
        required={"schema_version", "operation", "results"},
        allowed={"schema_version", "operation", "results"},
    )
    if root["schema_version"] != JUDGE_RESPONSE_SCHEMA_VERSION or root["operation"] != operation:
        raise RunnerError(f"Local grounding judge returned the wrong schema or operation for {operation}")
    return root


def _extract_claims(material: dict[str, Any], judge: dict[str, Any]) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    response = _invoke_judge(judge, "extract_claims", {
        "cases": [{"case_id": item["case_id"], "response": item["response"]} for item in material["cases"]],
    })
    results = response["results"]
    if not isinstance(results, list):
        raise RunnerError("Claim extraction results must be an array")
    by_case: dict[str, list[str]] = {}
    responses: list[dict[str, Any]] = []
    for index, raw in enumerate(results):
        field = f"grounding_judge_response.results[{index}]"
        item = _strict_object(raw, field, required={"case_id", "claims"}, allowed={"case_id", "claims", "abstained"})
        if "abstained" in item and not isinstance(item["abstained"], bool):
            raise RunnerError(f"{field}.abstained must be boolean")
        case_id = _reference(item["case_id"], f"{field}.case_id")
        claims = item["claims"]
        if not isinstance(claims, list) or len(claims) > 1_000:
            raise RunnerError(f"{field}.claims must be an array with at most 1,000 atomic claims")
        texts = [_text(claim, f"{field}.claims") for claim in claims]
        if len(set(texts)) != len(texts):
            raise RunnerError(f"{field}.claims must not contain duplicate claim text")
        if case_id in by_case:
            raise RunnerError("Claim extraction returned duplicate case_id values")
        by_case[case_id] = texts
        responses.append({"case_id": case_id, "claim_count": len(texts), "abstained": item.get("abstained")})
    expected_cases = {item["case_id"] for item in material["cases"]}
    if set(by_case) != expected_cases:
        raise RunnerError("Claim extraction must return exactly one result for every grounding case")
    claims_out: list[dict[str, str]] = []
    for case in material["cases"]:
        for index, claim_text in enumerate(by_case[case["case_id"]], start=1):
            digest = hashlib.sha256(claim_text.encode("utf-8")).hexdigest()
            claims_out.append({
                "case_id": case["case_id"],
                "claim_id": "claim-" + hashlib.sha256(
                    f"{case['case_id']}\x00{index}\x00{claim_text}".encode("utf-8")
                ).hexdigest()[:32],
                "claim_sha256": digest,
                "text": claim_text,
            })
    return claims_out, responses


def _review_extraction(material: dict[str, Any], claims: list[dict[str, str]], judge: dict[str, Any]) -> None:
    """A separate pass checks omissions and altered claims against the response."""
    case = material["cases"][0]
    response = _invoke_judge(judge, "review_claims", {"cases": [{
        "case_id": case["case_id"], "response": case["response"],
        "claims": [claim["text"] for claim in claims],
    }]})
    results = response["results"]
    if not isinstance(results, list) or len(results) != 1:
        raise RunnerError("Extraction review must return one result for the case")
    item = _strict_object(results[0], "extraction_review", required={"case_id", "complete", "missing_claims"}, allowed={"case_id", "complete", "missing_claims"})
    if item["case_id"] != case["case_id"] or not isinstance(item["complete"], bool):
        raise RunnerError("Extraction review returned an invalid case or completeness flag")
    missing = item["missing_claims"]
    if not isinstance(missing, list) or len(missing) > 1000:
        raise RunnerError("Extraction review missing_claims must be an array of at most 1000 claims")
    for claim in missing:
        _text(claim, "extraction_review.missing_claims")
    if not item["complete"] or missing:
        raise RunnerError("Extraction review found omitted or altered claims; review the response and rerun")


def _compare_claims(
    material: dict[str, Any], claims: list[dict[str, str]], judge: dict[str, Any],
) -> list[dict[str, Any]]:
    evidence_by_case = {item["case_id"]: item["evidence"] for item in material["cases"]}
    response = _invoke_judge(judge, "compare_evidence", {
        "claims": [
            {
                "case_id": claim["case_id"], "claim_id": claim["claim_id"],
                "claim": claim["text"], "evidence": evidence_by_case[claim["case_id"]],
            }
            for claim in claims
        ],
    })
    results = response["results"]
    if not isinstance(results, list):
        raise RunnerError("Evidence comparison results must be an array")
    expected = {item["claim_id"]: item for item in claims}
    compared: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(results):
        field = f"grounding_judge_response.results[{index}]"
        item = _strict_object(
            raw, field, required={"claim_id", "verdict", "confidence", "evidence_ids"},
            allowed={"claim_id", "verdict", "confidence", "evidence_ids"},
        )
        claim_id = _reference(item["claim_id"], f"{field}.claim_id")
        if claim_id not in expected or claim_id in compared:
            raise RunnerError("Evidence comparison returned an unknown or duplicate claim_id")
        verdict = item["verdict"]
        if not isinstance(verdict, str) or verdict not in _VERDICTS:
            raise RunnerError(f"{field}.verdict must be supported, contradicted, or insufficient")
        confidence = item["confidence"]
        if (
            not isinstance(confidence, (int, float)) or isinstance(confidence, bool)
            or not math.isfinite(float(confidence)) or confidence < 0 or confidence > 1
        ):
            raise RunnerError(f"{field}.confidence must be a number between 0 and 1")
        evidence_ids = item["evidence_ids"]
        if not isinstance(evidence_ids, list):
            raise RunnerError(f"{field}.evidence_ids must be an array")
        evidence_ids = [_reference(value, f"{field}.evidence_ids") for value in evidence_ids]
        if len(set(evidence_ids)) != len(evidence_ids):
            raise RunnerError(f"{field}.evidence_ids must contain unique values")
        allowed = {chunk["evidence_id"] for chunk in evidence_by_case[expected[claim_id]["case_id"]]}
        if unknown := sorted(set(evidence_ids) - allowed):
            raise RunnerError("Evidence comparison referenced unknown source chunks: " + ", ".join(unknown))
        if verdict in {"supported", "contradicted"} and not evidence_ids:
            raise RunnerError(f"{field}.evidence_ids cannot be empty for a {verdict} verdict")
        compared[claim_id] = {
            "case_id": expected[claim_id]["case_id"], "claim_id": claim_id,
            "claim_sha256": expected[claim_id]["claim_sha256"], "verdict": verdict,
            "confidence": round(float(confidence), 6), "evidence_ids": evidence_ids,
        }
    if set(compared) != set(expected):
        missing = sorted(set(expected) - set(compared))
        raise RunnerError("Evidence comparison omitted extracted claims: " + ", ".join(missing))
    return [compared[item["claim_id"]] for item in claims]


def evaluate_semantic_grounding(
    material: dict[str, Any], judge_config: object, *, target_command: object = None,
    subject_id: str | None = None, capture_source: str = "local_file",
) -> dict[str, Any]:
    """Extract claims, compare them with source text, and score the verdicts."""
    judge = _validate_judge(judge_config, target_command=target_command, subject_id=subject_id)
    material = validate_grounding_material(material)
    responses: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    partial_results: list[dict[str, Any]] = []
    for case in material["cases"]:
        single = {"schema_version": material["schema_version"], "cases": [case]}
        compared: list[dict[str, Any]] = []
        try:
            claims, extracted = _extract_claims(single, judge)
            _review_extraction(single, claims, judge)
            # One claim per invocation bounds the request size and timeout budget.
            for claim in claims:
                compared.extend(_compare_claims(single, [claim], judge))
        except RunnerError as exc:
            failures.append({"case_id": case["case_id"], "reason": str(exc)})
            partial_results.extend(compared)
            continue
        responses.extend(extracted)
        results.extend(compared)
    if failures and len(failures) == len(material["cases"]) and not partial_results:
        raise RunnerError("Semantic evaluation failed: " + failures[0]["reason"])
    total = len(results)
    supported = sum(item["verdict"] == "supported" for item in results)
    contradicted = sum(item["verdict"] == "contradicted" for item in results)
    insufficient = sum(item["verdict"] == "insufficient" for item in results)
    low_confidence = [item["claim_id"] for item in results if item["confidence"] < 0.7]
    return {
        "measurement_status": "measured" if total and not failures else "not_measurable",
        "reason": "Some cases failed semantic evaluation; completed evidence is retained but no full-run score is issued." if failures else ("" if total else "No factual claims were extracted; claim support has no denominator."),
        "completion_status": "partial" if failures else "complete",
        "requested_case_count": len(material["cases"]),
        "completed_case_count": len(responses),
        "failed_cases": failures,
        "partial_claim_results": partial_results,
        "verification_basis": "independent_local_semantic_judge",
        "calculation_version": GROUNDING_CALCULATION_VERSION,
        "rubric_version": GROUNDING_RUBRIC_VERSION,
        "claim_count": total,
        "supported_claim_count": supported,
        "contradicted_claim_count": contradicted,
        "insufficient_evidence_claim_count": insufficient,
        "grounded_claim_rate": round(supported / total, 6) if total and not failures else None,
        "contradiction_rate": round(contradicted / total, 6) if total and not failures else None,
        "insufficient_evidence_rate": round(insufficient / total, 6) if total and not failures else None,
        "compared_extracted_claim_rate": 1.0 if total and not failures else None,
        "extraction_review_status": "incomplete" if failures else "model_reviewed",
        "response_processing_rate": round(len(responses) / len(material["cases"]), 6),
        "mean_judge_confidence": round(sum(item["confidence"] for item in results) / total, 6) if total else None,
        "low_confidence_claim_ids": low_confidence,
        "case_results": results,
        "response_results": responses,
        "definition": "Atomic response claims independently compared with the retrieved local source chunks.",
        "judge_provenance": {
            "identity": judge["identity"], "version": judge["version"],
            "configuration_sha256": sha256(judge),
            "command_sha256": sha256(judge["command"]),
            "independent_from_target": True,
        },
        "material_provenance": {
            **grounding_material_summary(material), "capture_source": capture_source,
        },
        "limitations": [
            "Extraction completeness was reviewed in a separate model pass; it is not a proven percentage of all factual claims. Both passes may miss the same claim.",
            "Semantic judge results are model-assisted evidence and should be regression-tested against reviewed fixtures.",
            "Groundedness verifies claim support against the supplied chunks; it does not prove that the upstream retriever returned every relevant source.",
            "PRE-D retains hashes, verdicts, confidence, and evidence IDs in the report; raw responses and source text remain local and are omitted.",
        ],
    }


def grounding_material_summary(material: dict[str, Any]) -> dict[str, Any]:
    cases = material["cases"]
    return {
        "schema_version": material["schema_version"],
        "sha256": sha256(material),
        "case_count": len(cases),
        "source_chunk_count": sum(len(item["evidence"]) for item in cases),
        "response_sha256": sha256([item["response"] for item in cases]),
        "evidence_sha256": sha256([item["evidence"] for item in cases]),
        "retention": "Raw responses and source chunks were processed locally and were not added to the result package or report.",
    }
