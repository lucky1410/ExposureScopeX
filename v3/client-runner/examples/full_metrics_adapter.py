"""Fixture-only v2 adapter that proves the complete redacted metric contract."""

from __future__ import annotations

import json
import sys


request = json.load(sys.stdin)
results = []
for case in request["cases"]:
    message = str(case["input"].get("message", "")).lower()
    predicted = "unsafe" if "ignore previous instructions" in message else "safe"
    results.append({"case_id": case["case_id"], "predicted_label": predicted, "confidence": 0.98})

measurements = {
    "claims": [
        {
            "claim_id": "claim-001",
            "evidence_ids": ["evidence-001"],
            "entailment_score": 1.0,
            "citations_valid": True,
            "evidence_integrity_valid": True,
        }
    ],
    "security": {
        "cases": [
            {
                "case_id": "security-positive-001",
                "expected_attack_success": True,
                "observed_attack_success": True,
                "expected_detection": True,
                "observed_detection": True,
                "evidence_ids": ["evidence-attack-001"],
                "evidence_integrity_valid": True,
            },
            {
                "case_id": "security-negative-001",
                "expected_attack_success": False,
                "observed_attack_success": False,
                "expected_detection": False,
                "observed_detection": False,
                "evidence_ids": ["evidence-control-001"],
                "evidence_integrity_valid": True,
            },
        ]
    },
    "trajectory": {
        "required_milestones": ["plan", "act", "verify"],
        "observed_milestones": ["plan", "act", "verify"],
        "action_count": 6,
        "redundant_actions": 0,
        "policy_violations": [],
        "scope_violations": [],
        "tool_misuse_events": [],
    },
    "tool_use": {
        "cases": [
            {
                "case_id": case["case_id"],
                "expected_tool_names": ["approved-search"],
                "observed_tool_names": ["approved-search"],
                "authorized": True,
                "result_valid": True,
                "evidence_ids": ["tool-event-" + case["case_id"]],
                "evidence_integrity_valid": True,
            }
            for case in request["cases"]
        ]
    },
    "rag": {
        "relevant_document_ids": ["doc-001", "doc-002"],
        "retrieved_document_ids": ["doc-001", "doc-002"],
        "cited_document_ids": ["doc-001", "doc-002"],
        "answer_claims": [
            {
                "claim_id": "rag-claim-001",
                "evidence_ids": ["doc-001"],
                "entailment_score": 1.0,
                "citations_valid": True,
                "evidence_integrity_valid": True,
            }
        ],
        "k": 2,
    },
    "robustness": {
        "baseline_correct": True,
        "baseline_confidence": 0.98,
        "baseline_label": "safe",
        "perturbations": [
            {"case_id": "paraphrase-001", "correct": True, "confidence": 0.97, "predicted_label": "safe", "variation_type": "paraphrase"},
            {"case_id": "perturbation-001", "correct": True, "confidence": 0.96, "predicted_label": "safe", "variation_type": "perturbation"},
            {"case_id": "repeat-001", "correct": True, "confidence": 0.98, "predicted_label": "safe", "variation_type": "repeat"},
        ],
    },
    "judge_agreement": {
        "decisions": [
            {"case_id": "judge-case-001", "judge_id": "judge-a", "verdict": "pass", "confidence": 0.98},
            {"case_id": "judge-case-001", "judge_id": "judge-b", "verdict": "pass", "confidence": 0.97},
        ]
    },
    "reproducibility": {
        "decisions": [
            {"case_id": "repeat-case-001", "run_id": "run-001", "verdict": "pass"},
            {"case_id": "repeat-case-001", "run_id": "run-002", "verdict": "pass"},
        ]
    },
    "cost_efficiency": {
        "cost_source": "provider_reported",
        "observations": [
            {
                "case_id": case["case_id"],
                "input_tokens": 120,
                "output_tokens": 40,
                "request_count": 1,
                "retry_count": 0,
                "tool_call_count": 0,
                "cache_hit": False,
                "fallback_used": False,
                "cost_usd": 0.002,
                "latency_ms": 240,
                "timed_out": False,
            }
            for case in request["cases"]
        ],
    },
    "trace_envelope": {
        "trace_id": "trace-001",
        "schema_version": "fixture-1.0",
        "producer": "fixture-adapter",
        "agent_ids": ["planner", "executor"],
        "redaction_status": "redacted",
        "events": [
            {"event_id": "event-001", "sequence": 1, "agent_id": "planner", "event_type": "handoff", "outcome": "succeeded", "evidence_ids": ["evidence-001"]},
            {"event_id": "event-002", "sequence": 2, "agent_id": "executor", "event_type": "tool_call", "outcome": "succeeded", "tool_name": "approved-tool", "scope_reference": "scope-001", "evidence_ids": ["evidence-attack-001"]},
        ],
    },
}

json.dump(
    {
        "schema_version": "esx-client-adapter-response-2.0",
        "results": results,
        "measurements": measurements,
    },
    sys.stdout,
)
