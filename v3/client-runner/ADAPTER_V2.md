# ExposureScopeX Client Adapter v2

`command_json_v2` lets a customer run evaluation logic beside their AI system
and submit every ExposureScopeX metric area without moving raw test data into
the ExposureScopeX control plane.

It is an adapter protocol, not a model SDK. The adapter may call a model, RAG
stack, agent runtime, SIEM test environment, or local evidence ledger however
the customer chooses. It receives JSON on standard input and writes exactly one
JSON object to standard output. The runner invokes it with `shell=False` and a
bounded timeout.

## Request

```json
{
  "schema_version": "esx-client-adapter-request-2.0",
  "request_id": "uuid",
  "evaluation": {
    "subject_type": "multi_agent_system",
    "required_dimensions": ["classification", "confidence", "groundedness"]
  },
  "cases": [
    {"case_id": "case-001", "input": {"customer_defined": "local only"}}
  ]
}
```

The request and all case inputs remain local. The runner retains only a SHA-256
hash of the request.

## Response

Every response includes a label and confidence for every submitted case:

```json
{
  "schema_version": "esx-client-adapter-response-2.0",
  "results": [
    {"case_id": "case-001", "predicted_label": "safe", "confidence": 0.98}
  ],
  "measurements": {}
}
```

`predicted_label`, expected labels, and all identifiers are compact category or
opaque identifiers such as `safe`, `unsafe`, `policy-violation`, `doc-004`, and
`trace/run-001`. They must contain only letters, digits, `.`, `_`, `:`, `/`, or
`-`, and must not contain raw model text.

For every dimension in `evaluation.required_dimensions`, add the corresponding
entry to `measurements`. The runner and API both reject unknown fields, omitted
required measurements, raw/free-text references, duplicate identifiers, and
out-of-range scores.

## Measurement Entries

```json
{
  "measurements": {
    "claims": [
      {
        "claim_id": "claim-001",
        "evidence_ids": ["evidence-031"],
        "entailment_score": 0.96,
        "citations_valid": true,
        "evidence_integrity_valid": true
      }
    ],
    "security": {
      "cases": [
        {
          "case_id": "attack-001",
          "expected_attack_success": true,
          "observed_attack_success": false,
          "expected_detection": true,
          "observed_detection": true,
          "evidence_ids": ["evidence-attack-001"],
          "evidence_integrity_valid": true
        },
        {
          "case_id": "control-001",
          "expected_attack_success": false,
          "observed_attack_success": false,
          "expected_detection": false,
          "observed_detection": false,
          "evidence_ids": ["evidence-control-001"],
          "evidence_integrity_valid": true
        }
      ]
    },
    "trajectory": {
      "required_milestones": ["plan", "approved-tool", "verify"],
      "observed_milestones": ["plan", "approved-tool", "verify"],
      "action_count": 8,
      "redundant_actions": 1,
      "policy_violations": [],
      "scope_violations": [],
      "tool_misuse_events": []
    },
    "rag": {
      "relevant_document_ids": ["doc-001", "doc-002"],
      "retrieved_document_ids": ["doc-002", "doc-001"],
      "cited_document_ids": ["doc-001", "doc-002"],
      "answer_claims": [
        {
          "claim_id": "rag-claim-001",
          "evidence_ids": ["doc-001"],
          "entailment_score": 0.94,
          "citations_valid": true,
          "evidence_integrity_valid": true
        }
      ],
      "k": 2
    },
    "robustness": {
      "baseline_correct": true,
      "baseline_confidence": 0.96,
      "baseline_label": "safe",
      "perturbations": [
        {"case_id": "paraphrase-001", "correct": true, "confidence": 0.94, "predicted_label": "safe", "variation_type": "paraphrase"}
      ]
    },
    "judge_agreement": {
      "decisions": [
        {"case_id": "judge-case-001", "judge_id": "judge-a", "verdict": "pass", "confidence": 0.92},
        {"case_id": "judge-case-001", "judge_id": "judge-b", "verdict": "pass", "confidence": 0.89}
      ]
    },
    "reproducibility": {
      "decisions": [
        {"case_id": "repeat-case-001", "run_id": "run-001", "verdict": "pass"},
        {"case_id": "repeat-case-001", "run_id": "run-002", "verdict": "pass"}
      ]
    },
    "cost_efficiency": {
      "cost_source": "provider_reported",
      "observations": [
        {
          "case_id": "case-001",
          "input_tokens": 340,
          "output_tokens": 90,
          "request_count": 1,
          "retry_count": 0,
          "tool_call_count": 1,
          "cache_hit": false,
          "fallback_used": false,
          "cost_usd": 0.0042,
          "latency_ms": 840,
          "timed_out": false
        }
      ]
    }
  }
}
```

`claims` enables grounding/hallucination measurement. `security` needs at least
one expected-detection case and one negative control. `trajectory` measures
milestone coverage, efficiency, scope, policy, and tool misuse. `rag` measures
retrieval, citation validity, and claim faithfulness. `robustness` contains
paraphrase, perturbation, and repeated-run outcomes. The default release policy
requires coverage of all three variation types when robustness is required.
`judge_agreement` must have
two or more judges per compared case, and `reproducibility` two or more runs per
compared case.

`cost_efficiency` has exactly one observation for every submitted labelled case.
Set `cost_source` to `provider_reported` when the model provider returns
usage/cost, or `metered` when your local approved rate card calculates it. Each
observation carries usage totals only: tokens, request/retry/tool-call counts,
cache/fallback/timeout flags, cost in USD, and latency. Do not include model
names, account IDs, invoices, prompts, responses, or credentials. When this
dimension is required, the release policy gates cost per case, P95 latency,
timeout rate, and fallback rate alongside all selected quality and security
requirements.

For a multi-agent subject, include `trace_envelope`. A redacted envelope can
contain event metadata only, not prompts, arguments, outputs, or tool results:

```json
{
  "trace_envelope": {
    "trace_id": "trace-001",
    "schema_version": "customer-trace-1.0",
    "producer": "customer-runtime",
    "agent_ids": ["planner", "executor"],
    "redaction_status": "redacted",
    "events": [
      {"event_id": "event-001", "sequence": 1, "agent_id": "planner", "event_type": "handoff", "outcome": "succeeded", "evidence_ids": ["evidence-031"]}
    ]
  }
}
```

The runner calculates the redacted event digest itself. A metadata-only envelope
must declare its local trace digest and event count, but cannot contain events.
