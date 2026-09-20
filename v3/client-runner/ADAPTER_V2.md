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

## Connecting a full web application or multi-agent system

The adapter does not contain an ExposureScopeX agent. It calls the customer's
own application entry point once for each case. For a multi-agent web app, that
entry point should invoke the normal backend workflow; its internal agents,
retrievers, tool calls, and handoffs run as they normally would.

For a browser-only local application, use the built-in `browser_journey`
connector instead of adding an adapter. It supports explicit approved login,
local session reuse, and declarative post-login workflow checks. It is limited
to a loopback origin and reports safe step diagnostics only. For a non-browser
agent or a workflow that needs richer evidence, connect the adapter to an
existing local backend API, local command, or Python function. If the
application has no callable backend entry point, add a local test-only endpoint
that calls the normal workflow. Keep it private to the local environment.

Return a compact policy decision and a meaningful confidence, not the raw model
answer. For the starter's `safe`/`unsafe` convention, `unsafe` means the system
correctly recognized a request that should be refused or blocked. When the
application does not provide confidence, omit the `confidence` dimension and
field. Classification can run independently; do not manufacture a confidence.
Declare the origin in the reviewed evaluation configuration, not in an adapter
response: [confidence provenance](CONFIDENCE_PROVENANCE.md). Mapped categories and
unknown-origin numbers remain diagnostic only and cannot satisfy native
probability-calibration gates. This is a local-runner contract; compatibility
with a separately deployed platform upload API must be checked separately.

## Response

Every submitted case needs a matching result. Labels are required for
classification/confidence; confidence is required only when requesting
calibration. Semantic/evidence-only runs may omit both. A labelled example:

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

For advanced dimensions in `evaluation.required_dimensions`, add the corresponding
entry to `measurements` unless the reviewed configuration enables local
telemetry to supply that dimension. The runner then accepts the adapter's
partial evidence and joins non-overlapping, validated telemetry evidence after
execution. The runner and API both reject unknown fields, raw/free-text
references, duplicate identifiers, out-of-range scores, and conflicting
adapter/telemetry evidence.

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
    "tool_use": {
      "cases": [
        {
          "case_id": "case-001",
          "expected_tool_names": ["approved-search"],
          "observed_tool_names": ["approved-search"],
          "authorized": true,
          "result_valid": true,
          "evidence_ids": ["tool-event-001"],
          "evidence_integrity_valid": true
        }
      ]
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

`claims` supplies target-declared metadata only. It can support evidence-ID
alignment and negative controls, but cannot independently establish semantic
groundedness. For verified local groundedness, adapter v2 may additionally
return this top-level local-only material:

```json
{
  "grounding_material": {
    "schema_version": "pre-d-grounding-material-1.0",
    "cases": [
      {
        "case_id": "case-001",
        "response": "Generated response text",
        "evidence": [
          {"evidence_id": "doc-001", "text": "Retrieved source chunk"}
        ]
      }
    ]
  }
}
```

The material must cover every evaluated case. PRE-D passes it only to the
independent local semantic judge, then discards it. It is never added to the
result package or report. The judge performs claim extraction and evidence
comparison before PRE-D calculates supported, contradicted, and
insufficient-evidence rates. `security` needs at least
one expected-detection case and one negative control. `trajectory` measures
milestone coverage, efficiency, scope, policy, and tool misuse. `tool_use`
measures selected versus approved tools, authorization, and result validity per
case. `rag` measures
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

## Local grounding judge protocol

The configured `assurance.grounding_judge` command is invoked with
`shell=false`, a bounded timeout, and JSON on standard input. It must be a
different command and identity from the evaluated target.

The timeout applies separately to each case's extraction/review and to each
claim comparison. Each invocation receives one item. Stdout is capped while
reading at `max_response_bytes` (default 5 MB); stderr is discarded with a 64 KB
limit. Oversized output terminates the invocation. Keep the model's request
timeout below the command timeout to allow startup and JSON processing.

For `operation: extract_claims`, return exactly one result per case:

```json
{
  "schema_version": "pre-d-grounding-judge-response-1.0",
  "operation": "extract_claims",
  "results": [
    {"case_id": "case-001", "claims": ["One atomic factual claim."], "abstained": false}
  ]
}
```

The judge observes `abstained` from the actual response. Set it to true only for
an explicit refusal to answer due to insufficient evidence, not a disclaimer
attached to a substantive answer. Older judges may omit it, but then abstention
scoring remains unavailable. A response with no factual claims uses `claims: []`;
that alone is not an abstention or a successful answer.

An explicit `evidence: []` in grounding material records that no source was
retrieved. Such claims cannot receive supported or contradicted verdicts because
those verdicts require a source reference. Do not insert fabricated chunks.

After extraction, the judge must support `operation: review_claims`. PRE-D sends
one case with `case_id`, the original `response`, and extracted `claims`. Use a
separate model pass to check for omissions, altered meanings, and invented
assertions. Return:

```json
{
  "schema_version": "pre-d-grounding-judge-response-1.0",
  "operation": "review_claims",
  "results": [
    {"case_id": "case-001", "complete": true, "missing_claims": []}
  ]
}
```

If a factual assertion is missing or altered, return `complete: false` and list
omitted claims in `missing_claims`. PRE-D marks the case incomplete; it does not
silently accept the original extraction. This operation is mandatory even for
empty claim lists. Custom judges must implement it before using the hardened
semantic evaluator. The bundled Ollama bridge already supports it.

The report calls this `model_reviewed`, not proven full claim coverage. A second
model pass can still miss an omission. `compared_extracted_claim_rate` describes
comparison of the extracted claims only; `response_processing_rate` describes
completed cases. The ambiguous `semantic_coverage_rate` field has been removed.

PRE-D assigns stable run-local claim IDs and then invokes
`operation: compare_evidence`. Return exactly one result per claim:

```json
{
  "schema_version": "pre-d-grounding-judge-response-1.0",
  "operation": "compare_evidence",
  "results": [
    {
      "claim_id": "claim-a5d3e73f6bb44d59a7f6d91c1a6bd32f",
      "verdict": "supported",
      "confidence": 0.93,
      "evidence_ids": ["doc-001"]
    }
  ]
}
```

Allowed verdicts are `supported`, `contradicted`, and `insufficient`.
Supported and contradicted verdicts require at least one known evidence ID.
Missing cases, claims, verdicts, or unknown evidence IDs fail closed and no
full-run semantic score is produced. Successfully processed cases and claims
are retained when another case fails, with explicit failure diagnostics. Failed
cases are never silently excluded to produce a passing full-run score.

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
