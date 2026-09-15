# PRE-D Local Evidence Connectors

PRE-D can calculate advanced metrics without a custom result adapter when the
application already emits the required **redacted local metadata**. This guide
describes the supported paths. All records remain on the tester's computer.

## Choose a path

| Application | Recommended path |
| --- | --- |
| Application already emits OpenTelemetry JSON | Use the loopback collector. |
| Python agent or orchestration code | Use `LocalEvidenceEmitter`. |
| LangChain or LangGraph application | Add the provided callback and emitter. |
| OpenAI-compatible or Anthropic Python client | Record response usage with the provided helper. |
| Other runtime | Emit the documented opaque `esx.*` attributes through its OpenTelemetry integration. |

The runner never reads prompts, model outputs, document content, tool
arguments, cookies, credentials, or identity-provider state. An evidence
identifier is an opaque local ID such as `case-017`, `doc-004`, or
`trace-2026-09-16`.

## Existing OpenTelemetry

Start the local collector in a second terminal:

```text
esx-eval telemetry --out ./out/telemetry.jsonl
```

Point the test application's OTLP JSON exporter at the printed loopback URL
and provide the printed `X-ESX-Telemetry-Token`. The collector accepts only
`/v1/traces` on `127.0.0.1` and drops every attribute outside its allowlist.

For an HTTP evaluation, PRE-D sends an opaque `X-ESX-Case-ID` header with each
request. Copy that header into the span attribute `esx.case_id`. This links
usage and trace events to the test case without sending its prompt or response
to the report.

## Python Agents

Write to the same local telemetry file used by the report:

```python
from esx_eval_runner.connectors import LocalEvidenceEmitter

evidence = LocalEvidenceEmitter("out/telemetry.jsonl", agent_id="research-agent")

with evidence.case("case-017"):
    evidence.milestone("retrieval-complete")
    evidence.retrieval("doc-004")
    evidence.citation("doc-004")
    evidence.claim(
        "claim-017", "doc-004", support_score=0.94,
        citations_valid=True, evidence_integrity_valid=True,
    )
    evidence.tool_call(
        "approved-search", authorized=True, result_valid=True,
        evidence_id="tool-event-017", evidence_integrity_valid=True,
    )
    evidence.model_usage(
        input_tokens=420, output_tokens=96, latency_ms=810, cost_usd=0.0042,
    )
```

The writer rejects free text. It accepts only bounded identifiers, booleans, and
numeric operational metadata.

## LangChain And LangGraph

Both can use the content-safe callback for retriever and tool metadata. Ensure
the retriever exposes an opaque `esx_document_id` or `document_id` in document
metadata. Content is ignored.

```python
from esx_eval_runner.connectors import LocalEvidenceEmitter, langchain_callback

evidence = LocalEvidenceEmitter("out/telemetry.jsonl", agent_id="analyst-agent")
callbacks = [langchain_callback(evidence)]

with evidence.case("case-017"):
    result = graph.invoke({"request_id": "case-017"}, {"callbacks": callbacks})
```

The callback records tool names and retrieval document IDs only. Use the emitter
for milestones, citations, claims, security controls, and usage metadata that
the framework does not expose directly.

## OpenAI-Compatible And Anthropic Usage

The provider helpers extract only integer usage counters from an in-memory
response object. They do not serialize the response, request, model name, or
customer content. Measure elapsed time locally around the normal application
call, then record it inside the ESX case context:

```python
from esx_eval_runner.connectors import (
    LocalEvidenceEmitter,
    record_anthropic_message_usage,
    record_openai_response_usage,
)

with evidence.case("case-017"):
    response = client.responses.create(...)  # normal local application call
    record_openai_response_usage(evidence, response, latency_ms=810)

with evidence.case("case-018"):
    message = anthropic_client.messages.create(...)  # normal local application call
    record_anthropic_message_usage(evidence, message, latency_ms=760)
```

Provide `cost_usd=` only when your provider reports an approved local cost
figure. Otherwise add the local rate card in `telemetry.cost_efficiency`.

## Evidence Expectations

Some metrics require approved ground truth that application telemetry cannot
invent. The generated `esx-eval.json` enables telemetry and accepts optional
opaque expectations:

```json
{
  "telemetry": {
    "enabled": true,
    "trajectory": {
      "required_milestones": ["retrieval-complete", "approved-tool", "final-response"]
    },
    "tool_use": {
      "expected_tools_by_case": {
        "case-017": ["approved-search"]
      }
    },
    "robustness": {
      "baseline_case_id": "case-017",
      "baseline_label": "safe"
    },
    "rag": {
      "relevant_document_ids": ["doc-004", "doc-031"]
    },
    "cost_efficiency": {
      "input_cost_per_million_usd": 2.5,
      "output_cost_per_million_usd": 10.0
    }
  }
}
```

- `trajectory.required_milestones` defines the approved behavior to compare
  against observed trace milestones.
- `tool_use.expected_tools_by_case` defines the approved opaque tool names for
  every case being scored. Each corresponding `tool_call` must record its
  authorization and result-validity booleans. This is how PRE-D distinguishes
  a permitted, correct call from a merely observed call.
- `robustness.baseline_case_id` identifies one normal case. Emit only outcome
  metadata for that baseline and its controlled `paraphrase`, `perturbation`,
  or `repeat` variants with `evidence.robustness_observation(...)`.
- `rag.relevant_document_ids` is the labelled relevant set needed for recall.
- Pricing is optional. PRE-D uses reported `esx.cost_usd` when present; it uses
  the local rate card only when both metered rates are explicitly supplied.

If any required fact is unavailable, PRE-D leaves that metric `EVIDENCE NEEDED`
in the report. It never estimates a score from browser success, raw span count,
or a framework name.

## Run And Review

Run the usual local plan after the application has emitted evidence:

```text
esx-eval run --config ./esx-eval.json --out ./out/evaluation.json
esx-eval view --report ./out/evaluation.local-report.html
```

The report shows the number of redacted records used, derived metric dimensions,
browser/session boundaries, and the exact evidence needed for each remaining
gap.
