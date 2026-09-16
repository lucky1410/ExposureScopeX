# PRE-D Evidence Guide

Use this guide when you want PRE-D to calculate more than browser workflow
coverage. It explains exactly what evidence is needed, where it comes from,
and what PRE-D calculates locally.

PRE-D never needs raw customer prompts, model responses, document text, tool
arguments, passwords, cookies, or production data. Use opaque identifiers such
as `case-017`, `doc-004`, `tool-search`, and `trace-2026-09-16-01`.

## The simple model

Every score has three parts:

1. **Test expectation**: what the organization says should happen.
2. **Observed evidence**: what the application actually did during that case.
3. **Calculation**: PRE-D compares the two locally.

PRE-D marks a metric `NOT MEASURABLE` when either the expectation or the
observed evidence is missing. This is a coverage gap, not a failed score.

## Choose your evidence path

| Your application | What to use | What PRE-D can measure |
| --- | --- | --- |
| You only have a web page | Browser journey | Visible workflow coverage, browser errors, and session boundaries. |
| Your app has a local JSON API | Local API plan or adapter | Labels and genuine confidence when the API returns them. |
| Your app already emits OpenTelemetry | PRE-D loopback collector | Supported RAG, tool, trajectory, security, cost, and latency evidence. |
| You own Python/Node agent code | PRE-D evidence emitter or framework connector | The same advanced metrics with application-owned facts. |
| Your app cannot emit telemetry | `full_metric_measurements.json` fallback | Only the redacted facts you enter can be calculated. |

Browser success is not a model-quality result. A browser plan can show that an
approved user journey reached an expected visible signal, but it cannot see
private RAG retrievals, agent decisions, model confidence, or provider usage.

## What the user provides

The user supplies **expectations**, not raw application telemetry. Put these
facts in the generated `esx-eval.json` test plan or the optional telemetry
settings section.

| Metric area | User supplies | Example |
| --- | --- | --- |
| Classification | Test input and expected label, with at least two expected labels across the dataset. | `case-017` expects `safe`; `case-018` expects `blocked`. |
| Security | Approved attack/control case and expected allow/block outcome. | A prompt-injection case must be blocked. |
| RAG recall | The known relevant document IDs for the case. | `doc-policy-2026` and `doc-refunds-004`. |
| Tool use | The tools allowed or expected for each case. | `search-cases` then `open-case`. |
| Trajectory | Required milestones for a successful completion. | `retrieval-complete`, `evidence-reviewed`, `final-response`. |
| Robustness | A baseline case plus controlled paraphrase, perturbation, and repeat variants. | `case-017` is the baseline for `case-017-paraphrase`. |
| Agreement | The identities of independent judges. | `policy-judge-a` and `policy-judge-b`. |
| Repeatability | The same case run more than once. | Run `case-017` in `run-a` and `run-b`. |
| Cost fallback | Approved local model price rates, only when the provider does not report cost. | Input $2.50 and output $10.00 per million tokens. |

An expected result is a short, testable statement. Good examples are:

- "The unsafe action is blocked."
- "The answer cites `doc-policy-2026`."
- "The agent uses `search-cases` before `open-case`."
- "The workflow reaches the evidence view after sign-in."

Avoid vague expectations such as "the answer is good" or "the agent behaves
correctly." Break those into a label, policy, evidence reference, tool,
milestone, or visible signal.

## What the application emits

The running application supplies **observed facts**. Configure it to send
redacted metadata to the PRE-D loopback collector, or return the same data from
the local adapter. PRE-D associates observations with the evaluation case using
the opaque `case_id`.

| Metric area | Application emits | PRE-D calculates |
| --- | --- | --- |
| Classification | `predicted_label` | Accuracy, precision, recall, F1, and confusion matrix. |
| Confidence | Genuine confidence from 0 to 1, not a browser pass/fail value. | Brier score, calibration error, and confidence bins. |
| Groundedness | Claim ID, cited evidence ID, support score, citation and integrity flags. | Evidence-supported claim rate. |
| RAG | Retrieved and cited document IDs. | Retrieval precision/recall, citation coverage, and faithfulness inputs. |
| Security | Observed attack success, detection, block/control outcome, evidence ID. | Attack/control rates and evidence coverage. |
| Tool use | Observed tool names, authorization, valid-result flag, evidence ID. | Tool precision/recall, exact-set rate, unauthorized/invalid outcomes. |
| Trajectory | Ordered milestones, action count, redundant actions, policy/scope violations. | Milestone coverage, efficiency, compliance, and trajectory score. |
| Robustness | Correctness, predicted label, confidence, and variation type. | Consistency, variation coverage, and worst confidence drop. |
| Agreement | Judge verdicts and confidence per case. | Pairwise agreement and unanimous-case rate. |
| Repeatability | Verdicts for the same case across run IDs. | Run-to-run agreement and stability. |
| Cost and latency | Input/output tokens, requests, retries, tools, cache/fallback, cost, latency, timeout. | Totals, per-case values, p50/p95 latency, and efficiency values. |

## Start with the lowest-effort option

### Local decision evaluation

Use **Decision evaluation** in `esx-eval setup` when the application can expose
one local endpoint that invokes its real decision path. Import labelled cases
with at least two expected labels. PRE-D sends `case_id` and `input`, then
calculates accuracy, precision, recall, F1, and confidence calibration from
the returned label and confidence. This is entirely local; it does not require
an ExposureScopeX account or platform connection.

Optional opaque `evidence_ids` and an `abstained` boolean support
evidence-reference alignment and abstention checks. They are useful but do not
prove that an answer is grounded. Groundedness requires local claim-support,
citation-validity, and evidence-integrity observations.

See [`DECISION_EVALUATION.md`](DECISION_EVALUATION.md) for the dataset and
endpoint contract.

### Browser-only workflow evidence

Use browser journeys when you need to prove that a user can sign in and reach a
visible feature. This is useful for protected web applications, but it measures
workflow assurance only.

```text
esx-eval setup --directory ./my-application-evaluation
esx-eval run --config ./my-application-evaluation/esx-eval.json --out ./my-application-evaluation/out/evaluation.json
```

### Automatic local telemetry

If the application already emits compatible OpenTelemetry JSON, start the local
collector and point the test application's exporter to the printed loopback URL
with the printed telemetry token.

```text
esx-eval telemetry --out ./out/telemetry.jsonl
esx-eval run --config ./esx-eval.json --out ./out/evaluation.json --telemetry ./out/telemetry.jsonl
```

The collector keeps only allowlisted metadata. It discards raw prompts,
responses, document content, tool arguments, credentials, and arbitrary fields.

### Application-owned evidence emitter

For a Python application, the smallest explicit integration can look like this:

```python
from esx_eval_runner.connectors import LocalEvidenceEmitter

evidence = LocalEvidenceEmitter("out/telemetry.jsonl", agent_id="analyst-agent")

with evidence.case("case-017"):
    evidence.retrieval("doc-policy-2026")
    evidence.citation("doc-policy-2026")
    evidence.tool_call("search-cases", authorized=True, result_valid=True)
    evidence.milestone("retrieval-complete")
    evidence.model_usage(input_tokens=420, output_tokens=96, latency_ms=810)
```

This does not change the product's business behavior. It records only redacted,
structured facts around the existing model, retriever, tool, and agent calls.
See `CONNECTORS.md` for LangChain, LangGraph, and provider examples.

## Minimum evidence for a meaningful scorecard

Use this checklist before reading a local report as a release decision:

- Classification and confidence: at least 20 cases, at least two expected
  labels, and varied genuine confidence values.
- RAG: each evaluated case has retrieved IDs and an approved relevant set or
  reference answer.
- Groundedness: each evaluated response claim has an evidence ID and support
  outcome.
- Tool use: every case has an expected tool set and observed authorization and
  result status.
- Trajectory: every workflow has approved milestones and a correlated trace.
- Security: every test has an expected control outcome and observed result.
- Robustness and repeatability: every baseline has controlled variants or
  repeated runs.
- Cost and latency: every case has provider usage or explicitly configured
  local rate-card data, plus timing.

## Read the report correctly

| Report state | Meaning | What to do |
| --- | --- | --- |
| `MEASURED` | PRE-D received all required evidence and calculated the metric. | Review the score, sample size, evidence coverage, and limitations. |
| `NOT MEASURABLE` | Required evidence is absent or incomplete. | Follow the report's named missing-evidence instruction. |
| `NOT APPLICABLE` | The metric does not fit this run type. | Example: classification for a browser-only workflow plan. |
| `NOT RUN` | This evidence layer was not connected for this plan. | Example: decision evaluation in a browser-only plan. |
| `ASSERTION REVIEW` | A browser signal did not match. | Review the journey and signal; it is not automatically a product defect. |
| `SESSION BLOCKED` | Authentication did not complete, so the workflow was not reached. | Repair the approved test session and run again. |

## Privacy and safety rules

- Use a dedicated test tenant, synthetic data, and least-privilege test roles.
- Do not send production credentials, customer records, prompts, answers, or
  document contents to PRE-D telemetry.
- Use opaque IDs for documents, tools, claims, users, and evidence.
- Keep the collector bound to loopback and review the report before any optional
  signed platform upload.
- Do not treat discovery, raw span counts, browser success, or a framework name
  as evidence of deep semantic coverage.

## The honest PRE-D promise

PRE-D calculates every metric locally when its required evidence exists. It
does not invent scores for private state it cannot observe. Start with workflow
coverage, add automatic telemetry where the application supports it, and add a
small set of approved expectations for the product behavior that only your
organization can define.
