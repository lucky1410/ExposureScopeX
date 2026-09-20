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
| Groundedness | Generated response text, retrieved source chunks, and an independent local semantic judge. | Atomic claim support, contradiction, insufficient-evidence, coverage, and judge-confidence rates. |
| Hallucination | Local unsupported-claim and abstention controls, plus observed claims and abstention outcomes. | Unsupported-output and correct-abstention rates. |
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
prove that an answer is grounded. Groundedness requires the generated response,
the retrieved source text, and an independent local semantic judge. Adapter v2
can return this material automatically; an HTTP connector can map it; or the
user can provide a local grounding-material file.

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
- Groundedness: every evaluated case has its generated response and retrieved
  source list (explicitly empty if retrieval returned nothing); claim extraction and evidence comparison cover every
  extracted claim.
- Tool use: every case has an expected tool set and observed authorization and
  result status.
- Trajectory: every workflow has approved milestones and a correlated trace.
- Security: every test has an expected control outcome and observed result.
- Robustness and repeatability: every baseline has controlled variants or
  repeated runs.
- Cost and latency: every case has provider usage or explicitly configured
  local rate-card data, plus timing.

## Read the report correctly

### Semantic hallucination scoring

Add `hallucination` to `evaluation.required_dimensions`. It reuses the same
`assurance.grounding_judge` and grounding material as `groundedness`. Running both
uses one claim extraction and evidence comparison pipeline. No separate gold
claim file is needed for this semantic path.

The pipeline now reviews extraction in a separate model pass before comparing
claims to evidence. Omitted or altered claims detected by that review block the
case's score. `model_reviewed` describes this check; it does not certify that a
model captured every factual claim. Custom command judges must implement the
`review_claims` operation described in `ADAPTER_V2.md`.

Supply the actual generated response and source chunks through adapter v2,
mapped HTTP response fields, or the configured grounding-material file. The
judge compares each extracted factual claim with those sources. PRE-D reports:

- `unsupported_claim_rate`: contradicted plus insufficient-evidence claims,
  divided by all judged claims. Lower is better. The report also retains each
  count separately. Unsupported does not necessarily mean factually false.
- `hallucination_free_response_rate`: responses with no unsupported claims,
  divided by assessed responses. Confirmed abstentions are included. Responses
  with no claims and no confirmed abstention are excluded, and coverage shows
  that gap. This rate alone does not establish that useful answers were given.
- `correct_abstention_rate`: successful abstentions divided by cases whose
  dataset entry has `must_abstain: true`. An abstention containing unsupported
  claims does not qualify. Every required case needs a judge-observed boolean.
- `false_answer_rate`: the fraction of required-abstention cases that did not
  meet that abstention check. Without complete abstention evidence, both rates
  remain null.
- `unsupported_confident_answer_rate`: answers with unsupported claims divided
  by answers whose returned case confidence is at least 0.8. It uses application
  confidence, not judge confidence. Without qualifying cases, the rate is null.

Place `must_abstain` in the labelled dataset case, alongside `expected_label`;
the local runner preserves that expectation. The semantic judge identifies
abstention from the response independently of the application's own flag.
All-abstention runs can score abstention but have no claim-rate denominator.

The HTML and JSON retain provenance and coverage. `Verified` here means PRE-D
ran an independent model-assisted comparison, not that its judge is infallible.
Review low-confidence verdicts and validate the chosen judge against human-reviewed
examples before interpreting these results as release evidence. Raw answers and
source text are omitted from the reports.

### Before your first semantic acceptance test

1. Verify the installed package version matches the build being tested. For this
   release, `python -c "from esx_eval_runner import __version__; print(__version__)"`
   must print `0.15.1`.
2. Configure a real independent local judge, such as the bundled Ollama bridge
   with an already-installed model. A deterministic regression-test fixture is
   not a semantic judge. Custom judges must support extraction, extraction review,
   and evidence comparison. Record the judge identity and version.
3. Enable `groundedness` and `hallucination` in `evaluation.required_dimensions`.
   Supply the actual response and exact source chunks for each matching case ID.
   Preserve empty evidence when nothing was retrieved; do not invent supporting
   chunks. Add `must_abstain` expectations where the test requires abstention.
4. Start with a small human-reviewed pack containing supported, contradicted,
   insufficient-evidence, mixed-claim, and correct/incorrect abstention examples.
   This acceptance pack validates the judge; it is not a mandatory separate gold
   claim file for every subsequent semantic run.
5. Inspect extraction coverage, verdict counts, source references, abstention
   denominators, and provenance in the HTML/JSON. Confirm failures remain visible
   and do not turn partial evaluation into a perfect full-run score. Use the saved
   case IDs and your local source material to inspect disagreements.

Only broaden the pack after reviewing disagreements with the human answer key.
Passing runner regression tests establishes implementation behavior, not semantic
judge accuracy or universal truth. These scores assess support in the supplied
sources; missing support is not, by itself, proof of real-world falsehood.

### Preserve and regenerate results

Every run saves `<name>.semantic-results.json` alongside `<name>.json`. Keep
these files together. The semantic results file retains only verdict metadata,
hashes, provenance, and failure diagnostics. It is bound to the original package
by a hash, with a separate result digest to detect accidental changes; these
digests are not signatures or independent proof of authenticity.

`esx-eval report --package ./out/evaluation.json --out ./out/rebuilt.json`
automatically reuses the saved semantic results, without restarting the judge or
requiring raw material. To deliberately judge the material again, provide
`--config` and an explicit `--grounding-material` file. A changed or mismatched
saved result is rejected rather than silently reused.

Each case and each claim has an independent command timeout. If a case fails,
completed evidence remains visible in the report with failure diagnostics, but
full-run groundedness and hallucination scores remain unavailable until the
failed cases are rerun successfully.

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
- Do not send production credentials or customer records to PRE-D telemetry.
  Semantic grounding content uses the separate local judge path and is omitted
  from the package and report.
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
