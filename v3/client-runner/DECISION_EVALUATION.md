# PRE-D Local Decision Evaluation

Use this path when you need to measure an AI or business decision locally:
accuracy, precision, recall, F1, and confidence calibration. It does not
require an ExposureScopeX account or a platform connection.

## 1. Start the local setup

```text
esx-eval setup --directory ./pred-decision-evaluation
```

Choose **Decision evaluation**, enter the loopback endpoint that runs the real
local decision path, and select **Test local connection**. PRE-D sends one
fixed harmless probe and retains only response field names and types while you
confirm the mappings.

## 2. Import labelled cases

Import a JSON array or paste it into the local setup page. Start with
[`examples/decision-evaluation.sample.json`](examples/decision-evaluation.sample.json)
and replace its synthetic inputs with your own local test cases. Use at least
two expected labels for PRE-D's decision-grade aggregate scorecard. A single-class
pack still permits a raw match count, but cannot establish behavior on absent
classes; do not confuse that limitation with the formulas being undefined in
every single-class case.

```json
[
  {
    "case_id": "triage-001",
    "input": {
      "title": "Suspicious mailbox rule creation",
      "signals": ["sig-001", "sig-004"]
    },
    "expected": {
      "label": "escalate",
      "allowed_evidence_ids": ["sig-001", "sig-004"],
      "must_abstain": false
    }
  },
  {
    "case_id": "triage-002",
    "input": {
      "title": "Known maintenance event"
    },
    "expected": {
      "label": "do-not-escalate",
      "must_abstain": false
    }
  }
]
```

The generated plan keeps test inputs only in the local plan. The final result
package never includes them.

## 3. Implement or select the local endpoint

PRE-D sends each case as:

```json
{
  "case_id": "triage-001",
  "input": {
    "title": "Suspicious mailbox rule creation"
  }
}
```

The endpoint returns a local JSON response such as:

```json
{
  "label": "escalate",
  "confidence": 0.82,
  "evidence_ids": ["sig-001", "sig-004"],
  "abstained": false
}
```

`label` is required for classification. `confidence` is needed only for confidence
calibration; leave its mapping empty in guided setup if the app has no genuine
numeric confidence. Do not invent one to enable other metrics. The setup
page lets you map different field locations, such as `decision.label` and
`decision.confidence`, without editing a configuration file.

In the unpublished updated setup, also identify the confidence origin and meaning.
Numeric values alone do not establish probabilities: fixed category mappings
produce diagnostics, not native model calibration. See
[confidence provenance and release-gate migration](CONFIDENCE_PROVENANCE.md).

`evidence_ids` and `abstained` are optional. When supplied, PRE-D measures
evidence-reference alignment and correct abstention. Evidence ID overlap is
not a groundedness or hallucination score. Independent semantic evaluation needs
the actual response, its exact source material and a separate local judge or
reviewed claim evidence. A disabled retrieval feature does not rule out grounding
against captured tool results or other legitimate sources.

## 4. Run and read the report

```text
cd ./pred-decision-evaluation
esx-eval run --config ./esx-eval.json --out ./out/evaluation.json
esx-eval view --report ./out/evaluation.local-report.html
```

The first report section states separately whether PRE-D measured:

- Decision evaluation
- PRE-D telemetry evidence
- This run's evidence readiness

For a separate application-level recommendation across modules, use
[`esx-eval release`](RELEASE_REVIEW.md). A single-run readiness section is not
a whole-application release decision.

Browser workflows remain useful for authentication and protected UI coverage,
but they do not replace decision evaluation. For RAG, groundedness, tool use,
trajectory, security behavior, cost, or latency, add the redacted local
telemetry path described in `PRE-D_EVIDENCE_GUIDE.md`.
