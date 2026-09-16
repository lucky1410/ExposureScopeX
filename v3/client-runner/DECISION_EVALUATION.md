# PRE-D Local Decision Evaluation

Use this path when you need to measure an AI or business decision locally:
accuracy, precision, recall, F1, and confidence calibration. It does not
require an ExposureScopeX account or a platform connection.

## 1. Start the local setup

```text
esx-eval setup --directory ./pred-vini-evaluation
```

Choose **Decision evaluation**, enter the loopback endpoint that runs the real
local decision path, and select **Test local connection**. PRE-D sends one
fixed harmless probe and retains only response field names and types while you
confirm the mappings.

## 2. Import labelled cases

Import a JSON array or paste it into the local setup page. Start with
[`examples/decision-evaluation.sample.json`](examples/decision-evaluation.sample.json)
and replace its synthetic inputs with your own local test cases. Use at least
two expected labels; otherwise accuracy, precision, recall, and F1 would be
mathematically misleading.

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

`label` and `confidence` are required for the decision scorecard. The setup
page lets you map different field locations, such as `decision.label` and
`decision.confidence`, without editing a configuration file.

`evidence_ids` and `abstained` are optional. When supplied, PRE-D measures
evidence-reference alignment and correct abstention. Evidence ID overlap is
not a groundedness or hallucination score: those require claim-level support,
valid citations, and evidence-integrity metadata.

## 4. Run and read the report

```text
cd ./pred-vini-evaluation
esx-eval run --config ./esx-eval.json --out ./out/evaluation.json
esx-eval view --report ./out/evaluation.local-report.html
```

The first report section states separately whether PRE-D measured:

- Decision evaluation
- PRE-D telemetry evidence
- PRE-D local release readiness

Browser workflows remain useful for authentication and protected UI coverage,
but they do not replace decision evaluation. For RAG, groundedness, tool use,
trajectory, security behavior, cost, or latency, add the redacted local
telemetry path described in `PRE-D_EVIDENCE_GUIDE.md`.
