# Confidence Provenance and Independent Decision Metrics

These working-tree changes are unpublished. Installing the published 0.15.0
wheel does not install them.

## Choose the Measurement, Not a Mandatory Bundle

- Classification needs independent expected labels and observed predictions.
  It does not need confidence, telemetry or a semantic judge.
- Calibration needs numeric probabilities of the returned label being correct,
  labelled outcomes and a reviewed declaration of the values' origin/meaning.
- Decision evidence needs expected evidence IDs and/or abstention expectations,
  plus the corresponding observations. It does not require confidence or labels.
- Groundedness/hallucination use their own response, source and review evidence.
  Missing classification labels or confidence does not block these dimensions.

The existing multi-class scorecard policy remains: use at least two expected
classes for the aggregate classification/calibration scorecard. A tiny or
single-class pack does not establish performance on absent classes. A deliberate
minority oversample measures that pack, not the natural population distribution.

## Native Probabilities

Add this to the reviewed `evaluation` object only after checking the application's
contract. PRE-D cannot infer probability semantics from JSON's numeric type.

```json
"confidence_provenance": {
  "kind": "native_probability",
  "meaning": "predicted_label_correctness"
}
```

This means confidence in the **returned label being correct**. For example,
`P(positive)=0.10` with a predicted negative label is not `confidence=0.10` in
that negative label. Any conversion needs a reviewed, correct probability
contract; PRE-D does not silently convert it.

PRE-D verifies the arithmetic against supplied labels. The native origin remains
an evaluator declaration, not independent inspection of the model implementation.
It does not guarantee calibrated probabilities, correct gold labels, population
representativeness or production readiness.

## Adapter-Mapped Categories

```json
"confidence_provenance": {
  "kind": "adapter_mapped",
  "mapping": {"high": 0.9, "medium": 0.7, "low": 0.4}
}
```

The adapter performs its reviewed conversion and returns the resulting number.
PRE-D records the mapping and rejects returned numbers outside its values. It
does not independently verify the source category or apply the mapping itself.
Keep the categories anonymous and free of secrets.

ECE and correctness Brier arithmetic remains available as **diagnostics of this
mapping**. The report labels the metric `declared`, calculation
`verified_locally`, and `calibration_eligible: false`. The mapping is not evidence
of native application probability calibration, even if the resulting score is
perfect. Do not manufacture more confidence levels to silence a warning.

## Unknown and Older Configurations

Omitted provenance defaults to `{"kind":"unknown","meaning":"unspecified"}`.
Runs still calculate numeric diagnostics; classification results are unchanged.
Unknown-origin values cannot satisfy native calibration release gates. Older
reports carrying only `trust_status: verified` do not establish this provenance.
Rerun from a reviewed configuration rather than editing old report evidence.

The comparison-protocol hash includes confidence provenance and the mapping, so
changing either makes the runs incompatible for automatic regression comparison.

## Classification-Only Release

Use `evaluation.required_dimensions: ["classification"]`, omit the confidence
response path for HTTP, and return labels without inventing confidence.
New `release attach` and application setup select baseline defaults only for
requested dimensions. Existing suite policies are preserved on replacement.
For an existing release suite, explicitly review its gates, for example:

```json
"gates": [
  {"signal":"classification.accuracy","operator":"gte","threshold":0.95,"severity":"blocker"},
  {"signal":"classification.macro_f1","operator":"gte","threshold":0.9,"severity":"blocker"}
]
```

These are example policy thresholds, not an owner-approved universal release bar.
Do not remove a calibration requirement simply to make a release pass. Record
the scope decision with the product owner. Raw manifests that omit gates still
use the legacy classification-plus-confidence default template for compatibility.
Explicit decision gates can instead cover groundedness, abstention or other
supported task dimensions without adding unrelated classification/confidence.
Non-baseline tasks require explicit reviewed gates; PRE-D does not invent a
correctness threshold. Workflow suites still require execution and signal gates.

## Safe Full-Application Planning

Missing confidence is a metric-specific gap, not proof a whole module is
untestable. Map modules to interfaces, workers, roles, tasks and dependencies;
keep unmapped surfaces visible. Use independently reviewed synthetic examples
where appropriate, clearly separated from historical real-world evidence.
Do not pass expected answers to the generation path or use its own scores as
independent truth. Distinguish decision actions from gold class labels explicitly.

Keep source documents, records, credentials and raw traces on the application
owner's machine. Anonymous inventory, counts, synthetic schemas and approved
policy summaries suffice for planning, not independent proof of correctness.
Before active tests, verify the running build/configuration, authorized test
identities, disposable data, external-write isolation and reset procedure.
Localhost alone is not a safety boundary. Native load/recovery capabilities do
not authorize live writes, sending messages or disrupting a real application.
