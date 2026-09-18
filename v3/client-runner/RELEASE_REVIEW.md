# PRE-D application release review

PRE-D can combine existing local evaluation plans into an application release
review. It answers three questions within a declared scope:

1. Do the evaluated modules meet the release thresholds?
2. Which module, plan, case, or evidence gap needs attention?
3. What should the team inspect, change, and rerun?

The review produces a local JSON artifact, an interactive HTML report, and a
hash-linked audit log. It uses the existing browser, decision, semantic, and
telemetry metric engines. No ExposureScopeX connection, database, Docker service,
or new runtime dependency is required.

## Start with an application inventory

```text
esx-eval release init --application-id my-app --subject-version candidate-1 --module dashboard --module decisions --module integrations --out release.json
```

The generated manifest lists every module as required, with no executed plans.
It begins with `inventory_complete: false`. Add existing local evaluation
configurations to the modules, review the checks, and confirm the inventory.
An empty module remains an evidence gap. Repository discovery alone cannot
establish that a module was tested.

Use the real application's module names. PRE-D has no built-in customer-specific
module taxonomy. A module can contain multiple plans, including separate browser
personas, decision datasets, and multi-page or integration journeys.

## Attach the existing plans

```json
{
  "schema_version": "pre-d-release-manifest-1.0",
  "application": {
    "id": "my-app",
    "version": "candidate-1",
    "inventory_complete": true
  },
  "policy": {"max_report_age_hours": 24},
  "modules": [
    {
      "id": "decisions",
      "name": "Decision engine",
      "owner": "AI product team",
      "required": true,
      "required_kinds": ["decision"],
      "suites": [
        {
          "id": "decision-quality",
          "kind": "decision",
          "subject_id": "decision-engine",
          "config": "decisions/esx-eval.json",
          "minimum_cases": 20,
          "gates": [
            {"signal": "classification.accuracy", "operator": "gte", "threshold": 0.95},
            {"signal": "classification.macro_f1", "operator": "gte", "threshold": 0.90},
            {"signal": "confidence.expected_calibration_error", "operator": "lte", "threshold": 0.15}
          ]
        }
      ]
    },
    {
      "id": "dashboard",
      "owner": "Application team",
      "required_kinds": ["workflow"],
      "depends_on": ["decisions"],
      "suites": [
        {
          "id": "analyst-navigation",
          "kind": "workflow",
          "subject_id": "application-ui",
          "config": "browser/esx-eval.json",
          "minimum_cases": 6
        }
      ]
    },
    {
      "id": "integrations",
      "required": false,
      "exclusion_reason": "Live write integration awaits an isolated test tenant.",
      "suites": []
    }
  ]
}
```

`application.id` must match each plan's `evaluation.project_key`.
`application.version` must match `evaluation.subject_version`.
Each suite's `subject_id` must match `evaluation.agent_id`.

Manifest paths are relative to the manifest. Each plan runs from its own
directory, so its adapter scripts, session files, and other relative paths keep
their original meaning. Existing target, authentication, and sandbox restrictions
continue to apply. Excluded modules require a reason and cannot contain suites.

### Make required coverage explicit

Set `required_kinds` to `["workflow"]`, `["decision"]`, or both for each required
module. A decision pack does not satisfy a required browser workflow, and vice
versa. Missing plans remain evidence gaps even if all other scores are perfect.
Older manifests without this field still run, but their coverage is labelled
**Attached plans only**, not comprehensive module coverage.

`depends_on` lists other module IDs. Unknown references, duplicate references,
self-dependencies, and dependency cycles are rejected before execution. A module
cannot receive an unconditional Ship recommendation if a required dependency is
excluded, incomplete, or blocked. This is a dependency-readiness check, not an
integration test: supply real cross-module journeys to establish those behaviors.

The coverage table separates planned and executed suites for each test kind.
**Complete coverage does not mean passing behavior.** A fully executed suite can
have complete evidence and still fail its release gates. Blocked sessions,
missing metrics, and inadequate samples remain incomplete evidence.

Without explicit `gates`, a decision suite uses accuracy >= 0.95, macro F1 >=
0.90, and ECE <= 0.15. A workflow suite uses execution rate = 1 and signal match
rate = 1. Decision suites default to 20 cases; workflow suites default to 1.
These are editable starting policies, not universal production standards.
Twenty cases is a sample floor, not a statistical guarantee.

Every metric required by a run also needs a release gate. Otherwise the review
shows a policy gap. Additional supported gates include grounded claim rate,
unsupported claim rate, evidence-reference precision/recall, trajectory score,
tool authorization rate, retrieval recall, repeatability, and metered cost or
latency. A numeric metric must be measured, locally verified, and representative
before it can satisfy a gate. Model-judged semantic results retain a review
condition and must cover all executed responses.

## Run and review

```text
esx-eval release check --manifest release.json --run --out out/release-review.json
esx-eval view --report out/release-review.html
```

Plans run sequentially to keep resource use bounded. The existing adapter and
browser timeouts apply. Each suite gets its own output directory under
`out/release-review.runs/<review-id>/<suite-id>/`. A failed suite remains an
evidence gap while other valid plans continue. No failed plan is automatically
retried, which avoids replaying application actions unexpectedly.

The report includes the release recommendation, module results, threshold
comparisons, findings with their module/plan/case references, suggested actions,
and source report links. Recommendations identify investigation areas; they do
not invent exact source-file root causes.

Each invocation retains its artifacts for review. PRE-D does not start a daemon
or perform background runs. Teams can remove obsolete review folders according
to their own local retention policy.

## Review existing reports without running the app

Replace a suite's `config` with `report`, pointing at its completed
`*.local-report.json`. Then run:

```text
esx-eval release check --manifest release.json --out out/release-review.json
```

Without `--run`, configuration-backed suites are marked as not run. This command
never silently calls the app. Mixed report-backed and configuration-backed
suites are supported; `--run` executes only the configuration-backed suites.

Reports need the run provenance emitted by this version: project, subject
version, original run timestamp, and run ID. Older reports can be regenerated
from their original package using `esx-eval report`; that preserves the original
run timestamp. Regeneration does not make stale evidence fresh. Missing,
malformed, stale, mismatched, and reused reports do not satisfy release coverage.

## Compare a candidate against a baseline

Preserve each version's release-review JSON, then provide the previous review:

```text
esx-eval release check --manifest candidate-release.json --baseline out/previous-release.json --run --out out/candidate-release.json --require-ship
```

Omit `--run` when the candidate manifest already points to completed reports.
The baseline is read-only and is never executed. It must belong to the same
application and have a historical timestamp. Its age does not invalidate it as
a historical comparison; the candidate still needs fresh evidence. Baseline
validation happens before any candidate adapter runs. Output paths cannot
overwrite the baseline, input reports, or manifest.

The release HTML and JSON show:

- Metric values and deltas for matching tests, with lower-is-better handling for
  calibration error and Brier score.
- Newly failing and newly passing case IDs, including case regressions hidden
  by unchanged aggregate scores.
- Added/removed modules and suites, changed scope requirements and policies.
- Explicit reasons when results are **Not comparable**. Removed tests are not
  described as fixed defects.

Comparison currently supports classification, confidence, workflow outcomes,
and decision-evidence reference metrics. Both suites need distinct executions,
complete verified evidence, identical dataset-content and evaluation-protocol
fingerprints, matching subject/type, sample policy, and metric gates. Dataset
version names alone are not enough. Raw case inputs and credentials are not
copied into release reports; only fingerprints and content-free case outcomes
are retained. Fingerprints identify the supplied pack and scoring setup, not
the external application's complete runtime environment or dataset independence.

For browser suites, the protocol fingerprint also includes the adapter plan.
Changing selectors, personas, or session configuration can therefore require a
new matched baseline rather than an apparently improved workflow score.

Older packages without original fingerprints cannot acquire them from a newer
configuration through report regeneration. Rerun the baseline pack when those
fingerprints are absent. Existing reviews remain usable without `--baseline`.

Advanced semantic and telemetry metrics still participate in the candidate's
normal release gates. Regression comparison for those metrics is deliberately
not yet supported: matching source/judge/telemetry protocols must be established
first. Requesting a comparison with unavailable checks creates an evidence gap,
not an invented delta or a product defect.

Optional comparison policy:

```json
{
  "max_report_age_hours": 24,
  "regression_severity": "warning",
  "regression_tolerance": 0.0
}
```

The defaults report any observed decline beyond numeric rounding as a condition.
Use `blocker` for `regression_severity` to block on such declines. Tolerance is an
absolute score difference, not a relative percentage (0.01 means one percentage
point on a 0-1 rate). Newly failing cases remain visible regardless of aggregate
tolerance. Changing policy is itself flagged for review. Differences describe
the matched pack, not statistical significance or production-wide improvement.

## Interpret the recommendation

| Recommendation | Meaning |
| --- | --- |
| Ship | All required declared checks passed, with no remaining evidence gaps or conditions. |
| Ship with conditions | Required checks passed, but explicit exclusions, policy warnings, or judge-review conditions remain. |
| Do not ship | An observed result failed a blocking threshold. Evidence gaps remain visible alongside it. |
| Insufficient evidence | Required modules, runs, measurements, sample sizes, or release policies are incomplete. |

Blocked authentication is an execution gap. A browser assertion mismatch is a
failed workflow check requiring review; it is not automatically a confirmed app
defect. Target-declared perfect scores cannot satisfy a verified release gate.
Poor calibration remains visible even if classification is perfect.

For CI, add `--require-ship`. Exit codes are `0` for a written report (or Ship
when gating is enabled), `2` when gating requires Ship and the recommendation
differs, and `1` for command/manifest errors. Conditional release acceptance stays
with the release owner.

## Current boundary

This is the first application-level release review layer. Completeness is
relative to the inventory, plans, cases, and thresholds the team supplied. It
does not automatically discover every business journey or add load testing,
infrastructure verification, arbitrary permission probes, or source-level root
cause analysis. Those require additional evaluation capabilities and evidence.

The report keeps individual metrics separate. It does not average a failing
critical module into an overall green application score. Artifact fingerprints
support reproducibility and audit review; they are not independent attestations
of the target application's implementation.

## Try a synthetic report

From the `v3/client-runner` source directory, run:

```text
python -m examples.run_release_fixture --out-dir ./out/release-demo
python -m examples.run_release_fixture --compare --out-dir ./out/release-comparison-demo
```

This fixture calls only its own deterministic local adapter. It produces one
healthy module, one with poor calibration despite perfect labels, one uncovered
module, and an explicit exclusion. The expected recommendation is **Do not
ship**, with the coverage gap and conditions still visible. These are synthetic
regression results, not evidence about a real application.

The comparison variant first runs a healthier synthetic baseline, then a candidate
with worse calibration. It keeps the missing coverage visible alongside the
regression. Both runs use only the fixture's deterministic local adapter.
