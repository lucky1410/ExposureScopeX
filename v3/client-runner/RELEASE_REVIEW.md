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

## Execute the entire declared inventory

The `scope`, `bind`, `attach`, `preflight`, and `run` commands below require
PRE-D Local 0.15.0 or later for all coverage and history features below. The existing `release check` workflow
remains supported for explicitly partial runs and report review.

PRE-D can run all modules using their approved browser and decision plans in
one invocation. There is no built-in list of supported business modules. A
settings, administration, or non-AI module can use workflow tests; an AI module
uses decision tests; a mixed module needs both. Existing personas, sessions,
semantic judges, telemetry, and adapter settings stay in their original plans.

First list **every** module. Use `--inventory-complete` only after reviewing this
list; it is your scope declaration, not automatic discovery certification.

```text
esx-eval release init --application-id my-app --subject-version candidate-1 --module dashboard --module decisions --module settings --inventory-complete --out release.json
esx-eval release scope --manifest release.json --module dashboard --profile workflow --persona analyst
esx-eval release scope --manifest release.json --module decisions --profile mixed --persona analyst
esx-eval release scope --manifest release.json --module settings --profile workflow --persona admin
esx-eval release attach --manifest release.json --module dashboard --suite-id dashboard-ui --config dashboard/esx-eval.json --read-only
esx-eval release attach --manifest release.json --module decisions --suite-id decisions-api --config decisions/esx-eval.json --read-only --require-kind workflow
esx-eval release attach --manifest release.json --module decisions --suite-id decisions-ui --config decisions/browser.json --read-only
esx-eval release attach --manifest release.json --module settings --suite-id settings-ui --config settings/esx-eval.json --read-only
```

These commands do **not** yet create a runnable full scope: review the generated
objectives and bind each to real cases in those plans. For example, if the
dashboard plan contains the reviewed case `open-dashboard`:

```text
esx-eval release bind --manifest release.json --module dashboard --requirement workflow-analyst-happy-path --suite-id dashboard-ui --case-id open-dashboard --assertion "The analyst sees the expected dashboard heading after login."
esx-eval release preflight --manifest release.json --out out/preflight.json
```

Repeat binding for the actual negative, recovery, authorization, decision, and
integration objectives. Preflight names every missing binding before making any
target call. Once it is ready:

```text
esx-eval release run --manifest release.json --out out/release-review.json --require-ship
```

Alternatively, `esx-eval setup --application` provides local forms and case
selectors for this process. See [Application setup](APPLICATION_SETUP.md).

`attach` validates application/version/subject bindings and stores relative
config paths. It adds the plan's kind to the module's required test kinds;
`--require-kind` can declare additional kinds that are still needed. Repeat it
for additional workflows, decision tasks, personas, or metric packs. Existing
suite replacement requires `--replace` and preserves its release thresholds.
It does not invent expected outcomes or silently rewrite the evaluation plan.

`preflight` calls no adapter or browser. It checks every module for missing or
invalid plans, unconfirmed test kinds/objectives, missing case/persona bindings,
unasserted browser journeys, exclusions, reused reports, duplicate
plans, and missing or stale execution approvals. A valid config is not a
connectivity check. Fix all listed issues before the all-module run starts.

`run` performs that same preflight before calling any target. Unlike
`check --run`, it refuses to start a partial application run. Every module must
be included with runnable configs; an existing report cannot substitute for
fresh execution. After dispatch starts, a suite failure is recorded and the
remaining approved suites still run sequentially. No failed suite is retried
automatically. Blocked or failed executions cannot yield complete coverage.

Approval is bound to the config hash. Reattach with `--replace` after reviewing
a changed config. For writes, use `--isolated-writes --isolation-note "..."`
instead of `--read-only`, describing the disposable environment and disabled or
sandboxed external integrations. These flags record operator approval; they do
not intercept app-side writes, verify isolation, or provide rollback. A read-only
plan still needs review, including login and backend side effects. Do not mark a
write plan read-only simply to pass preflight.

The report's **What actually ran** section and JSON `execution_review` distinguish
execution attempts, fully executed modules, existing reports, unexecuted modules,
and whether a baseline comparison was performed. All-module execution means
every declared suite/case completed, not that every possible behavior was tested
or that the quality gates passed. `all_modules_executed` is independent of the
release recommendation.

The report now also shows:

- **Metric dimension coverage** for every suite, separating gated,
  measured-only, and not-requested dimensions.
- **Population coverage** for decision suites when the manifest declares the
  larger labelled population available to that suite.
- **Historical trend context** when you supply one or more `--history` release
  reports in addition to or instead of a direct `--baseline`.

**Coverage advisories** appear in setup, preflight JSON, and release HTML/JSON.
They explain unrequested baseline dimensions, absent population context, and
weak workflow assertions without changing the numeric scores or release verdict.
Missing or blocked reports remain listed in dimension coverage. If the requested
dimensions cannot be established, their request status is explicitly unknown.

Workflow signal strength describes the **planned checks after the final
navigation or interaction**, not a pass result. Visible text and visible-element
assertions are distinguished from title-only, route-only, and non-visible
element-state checks. A case with no final assertion is also flagged. Deliberate
absence checks can be appropriate for negative paths; review the intended outcome.
Text and selector waits are accepted consistently by plan and objective validation.
New local reports retain only case IDs and signal categories for reuse, without
page text or selectors. Older reports lacking this metadata disclose unknown
assertion strength.

The **test objective** summary is separate from execution completeness. Each
objective names its test kind, category, optional browser persona or module
dependency, actual suite/case IDs, and a reviewer-written assertion description.
Its status follows the recorded case outcomes: passed, failed, missing, or
incomplete (blocked). A failed objective blocks release even if an aggregate
score is high. Incomplete or duplicated case ledgers cannot satisfy objectives.
This verifies the mapping and outcomes, not the semantic sufficiency of a test.
Reviewers must not label a heading check as proof of a business transaction.

`depends_on` alone is a declared relationship, not an executed integration.
Reports explicitly distinguish declared-only dependencies from passed or failed
mapped integration cases. An untested dependency path is an evidence gap.
Changing objectives, personas, assertions, or case bindings is disclosed in a
baseline comparison rather than called an application improvement.

All-module runs require objectives for every declared test kind. The older
`release check` path still supports bounded reviews without that depth model;
its HTML explicitly says test depth is unspecified, and must not be read as
proof of whole-application coverage.

Exit codes for `preflight`/`run`: `0` means ready/fully executed, `2` means blocked
or incomplete, and `1` means a command or manifest error. With `--require-ship`,
`run` also returns `2` for a non-Ship recommendation. Use a fresh full execution
with `--baseline out/previous-release.json` to test regressions, not just prepare
a hypothetical baseline.

Use repeated `--history` flags when you want conservative trend context across
more than one prior release review:

```text
esx-eval release run --manifest release.json --history out/release-2.json --history out/release-3.json --out out/release-4.json
```

History is sorted by actual timestamps, including timezone offsets. Regenerated
artifacts from the same source run do not add another comparable observation.
History remains descriptive; use `--baseline` for the existing regression gate.

Application-specific routes, expected outcomes, labelled data, approved sessions,
and safe execution interfaces still need to exist. For a module without those,
PRE-D explains what plan is missing instead of inventing a passing test. The
current engines cover browser workflows and decision/API/command evaluations;
they do not automatically supply load tests, arbitrary API contract tests, or
every infrastructure test a production release may need.

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
          "population": {
            "available_case_count": 13133,
            "class_counts": {"allow": 12976, "review": 157},
            "source": "Held-out labelled archive"
          },
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

Optional suite `population` metadata is descriptive context, not an implicit
gate. It lets PRE-D say what share of a declared labelled universe was sampled
by the executed decision pack. Without it, PRE-D truthfully reports only the
executed pack size and class mix.
Class counts may cover only part of the available population; the report derives
the remaining unclassified count. If executed totals or per-class counts exceed
the declared population, coverage fractions are withheld and an inconsistency
advisory is shown. Suite populations may overlap, so their summed totals are not
a count of unique application records.

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

Each module also carries a separate review-scope state in the release report:
`evaluated`, `inspected`, `blocked`, or `untouched`. This does not replace the
release verdict. It answers a narrower question: how far the review actually
got for that module. `evaluated` requires complete, usable executed evidence from
every attached suite and every required executable kind. `inspected` means only manual review metadata
was recorded. `blocked` means an executable review was planned but did not
complete, or a required executable path remains missing beside other review
activity. `untouched` means no executable evidence or manual review note is
recorded.

Optional `review_methods` let the reviewer record non-executable review work
without pretending it was tested. For example:

```json
{
  "id": "integrations",
  "required": true,
  "review_methods": [
    {
      "id": "runbook-review",
      "label": "Runbook review",
      "status": "inspected",
      "summary": "Reviewed rollback runbook and dependency owners.",
      "evidence_pointer": "notes/release-review.md"
    }
  ],
  "suites": []
}
```

That module still remains an evidence gap until real suites exist, but the
report can now show that the team inspected it instead of leaving it invisible.

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
comparisons, the review-scope matrix, findings with their module/plan/case
references, suggested actions, and source report links. Recommendations
identify investigation areas; they do not invent exact source-file root causes.

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
