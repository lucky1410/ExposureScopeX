# Whole-System Testing Contract

Available in PRE-D Local 0.15.1. No platform account or Docker is required by
PRE-D. The application itself may have its own dependencies.

PRE-D coordinates its existing AI/browser, HTTP, code, security, load, recovery
and history engines. The new contract prevents an attached module, suite-level
pass or URL-only check from silently becoming whole-system behavior coverage.
This is not automatic certification of every behavior in any arbitrary app.

## Safe Setup

Confirm disposable data, disabled/mocked live writes and messaging, non-admin
test identities, tenant fixtures, a reset procedure and owner-approved budgets.
Keep credentials and raw customer data on the tester's machine. Approval flags
record permission; they do not isolate your application.

Install the published wheel or this source version, then:

```text
esx-eval system discover --project my-app --version candidate --repo ../my-app --openapi ./openapi.json --base-url http://127.0.0.1:8000 --out ./system-plan.json
esx-eval system scope --plan ./system-plan.json --init
esx-eval system setup --plan ./system-plan.json
```

Either repository or OpenAPI input is sufficient. Discovery and setup do not
call the target. Draft objectives and inventory totals remain unreviewed.

## Review in Setup

1. Confirm components, business-module grouping, layers, roles, dependencies,
   enabled capabilities and missing surfaces. Discovery is not exhaustive.
2. Supply independent behavior expectations, test data and applicable evidence.
   Missing confidence does not make an entire module untestable. Mapped scores
   are not native probabilities; semantic checks do not require class labels.
3. In **Whole-system behavior contract**, confirm inventory totals by kind.
   Match the counting units: API operations are not router-file counts, and
   source files are not necessarily business modules. Mismatches remain gaps.
4. Add every critical behavior, not only one generic objective per module.
   Bind each to a check and explicit case IDs or JSON assertion paths.
5. Bind a running-build assertion to the actual candidate ID or source/image
   digest. Version-control HEAD alone is insufficient for a dirty checkout or
   older running container.
6. Review policy and inventory, save, then approve separately from the CLI.

Authorization requires an objective for each declared role on components that
require that layer. Include allowed-path controls, not only denied requests.
Tenant testing needs known fixtures plus ownership-positive and cross-tenant
negative controls. PRE-D cannot infer the intended product policy from role names.

## Evidence Bindings

| Check | Objective fields | Evidence requirement |
| --- | --- | --- |
| HTTP | `assertion_paths` | Recorded content/budget assertions, not status alone |
| AI evaluation | `case_ids` | Actual executed cases and usable verified metric gates |
| Browser evaluation | `case_ids` | Executed cases with visible outcome assertions after the last interaction |
| JUnit command | `case_ids` | Unique executed testcase identities; skipped/missing/duplicate cases do not establish coverage |
| Load | `assertion_paths` | Observed request assertions and approved bounded workload budgets |
| Recovery | `assertion_paths` | Observed disruption and recorded restoration assertions |

JUnit IDs are `classname::name`, or `name` if classname is absent. Use actual
testcase IDs, not suite names. Non-classification cases may be recorded as
executed without pretending they have a per-case classification verdict.

Failed checks count as evaluated and failed, never as release success. Exclusions
remain whole-system gaps. A passing JUnit case is not marked failed because a
different test failed, but the suite failure still blocks release. Aggregate AI
gate failures apply to the bound evaluation. Semantic judges remain fallible.

## Running Candidate Identity

Create an approved native HTTP GET check with a JSON assertion such as
`{"path":"build_id","equals":"reviewed-candidate-digest"}`. Bind it using:

```json
{
  "check_id": "running-build",
  "assertion_path": "build_id",
  "expected_value": "reviewed-candidate-digest"
}
```

This goes in `scope_contract.build`. Configure a test identity if required.
PRE-D checks the candidate before and after execution. A wrong/unreachable
candidate at the start stops further dispatch. A mismatch at the end invalidates
clean readiness and excludes that run's signals from regression comparisons.

This is target-observed identity, not independent source/container attestation.
It cannot detect every transient deployment between the two probes. Your build
pipeline must expose an honest immutable identifier and prevent deployments
during evaluation. Earlier observed results remain inspectable.

## Execute and Review

```text
esx-eval system approve --plan ./system-plan.json
esx-eval system preflight --plan ./system-plan.json --require-whole-system
esx-eval system run --plan ./system-plan.json --require-whole-system --out ./runs/candidate-001 --history ./pred-history.sqlite
```

Only add `--isolated-writes --allow-disruption` to approval for reviewed isolated
recovery experiments, never to bypass missing safety controls. Strict preflight
checks planning completeness, not future runtime success. Omit strict mode only
for intentional partial diagnostics; the report still shows incomplete scope.

Open `system-report.html`. Its executive view separates verdict, failed/blocked
checks, behavior coverage, modules and detailed evidence. Objectives show bound
evidence, status and next action. HTML/JSON agree; root-cause file/line claims
are not invented from a failing check.

## Reproduce Acceptance

From `v3/client-runner` in the source archive or checkout:

```text
python -m unittest discover -s tests -p test_whole_system.py -v
python tests/run_whole_system_acceptance.py --out ./whole-system-acceptance
```

Use a new output directory. The disposable ten-module/four-role reference app
produces healthy, seeded-fault, repaired, missing-behavior, wrong-candidate and
changed-candidate runs. Inspect `testing-readiness.html`,
`acceptance-results.json` and `artifact-manifest.json`.

Real HTTP requests, test subprocesses and worker interruption/recovery execute
locally. The decision engine/probabilities are simulated. This reference does
not validate production models/judges, real browser journeys, production-scale
load or a customer app. Existing browser/semantic regressions remain separate.
Passing means ready for controlled application testing, not customer release
approval. The application owner still supplies reviewed scope, real adapters,
independent expectations, role identities, actual evidence and a safe environment.
