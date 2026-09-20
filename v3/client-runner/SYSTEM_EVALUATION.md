# PRE-D Local System Evaluation

**Available in PRE-D Local 0.15.0.**

For reusable setup, a read-only source policy, bounded local planning assistance
and traceable baseline comparisons, start with [local onboarding](LOCAL_ONBOARDING.md).
Protected profiles block unrestricted external commands; the command layers
below retain their earlier explicit isolation requirements.

PRE-D can now coordinate more than AI scorecards: source/API inventory,
reviewed HTTP contracts, existing browser and AI evaluations, external code and
security suites, role/tenant checks, bounded load/recovery experiments, and
local rolling history. Existing metric engines are retained, not replaced.

This is an executable, reviewed system plan, not an autonomous certification of
an arbitrary application. Every discovered component remains a coverage gap
until its required checks execute. An inventory confirmation is the operator's
scope declaration, not proof that discovery found every business capability.

For behavior-level completeness, candidate identity checks and strict planning
preflight, use the [whole-system testing contract](WHOLE_SYSTEM_TESTING.md).
Legacy plans without this contract remain selected-check evaluations, not
whole-system coverage claims.

Business-logic planning is available as a reviewed, non-invasive drafting layer
through `system assist --business-context`. It uses owner-supplied rules plus
read-only inventory to draft actors, entities, states, permissions, decision
rules, dependencies and expected outcomes into behavior objectives. Code
behavior remains separate from intended business behavior: accepted suggestions
are hypotheses until the application owner reviews them and binds real evidence.

## Layer Map

| Layer | Implemented path | What still comes from the application team |
| --- | --- | --- |
| 0: inventory and evaluation integrity | Static source/OpenAPI discovery, disabled check drafts, guided inventory review, explicit component/layer/role coverage | Confirm business-module grouping, mounted routes, runtime flags, dependencies and undiscovered components |
| 1: decision regression | Existing AI engines, label-only scoring, decision-evidence fix, stratified labelled sampling, compatible rolling baselines, foreground scheduled cycles | Independent labels, approved real adapters/endpoints, metric budgets and representative sampling |
| 2: code and integration | Execute approved argv commands, ingest fresh JUnit results, assert HTTP status/content/numeric budgets, map cross-component checks | Actual unit/integration tests, fixture data, expected contracts and installed test runners |
| 3: adversarial and authorization | API x role drafts, tenant-boundary templates, existing security evaluation packs, external security tools emitting JUnit | Allow/deny matrix, test identities, two isolated tenants, independent attack outcomes and positive controls |
| 4a: operational behavior | Health/queue counters through JSON budget assertions, read-only load probes with latency and failures, longitudinal alerts | Instrumented health endpoints, workload budgets and realistic staging conditions |
| 4b: recovery | Approved injection and cleanup argv, observed disruption, health restoration deadline, stop on cleanup failure | Disposable infrastructure, concrete failure scenarios, meaningful recovery/idempotency assertions |

Layer 2 does not generate a complete unit-test suite. Layer 3 is not an automatic
penetration test. Layer 4a is bounded (100 requests, concurrency 8 per load
check), not a production capacity benchmark. Layer 4b is not an infrastructure
provisioner or universal chaos engine. No module is silently excluded because
it lacks a numeric confidence: use the evidence path appropriate to its behavior.

## Install This Source Version

From the repository root, use an evaluator virtual environment:

```text
python -m pip install -e ./v3/client-runner
esx-eval system --help
```

No Docker, ExposureScopeX account or hosted database is required. Optional
history uses one local SQLite file. Browser checks still require Playwright;
semantic checks still require a configured independent local judge. Installing
PRE-D does not install models, configure an OS scheduler, or contact the target.

## Discover, Review, Approve, Run

```text
esx-eval system discover --project my-app --version candidate --repo ../my-app --openapi ./openapi.json --base-url http://127.0.0.1:8000 --out ./system-plan.json
esx-eval system setup --plan ./system-plan.json
esx-eval system approve --plan ./system-plan.json
esx-eval system preflight --plan ./system-plan.json
esx-eval system run --plan ./system-plan.json --out ./runs/candidate-001 --history ./pred-history.sqlite
```

Either `--repo` or `--openapi` is sufficient. OpenAPI must be a local 3.x JSON
document; remote references are not fetched. Source discovery covers literal
Python decorators, Express-style routes, Next app pages, React routes, test
files, service/job locations and selected model/retrieval symbols. Candidates
are heuristics, not live routes or confirmed runtime feature states. Repository
code is not imported or executed during discovery. Large/unreadable files,
unsupported frameworks, dynamically mounted routes and scan limits are disclosed.

The loopback setup page lets you:

- Regroup candidates into modules and add missing components.
- Select required layers, record feature flags and dependency component IDs.
- Draft API-role checks and add HTTP, tenant, code, load and recovery checks.
- Set expected statuses, JSON assertions, environment-based identities and budgets.
- Attach existing AI/browser plans without reauthoring their metrics.
- Save the plan without running the target; every edit invalidates prior approval.

Drafts are disabled. Enter independently reviewed expectations, then enable the
check. A status-only HTTP 200 is labelled as narrow evidence, not content proof.
Named-role identities must reference environment variables; put the complete
header value, such as `Bearer ...`, in that variable. The tool cannot prove that
a credential actually belongs to the role you named: include an identity/role
assertion against a trusted test endpoint when applicable.

CLI approval binds the exact plan and bound evaluation configuration hashes.
HTTP targets must be loopback, or HTTPS explicitly marked `staging`. Redirects
are not followed and proxy environment settings are not used for native probes.

**Approval does not sandbox commands or app behavior.** Use test identities,
disposable data and isolated integrations. A GET can still have app-defined side
effects. Commands, adapters, test frameworks and models can access the network
and filesystem with the evaluator's permissions. Never run untrusted commands.

## Connect AI Metrics and Browser Workflows

```text
esx-eval system bind --plan ./system-plan.json --config ./decisions/esx-eval.json --component COMPONENT_ID --id decisions
```

Use a component ID from the inventory or choose it in setup. Bound plans must
match the system project/version. Review and enable the added check. Existing
browser session handling, personas, workflow packs, local telemetry,
groundedness and hallucination paths remain available.

Metric gates are explicit:

```json
[
  {"signal": "classification.accuracy", "operator": "gte", "threshold": 0.95},
  {"signal": "decision_evidence.correct_abstention_rate", "operator": "gte", "threshold": 0.95}
]
```

Defaults for classification, confidence and workflow are suggestions, not safety
standards. Every requested dimension must have an applicable gate. A missing
gate/evidence is blocked; a target-declared score cannot pass a verified gate.
Dimension inventories show unrequested baseline/advanced metrics, rather than
implying all 14 were tested. Do not request irrelevant dimensions merely to fill
a report. Semantic judge verification remains fallible, not proof of truth.

Input requirements are now independent:

- `classification`: local expected labels plus real returned labels; no confidence required.
- `confidence`: expected/returned labels plus genuine finite 0..1 confidences.
- `decision_evidence`: expected and observed evidence references and/or abstention, without requiring classification/confidence.
- Semantic groundedness/hallucination: actual response/source material, independent judge and relevant abstention expectations; classification labels/confidence are not prerequisites.

In existing guided decision setup, leave confidence mapping empty when the app
does not return it. The generated plan omits calibration instead of inventing
a score. Other dimensions retain their own evidence contracts.

## Population and Sampling

Supply a dataset object containing `version` and labelled `cases` with unique
`case_id`, `input`, and `expected_label` fields:

```text
esx-eval system sample --dataset ./labelled-population.json --per-class 25 --seed 42 --out ./sampled-dataset.json
```

Use the returned object as the evaluation config's `dataset`, with the same
`evaluation.dataset_version`. Sampling is deterministic, without replacement,
up to 500 selected cases. It never creates gold labels. Counts refer only to the
supplied file, not unseen production data. System reports show planned fractions
and per-class representation; missing population counts stay unknown. Sample
fraction alone is not statistical confidence or coverage of every behavior.
`release attach` also preserves plan population metadata and rejects conflicts.

## Functional, Operational and Integration Checks

A native check can assert:

```json
{
  "id": "queue-health",
  "type": "http",
  "layer": "reliability",
  "component_ids": ["queue-component"],
  "enabled": true,
  "reviewed": true,
  "method": "GET",
  "path": "/health/queue",
  "role": "anonymous",
  "expected_status": [200],
  "json_assertions": [
    {"path": "ready", "equals": true},
    {"path": "dead_letter_count", "operator": "lte", "value": 0}
  ]
}
```

Dotted paths support arrays (`items.0.tenant_id`). Equality is type-aware;
numeric budgets accept `gte`, `lte`, `gt`, `lt`. Native response bodies are not
retained; the report records response hashes, assertion outcomes, status and
non-text observed/expected values. Use protected local application logs for
raw diagnostic content. Requests/responses are bounded to 1 MB.

For dependencies, list `depends_on` component IDs and bind a meaningful
`integration` check to both sides. A status-only check cannot complete dependency
coverage. The operator must review that the assertion really exercises the
dependency: mapping two IDs alone does not independently establish causality.

## Code, Security and Tenant Checks

Use the JUnit template with an argv array, working directory and result path:

```json
{
  "command": ["python", "-m", "pytest", "tests", "--junitxml=pred-tests.xml"],
  "cwd": "../my-app",
  "result_file": "../my-app/pred-tests.xml",
  "format": "junit"
}
```

The command is not run through a shell. A zero exit code without fresh test-case
results is insufficient. Failed tests fail the check; skipped tests leave it
blocked. XML is bounded and entity declarations rejected. The framework's
assertions still need review; PRE-D cannot guarantee their independence or depth.
On Windows, system commands use a gated Job Object to contain ordinary child
processes before the command starts; this avoids relying on `taskkill` access.
Failure to establish containment blocks execution. Commands must not be used
to launch persistent background services. This lifetime control does not
restrict their network/filesystem access or make untrusted programs safe.

`system roles --plan ... --role admin --role analyst --role read_only` drafts
explicit API x role slots. Expected allow/deny statuses start empty. Do not
infer a hierarchy from role names. The tenant template uses tenant B's identity
against a known tenant A fixture; add owning-tenant positive controls and
relevant list/get/write paths. Merely receiving a 403 on an arbitrary URL is not
proof of tenant isolation.

For prompt injection, attach a reviewed local security evaluation plan with
attack cases, independent expected outcomes and observations from the real
agent path, or a JUnit-producing adversarial harness. No arbitrary external
target attack or comprehensive exploit crawler is generated automatically.

## Load and Recovery

Load checks send 1..100 read-only requests with 1..8 concurrency, record actual
observations/P95/failure rate and evaluate a reviewed `max_p95_ms` budget. A
transport failure is not automatically labelled an application-capacity defect.
Reports separate contract failures from blocked transport observations. The
failure rate is the fraction of all unsuccessful requests (failed or blocked).
Incomplete transport evidence cannot pass the load check or feed a complete
latency baseline; observed contract failures still remain failures.

Recovery checks require a healthy starting probe, explicit injection and cleanup
argv, and distinct `disruption_expected_status` values (for example 503 versus
healthy 200). Cleanup always runs after attempted injection. If disruption was
not observed, the result is blocked rather than a fake recovery pass. Cleanup
failure stops subsequent checks and monitor cycles; inspect/restore manually.
The built-in probe is HTTP status/content, so process-kill scenarios need an
external health supervisor that can report the disrupted state, or an external
JUnit harness. A connection refusal alone is intentionally not proof of injection.

```text
esx-eval system approve --plan ./system-plan.json --isolated-writes --allow-disruption
```

An `isolation_note` is required. These flags record consent, not environmental
isolation. Do not point injection commands at live production workloads.

## Local Regression History

Example rules file:

```json
{"rules": [
  {"check_id":"decisions","signal":"classification.accuracy","direction":"decrease","delta":0.05},
  {"check_id":"decisions","signal":"observed_abstention_rate","direction":"increase","delta":0.15},
  {"check_id":"queue-load","signal":"p95_latency_ms","direction":"increase","delta":200}
]}
```

```text
esx-eval system monitor --plan ./system-plan.json --out ./runs --history ./pred-history.sqlite --rules ./trend-rules.json --cycles 7 --interval-seconds 86400
esx-eval system trend --history ./pred-history.sqlite --project my-app --rules ./trend-rules.json
esx-eval system prune --history ./pred-history.sqlite --project my-app --keep 30
```

Monitoring is an opt-in foreground process, 1..100 cycles, intervals 60..86400
seconds. It must remain running; no system service or OS job is installed. You
may instead invoke `system run` from an existing CI/OS scheduler. Stop with
Ctrl+C. Rules produce local `alerts.json` and exit status, not email/webhooks.

The baseline is the median of compatible prior runs (default last 10, at least
2 prior observations). Check, dataset/protocol, identity references, environment
and metric-version changes are excluded. Application-version-only changes can
be compared. Runtime data/credential/provider changes outside the recorded
contract still require operator interpretation. This is a configurable absolute
change detector, not a statistical significance test or automatic root cause.
Absent/missing evidence cannot become a stable trend.

History stores result snapshots locally and verifies hashes. Hashes detect
accidental changes, not authenticity against a malicious editor. Pruning is
explicit; it removes database rows only, not report directories, and does not
necessarily shrink the SQLite file. Set your own artifact retention policy.

## Reading the Report

Each run creates `system-report.html`, `system-report.json`, hash-linked
`audit.jsonl`, and full local metric reports for executed AI/browser plans.
Open the HTML locally; no server or platform account is needed.

- **Do not ship:** at least one reviewed check failed. Inspect the expected outcome before attributing an application defect.
- **Insufficient evidence:** required checks, roles, dependencies, enabled capabilities or inventory review remain incomplete.
- **Checks passed within reviewed scope:** the reviewed checks completed successfully; not a universal production-readiness certificate.

Executive summary, actionable failed/blocked checks, coverage and expandable
evidence are separated. Coverage-complete means executed, not necessarily
passed. Missing and declared metrics are never promoted to verified by the
system wrapper. Recommendations identify the mapped surface and next inspection,
not an invented root-cause file/line.

Exit codes: 0 for successful reviewed checks (and stable configured trends), 2
for failed/incomplete checks or alert/insufficient history, 1 for invalid
configuration/execution setup, 130 for user interruption.

## Acceptance Before Using a Real Application

The full six-stage checklist and reproducible evidence command are in
[`SYSTEM_ACCEPTANCE.md`](SYSTEM_ACCEPTANCE.md). It includes negative controls,
repaired reruns and an optional real-time three-cycle scheduling test.

Run `python -m unittest discover -s tests -q` from `v3/client-runner`.
The fixtures exercise live loopback HTTP failures, actual subprocess adapters,
semantic judge contracts, JUnit, identities, recovery, history and setup APIs.
Fixture semantic judgments are deterministic test doubles, not validation of
any particular production judge/model.

For a disposable, synthetic end-to-end example, from that same directory run:

```text
python -m examples.system_reference_demo --out ./reference-system-run
```

It starts a temporary loopback app, executes three real runs, deliberately
returns wrong decisions and a disabled capability, and seeds a health regression.
Inspect `reference-system-run/run-3/system-report.html` and `alerts.json`.
The reference app stops afterward; this is not evidence about a customer app.

Latest whole-system validation passed 393 installed-wheel tests and 22 retained
reference acceptance assertions on Windows/Python 3.12.14. The new setup
draft/bind/save flow and report dashboard were inspected in the browser; see
`WHOLE_SYSTEM_TESTING.md` to reproduce the six reference scenarios. These are
synthetic application checks, not evidence of customer application coverage.

Earlier six-stage baseline validation: 360 tests passed against an installed locally
built wheel, including 58 system/baseline/acceptance regressions. The setup save/add
component flow was exercised in the browser without console errors. Standalone
report HTML is covered by content/escaping tests; visual review of the local
file was blocked by the browser's file-URL policy in this environment.
The dedicated six-stage pack also passed 59/59 checks, including the real
three-cycle monitor with two 60-second waits. Its report index preserves
202 hashed artifacts; see `SYSTEM_ACCEPTANCE.md` for the exact scope.

Then review a real application's inventory, implement independent tests for
every required component/layer/role, seed known defects, and verify that they
are detected and later cleared by the same checks. This implementation does
not establish full coverage of an external application that has not been run.
