# PRE-D Local System Evaluation

**Available in PRE-D Local 0.15.1.**

For reusable setup, a read-only source policy, bounded local planning assistance
and traceable baseline comparisons, start with [local onboarding](LOCAL_ONBOARDING.md).
Protected profiles block unrestricted external commands; the command layers
below retain their earlier explicit isolation requirements. Exact reviewed local
commands can be allowed with `trusted_command_policy` entries keyed by check ID,
field and argv hash; command changes block approval again.

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

## Module Evaluation Map

Every system report now includes a results-based module evaluation map. It
classifies discovered and configured work into eight product-facing areas:

| Area | What PRE-D can report | Minimum evidence |
| --- | --- | --- |
| AI decision modules | Accuracy, precision, recall, F1, confidence, abstention and decision evidence | Labelled cases, real predictions, genuine confidence when requested, evidence/abstention expectations |
| RAG / knowledge modules | Groundedness, hallucination, retrieval relevance and evidence coverage | Response text, source chunks, retrieval/evidence IDs and an independent local judge |
| Browser workflow modules | Login, navigation, page reachability, visible signals and browser diagnostics | Reviewed journeys, approved session/persona and stable content assertions |
| API workflow modules | Status, schema/content assertions and expected business outputs | Safe endpoint, reviewed inputs, expected statuses and JSON assertions |
| Security modules | Authorization, tenant isolation, unsafe action blocking and prompt-injection outcomes | Role matrix, isolated tenants/fixtures, adversarial cases and expected outcomes |
| Reliability modules | Retries, stuck states, dead letters, timeout handling and recovery checks | Health counters, bounded load budgets, isolated failure/recovery checks |
| Cost / latency modules | Tokens, runtime, cost, throughput and p95 latency | Per-case usage telemetry or bounded load observations |
| Admin / config modules | Role access, configuration visibility, drift and safe admin workflows | Test roles, read-only fixtures, config assertions and explicit approval for writes |

The map does not turn discovery into proof. Each area is labelled as
`evaluated`, `partial`, `failed`, `blocked`, `configured_not_run`,
`planned_only`, or `not_applicable`, with verified, declared, blocked or missing
evidence strength. The report also shows which metric groups were verified and
what action is needed next.

Metric groups are area-scoped. A decision check that measures classification
does not make cost/latency, RAG, security, or admin/config metrics appear
verified unless those dimensions were actually measured for that area.

Browser workflow failures distinguish assertion mismatch from incomplete suite
execution. If a reviewed workflow pack has 14 planned journeys but only one
journey executes, the system report marks the check as
`workflow_suite_incomplete`, preserves planned/executed/blocked/not-run counts,
and lists the blocked or not-run case rows so the evaluator can repair the
session, persona, route binding, or case selection.

## Coverage Readiness And Evidence Gaps

Use the readiness commands before a costly or time-sensitive full run. They do
not call the target application and they do not edit application code.

```text
esx-eval system validate-workflows --plan ./system-plan.json --out ./workflow-readiness.json
esx-eval system draft-packs --plan ./system-plan.json --out ./coverage-drafts.json
esx-eval system evidence-gaps --plan ./system-plan.json --out ./evidence-gaps.json
```

`validate-workflows` catches browser workflow authoring problems before
Playwright starts: missing approved sessions, missing persona profiles, weak
path/title/element-only assertions and workflow cases that are not bound to a
reviewed behavior objective.

`draft-packs` creates review-only templates for broader coverage: browser
workflow cases for pages, API assertion checks for endpoints, decision/RAG
dataset requirements for AI candidates, role/authorization review prompts and
bounded reliability templates. Drafts contain explicit `REVIEW_*` placeholders,
are disabled by design and never count as evidence until a tester reviews,
binds, approves and executes them.

`evidence-gaps` writes both JSON and HTML. It lists missing module layers,
missing baseline metric dimensions, weak workflow assertions, enabled checks
that did not execute and blocked checks. This is the practical repair list for
the next run; it is not a release verdict by itself.

The setup page and every evidence-gap report also include a **Full-platform
setup checklist**. It converts missing coverage into ordered work:

- confirm inventory and behavior scope
- optionally export/import strict agent-authored drafts
- repair browser sessions, personas and weak assertions
- bind missing module evidence by pack type
- approve, preflight and run only after review

For each missing component, the checklist names the missing layers and metric
dimensions, the suggested pack type, and the concrete evidence the tester must
provide. This is the default repair path when a report says a module was
discovered but not evaluated.

System reports also embed the same evidence-gap panel after execution, so a
failed or incomplete run explains what to fix next instead of only showing a
headline coverage number.

Reports are summary-first. The default HTML view starts with the verdict,
coverage counts, proof-backed finding count and harness recommendation count.
Large evidence tables, raw per-check payloads and setup repair maps are
collapsed by default. The JSON still retains full details for audit review.

Finding counts are classed before they are shown. Executed evidence appears as
`observed_defect` or `blocked_evidence`. Missing or weak harness work appears as
`coverage_gap` or `setup_gap`. Coverage gaps carry `coverage_priority`; they do
not use defect severity and must not be read as application failures.

Every system and evidence-gap report includes **Harness engineering
recommendations** derived from the traceable findings. These are not additional
application defects; they are workstreams that explain which harness to build or
repair next, with priority, implementation guidance, acceptance criteria, owner
inputs and linked finding IDs.

## Agent-Assisted Authoring Without App Changes

PRE-D can reduce manual setup by handing a coding agent a bounded authoring
task, then validating what comes back. The agent can read and reason about
metadata, source files and review gaps, but it cannot decide coverage, approve
checks, score metrics or modify the application.

```text
esx-eval system agent-tasks --plan ./system-plan.json --out ./agent-tasks.json
esx-eval system import-agent-pack --plan ./system-plan.json --pack ./agent-pack.json
```

`agent-tasks` exports a JSON task pack with component metadata, source evidence
paths, existing checks, coverage readiness, evidence gaps, draft templates and
a strict non-invasive contract. It includes paths and route metadata, not source
file contents, and it makes no target calls.

The coding agent returns a `pre-d-agent-pack-1.0` file containing proposed
behavior objectives, system checks or evaluation-config bindings. Every
proposal must carry at least one source anchor:

- `component`: an existing PRE-D component ID.
- `openapi_path`: a method/path that matches discovered API inventory.
- `source_file`: a relative file path that PRE-D can verify against source
  evidence or the protected source roots.

`import-agent-pack` rejects stale plan hashes, missing anchors, target-call
claims, application-code modification claims, enabled checks, reviewed checks,
unknown components, hallucinated OpenAPI paths and unverifiable source files.
Accepted proposals are written only into the PRE-D plan as disabled,
unreviewed drafts with `agent_provenance`; approval is invalidated and the
inventory must be reviewed again.

This design keeps responsibilities separated:

- Claude/Codex helps draft what should be evaluated and why.
- PRE-D validates anchors, runs checks, calculates metrics and writes reports.
- The human reviewer approves scope, expectations, identities, thresholds and
  any executable action.

## Source Protection Scan Limits

Protected profiles hash bounded source files and intentionally skip generated
or cache directories such as `.git`, `node_modules`, `.venv`, `dist`, `build`
and `.terraform`. Large repositories can tune the scan without editing JSON:

```text
esx-eval system bootstrap --project my-app --version candidate \
  --repo ../my-app --source-max-bytes 700000000 \
  --source-exclude-dir backups --out ./system-plan.json

esx-eval system refresh --plan ./system-plan.json \
  --source-exclude-dir generated-cache
```

`system refresh` preserves reviewed scan limits by default. Override only the
limits you want to change; the stored source snapshot is regenerated with the
same effective limits.

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

Protected profiles do not make subprocesses read-only. They make the trade-off
explicit and observable: source fingerprints are checked before/after execution,
PRE-D artifacts must stay outside the protected repository, and command checks
or command-based adapters require exact reviewed `trusted_command_policy`
entries. A changed argv, missing reason or result file inside the protected
repository blocks preflight.

Example trusted command entry:

```json
{
  "trusted_command_policy": {
    "schema_version": "pre-d-trusted-local-commands-1.0",
    "reviewed": true,
    "entries": [
      {
        "check_id": "backend-pytest",
        "field": "command",
        "argv_sha256": "sha256 from esx_eval_runner.system_safety.command_sha256(command)",
        "reason": "Approved local test runner in isolated evaluator workspace."
      }
    ]
  }
}
```

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
