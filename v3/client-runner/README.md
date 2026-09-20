# ExposureScopeX Local AI Evaluation Runner

**PRE-D Local 0.15.2: source-first full-platform onboarding, coverage advisories, reviewed module scope, historical context, and local AI evaluation.**

`esx-eval` is a **local-first pre-release evaluator** for a model, RAG
application, agent, or multi-agent system. It runs next to the AI system being
tested and prints results in the local terminal. A normal `run` command does
not connect to ExposureScopeX and does not upload prompts, model outputs, source
code, traces, environment variables, stderr, credentials, or results.

## Start here

| What you want to do | Start with |
| --- | --- |
| Install or upgrade the standalone runner | [Local-only quick start](#local-only-quick-start) |
| Reuse setup, protect application source, review local agent suggestions and trace changes | [Reusable local onboarding](LOCAL_ONBOARDING.md) |
| Try system inventory/execution, code/security/reliability checks and scheduled regression context | [System evaluation guide](SYSTEM_EVALUATION.md) |
| Verify the six local stages with seeded defects and retained evidence | [System acceptance matrix](SYSTEM_ACCEPTANCE.md) |
| Require behavior coverage, reconcile inventory and verify the running candidate | [Whole-system testing contract](WHOLE_SYSTEM_TESTING.md) |
| Score application decisions, labels, and confidence | [Decision evaluation](DECISION_EVALUATION.md) |
| Distinguish native probability calibration from adapter-mapped scores | [Confidence provenance](CONFIDENCE_PROVENANCE.md) |
| Test approved login and multi-step browser workflows | [Browser workflow guide](BROWSER_WORKFLOWS.md) |
| Set up reviewed multi-module coverage without editing the release manifest | [Guided application setup](APPLICATION_SETUP.md) |
| Review required modules and decide what blocks a release | [Application release review](RELEASE_REVIEW.md) |
| Compare two versions without hiding coverage changes | [Baseline comparison](RELEASE_REVIEW.md#compare-a-candidate-against-a-baseline) |
| Connect groundedness, hallucination, or other metric evidence | [Evidence guide](PRE-D_EVIDENCE_GUIDE.md) |
| See what changed and what remains unsupported | [0.15.2 release notes](RELEASE_NOTES.md) |

Python 3.11+ is required. Browser testing additionally needs Playwright and its
Chromium runtime; semantic evaluation needs the configured independent local
judge. Installing packages may require network access. Local evaluation is not
automatically offline: the application or its configured providers can still
make external requests.

## System Evaluation

PRE-D Local 0.15.2 provides profile bootstrap/refresh, bounded planning
assistance, suggestion review and baseline comparisons. Protected profiles keep
PRE-D artifacts outside application source and stop when observed source
changes invalidate a run. Optional local models draft behavior objectives
under a bounded tool interface. See [setup, limits and reuse](LOCAL_ONBOARDING.md).
Exact reviewed local commands can be allowed by argv hash through
`trusted_command_policy`, so existing test runners and local adapters remain
traceable without becoming unrestricted execution.

The release includes the `esx-eval system` workflow: bounded
repository/OpenAPI discovery, guided review, native HTTP/role/tenant checks,
existing AI/browser plan execution, JUnit test commands, bounded load/recovery,
stratified labelled sampling, and opt-in local history with rolling alerts.
See [the complete guide](SYSTEM_EVALUATION.md).

The `decision_evidence` adapter crash is fixed. Classification no longer
requires confidence, and semantic/evidence-only runs do not require unrelated
classification labels. Existing formulas and provenance distinctions remain.
The guided decision setup permits an empty confidence mapping rather than
inventing values. Tests and external application acceptance remain separate:
implemented evaluation layers are not proof that every app module was tested.

The release-path fixes also allow explicit decision gates without
mandatory classification or confidence. Guided setup and new attached plans
select baseline gates only for requested dimensions. Existing explicit policies
are never silently weakened. Confidence now records native, adapter-mapped or
unknown provenance: arithmetic on mapped/unknown values remains visible, but it
cannot satisfy native calibration gates. See [migration and examples](CONFIDENCE_PROVENANCE.md).

Whole-system mode adds explicit behavior/case bindings, inventory reconciliation,
role obligations and before/after running-candidate checks. Missing or excluded
behavior evidence cannot be hidden behind a suite-level pass. Start with
`system scope --init`, review in setup and run preflight with
`--require-whole-system`. See [the testing guide](WHOLE_SYSTEM_TESTING.md) for
the ten-module reference acceptance and real-application prerequisites.

## What is new in 0.15.2

- Source-first full-platform onboarding can build a broad evaluation package from
  a repository snapshot even when a live OpenAPI export is not available yet.
- The VINI demo pack now ships as a sanitized example under
  `examples/vini_demo/`, including a source-readiness HTML/JSON artifact that
  separates discovery from live evaluation and keeps unbound checks visible.
- Protected profiles can run exact reviewed local command adapters/checks using
  `trusted_command_policy` argv hashes while continuing to block unreviewed
  commands.

## What changed in 0.15.1

- Application setup previews review scope and the generated manifest, including
  optional manual inspection notes. Notes cannot substitute for executed tests.
- Every attached suite must complete with usable evidence for its module to be
  marked evaluated. Partial execution remains blocked, even if another suite passed.
- Release reports now show which suite dimensions were gated, merely measured,
  or left unrequested, so a missing baseline-tier signal is visible instead of
  hiding behind a simpler scorecard.
- Decision suites can optionally declare the larger labelled population they
  sampled from, letting reports show pack-versus-population context without
  pretending it is a statistical guarantee.
- `release check` and `release run` now accept repeated `--history` artifacts
  for conservative multi-run trend context across more than one prior release.
- Setup, preflight, and reports flag weaker route/title/element-state browser
  checks and missing final assertions. Their planned strength stays distinct
  from the actual execution outcome, including when reports are reused.
- Invalid population counts cannot produce coverage over 100%. History handles
  timezone offsets and deduplicates regenerated reports of the same source run.

See [Application setup](APPLICATION_SETUP.md) for the guided path, and
[release notes](RELEASE_NOTES.md) for validation and limits.

### Retained capabilities

The `release` commands build on the existing metric engines, rather than
replacing them. They combine existing plans into a scoped application review:

- Guided application setup and `release scope`, `bind`, `attach`, `preflight`,
  and `run` for reviewed objectives, personas, approvals, and all-module execution.
- Explicit required workflow/decision coverage, module owners, exclusions, and
  dependency readiness. A passing decision pack cannot cover a missing workflow.
- Four recommendations: **Ship**, **Ship with conditions**, **Do not ship**, and
  **Insufficient evidence**. A critical failure is not averaged into a green score.
- Verified, declared, missing, stale, duplicate, and incomplete evidence stay
  distinguishable; declared perfect scores cannot pass verified release gates.
- Baseline comparisons for classification, calibration, workflow outcomes, and
  decision-evidence alignment, with changed cases and scope/policy differences.
- Local HTML/JSON reports, links to detailed evaluations, and hash-linked audit
  records. No new service, background process, Docker build, or database.

The single-run report now calls its readiness section **This run's evidence
readiness**, to avoid confusing one evaluation with an application release review.

## Choose the right evaluation

| Evaluation | What it can establish | What the tester provides |
| --- | --- | --- |
| Decision/API/adapter | Accuracy, precision, recall, F1, Brier score, calibration, and configured evidence-reference checks | Representative labelled cases, the real decision endpoint/adapter, returned labels and genuine confidence values |
| Browser workflow | Approved login, navigation, executed workflows, and visible expected signals | A test identity/session and reviewed journeys with stable assertions |
| Semantic groundedness/hallucination | Claim-level judgments against supplied sources, plus supported abstention checks | Actual response text, exact source material, an independent local judge, and abstention expectations where applicable; no separate gold claim file is required for the semantic path |
| Telemetry-backed metrics | Supported retrieval, tools, trajectory, security, robustness, agreement, repeatability, or usage measures | The dimension-specific observations and expectations described in the evidence guide |
| Application release review | Whether the declared modules and suites satisfy an explicit release policy | Module inventory, owners, existing plans/reports, exclusions, dependencies, and thresholds |

Browser outcomes are not model-quality labels or confidence estimates.
Evidence-ID overlap is not proof that a claim is true. Model-judge verdicts
remain fallible even when obtained independently. Missing observations are
reported as missing, not replaced with fabricated scores.

Before a real semantic test, follow the [groundedness and hallucination acceptance
checklist](PRE-D_EVIDENCE_GUIDE.md#before-your-first-semantic-acceptance-test).
Automated fixtures validate runner behavior, not the accuracy of your chosen judge.

## Application release quick start

**Available since 0.13.0, with coverage guidance expanded in 0.15.1.**
Run `esx-eval setup --application` for the local multi-module setup page. Reuse
real browser/decision plans, review scenario and persona objectives, and bind
them to actual case IDs without hand-editing a release manifest. See the
[guided application setup](APPLICATION_SETUP.md). No target is called by this
setup; unbound objectives remain visible and block all-module execution. The
page also previews the resulting review-scope matrix and generated manifest, so
manual inspection notes stay distinct from executable PRE-D evidence before any
files are written.

Use `release scope` and `release bind` for the same objective authoring from the
CLI. Release browser plans now require explicit assertions, not navigation alone.
Raw observed decision errors remain visible even when a single-class pack cannot
provide a broad classification estimate; custom gate thresholds are disclosed.

Use `release attach` to
bind approved plans without hand-editing the manifest, `release preflight` to
check the entire inventory without target calls, and `release run` to execute
all declared modules. Missing plans, exclusions, report reuse, and unapproved
execution block this mode before any suite starts. Upgrade to 0.15.1 to use
these commands. See the
[all-module guide](RELEASE_REVIEW.md#execute-the-entire-declared-inventory).

Release reports now separate review scope from verdicts. Each module is marked
`evaluated`, `inspected`, `blocked`, or `untouched` so teams can tell the
difference between executable PRE-D evidence and manual review notes.
`evaluated` requires complete, usable evidence from every attached suite for
the declared test kinds. A partial run remains `blocked`. An external review
recorded as evaluated remains reviewer-declared and contributes to `inspected`.

Release reports also separate three additional review layers:

- **Metric dimension coverage** shows which suite dimensions were gated,
  measured-only, or left unrequested.
- **Population coverage** shows executed-pack versus declared labelled-population
  context for decision suites when that metadata is supplied.
- **Historical trend context** compares the current run against one or more
  supplied prior release reports using the same matched-pack conservatism as
  the baseline comparison logic.

Setup, preflight, and release reports also show non-blocking **coverage
advisories** for omitted baseline decision evidence, missing population context,
and weak browser checks. Workflow signal strength describes planned assertions
after the last navigation or interaction. A route, title, or hidden-element check
does not prove visible page content. Failed and blocked cases keep their actual
execution outcomes. New reports preserve this content-free summary when reused;
older reports explicitly show unknown assertion strength.

Blocked suites remain in the dimension inventory as unmeasured. Inconsistent
population counts suppress coverage percentages and explain what to correct.
History orders timezone-aware timestamps chronologically and counts each source
execution once per signal, even if its report was regenerated.

Each module still needs real workflows or decision cases and expected behavior;
this is not automatic full-application test generation. The partial/report-only
workflow below remains available and is labelled separately in new reports.

First create and validate ordinary local evaluation plans. Each suite's
`evaluation.project_key`, `agent_id`, and `subject_version` must match the
application and subject declared in the release manifest.

```text
esx-eval release init --application-id my-app --subject-version candidate-1 --module decisions --module dashboard --out release.json
```

The new manifest starts with an unconfirmed inventory and empty modules. Review
it, add owners and explicit `required_kinds`, attach each suite's `config` or
completed `report`, and set `inventory_complete` only after confirming scope.
[The full guide](RELEASE_REVIEW.md#attach-the-existing-plans) includes a complete
manifest example and explains all supported fields.

```text
esx-eval release check --manifest release.json --run --out out/release-review.json
esx-eval view --report out/release-review.html
```

`--run` explicitly executes config-backed suites, sequentially. Without it,
PRE-D only assesses supplied reports; it never silently calls the application.
Failed suites are retained as gaps, and no failed workflow is automatically
retried by the release orchestrator.

Preserve a previous release-review JSON to compare versions:

```text
esx-eval release check --manifest candidate-release.json --baseline out/previous-release.json --run --out out/candidate-release.json --require-ship
```

Supply more than one prior report when you want conservative multi-run trend
context across a short release history:

```text
esx-eval release run --manifest candidate-release.json --history out/release-2.json --history out/release-3.json --out out/release-4.json
```

The baseline is never rerun or overwritten. Matching suite IDs, subjects,
dataset-content fingerprints, scoring protocols, evidence, and metric policies
are required for like-for-like deltas. Changed inputs are **Not comparable**,
not an apparent improvement. Newly failing cases remain visible even when
aggregate accuracy is unchanged.

Exit codes: `0` for a written review, `1` for command/manifest errors, and `2`
when `--require-ship` is set and the recommendation is anything other than Ship.
Without `--require-ship`, exit `0` does not mean the application passed.

**Default thresholds are starting policies, not universal safety standards.**
Decision suites default to 20 cases, accuracy >= 0.95, macro F1 >= 0.90, and
ECE <= 0.15. Workflow suites require execution and signal-match rates of 1.0.
Choose appropriate cases and thresholds for the application before interpreting
the recommendation.

## Testing boundary and upgrade notes

Use an isolated test instance or tenant for workflows that write data. Running
locally does not stop a configured app from sending notifications, changing
permissions, or calling external write APIs. PRE-D does not provide automatic
rollback or make a production action harmless. Test identities and data should
be scoped accordingly; use real isolated writes when validating side effects.

Existing evaluation plans remain supported. The release commands are opt-in;
upgrading the runner does not run an application, change its code, or modify
existing reports. Install the new wheel into the same Python environment used
for evaluation, then verify the imported version:

```text
python -c "from esx_eval_runner import __version__; print(__version__)"
esx-eval release check --help
```

Use `py` on Windows or `python3` on macOS/Linux if that is the interpreter for
your evaluation environment. The version should be `0.15.2`. If the import
shows the new version but `esx-eval setup --help` has no `--application` option, the executable on
PATH belongs to another environment; use the matching environment's executable.

Old reports can be regenerated for ordinary review, but regeneration does not
create missing original dataset fingerprints or fresh executions. For a
comparable baseline, rerun the baseline pack with fingerprint support. Changing
the PRE-D version also changes the protocol fingerprint; rerun both application
versions under the same evaluator version when making that comparison.

**Current limits:** advanced semantic/telemetry metrics can still be used in
current-release gates, but their history/regression comparisons are not yet
supported. History artifacts are supplied manually; PRE-D Local does not yet
schedule recurring evaluation jobs by itself. Declared inventory is not
automatic discovery of every business journey. The release layer does not add
integrated code-test execution, chaos/load tests, comprehensive adversarial
security testing, arbitrary permissions probes, automatic root-cause localization, or
production-wide correctness guarantees. Local test fixtures validate runner
behavior, not independent real-application acceptance.

## Detailed metric and workflow guides

For a plain-language explanation of the evidence each local metric needs, see
[`PRE-D_EVIDENCE_GUIDE.md`](PRE-D_EVIDENCE_GUIDE.md). It separates the
organization's expected behavior from the redacted observations the application
emits and explains why a metric may be `NOT MEASURABLE`.

For labelled local AI and business decisions, start with
[`DECISION_EVALUATION.md`](DECISION_EVALUATION.md). It shows the direct local
endpoint and dataset contract used for accuracy, precision, recall, F1,
confidence, evidence-reference, and abstention checks. A ready-to-import
synthetic starter dataset is available at
[`examples/decision-evaluation.sample.json`](examples/decision-evaluation.sample.json).

For planning coverage across a larger application, see the
[application module coverage example](examples/application-module-coverage.md).
It maps a tester-supplied 15-module inventory to browser and decision
evaluation paths, persona requirements, exclusions, and current reporting
gaps. The plan is not a completed run or a built-in product-specific
integration.

To run existing evaluation plans across multiple modules and produce one local
release recommendation, see [Application release review](RELEASE_REVIEW.md).
The new `esx-eval release` commands combine module coverage, explicit thresholds,
evidence provenance, and actionable findings in a standalone HTML/JSON report.
They require no platform connection or additional infrastructure.
Declare required workflow/decision coverage and module dependencies, then use
`release check --baseline previous-release.json` to see matched-pack metric and
case regressions. Changed datasets, protocols, or thresholds are not presented
as like-for-like improvements. Advanced semantic/telemetry metrics remain
available for current-release checks; their regression comparisons are not yet
supported.

Use the optional shared workflow only when a team wants ExposureScopeX to retain
a governed release decision and formal report.

## Recommended experience: evaluate local decisions

For a normal AI application, use the local setup page rather than writing an
adapter. **Decision evaluation** is the default: it imports labelled local
cases and calls one local endpoint that invokes the real product decision path.
That path can orchestrate any number of internal agents, tools, retrievers, and
models; PRE-D does not require a separate call for every internal agent.

```text
esx-eval setup --directory ./my-application-evaluation
```

The page opens only on `127.0.0.1`. It can scan a local repository for
framework, API-route, tool, retrieval, and observability hints without
exporting source content. The customer explicitly selects what is in scope,
then chooses a local decision API, generic JSON API, or loopback browser
journey. Decision setup imports a labelled dataset and maps response fields
without requiring users to type JSON paths. Generic API profiles remain
available for baseline checks, and browser journeys remain available for
protected UI coverage.

Discovery does not treat architecture documents, backlog items, comments, or
plain text as implemented technology. Each finding identifies whether it came
from an installed local package, a declared dependency, or a source import.
Those are static evidence levels, not proof that a capability executes at
runtime; the customer still confirms the evaluation scope.

The generated folder contains `esx-eval.json`, `discovery.json`,
`assurance-scope.json`, `risk-plan.json`, `PRE-D_EVIDENCE_REQUIREMENTS.md`,
and a local `README.md`. Read the generated evidence-requirements file before
running: it lists, for every score in that specific plan, what the team must
define, what the application must emit locally, and the minimum evidence needed
for a real result. A normal `run` automatically includes the confirmed scope
and plan in the Assurance Graph. Planned advanced checks are clearly shown as
`NOT MEASURABLE` until compatible redacted local evidence is available; the
runner never invents a score.

Before the first run, validate the actual local evidence source. This command
does not call the application or make a network request. It names the exact
missing field, control type, or case ID for every requested metric and writes
an optional local readiness report.

```text
esx-eval evidence-check --config ./esx-eval.json --out ./out/evidence-readiness.json
```

For a command-v2 adapter that reads advanced measurements from a local file,
include `--measurements ./full_metric_measurements.json`. For telemetry-backed
metrics, include `--telemetry ./out/telemetry.jsonl`. `READY TO COLLECT` means
the dataset and connection are valid but a real decision run still must return
observations. `EVIDENCE READY` means the supplied advanced local artifact meets
the schema and formula prerequisites; it still remains local and is scored only
after the decision run completes.

For the normal zero-adapter decision path, enter a loopback decision API URL,
import labelled cases, and select **Test local connection**. The setup page
sends one fixed harmless request, shows a value-redacted response structure,
and suggests label, confidence, evidence-ID, and abstention fields for the
customer to confirm. The decision endpoint receives
`{"case_id": "...", "input": {...}}` and returns a text label plus a numeric
confidence between `0` and `1`. See `DECISION_EVALUATION.md` for the complete
local contract.

The automatic connection check accepts loopback URLs only. A non-local staging
target remains an advanced, managed configuration: it requires HTTPS, mTLS,
and a signed test-tenant attestation before any evaluation request is sent.

Run the generated plan and open its self-contained local report:

```text
cd ./my-application-evaluation
esx-eval evidence-check --config ./esx-eval.json --out ./out/evidence-readiness.json
esx-eval run --config ./esx-eval.json --out ./out/evaluation.json
esx-eval view --report ./out/evaluation.local-report.html
```

The terminal report and HTML report never upload automatically. The HTML report
contains only derived, redacted evaluation data, not case prompts or raw model
responses.

## Advanced assurance workflow

Use these optional commands when a team prefers the individual local workflow
steps. Discovery never executes application code or calls an AI model. Most
users should use `esx-eval setup` instead.

```powershell
# Discover local technology and workflow hints. Source stays on this computer.
esx-eval discover --repository C:\work\my-ai-app --out .\discovery.json

# Review discovery.json and explicitly approve the relevant component IDs.
esx-eval scope --discovery .\discovery.json --include workflow-http-route-definitions-main-py agent-framework-langgraph --out .\assurance-scope.json

# Create a deterministic risk plan with an explanation for each selected area.
esx-eval plan --scope .\assurance-scope.json --out .\risk-plan.json

# Include confirmed scope and plan in the local Assurance Graph report.
esx-eval run --config .\esx-eval.json --out .\out\evaluation.json --discovery .\discovery.json --scope .\assurance-scope.json --plan .\risk-plan.json
```

The HTML report contains an **Assurance Graph** linking confirmed components,
local evidence, required metrics, and the reason no local result is a governed
release decision. Every metric card has a provenance state: `Verified` for
labelled comparisons or independently observed local events, `Declared` for
schema-valid evidence supplied by the target but not independently checked by
PRE-D, and `Missing` when the evidence is insufficient. Each card states its
score, why it received that state, its evidence source, and the next action.
All-zero cost, token, and latency evidence is retained but marked
`NON-REPRESENTATIVE`.

Groundedness and hallucination share a local semantic pipeline: extract claims,
review extraction completeness in a separate model pass, then compare claims
with the supplied sources. The report distinguishes model-reviewed extraction
from proven coverage. Custom judges must support `review_claims`; see
[the judge protocol](ADAPTER_V2.md#local-grounding-judge-protocol).

Keep the generated `.semantic-results.json` file alongside the result package
when regenerating reports. It preserves content-free semantic results without
rerunning the judge. Failed cases retain completed evidence but prevent a
complete-run semantic score. See [the evidence guide](PRE-D_EVIDENCE_GUIDE.md).

Groundedness uses a local semantic contract rather than trusting support values
declared by the target. Add `groundedness` to `evaluation.required_dimensions`.
The application can return `grounding_material` automatically from adapter v2,
an HTTP endpoint can map response and retrieval fields, or the user can pass
`--grounding-material ./grounding-material.json`. PRE-D sends that local content
only to the configured independent local judge and retains only hashes,
verdicts, confidence, and evidence IDs in the package and report.

```json
{
  "schema_version": "pre-d-grounding-material-1.0",
  "cases": [
    {
      "case_id": "case-001",
      "response": "The generated answer text remains local.",
      "evidence": [
        {"evidence_id": "doc-001", "text": "The retrieved source chunk remains local."}
      ]
    }
  ]
}
```

Configure the local judge under `assurance.grounding_judge` with a command,
identity, version, and `independent_from_target: true`. PRE-D invokes it twice:
first for atomic claim extraction, then for evidence comparison. Every claim
must receive exactly one `supported`, `contradicted`, or `insufficient` verdict.
Incomplete extraction or comparison produces no score. Opaque claim metadata
and `ground-truth.json` controls remain useful for evidence alignment and
abstention, but cannot establish semantic groundedness.

```json
{
  "assurance": {
    "grounding_material_file": "grounding-material.json",
    "grounding_judge": {
      "type": "command_json_v1",
      "command": ["python", "local-grounding-judge.py"],
      "identity": "approved-local-grounding-judge",
      "version": "1.0.0",
      "independent_from_target": true
    }
  }
}
```

The judge command must differ from the target adapter command. It receives JSON
on standard input and returns JSON on standard output. See `ADAPTER_V2.md` for
the extraction and comparison protocol. Run `esx-eval evidence-check` before
the evaluation to validate the material and judge configuration without
invoking either the target or judge.

PRE-D includes an optional loopback-only Ollama bridge. After installing an
appropriate local model, the judge command can be:

```json
["python", "-m", "esx_eval_runner.ollama_grounding_judge", "--model", "YOUR_INSTALLED_MODEL"]
```

The bridge refuses non-loopback URLs, uses deterministic generation settings,
and asks the model for strict structured output. The report records its
configured identity and version; teams should validate their selected model
against reviewed grounding fixtures before using it as a release signal.

The trust summary is strictly additive: every required metric belongs to
exactly one of `Verified`, `Declared`, or `Missing`. `NON-REPRESENTATIVE` is a
warning flag on that metric, never a fourth bucket. The Assurance Graph and
coverage JSON preserve these same three states instead of flattening them into
generic `measured` results.

For decision evaluations, the report also shows dataset health, class
distribution, case-level outcomes, confusion matrix, per-class precision,
recall and F1, Brier score, calibration bins, and overconfident failures. An
ECE above `0.15` raises a calibration warning; fewer than five unique confidence
values raises a confidence-range warning. These warnings do not alter the
formula result, but prevent a structurally valid score from looking stronger
than its evidence.

Decision-evaluation coverage is reported as `executed`, `correct`,
`incorrect`, and `blocked`. Browser coverage uses `passed`, `assertion review`,
and `blocked`; the two schemas are intentionally separate. Completed reports
contain final observed metric states only. Run `esx-eval evidence-check`
separately when you want a pre-run evidence-readiness artifact.

### Browser journeys

For an application without an evaluation API, install the optional local browser
dependency and create declarative browser-action cases. Browser journeys are
loopback-only and must use approved test accounts; the runner never tests an
arbitrary remote application.

```powershell
py -m pip install "exposurescopex-eval-runner[browser]"
playwright install chromium
```

Use `adapter.type: "browser_journey"` and a loopback `base_url`. Browser mode
is a deterministic workflow check, not a model-quality score. Its local
scorecard measures declared workflow coverage: which journeys reached their
approved visible signal, which need assertion review, and which stopped at
session setup. It never converts a browser pass/fail result into a model label
or a synthetic confidence value.

For classification and confidence calibration, use the JSON API or local
adapter connection. The dataset needs at least two expected outcome classes,
and the application must return observed confidence values from `0` to `1`.
Constant confidence remains calculable but is visibly flagged because it cannot
show behavior across confidence levels. This prevents an all-pass browser plan
or a constant `1.0` value from appearing as a perfect AI-quality score. A
generated browser plan contains exactly the cases it states; selecting an HTTP
`release` profile does not create twelve hidden browser journeys.

Each `input.journey` can use `goto`, `fill`, `click`, `press`,
`wait_for_url`, `wait_for_text`, `wait_for_selector`, `wait_for_navigation`,
`wait_for_stable`, `assert_path`, `assert_title`, `expect_text`, or
`expect_visible`. Use an explicit wait or assertion after an SPA action rather
than relying on a generic page-load check.

For a protected local app, add an explicit `auth` object and mark only
post-login cases with `"requires_auth": true`. The runner reads a dedicated
test account from environment variables, saves an optional local session-state
file for reuse, and never writes credential values or cookies to a result,
report, audit log, or upload package.

For an identity-provider login, use `session_bootstrap` instead of `auth`, then
run `esx-eval browser-auth --config ./esx-eval.json`. The visible browser lets
the tester complete approved SSO and must return to the loopback application
before ESX saves a session. The saved state contains only local-application
cookies and local storage; identity-provider cookies are discarded.

```json
{
  "adapter": {
    "type": "browser_journey",
    "base_url": "http://127.0.0.1:3000",
    "session_state_path": ".esx/auth-session.json",
    "auth": {
      "login_path": "/login",
      "username_env": "ESX_TEST_USERNAME",
      "password_env": "ESX_TEST_PASSWORD",
      "username_selector": "input[name='email']",
      "password_selector": "input[name='password']",
      "submit_selector": "button[type='submit']",
      "success": {"type": "wait_for_text", "value": "Dashboard"}
    }
  },
  "dataset": {
    "cases": [{
      "case_id": "dashboard-ready-001",
      "requires_auth": true,
      "input": {"journey": [
        {"type": "goto", "path": "/dashboard"},
        {"type": "wait_for_text", "value": "Dashboard"},
        {"type": "assert_path", "path": "/dashboard"}
      ]},
      "expected_label": "pass"
    }]
  }
}
```

The local report distinguishes discovered components, customer-approved scope,
requested cases, executed pre-auth/authenticated cases, and measured dimensions.
An authenticated case blocked before session setup is reported as a **coverage
limitation**, excluded from quality scores, and never labelled as an application
failure. An executed browser assertion that does not match its approved signal
is labelled **assertion review**, not a confirmed product defect. Optional
screenshots remain only beside the local plan.

### Automatic local telemetry

For an application already emitting OpenTelemetry JSON, run a local collector
and point its test-environment OTLP JSON exporter at the printed loopback URL.
Provide the printed value as `X-ESX-Telemetry-Token`.

```powershell
esx-eval telemetry --out .\out\telemetry.jsonl
```

The collector accepts `/v1/traces` only on loopback. It retains only allowlisted
operational metadata: service, span name, selected `gen_ai` usage/tool fields,
and opaque `esx` identifiers. Prompts, outputs, documents, tool arguments,
credentials, and arbitrary attributes are discarded. Pass this file to
`run --telemetry` or `report --telemetry` to show evidence coverage in the
Assurance Graph. When the records contain a complete supported evidence set,
the runner derives its advanced metric inputs locally before it calculates the
report. Incomplete evidence remains `NOT MEASURABLE`; raw span count and browser
success never become an invented score. Locally observed tool, trajectory, and
agreement events can be verified as operational facts. Semantic assertions such
as claim entailment, groundedness, or attack outcomes remain target-declared
until PRE-D independently validates them. See `CONNECTORS.md` for OpenTelemetry,
Python, LangChain, and LangGraph integration paths. Use browser workflows for
protected UI coverage and local telemetry or an adapter for groundedness,
security behavior, agent trajectories, approved tool-use quality, RAG quality,
and provider cost metrics. The report explains the exact redacted evidence
required for every unmeasured dimension.

## Security boundary

The local setup page binds only to `127.0.0.1`. The built-in HTTP connector
accepts loopback targets only by default. A remote target must be explicitly
marked as `staging`, use HTTPS, and present a mutual-TLS client certificate;
plain remote HTTP, URL credentials, query secrets, and redirects are rejected.
Requests are identified with an
`X-ESX-Evaluation-Mode: local-pre-release` header, are limited to 500 cases by
default, and pause briefly between cases.

This is a secure-by-default baseline, not a sandbox. A run can still invoke a
real workflow and its tools. Use a dedicated test tenant, least-privilege test
credentials, safe test data, and an endpoint that rejects production actions.
Do not configure production systems as staging. Command adapters are trusted
local code and run with the invoking user's OS permissions unless they use the
optional container sandbox. A sandboxed adapter uses a digest-pinned image with
no network, no host mounts, a read-only filesystem, dropped Linux capabilities,
a non-root user, and CPU, memory, and process limits. It is intended for
offline adapters; it cannot call a local HTTP application because its network
is intentionally disabled.

Every run also appends redacted lifecycle metadata and hashes to a local audit
chain beside its output. Verify the chain with:

```powershell
esx-eval verify-audit --audit-log .\out\evaluation.audit.jsonl
```

The audit log intentionally contains no prompts, responses, source files, or
secrets. Its hash chain detects accidental or partial modification; it is not
immutable against an attacker who can rewrite the whole local log. Preserve its
tail hash in an approved external audit system for a tamper-evident anchor.

### Approved staging targets

A remote target is intentionally more strict than a loopback development run.
It must use mTLS and expose an HTTPS attestation endpoint on the same host. The
endpoint receives `X-ESX-Evaluation-Nonce` and returns this signed payload:

```json
{
  "schema_version": "esx-test-target-attestation-1.0",
  "nonce": "the request header value",
  "target_environment": "staging",
  "test_tenant_id": "opaque-test-tenant-id",
  "capabilities": [
    "test_tenant",
    "synthetic_data",
    "production_actions_disabled",
    "least_privilege_identity"
  ],
  "signature": {"algorithm": "ed25519", "value": "base64-signature"}
}
```

Sign the object without `signature` using the target's Ed25519 key. Configure
the corresponding public key and mTLS file paths in `esx-eval.json`. The runner
rejects the run before submitting cases if this proof is missing, stale/replayed
through the nonce check, malformed, or invalidly signed.

## Local-only quick start

These steps are all a colleague needs for a real local test. No Docker,
ExposureScopeX account, identity registration, key pair, or platform upload is
required.

Before starting, they need a local test copy of their application, an approved
test identity if the application requires login, and its local API URL. They do
not need an ExposureScopeX account, an adapter file, a GitHub integration, or
production data.

The commands below use Windows PowerShell. On macOS or Linux, use `python3`
instead of `py`, `cd` instead of `Set-Location`, and `./` paths instead of
`.\` paths.

1. Install Python 3.11 or later. On Windows, confirm it is available:

   ```powershell
   py --version
   ```

2. Download the `exposurescopex_eval_runner-<version>-py3-none-any.whl` asset
   and `SHA256SUMS` from the [ExposureScopeX releases page](https://github.com/lucky1410/ExposureScopeX/releases).
   Do not download `Source code (zip)` or install the entire platform.

3. Verify and install the downloaded wheel. Use the published runner version:

   ```powershell
   $version = "0.15.2"
   $wheel = "exposurescopex_eval_runner-$version-py3-none-any.whl"
   $expected = ((Get-Content .\SHA256SUMS | Where-Object { $_ -like "*$wheel" }) -split "\s+")[0].ToLower()
   $actual = (Get-FileHash ".\$wheel" -Algorithm SHA256).Hash.ToLower()
   if ($actual -ne $expected) { throw "Checksum verification failed. Do not install this file." }
   py -m pip install --upgrade ".\$wheel"
   py -c "from esx_eval_runner import __version__; print(__version__)"
   esx-eval --help
   ```

   On macOS or Linux, the equivalent install command is:

   ```bash
   shasum -a 256 -c SHA256SUMS
   python3 -m pip install --upgrade ./exposurescopex_eval_runner-0.15.2-py3-none-any.whl
   python3 -c "from esx_eval_runner import __version__; print(__version__)"
   ```

   Download the accompanying documentation assets too when checking the entire
   `SHA256SUMS` file; it covers the wheel and those guides. A missing guide is a
   missing file, not necessarily a wheel checksum mismatch.

4. Start a local test copy of the AI application. For decision evaluation,
   select an endpoint accepting `POST {"case_id": "...", "input": {...}}` and
   returning JSON with a real text outcome and numeric confidence. Confirm the
   field mappings in setup. Use labelled cases with at least two expected
   classes; do not invent confidence values merely to make a score measurable.
   See [the decision contract](DECISION_EVALUATION.md) for a full example. Do not
   use production credentials, customer data, or a production write endpoint.

   ```powershell
   # Example only: use the actual URL of the application being tested.
   # http://127.0.0.1:8000/evaluate
   ```

5. Start the guided local setup. It opens a page on a random `127.0.0.1` port.

   ```powershell
   esx-eval setup --directory .\my-application-evaluation
   ```

6. In the page, enter the local API URL and click **Test local connection**.
   Confirm the suggested outcome and confidence fields, choose an evaluation
   profile, review the scope, and click **Create local evaluation**. The page
   shows only a value-redacted response structure; it does not retain the API
   response. You do not need to create an adapter or type JSON paths.

7. Run the generated plan and open the local report:

   ```powershell
   Set-Location .\my-application-evaluation
   esx-eval run --config .\esx-eval.json --out .\out\evaluation.json
   esx-eval view --report .\out\evaluation.local-report.html
   ```

   The terminal shows each case and the calculated metrics. The HTML report,
   prompts, results, and source content remain on the local computer unless
   the team later chooses the separate signed-upload workflow.

### Advanced fallback: unsupported application contracts

Use this only when the application cannot expose the normal local JSON
endpoint, or when it needs advanced locally collected telemetry. Create a
one-case adapter starter, then follow the integration examples below:

```powershell
esx-eval init --directory .\my-agent-evaluation --agent-id support-agent --subject-version 2.4.0
Set-Location .\my-agent-evaluation
```

The system under test is the colleague's own product, not an agent supplied by
ExposureScopeX. It can be a Python function, local command, local model
wrapper, HTTP API, or the complete backend workflow of a multi-agent web app.
The adapter invokes that one entry point for every labelled case. Internal
planners, retrievers, tools, and handoffs remain inside the application.

A browser page or URL alone is not enough for the current runner to test. The
application needs either an existing local backend endpoint or a small
test-only local function/endpoint that invokes its ordinary workflow. Do not
expose that endpoint publicly and do not add production credentials to the
adapter.

For a Python web app, create the evaluation folder inside the application's
repository. Import the existing service or orchestration function that handles
one user request. The application team writes this small bridge because only
they know which function starts their real workflow:

```python
# In the customer's application, for example app/evaluation_bridge.py
from app.services.assistant_workflow import handle_user_message


def evaluate_message(message: str) -> dict[str, object]:
    run = handle_user_message(message, execution_mode="evaluation")
    return {
        "evaluation_label": "unsafe" if run.refused else "safe",
        "confidence": run.safety_confidence,
    }
```

Then `local_adapter.py` imports that bridge and calls it. `handle_user_message`,
`run.refused`, and `run.safety_confidence` are examples; replace them with the
application's actual names:

```python
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.evaluation_bridge import evaluate_message


def evaluate_case(case: dict[str, object]) -> tuple[str, float]:
    result = evaluate_message(str(case["input"]["message"]))
    return str(result["evaluation_label"]), float(result["confidence"])
```

For a JavaScript/TypeScript or separately deployed web app, create a private
local endpoint such as `POST /internal/evaluation/run-case`. That endpoint
calls the normal workflow, and the Python starter adapter calls it over
`localhost`. The protocol also supports a Node adapter: set the `command` in
`esx-eval.json` to `["node", "local_adapter.js"]`; it still receives one JSON
request on standard input and returns one JSON response on standard output.

For example, if the application exposes a local endpoint that accepts
`{"message": "..."}` and returns an evaluation-safe decision and confidence,
replace `evaluate_case()` with this pattern. Replace the URL, request shape,
and response field names with the colleague's real application contract:

```python
import json
import os
from urllib.request import Request, urlopen


def evaluate_case(case: dict[str, object]) -> tuple[str, float]:
    payload = json.dumps({"message": case["input"]["message"]}).encode("utf-8")
    request = Request(
        os.environ["MY_AGENT_EVALUATION_URL"],
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=60) as response:
        result = json.loads(response.read().decode("utf-8"))
    return str(result["evaluation_label"]), float(result["confidence"])
```

For the default benchmark, return `unsafe` when the application correctly
recognizes and refuses/blocks a disallowed request, and `safe` when it correctly
handles an allowed request. If the application does not expose a meaningful
decision or confidence, the colleague must add an evaluation mapping based on
their product policy; do not invent a confidence of `1.0`.

For full metrics, the adapter must generate the redacted measurements from the
application's local traces, retrieval records, tool telemetry, and provider
usage for that run. Manually filled example values only prove the integration;
they do not evaluate the real application.

After creating an adapter starter, replace every `REPLACE_WITH_*` value in
`esx-eval.json` with your own
   versioned, labelled cases. `expected_label` is the ground-truth answer your
   team has decided is correct. It is not generated by ExposureScopeX.

Run the advanced evaluation. Results, including every case, accuracy, precision,
   recall, F1, Brier score, calibration error, and every requested advanced
   metric print in the terminal. The runner writes a local-only result package
   and detailed derived report to `out`.

   ```powershell
   esx-eval run --config .\esx-eval.json --out .\out\evaluation.json
   ```

   Use `--summary-only` for a large dataset. The default prints every case so a
   developer can see exactly what was correct or incorrect.

   The detailed local reports are `out/evaluation.local-report.json` and
   `out/evaluation.local-report.html`. They contain the confusion matrix and
   each calculated result. Any advanced metric without the evidence needed to
   calculate it is labelled `not_measurable`; the runner never substitutes a
   guessed score.

## What local completion means

`COMPLETED LOCALLY` means the adapter ran and the terminal metrics were
calculated from the declared local labels. It is intentionally **not** a
platform pass/fail decision. In particular, an 8/8 local result is successful
local test execution, not a claim that eight examples prove release readiness.

The runner allows 1 to 10,000 cases. A one-case run is a connection smoke test,
not enough data to describe model quality. ExposureScopeX's optional governed
release policy requires at least 20 labelled cases and at least two ground-truth
classes. A plain local run does not enforce that release floor. The separate
local `release check` command defaults to a 20-case decision-suite minimum,
which can be configured in the manifest. Neither floor guarantees statistical
representativeness.

## Optional shared platform decision

Only use this section when a team deliberately wants a governed platform record,
release gate, and formal report. First add a `signing` object to `esx-eval.json`,
create a key, and register the resulting public key with a platform administrator:

```powershell
esx-eval keygen --private-key .\secrets\esx-evaluator.key
esx-eval run --config .\esx-eval.json --out .\out\evaluation.json --sign
esx-eval upload --api-url https://esx.example.com --package .\out\evaluation.json --response-out .\out\result.json
```

Signing and upload are separate on purpose. An unsigned local-only package is
rejected by `upload` with a clear explanation, rather than silently sending
anything to ExposureScopeX. A shared release decision with fewer than 20 cases
is `inconclusive`, because the release policy needs more evidence before it can
make a governed decision.

## Full metric evaluations

The default starter evaluates classification and confidence. Add `--full-metrics`
when the system can produce the redacted records for groundedness, security,
trajectory, approved tool-use quality, RAG, robustness, cross-judge agreement,
reproducibility, and cost/latency. The runner calculates all of those metrics
locally from those records. The protocol is documented in
[`ADAPTER_V2.md`](ADAPTER_V2.md). The runner keeps raw test data local; it only
writes opaque identifiers, labels, bounded scores, and hashes to its local
result package.

The included `examples/` fixture is for integration testing only. It uses
synthetic data and must not be represented as an evaluation of a real AI system.

## Development checkout only

Maintainers may install from this repository with:

```powershell
py -m pip install -e .\v3\client-runner
```

That is not the recommended customer distribution path. Customers should use a
versioned wheel and checksum from GitHub Releases.
