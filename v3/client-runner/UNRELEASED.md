# PRE-D Local 0.15.1 Release Working Notes

Published scope for the 0.15.1 release.

- Added reusable protected application profiles, conservative discovery refresh,
  retained check/evidence bindings and explicit source/contract change review.
- Added a bounded local planning loop with inventory-only tools, validated
  suggestions and acceptance into unreviewed behavior objectives.
- Added source/output boundaries, fingerprints, stop-on-change reporting and
  blocking of unrestricted commands in protected profiles.
- Added setup controls, HTML/JSON baseline comparisons, profile audit events
  and compatible verified-metric deltas. Baselines remain explicitly selected.
- Added onboarding regression/acceptance fixtures and the LOCAL_ONBOARDING guide.
- Added a non-invasive business-logic planner path for `system assist
  --business-context`. Owner-supplied business rules now draft reviewed
  behavior objectives with business rule IDs, intended behavior and evidence
  requirements, while preserving the existing no-target-call, no-source-edit,
  no-auto-approval boundary.

- Added explicit whole-system behavior contracts with reviewed inventory totals,
  per-layer/role objectives, exact test-case/content bindings and coverage gaps.
- Added running-candidate identity checks before/after dispatch. Wrong candidates
  prevent further execution; changed candidates cannot receive clean readiness
  or feed regression baselines.
- Added `system scope`, strict whole-system preflight/run switches, guided setup
  fields, behavior-level report tables, and ten-module/four-role acceptance with
  healthy, seeded-fault, repaired and incomplete/invalid-candidate controls.
- Kept omitted required layer/role objectives in the report denominator instead
  of shrinking coverage to the authored subset. Fixed setup text/JSON edits so
  they commit before blur, with malformed JSON blocked before save.

- Removed mandatory classification/confidence coupling from explicit decision
  release gates. New attached and guided plans select baseline defaults only for
  requested dimensions; existing explicit policies are preserved.
- Added reviewed confidence provenance: native returned-label probability,
  adapter-mapped categories, or unknown. Mapped/unknown arithmetic stays visible
  as diagnostics, but cannot satisfy native calibration gates or verified trends.
- Included confidence origin/mapping in comparison-protocol identity, guided
  setup, evidence preflight, HTML/JSON reports and local instructions.
- Kept classification headlines independent of confidence and semantic-only
  results independent of unrelated label requirements.
- Fixed a Windows timeout-cleanup race by waiting on owned job process handles
  before returning. Repeated timeout and background-child cleanup fixtures cover
  immediate working-directory removal.

- Fixed command-v2 `decision_evidence` normalization and decoupled classification,
  confidence and semantic/evidence-only input requirements.
- Preserved dataset population metadata when attaching release suites.
- Added `system discover`, `setup`, `bind`, `roles`, `approve`, `preflight`,
  `run`, `sample`, `monitor`, `trend`, and explicit history pruning.
- Added reviewed source/API inventory, module/layer/role/dependency gaps,
  HTTP/JSON budget assertions, JUnit command execution and existing AI/browser
  execution with explicit verified-only gates.
- Added bounded read-only load checks and separately approved recovery scenarios
  that require observed disruption and restoration, with cleanup failure stops.
- Added optional local SQLite history and compatible rolling-median change
  alerts. Scheduling is foreground/opt-in, not an installed background service.
- Added guided local review and executive-first HTML/JSON system reports,
  dimension availability, population context, audit hashes and detailed reports.
- Added loopback integration tests and the detailed `SYSTEM_EVALUATION.md` guide.
- Added a six-stage executable acceptance matrix, a disposable multi-role,
  multi-tenant reference application, real worker crash/recovery, and retained
  HTML/JSON acceptance evidence (`SYSTEM_ACCEPTANCE.md`).
- Hardened system capability booleans and metric gate bounds; rejected encoded
  XML entity declarations and malformed setup requests; kept transport-only
  load failures blocked rather than presenting them as application defects.
- Retained observed disruption evidence when recovery misses its deadline.
- Replaced Windows `taskkill` timeout cleanup with a gated Job Object launcher:
  the reviewed command cannot start before containment succeeds, and owned
  child processes terminate with the command's job. This is lifetime control,
  not a filesystem/network security sandbox.

Latest whole-system validation: 393 tests passed against the installed wheel on
Windows/Python 3.12.14. The six-run reference acceptance passed 22/22 assertions
across ten modules and four roles, with 56 integrity-checked artifacts. All 40
installed Python modules matched source. Browser setup draft/bind/save and invalid
JSON handling were exercised; the saved values persisted and no console errors
were captured. The readable dashboard and missing-role report were inspected.
This is controlled synthetic acceptance, not a customer application evaluation,
production-model validation, cross-platform certification or published release.

Earlier provenance validation: 379 tests passed against the locally built and installed
wheel on Windows with Python 3.12.14, including 17 confidence-provenance tests and
two repeated process-cleanup tests. All 39 installed Python modules matched the
source. Python compilation and generated setup JavaScript syntax checks passed.
This update was not visually reviewed in a browser, tested on Python 3.14, or
tested against a live customer application.

Earlier system-layer validation: 360 tests passed against the locally built and installed wheel
(58 system/baseline/acceptance tests). The synthetic three-run reference app produced the expected
decision/content failures and rolling health-regression alert. Setup browser
save/add-component checks passed with no captured console errors.
The six-stage acceptance pack passed 59/59 checks, including real timed
monitoring, observed worker termination/recovery, and 202 integrity-checked
artifacts. These acceptance checks overlap the full regression suite.

These changes do not provide autonomous full-app test authoring, universal
business-module discovery, a production chaos environment, automatic defect
root-cause proof, or a guarantee of complete coverage. Real-app acceptance is
still required; no live production target was tested during development.

## Business-Logic Planner

- `system assist --business-context ./business-context.json` now accepts a
  bounded local JSON rule file with actors, entities, states, permissions,
  dependencies, expected outcomes and negative outcomes.
- The planner converts reviewed business rules into pending suggestions and,
  when accepted, unreviewed whole-system behavior objectives. It carries
  `business_rule_id`, intended behavior and evidence-needed metadata into the
  setup UI and system report.
- The local model planner receives only inventory metadata and bounded
  business-rule summaries. It cannot call the application, read source bodies,
  change code, approve execution, create labels or score results.
- Business-rule suggestions remain hypotheses until the application owner
  reviews them and binds executable evidence. Implemented code behavior still
  never becomes the oracle by default.
