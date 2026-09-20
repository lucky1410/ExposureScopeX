# PRE-D Local 0.15.3

This patch release hardens the 0.15.x full-platform workflow against the
blockers found during real application testing. It keeps the 0.15.2
source-first onboarding model, but fixes the most misleading failure modes:
large repository fingerprints, stale browser sessions, generic binding errors,
and under-explained terminal report states.

## What changed in 0.15.3

- Source protection now ignores generated/vendor/build directories and common
  binary artifacts by default, records scan limits in the profile, and lets
  teams raise those limits explicitly when a repository needs it.
- Incomplete fingerprints are now reported as scan-limit/unreadable/link issues,
  not as proof that source code changed. Actual source drift remains a separate
  blocking condition.
- Setup, preflight, execution and after-check verification now use the same
  source scan limits, so protected profiles do not fail because different phases
  fingerprinted a real repository differently.
- Saved browser sessions are validated against the configured success signal
  before protected workflows run. Stale SSO/session-bootstrap profiles now block
  at session setup with a reauthentication reason, while form-auth profiles can
  refresh through approved environment variables.
- Objective binding errors now name the expected component, layer and role
  mismatch, making planner/reviewer fixes traceable.
- System HTML reports now explain what an executed component means and distinguish
  source `changed`, `incomplete`, and `not_configured` states.
- Added regression tests for generated-tree exclusion, incomplete fingerprint
  blockers, detailed binding errors, and stale-session detection.

## What changed in 0.15.2

- Added a sanitized VINI demo profile pack under `examples/vini_demo/` for
  building a local full-platform evaluation package without modifying the target
  application.
- Added source-readiness HTML/JSON generation that clearly separates discovered
  surface, drafted checks, missing runtime evidence and next setup actions.
- Made the demo builder OpenAPI-enhanced instead of OpenAPI-required: repo-only
  source inventory can start immediately, then API/runtime evidence can be bound
  later.
- Hardened protected-profile command execution with `trusted_command_policy`
  argv hashes so exact reviewed local adapters and JUnit commands can run while
  changed or unreviewed commands remain blocked.
- Added regression coverage for reviewed trusted commands, command adapters and
  nested judge commands under protected source profiles.

## What changed in 0.15.1

This release expands PRE-D Local from selected AI/browser scorecards into a
reviewed local system-evaluation workflow. It adds protected reusable profiles,
whole-system behavior contracts, business-rule planning, source/change
traceability, role/tenant/code/reliability layers, and local regression context.
The existing local AI metrics, including classification, confidence,
decision-evidence, semantic groundedness and hallucination, remain available.

No ExposureScopeX account, hosted database, or Docker service is required. This
is a controlled acceptance-testing release, not whole-production certification.

## What changed

- Added `esx-eval system bootstrap`, `refresh`, `assist`, `accept`, `setup`,
  `scope`, `roles`, `bind`, `approve`, `preflight`, `run`, `monitor`, `trend`,
  `sample`, and `compare` for local system evaluation without an ExposureScopeX
  account, Docker, or hosted database.
- Added read-only protected application profiles. PRE-D stores artifacts outside
  the application repository, fingerprints source before/after execution, stops
  on observed source changes, and records audit hashes.
- Added whole-system behavior contracts with reviewed inventory totals,
  per-module/per-layer/per-role objectives, explicit check bindings and visible
  coverage gaps. Missing objectives stay in the denominator.
- Added a bounded local planning agent and business-logic planner. Owner-supplied
  business rules can draft unreviewed behavior objectives with `business_rule_id`,
  intended behavior and evidence-needed metadata. The planner cannot call the app,
  read source bodies, edit code, approve execution, invent labels or score results.
- Added source/OpenAPI inventory, native HTTP assertions, role and tenant check
  templates, JUnit command-result ingestion, bounded load probes, approved
  recovery scenarios, optional local history, rolling-median alerts and baseline
  comparison reports.
- Added confidence-provenance handling so native returned-label probability,
  adapter-mapped categories and unknown confidence are not treated the same.
- Setup, preflight and HTML/JSON reports surface coverage advisories for omitted
  baseline dimensions, weak browser assertions, population context, missing
  bindings, source changes and declared versus verified evidence.

## Browser evidence and regression fixes

- Planned final content assertions are distinguished from route-only, title-only,
  and element-state checks, plus cases with no final assertion. A hidden-element
  wait or an assertion before the last interaction is not visible-content proof.
- Signal strength stays separate from pass/fail/blocked outcomes. New local reports
  preserve only case IDs and strength categories for reuse; legacy reports disclose
  unknown strength instead of inventing a result.
- Text and selector waits are accepted consistently by plan and objective validation.
- Normalized manifests with partial class-population metadata can be reloaded.
- Partial execution, missing sibling suites, malformed classification evidence,
  malformed history identifiers, and duplicate history artifacts have regression
  coverage and remain explicit gaps rather than apparent successes.

## Install and test

Download the wheel, `SHA256SUMS`, README, and guides from this release. Verify
checksums as described in the README, then install in the evaluator environment:

```text
python -m pip install --upgrade ./exposurescopex_eval_runner-0.15.3-py3-none-any.whl
python -c "from esx_eval_runner import __version__; print(__version__)"
esx-eval setup --application
```

Use `py` or `python3` where appropriate. Browser testing additionally requires
Playwright and Chromium. Existing plans remain supported; upgrading does not
execute the target application or rewrite previous reports.

For reusable system setup, start with:

```text
esx-eval system bootstrap --project sample-app --version candidate-1 --repo ../application --out ./application-profile.json
esx-eval system setup --plan ./application-profile.json
```

For groundedness and hallucination, use the new acceptance checklist in
`PRE-D_EVIDENCE_GUIDE.md`: real response/source material, a configured independent
local judge, both requested dimensions, and a small human-reviewed acceptance pack.
The semantic path does not require a separate gold claim file. Unsupported claims
mean unsupported by the supplied sources, not necessarily false in the real world.

## Validation and limits

- Local validation for this source passed 84 system tests with 1 Windows symlink
  skip, compiled all runner modules, built a local wheel, verified that
  `system_business.py` is packaged, and ran an installed-wheel business-context
  CLI smoke test.
- The GitHub release workflow reruns the full suite plus retained system and
  whole-system acceptance scripts before building and publishing the versioned
  wheel and documentation with SHA-256 checksums.
- Patch update: the monitor cleanup acceptance test now asserts only the actual
  monitor interval sleep, avoiding unrelated process-polling sleeps in CI while
  preserving the stop-before-next-cycle guarantee.
- Deterministic fixtures do not establish real-model judge accuracy. Independent
  semantic-judge validation and representative application acceptance remain needed.
- `system monitor` is a foreground opt-in loop, not an installed scheduler or
  background service. Alerts are local files and exit codes, not outbound
  notifications.
- Protected profiles block unrestricted command/recovery execution unless a
  separately isolated environment is approved. Built-in HTTP/browser checks can
  still affect application data if the target endpoint has side effects.
- Inventory, population metadata, and manual review notes are reviewer declarations.
  PRE-D cannot infer every business module, generate every test oracle, or prove
  whole-application correctness from a sampled pack.
- Local execution and approved-write policies do not intercept external side
  effects or provide rollback. Use approved isolated environments for writes.
- Cross-version protocol changes can make historical artifacts not comparable.
  Rerun baseline and candidate packs with the same evaluator for like-for-like gates.
