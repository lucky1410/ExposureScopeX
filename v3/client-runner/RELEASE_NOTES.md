# PRE-D Local 0.13.0

This release adds guided application setup and reviewed all-module execution
on top of PRE-D's existing local AI evaluation engines. It is ready for
controlled acceptance testing, not a claim of full production certification.
No ExposureScopeX account, hosted database, or Docker service is required.

## Easier application setup

- `esx-eval setup --application` opens a local form for application identity,
  module inventory, existing evaluation plans, personas, and dependencies.
- Preview real case IDs and required metric dimensions, then bind cases to
  reviewed objectives without hand-editing the release manifest.
- Setup does not execute adapters, import application code, invent cases or
  expected labels, silently configure a judge, or upload evidence.
- Creation is tied to the previewed plans, parsed cases, bindings, and output
  directory. Changes require fresh review; existing folders are not overwritten.
- Local routes validate the host and CSRF token. Directory-sensitive handlers
  share a lock so concurrent requests cannot resolve paths in another plan's folder.

## Reviewed all-module execution

- `release scope` drafts generic positive, negative, boundary, recovery,
  authorization, and integration objectives. These are review templates, not tests.
- `release bind` connects an objective to actual suite/case IDs and an assertion
  description. Browser persona bindings must match the configured cases.
- `release attach` records an approved config and its execution policy.
- `release preflight` validates the entire declared inventory without calling
  a target. Missing plans, kinds, objectives, bindings, assertions, or approvals
  block the all-module run. Exclusions and report reuse cannot masquerade as execution.
- `release run` executes all approved suites sequentially after preflight.
  A failing suite does not silently skip later suites. Execution completeness
  stays separate from passing quality gates and objective outcomes.
- Browser release plans require explicit assertions; page navigation alone is
  insufficient. Custom role metadata is supported without granting permissions.
  Configured but unused personas remain visible with zero executed cases.

## More useful release reports

- Reports show what actually ran, objective outcomes, mapped case IDs, reviewer
  assertions, personas, and dependency coverage separately.
- A declared dependency is not an exercised integration. Missing cross-module
  tests remain gaps; failed mapped objectives block the release recommendation.
- Complete per-case wrong decisions remain visible even when a single-class
  dataset cannot support the broader classification estimate.
- Custom thresholds are disclosed against starting defaults, not treated as
  universal release standards. Changed objective mappings are visible in comparisons.
- Existing classification, precision/recall/F1, calibration, semantic
  groundedness/hallucination, and supported telemetry metrics are retained.
  Verified/declared/missing provenance still controls release gates; no new
  composite score substitutes for the underlying measurements.

## Install and test

Download the wheel, `SHA256SUMS`, README, and `APPLICATION_SETUP.md` from this
release. Verify the wheel checksum using the README instructions, then install
into the same Python environment used for evaluation:

```text
python -m pip install --upgrade ./exposurescopex_eval_runner-0.13.0-py3-none-any.whl
python -c "from esx_eval_runner import __version__; print(__version__)"
esx-eval setup --application
```

Use `py` or `python3` where appropriate. Browser tests additionally require
Playwright/Chromium; semantic evaluations require the configured local judge.
Existing evaluation plans and the bounded `release check` workflow remain supported.
Existing manifests need reviewed objectives and execution approvals before they
can use strict `release run`; review them rather than replacing prior evidence.

## Validation and boundaries

- 271 local regression tests pass, including multi-module execution fixtures,
  objective/persona binding, missing coverage, report comparisons, and setup routes.
- Guided browser setup was exercised through preview, binding review, manifest
  creation, and a subsequent synthetic local release run. Responsive layout was
  checked. These are implementation checks, not real-application acceptance.
- Real-application acceptance, representative scale testing, and independent
  semantic-judge validation remain necessary.
- The inventory and assertion descriptions are reviewer declarations. PRE-D
  cannot prove every business behavior is covered or invent a correct test oracle.
- Read-only and isolated-write approvals do not intercept external side effects,
  validate isolation, or provide rollback. Use approved isolated environments for writes.
- Advanced semantic/telemetry baseline deltas are not supported yet; valid
  evidence can still participate in current-release gates.
- No competitor feature-parity claim, automatic source-code diagnosis, or
  autonomous exhaustive application crawler is introduced by this release.
