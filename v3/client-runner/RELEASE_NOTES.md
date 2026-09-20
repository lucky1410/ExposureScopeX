# PRE-D Local 0.14.0

This release makes gaps in application evaluation more visible and hardens
coverage reporting, population context, and history comparisons. It builds on
0.13.0's guided setup and reviewed all-module execution. The existing local AI
metrics, including semantic groundedness and hallucination, remain available.

No ExposureScopeX account, hosted database, or Docker service is required. This
is a controlled acceptance-testing release, not whole-production certification.

## What changed

- Setup, preflight, and HTML/JSON reports now surface coverage advisories for
  omitted baseline decision dimensions, missing population context, and weak
  browser assertions. Advisories do not manufacture scores or alter release gates.
- Every suite has a metric-dimension inventory, including blocked suites.
  Gated, required-only, measured-only, unrequested, and unknown-request states
  remain distinct from verified, declared, or missing measurement evidence.
- Optional suite population metadata shows executed-pack versus declared
  labelled-population coverage, including per-class context. Inconsistent counts
  suppress percentages instead of producing values above 100%. This is descriptive
  context, not a guarantee of representativeness or unique application records.
- Repeated `--history` inputs on `release check` and `release run` provide
  conservative multi-run context. Timestamps are ordered chronologically across
  timezone offsets; regenerated reports of the same execution do not add another
  observation. Use `--baseline` for the existing matched-pack regression gate.
- Module review scope distinguishes evaluated, inspected, blocked, and untouched.
  Every attached suite and required executable kind needs complete usable evidence
  for evaluated status. Manual review notes never stand in for PRE-D execution.
- Guided setup previews the review-scope matrix and generated manifest, including
  optional inspection notes, before creating the reviewed release folder.

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
python -m pip install --upgrade ./exposurescopex_eval_runner-0.14.0-py3-none-any.whl
python -c "from esx_eval_runner import __version__; print(__version__)"
esx-eval setup --application
```

Use `py` or `python3` where appropriate. Browser testing additionally requires
Playwright and Chromium. Existing plans remain supported; upgrading does not
execute the target application or rewrite previous reports.

For groundedness and hallucination, use the new acceptance checklist in
`PRE-D_EVIDENCE_GUIDE.md`: real response/source material, a configured independent
local judge, both requested dimensions, and a small human-reviewed acceptance pack.
The semantic path does not require a separate gold claim file. Unsupported claims
mean unsupported by the supplied sources, not necessarily false in the real world.

## Validation and limits

- 302 local regression tests cover runner behavior, including 20 hardening tests
  for coverage, report reuse, population validation, and historical comparisons.
- The release workflow reruns the full suite before building and publishing the
  versioned wheel and documentation with SHA-256 checksums.
- Deterministic fixtures do not establish real-model judge accuracy. Independent
  semantic-judge validation and representative application acceptance remain needed.
- History is manually supplied and descriptive. Automatic scheduling, rolling
  drift alerts, and advanced semantic/telemetry history comparisons are not added.
- Integrated arbitrary code-test execution, comprehensive adversarial role/tenant
  testing, chaos/load/recovery testing, and automatic source-level diagnosis remain
  outside this release. Not all proposed evaluation layers are complete.
- Inventory, population metadata, and manual review notes are reviewer declarations.
  PRE-D cannot infer every business module, generate every test oracle, or prove
  whole-application correctness from a sampled pack.
- Local execution and approved-write policies do not intercept external side
  effects or provide rollback. Use approved isolated environments for writes.
- Cross-version protocol changes can make historical artifacts not comparable.
  Rerun baseline and candidate packs with the same evaluator for like-for-like gates.
