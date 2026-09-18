# PRE-D Local 0.12.0

This release adds a local application release-review layer on top of the
existing decision, browser, semantic, and telemetry metric engines. It does
not require the ExposureScopeX platform, a database, or a Docker service.

## Application release review

- `esx-eval release init` creates an explicit module inventory.
- `esx-eval release check` assesses completed reports. `--run` explicitly runs
  config-backed suites sequentially before assessment.
- Modules declare owners, required workflow/decision coverage, exclusions, and
  dependencies. Uncovered required modules remain gaps, not passing results.
- Policies produce Ship, Ship with conditions, Do not ship, or Insufficient
  evidence. Critical failures are never averaged away.
- Report identity, timestamps, distinct executions, counts, minimum samples,
  metric provenance, and representativeness are checked before accepting gates.
- Findings identify affected modules/suites, available case IDs, owners, evidence
  pointers, and recommended next actions without inventing code-level causes.
- Standalone HTML/JSON reports and hash-linked audit logs remain local.

## Baseline comparison

- `--baseline previous-release.json` compares against a read-only historical
  release review without executing that previous application version.
- Classification, calibration, workflow outcomes, and decision-evidence
  alignment can be compared when original datasets and scoring protocols match.
- Numeric regressions and newly failing case IDs are visible even when the
  candidate still passes an absolute threshold or aggregate scores are unchanged.
- Removed modules/suites and altered release policies are explicit changes,
  not proof of a fix. Unmatched evidence is Not comparable.
- Configurable regression severity and absolute tolerance support local CI
  gates. `--require-ship` exits 2 for any non-Ship recommendation.
- Package fingerprints survive report regeneration; old packages do not acquire
  fabricated fingerprints from a later configuration.

## Existing metrics are retained

Decision correctness, precision/recall/F1, confidence calibration, groundedness,
hallucination, evidence-reference alignment, and supported telemetry-backed
metrics remain available with their existing evidence requirements and trust
labels. The release layer evaluates their results; it does not replace their
formulas with a composite application score.

The single-run readiness card is renamed to **This run's evidence readiness**
to separate it from the new application-level release review.

## Install and test

Download the wheel and `SHA256SUMS` from this GitHub release. The accompanying
README and guides describe setup, inputs, examples, interpretation, and limits.

```text
python -m pip install --upgrade ./exposurescopex_eval_runner-0.12.0-py3-none-any.whl
python -c "from esx_eval_runner import __version__; print(__version__)"
esx-eval release check --help
```

Use the Python executable for your evaluation environment (`py` or `python3`
where appropriate). Follow README checksum verification before installation.
Ordinary evaluation plans remain supported; release reviews are opt-in.

From the `v3/client-runner` source checkout, the synthetic comparison demo is:

```text
python -m examples.run_release_fixture --compare --out-dir ./out/release-comparison
```

That demo invokes only its deterministic local adapter, never a real application.

## Validation and boundaries

- The local runner suite passes 163 regression tests, including multi-suite
  adapter execution, comparison policy, missing coverage, changed-case
  detection, dependency readiness, and HTML evidence-link checks.
- Real-application acceptance testing and browser visual QA remain pending.
- Advanced semantic/telemetry regression comparisons are not yet supported;
  those metrics still participate in current-release checks when evidence permits.
- Old baseline packages without original fingerprints need rerunning. Compare
  application versions under the same PRE-D version and evaluation protocol.
- Inventory completeness is declared by the release owner. There is no automatic
  full-production coverage, exact source-code diagnosis, or safety certification.
- Test writes in an isolated instance/tenant. Local execution does not intercept
  external side effects or guarantee rollback.
