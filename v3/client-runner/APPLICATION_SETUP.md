# PRE-D guided application evaluation

This guide requires **PRE-D Local 0.15.1 or later** for all coverage previews below. Verify the installed version
with `python -c "from esx_eval_runner import __version__; print(__version__)"`.

## One local starting point

```text
esx-eval setup --application
```

The page runs on a temporary loopback server. No account, ExposureScopeX
connection, hosted database, Docker service, or customer GitHub access is needed.
Stop the command with Ctrl+C when finished. The app being tested or its own
providers can still use a network; local PRE-D is not a network sandbox.

1. List the application version and all modules. Pick workflow, decision, or
   mixed coverage for each. Add required browser personas and module dependencies.
   Optionally record manual review notes for inspections, approvals, or runbook
   checks you want visible later in the report.
2. Select existing local evaluation plan paths. Review their test cases and
   their required metric dimensions. Inspect the resulting review-scope matrix
   and generated manifest preview, then bind each suggested objective to real
   cases and describe the assertion actually made by those cases.
3. Confirm the inventory and execution scope. Create a new local release folder,
   read the preflight gaps, then run the shown release command when ready.

The page creates a manifest, not a fake successful run. Setup and preflight do
not call the target. Missing objectives or bindings are visible and block an
all-module run. Existing folders and plans are not silently overwritten.
Creation is bound to the previewed configuration, parsed cases, objective
bindings and destination. If these change, preview and approve again. This
snapshot does not attest to external adapter code or freeze the target app.

The review-scope preview answers a narrower question than the release verdict:
how far the review has actually progressed for each module. `evaluated` means
all declared executable suites completed with usable PRE-D evidence,
`inspected` means only reviewer-declared activity exists (including external
evaluations), `blocked` means executable PRE-D coverage is incomplete,
and `untouched` means no review activity is recorded. Manual review notes stay
visible in the manifest preview and final report, but they do not satisfy
executable PRE-D evidence requirements by themselves.

Read **coverage advisories** alongside blocking preflight issues. Advisories
highlight baseline decision evidence omitted from the plan, missing population
context, and weaker browser signals. They do not prevent execution. The workflow
summary lists planned content, title, route, and element-state checks, plus cases
without an assertion after the last navigation or interaction. A hidden-element
wait is not proof that the intended page rendered. Review the assertion and its
later execution outcome separately. These same cautions appear in the release
report, including when a suite was blocked.

If you already know the larger labelled population behind a decision suite,
add optional suite `population` metadata in the manifest after setup. The
release report can then show executed-pack versus available-pack context
without pretending the pack is automatically representative.

If a module has no plan, use the linked decision/API or browser setup first.
For a command adapter, reuse its existing validated PRE-D config. The application
setup is an orchestration layer, not an automatic adapter author or product oracle.

## Choose what is evaluated

| Use case | Plan and evidence | What PRE-D can report |
| --- | --- | --- |
| Labelled decisions | Actual endpoint/command outputs plus representative labelled cases | Accuracy, precision/recall/F1, Brier score and calibration when valid confidence exists |
| RAG answers | Response text, exact retrieved chunks, local judge, and relevant-document labels for retrieval metrics | Configured semantic groundedness/hallucination and retrieval metrics; no evidence-ID shortcut to truth |
| Agent behavior | Expected outcomes plus supported tool/trajectory/security telemetry and test expectations | Existing metric engines with verified/declared/missing provenance retained |
| Authenticated web UI | Reviewed browser journeys, explicit assertions, isolated sessions and personas | Workflow execution, observed assertion outcomes, blocked sessions and diagnostics |
| Whole application | All module plans, reviewed objectives, integration cases and explicit release thresholds | What ran, what failed, what remains untested, and evidence-linked next actions |

The setup retains existing judge, telemetry and adapter configuration. It does
not enable metrics for which the plan has no valid evidence or silently download
models. Browser results do not become decision metrics.

## Review objectives, not just module counts

The reusable objective templates cover positive paths, negative paths, decision
boundaries, workflow recovery, persona authorization, and declared dependencies.
They are **suggestions for review**, not executable tests and not certification
that these categories are sufficient for a particular product.

Case bindings require actual case IDs and matching browser personas. Workflow
plans need explicit success assertions; opening a page alone is insufficient.
An assertion description is a reviewer declaration. PRE-D cannot prove that a
case titled `permission-test` really exercises every permission boundary.
Likewise, a manual review note can prove that someone inspected a runbook or
dependency map, but it cannot turn an unexecuted module into evaluated coverage.

Passing module suites separately does not prove the integration between them.
Add a real cross-module assertion and bind it to an integration objective. Do
not connect production-writing actions unless their environment is deliberately
isolated and the side effects are approved. Approval flags are not rollback or
write-interception mechanisms.

## Failure-to-fix loop

- Start with the release summary: actual execution, objective outcomes, blockers,
  evidence gaps and selected thresholds.
- Open the implicated module, objective and case in the detailed local report.
- Review the expected result, session/setup problem, failed assertion or model
  output. A weak assertion is not automatically an application defect.
- Fix the app or a demonstrably wrong test expectation. Rerun the same full pack.
- Pass `--baseline previous-release.json` to compare supported metrics and cases.
  Changed datasets, protocols, thresholds or objective bindings stay visible.
- Add repeated `--history previous-N.json` inputs when you want conservative
  multi-run trend context across more than one earlier release review.

Observed wrong decisions remain visible on single-class packs even if broader
classification is not measurable. This does not manufacture macro F1 or turn a
small dataset into a production-wide estimate. Target-declared metrics still
cannot satisfy verified release gates.

## Patterns adopted from evaluation tools

These are design references, not bundled dependencies, copied proprietary code,
or claims of feature parity. Documentation reviewed 2026-09-19.

| Reference | Useful pattern | PRE-D application |
| --- | --- | --- |
| [LangSmith evaluation quickstart](https://docs.langchain.com/langsmith/evaluation-quickstart) | Separate dataset, target, and evaluator | Keep plans and real cases explicit; guided application setup composes them without changing their metrics |
| [Braintrust datasets](https://www.braintrust.dev/docs/annotate/datasets) | Reusable versioned cases and human-reviewed expectations | Retain local dataset/protocol fingerprints and expose reviewed case-to-objective bindings |
| [Arize Phoenix experiments](https://arize.com/docs/phoenix/datasets-and-experiments/how-to-experiments) | Tasks, evaluators and comparable experiments | Reuse local plans, preserve telemetry evidence, and compare genuinely matched baseline runs |
| [DeepEval quickstart](https://deepeval.com/docs/getting-started) | Explicit test cases and metric-specific evaluation | Preserve PRE-D's separate decision, semantic, workflow and telemetry requirements instead of a universal score |
| [Promptfoo assertions](https://www.promptfoo.dev/docs/configuration/expected-outputs/) | Explicit output assertions and reusable test configuration | Require asserted release workflows; retain per-case outcomes and a reproducible CLI |
| [Openlayer test configuration](https://docs.openlayer.com/tests/test-configuration) | Per-test data, thresholds and configurable checks | Disclose selected release gates and default-policy changes beside the results |

New in this implementation: guided multi-module authoring, objective templates,
explicit case binding, scenario/persona outcomes, dependency coverage disclosure,
and stronger release evidence reporting. Metrics, fingerprints, detailed local
reports, and supported baseline comparison already existed and are reused.

Not implemented by this change: hosted observability, arbitrary autonomous app
crawling, automatic correct labels, a full dataset-versioning service, human
annotation queues, universal API/load/infrastructure testing, or parity with
every feature in those products. Real-app acceptance and representative scale
testing are still needed before making broad production-readiness claims.
