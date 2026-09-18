# PRE-D Local: VINI module coverage plan

Status: planning artifact, not an executed evaluation or runnable configuration.
Prepared on 2026-09-18 from the tester's module inventory and the current PRE-D
source checkout. Capabilities in this checkout may not be in the installed
release. No VINI environment, source code, credentials, or new run artifacts
were inspected for this plan.

PRE-D is the evaluator. VINI is one application used to test PRE-D. Module
names below belong in a customer evaluation plan; they are not built-in PRE-D
categories or assumptions about other applications.

## Inventory and scope

The supplied inventory contains approximately 15 product modules, 33 backend
route files, and 21 frontend pages. Use the 15 product modules as the initial
inventory; route files and pages are supporting entry points, not additional
modules. Preserve this inventory even when a module is deferred.

This plan has 12 candidate modules and 3 deferred modules. Candidate means
eligible for local test preparation after checking the stated prerequisites;
it does not mean approved, executed, or passed. Live writes and several
subfeatures remain excluded within the candidate modules.

The first pass targets 6 core modules: Command Center, Investigation Queue,
Investigation Detail/Analysis, Hunts & Campaigns, Hunt Findings, and DLP.
Threat Intelligence follows in the second pass despite being a core area,
so the first pass can concentrate on the highest-priority reported problems.

Governed Automation/Action Policy is tracked as an excluded cross-module
capability rather than invented as a sixteenth product module. Authentication
and access control are cross-module prerequisites.

## Fifteen-module matrix

Every row starts as **not demonstrated in this plan**. Earlier tester feedback
is useful context but cannot establish current module coverage without the
matching case IDs, application version, configuration, and run artifact.

| ID and module | Priority / type | Existing PRE-D path | Evidence or setup needed next | Scope boundary |
| --- | --- | --- | --- | --- |
| M01 Command Center | Core / workflow | Authenticated browser cases and visible-signal checks | Approved route; stable dashboard signal; a known fixture to check one count or drill-down | Candidate, pass 1. Read views only. |
| M02 Investigation Queue | Core / workflow | Browser navigation, filtering, waits, and assertions | Known queue records; filter expectations; open-detail signal; expected contents of the reported empty escalate modal | Candidate, pass 1. Open the modal only after confirming that opening it causes no write; exclude submission. |
| M03 Investigation Detail/Analysis | Core / mixed | Browser cases plus separate local decision/API or command-adapter cases | Known investigation; evidence-tab signals; real disposition function; labelled decisions and returned confidence | Candidate, pass 1. Exclude escalation, closure, and automated external actions. |
| M04 Threat Intelligence | Core / workflow initially | Browser list/detail cases | Known indicator fixture; search/filter expectations; provenance display signal | Candidate, pass 2. Exclude feed changes, external enrichment triggers, and indicator publication. Add decision evaluation only if a decision contract exists. |
| M05 Hunts & Campaigns | Core / mixed | Browser cases plus local conclusion evaluation | Existing scenario fixture; builder signals; isolated conclusion function; labelled outcomes and source material | Candidate, pass 1. Do not create campaigns or launch live hunts. |
| M06 Hunt Findings | Core / mixed | Browser findings cases plus local conclusion/evidence evaluation | Known finding and empty-result fixtures; expected conclusion labels; evidence-reference expectations | Candidate, pass 1. Exclude finding disposition writes and follow-up actions. |
| M07 Detection Engineering | Secondary / mixed | Browser inspection; local adapter for rule-draft output | Known rule fixture; isolated draft generator; reviewed validity/quality expectations appropriate to its output | Candidate, pass 3. Live rule creation/push is excluded. Successful draft generation alone does not prove rule quality. |
| M08 DLP | Core / mixed | Browser review cases plus labelled local verdict evaluation | Real verdict path; positive, negative, and insufficient-evidence fixtures; label/confidence mapping; expected evidence IDs | Candidate, pass 1. Isolate verdict computation from enforcement and external writes. |
| M09 Triage Guidance | Secondary / workflow initially | Browser content and navigation checks | Known guidance fixture and expected visible content | Candidate, pass 2. If guidance is generated, add response/source material and independent claim evaluation before scoring its quality. |
| M10 Assets & Identities | Secondary / workflow | Browser search, list, detail, and relationship checks | Seeded local assets/identities; known relationships; restricted-record expectations | Candidate, pass 2. Exclude identity changes, sync triggers, and external lookups with side effects. |
| M11 Audit & Activity | Secondary / workflow | Browser filter/detail checks | Seeded audit events and expected actor/action/time fields; allowed visibility by role | Candidate, pass 2. Viewing events does not prove audit completeness for actions that were never tested. |
| M12 Integrations | Secondary / workflow | Browser configuration/status inspection | Seeded connection status and expected redacted display | Candidate, pass 3. Exclude connect, sync, credential updates, and test-connection actions that contact live services. |
| M13 Users & Shift Coverage | Secondary / workflow | Browser engine could support a future isolated roster fixture | A separately approved disposable identity/roster environment | Deferred at tester request. No automated interaction in the current plan. |
| M14 Agent Runtimes/Prompts/SLM | Secondary / configuration | Browser engine could support future inspection fixtures | Disposable runtime configuration and an explicit test purpose | Deferred at tester request. No model, prompt, registration, or runtime changes. |
| M15 MCP Administration | Secondary / configuration | Browser engine could support future inspection fixtures | Disposable MCP configuration and an explicit test purpose | Deferred at tester request. No server/tool registration or configuration changes. |

The legacy hunt analyst agent is excluded as reported unused code. Its discovery
must not create an execution requirement or inflate coverage.

## What current PRE-D supports, and what remains

The current checkout provides authenticated browser sessions, recording,
reviewed workflow packs, explicit case assertions, isolated persona profiles,
local decision endpoints/command adapters, and local metric computation.
These are reusable mechanisms; VINI still supplies its actual routes, expected
behavior, test data, and callable decision interfaces.

The source also exposes these limits relevant to broader coverage:

| Area | Current behavior | Remaining work |
| --- | --- | --- |
| Module reporting | `module_coverage` groups browser diagnostics and planned cases by `capability_area`. | Add a customer-defined module inventory and explicit case-to-module mapping; retain modules with no cases. Discovery categories cannot reliably reconstruct all 15 modules. |
| Mixed modules | Overall decision coverage exists; browser module rows consume browser diagnostics. | Join browser and decision results by module, retaining separate outcomes and denominators. A decision run must not leave a module looking unexecuted or imply its UI was covered. |
| Roles | Browser role metadata accepts `admin`, `analyst`, `read_only`, and `service`; sessions are isolated per persona. | Support arbitrary customer role labels, including `soc_lead`, without changing the target app's permissions. |
| Workflow authoring | Recording, candidate packs, stable assertions, and selector hints are available. | Review each application's paths and signals; automatic discovery cannot establish business expectations. |
| Scope enforcement | The runner checks local origins and reviewed configuration. | A loopback origin does not prevent the target backend from writing to external services. The test application needs isolated dependencies for any potentially mutating workflow. This document does not enforce exclusions in the runner. |
| Run breadth | Guided decision import accepts up to 500 cases; the general dataset validator allows up to 10,000. Browser configuration allows up to 32 persona profiles. | Validate actual runtime/resource use with representative packs. These are configuration limits, not tested throughput or whole-product coverage guarantees. |

Implementation references: [coverage model](../esx_eval_runner/assurance.py),
[browser validation](../esx_eval_runner/browser.py),
[runner validation](../esx_eval_runner/runner.py), and
[guided setup](../esx_eval_runner/setup.py).

## Persona plan

Start with the four enforced VINI roles reported by the tester. Treat the nine
design personas as business descriptions until their intended permissions have
been mapped to actual accounts and independently stated expected behavior.

| Actual VINI role | Proposed test purpose | PRE-D representation today |
| --- | --- | --- |
| `read_only` | Check permitted views and expected denial of writes/restricted records | Separate persona and session using role `read_only` |
| `analyst` | Core queue, investigation, DLP, and hunt workflows | Separate persona and session using role `analyst` |
| `soc_lead` | Check intended lead-only views/actions and analyst-to-lead boundaries | Exact role metadata is unsupported. Record this as a gap rather than relabelling the account as admin. |
| `admin` | Approved configuration inspection and expected visibility | Separate persona and session using role `admin`; deferred modules remain excluded |

An authenticated session proves an identity was established; it does not prove
authorization is correct. Expected permissions must come from the intended
access policy, not be inferred from whatever the current app allows. Test
disallowed operations against disposable local state or a side-effect-free
authorization surface. A hidden button alone cannot prove API enforcement.

The reported read-only feedback-write issue is an unverified issue here. It
needs its own reproduction and expected-policy check in an isolated target.

## First-pass case backlog

These are case designs, not generated labels or ready-to-run JSON. The tester
must bind them to real fixtures and reviewed selectors/decision interfaces.

| Pack | Minimum useful scenarios | Result to retain |
| --- | --- | --- |
| Authentication | Valid session, expired session, unauthenticated protected-page access | Persona, session outcome, whether the workflow could start |
| M01 dashboard | Known-data dashboard; drill-down to the expected fixture | Expected signal, observed match/review status, destination |
| M02 queue | Known record/filter; empty filter result; open detail; inspect escalation modal without submitting | Case ID, role, completed steps, precise failed assertion if any |
| M03 investigation | Known case/evidence tabs; escalation vs closure decision examples; insufficient evidence | Browser observations separately from decision labels, confidences, and expected outcomes |
| M05/M06 hunts | Open existing scenario and findings; no-findings case; supported conclusion vs insufficient evidence | Map each case to its module; keep conclusion evaluation separate from UI reachability |
| M08 DLP | Real credential exposure, harmless lookalike, and insufficient evidence; associated review page | Reviewed gold label, actual verdict/confidence, evidence references, and per-case correctness |

For the reported DLP failure, preserve the original inputs and approved expected
labels as regression cases. Call the real decision implementation with external
actions disabled. A fixture that returns canned correct labels only tests the
adapter plumbing. Record whether the failure reproduces on the tested build;
this plan does not independently establish the reported 100% error rate.

For each decision task, use its own reviewed label set and positive class or
macro-averaging policy. Include representative correct/incorrect possibilities,
edge cases, and insufficient-evidence cases. Keep a held-out set beyond any
cases used to tune the application. Tiny starter packs establish connectivity
and regressions, not production accuracy.

## Evidence to prepare locally

1. Application build/version and a local test environment with fixture records.
   Inspect the application's external dependencies before running a candidate
   workflow; local hosting by itself does not isolate live integrations.
2. Real route paths and stable expected signals for the six first-pass modules.
   Keep passwords and session files on the tester's machine.
3. Separate test accounts/sessions for the intended roles, plus the expected
   access policy. Begin with supported persona roles; track `soc_lead` as pending.
4. Local endpoints or command adapters for disposition, DLP verdicts, and hunt
   conclusions, each exercising the real decision logic without external writes.
5. Labelled cases and the application's returned labels/confidences for each
   decision task. Use [the decision guide](../DECISION_EVALUATION.md).
6. For groundedness/hallucination only: actual response text, exact source chunks
   (including explicitly empty retrieval), independent local judge configuration,
   and required review/abstention expectations. Use
   [the evidence guide](../PRE-D_EVIDENCE_GUIDE.md). Missing semantic evidence
   does not invalidate separately measured classification results.

## Execution order

1. Bind the inventory to the target's actual routes and fixtures. Keep M13-M15,
   governed automation, live rule push, and the legacy agent outside executable
   plans. Review both browser actions and adapter behavior for the exclusions.
2. Run one browser case and one real decision case to validate setup. Then run
   the six-module first pass with dedicated output locations per plan.
3. Check per-case outcomes and confidence warnings. Diagnose session blockage,
   assertion mismatch, adapter errors, and incorrect decisions separately.
4. Add alternate supported personas and negative cases. Expand to M04, M09,
   M10, and M11, then isolated drafting/status checks for M07 and M12.
5. Save reviewed browser packs using the existing
   [workflow-pack commands](../BROWSER_WORKFLOWS.md). Retain decision datasets
   and their endpoint/adapter configs separately for reruns.

Use one decision plan per task initially. A single plan can call an application
adapter that orchestrates multiple components, but that does not automatically
produce per-module results. Until combined reporting is implemented, link the
separate browser and decision artifacts in the tracker below.

## Coverage tracker and acceptance

For each module, maintain this record alongside the local artifacts:

| Field | What to record |
| --- | --- |
| Module ID and scope | M01-M15; candidate, approved, or deferred; excluded subfeatures |
| Target and plan version | Application build, dataset/plan revision, PRE-D version |
| Browser cases | Planned IDs, completed IDs, matched signals, review-needed outcomes, blocked IDs |
| Decision cases | Planned IDs, scored IDs, correct/incorrect outcomes, blocked/error IDs |
| Personas | Actual target roles tested and expected access outcomes |
| Evidence | Local report path, run identifier, metric provenance and missing prerequisites |
| Next action | Concrete setup fix, assertion review, product defect investigation, or untested scenario |

This tracker is maintained manually for now; it is not an accepted runner
configuration schema. No module is marked passed by this document.

Use these counting rules when judging breadth:

- Keep the full 15-module inventory visible. Show 12 candidates and 3 deferred
  modules separately; deferral is not a pass or a test failure.
- A module is partially exercised once one planned check completes. To mark its
  planned coverage complete, all required browser/decision cases and personas
  for that module must finish with usable evidence. For mixed modules, both
  paths must be represented unless a narrower scope was explicitly recorded.
- Completed failing checks count as exercised coverage, while their failures
  remain visible. Blocked or unattempted checks do not count as executed.
- Report completed-required-checks / planned-required-checks per module. If no
  checks are defined, show "not planned", not 100% or 0% quality.
- Report modules with complete planned coverage / approved modules alongside
  the full inventory and exclusions. Label this scoped plan coverage; it does
  not establish complete behavioral coverage of the application.
- Keep case counts and quality results separate. Six modules with one page
  check each are narrower than six modules with representative decisions,
  negative cases, role boundaries, and evidence checks.
- Keep classification/calibration results per task. Do not combine unrelated
  label spaces into a single accuracy score or treat declared semantic evidence
  as independently verified.

The first-pass completion condition is reviewable artifacts for all six target
modules, expected role coverage recorded, and every blocked/missing check
explicit. Product release acceptance is a separate decision using reviewed
task-specific thresholds and resolved critical failures. High accuracy on a
small pack cannot compensate for a known incorrect high-impact decision.
