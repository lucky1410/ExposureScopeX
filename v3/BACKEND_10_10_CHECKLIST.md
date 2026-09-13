# Backend 10/10 Release Checklist

Status: engineering release standard  
Scope: deterministic scan execution, evidence, validation, coverage, and backend delivery  
Applies to: Light, Medium, and Aggressive profiles  
Last updated: 2026-09-11

## 1. What 10/10 Means

Backend `10/10` does not mean the platform magically finds every possible issue
on every target forever. It means the backend is enterprise-trustworthy:

- it executes truthfully,
- it enforces scope and safety reliably,
- it preserves forensic evidence correctly,
- it validates findings honestly,
- it reports real coverage instead of synthetic progress,
- and it proves its quality with repeatable benchmarks.

If any one of those pillars fails, the backend is not `10/10`.

## 2. Release Standard

The backend is `10/10` only when every section below is green.

| Domain | Standard |
|---|---|
| Execution integrity | Every required stage reaches a truthful terminal state with no silent stalls, hidden retries, fake progress, or orphan work |
| Scope and safety | Exact-origin scope, path policy, port policy, authorization, and prohibited-action boundaries are enforced in every stage |
| Evidence custody | Every retained artifact has immutable storage, SHA-256, provenance, and traceability to stage, scan, and finding |
| Finding integrity | Findings are deduplicated, evidence-linked, reproducible, and never promoted beyond what evidence supports |
| Coverage honesty | Reports and APIs disclose what was applicable, completed, failed, skipped, blocked, inconclusive, and not tested |
| Benchmark quality | Precision, recall, F1, repeatability, and evidence completeness are measured on labelled fixtures before release claims |
| Partial/failure resilience | Partial, failed, cancelled, and blocked runs still preserve usable findings, evidence, and reports |
| Production portability | Local and production topologies preserve scan semantics, contracts, and evidence behavior |
| Security boundary | Scanning remains deterministic, non-AI, non-exploitative, and permission-bounded |
| Operability | Health, lifecycle state, debugging signals, and incident diagnosis are first-class rather than ad hoc |

## 3. Scoring Model

Use this as an engineering scorecard, not marketing language.

| Score | Meaning |
|---|---|
| 0-3 | Concept or unstable prototype |
| 4-5 | Functional but unreliable |
| 6-7 | Working foundation with known release blockers |
| 8-9 | Strong release candidate with bounded residual risk |
| 10 | Release-grade by declared contract and benchmark |

The score is capped by the weakest critical domain. A backend with excellent
finding logic but poor evidence custody is not `10/10`; it is not releasable.

## 4. Critical Gates

All of these must pass before a profile is called `10/10`.

### 4.1 Execution Integrity

- Required stages cannot disappear or remain ambiguous.
- Stage progress must come from real execution state, not estimates.
- Timeouts must terminate the whole process group and record the real cause.
- Heartbeats must distinguish active work from stalled work.
- Re-runs must not corrupt previous scan artifacts or findings.

### 4.2 Scope and Safety

- Redirects outside the exact authorized origin are blocked or disclosed.
- Browser evidence from out-of-scope final URLs is never admissible proof.
- Scope files, when supplied, are enforced consistently across every stage.
- Safe-route exclusions remain active in crawl and browser navigation.
- No stage performs destructive or unapproved state-changing actions.

### 4.3 Evidence Custody

- Every artifact is hash-verified before release use.
- Source artifact IDs and finding evidence must remain consistent.
- Terminal screenshots are real captures tied to transcript hashes.
- Browser screenshots are original captures, not renderings or recreations.
- Missing or invalid evidence downgrades the affected finding honestly.

### 4.4 Finding Integrity

- Findings must map to stable fingerprints.
- Shared evidence must not create duplicate or inflated findings.
- Candidate, confirmed, rejected, and inconclusive states must be explicit.
- Deterministic oracles and safe replay decide confirmation where applicable.
- Tool-native labels must not be released as analyst-quality findings without normalization.

### 4.5 Coverage Honesty

- The API must expose methodology-family coverage.
- Reports must separate completed coverage from observed-only data.
- Single-response findings must disclose their boundary clearly.
- Unsupported families must appear as not tested, not disappear silently.
- Profile names must not imply deeper testing than the platform actually performed.

### 4.6 Benchmark Quality

- Fixtures are immutable and versioned.
- Ground truth is mapped to stable case IDs.
- False positives and false negatives are measured explicitly.
- Evidence completeness is included in the release gate.
- No precision, recall, F1, or “better than human” claim is made without published benchmark context.

### 4.7 Partial and Failure Resilience

- Failed or partial scans still emit findings for completed work.
- Reports explain exactly where execution stopped or degraded.
- Validation still runs when its inputs remain available.
- Evidence bundles remain usable even when the scan did not complete fully.

### 4.8 Production Portability

- The same plan contracts apply locally and in production.
- Queue or worker topology changes do not change scan semantics.
- Scanner tools remain isolated from the API dependency surface.
- Backend behavior remains deterministic across deployment modes.

## 5. Profile-Specific 10/10 Meaning

### Light 10/10

Light is `10/10` when it is a trustworthy rapid exposure baseline:

- honest exact-origin scope enforcement,
- stable service, TLS, crawl, headers, Nuclei baseline, and evidence validation,
- repeatable outputs,
- benchmarked header/configuration/exposure quality,
- clean handling of partial and failure states,
- and release-grade reporting of what Light does and does not cover.

### Medium 10/10

Medium is `10/10` when it becomes an evidence-backed, analyst-equivalent,
non-destructive application assessment:

- all Light guarantees,
- route, form, parameter, session, and API inventory surfaced clearly,
- deterministic safe validation adapters for auth, authz, input, API, and session families,
- benchmark-backed precision and recall for Medium-applicable cases,
- and no inflated claims based only on deeper crawl or longer runtime.

### Aggressive 10/10

Aggressive is `10/10` when it is the highest approved non-exploitative depth:

- all Medium guarantees,
- broader approved surface coverage,
- richer multi-role and workflow evidence where authorized,
- benchmark-backed superiority claims only where actually measured,
- and no “better than human” claim without a published human-baseline comparison.

## 6. Honest Current Status

This is the working assessment as of 2026-09-11.

| Domain | Current status |
|---|---|
| Execution integrity | Improving; real stage states exist, but still needs stronger release gating and broader Medium validation coverage |
| Scope and safety | Stronger than earlier iterations; exact-origin and screenshot-scope handling materially improved |
| Evidence custody | Light report path hardened: hashes and provenance remain traceable, shared protocol exhibits are deduplicated, secrets are redacted, and terminal/browser evidence is presented with honest capture semantics; live Docker acceptance remains required |
| Finding integrity | Better than before; still needs stronger normalization and broader deterministic validation beyond current Light-style families |
| Coverage honesty | Light reports now consume canonical methodology-family coverage with truthful fallback behavior; Medium and Aggressive still require benchmark-backed coverage validation |
| Benchmark quality | Foundation exists; not yet sufficient to justify enterprise-grade claims across profiles |
| Partial/failure resilience | Present and improving; still needs more acceptance coverage for mixed-success runs |
| Production portability | Architecture is sound; production-grade isolation and scale behavior still need validation |
| Security boundary | Strong direction; deterministic and non-AI scanning boundary is established |
| Operability | Adequate for development; needs stronger diagnostics and release-level observability discipline |

Conclusion: the backend is not `10/10` yet. It is a strong foundation moving
toward release-grade, with the largest remaining gaps in Medium validation,
benchmark proof, and release-level operability.

## 7. Work Sequence

Work in this order. Do not jump ahead to “premium reporting” before the fact
set is strong enough.

### Phase 1: Light hardening

- close remaining evidence edge cases
  Current batch: client reports now separate Project Scope and Profiling, add per-finding evidence-traceability tables, and present request/response summaries before raw protocol excerpts.
  Current batch: report generation redacts credentials and session material even when regenerating legacy artifacts, canonicalizes client-facing URLs while retaining raw scanner values for forensic traceability, and renders shared request/response evidence once with explicit cross-references.
  Current batch: terminal exhibits disclose their post-execution capture semantics, show the recorded command and readable output excerpt, and retain the complete transcript as canonical machine-readable evidence.
- eliminate misleading success states
  Current batch: report generation now preserves truthful terminal report states (`final`, `partial`, `failed`, `blocked`, `cancelled`) instead of flattening all degraded runs into `partial`.
  Current batch: scan dispatch now rejects overlapping active runs for the same assessment, preventing mixed evidence and conflicting terminal states.
  Current batch: finalization and report regeneration now use canonical `scan_coverage` rows, eliminating false pending or unclassified families after successful stages.
- improve acceptance tests for partial, failed, and blocked runs
  Current batch: reporting tests now cover terminal-state mapping, document-history truthfulness, and explicit execution-exception disclosure.
  Current batch: all 78 local backend tests pass, including adapters, scope files, profile contracts, benchmarking, redaction, reporting, workflow behavior, JSON-safe manifests, and missing-report recovery; a deterministic 14-page PDF fixture also passes visual QA and assertions for coverage labels, evidence references, canonical URLs, and secret removal.
  Current batch: advisory-locked runner startup recovery now backfills terminal scans whose report record was not committed, without requiring the assessment scan to run again.
- finalize Light benchmark gates
  Current batch: benchmark threshold floors are now codified in backend logic for Light, Medium, and Aggressive measured precision, recall, and evidence completeness.

### Phase 1.1: assessment-entry truthfulness

- align assessment preview with the real coverage contract
  Current batch: preview now returns methodology coverage depth, current release claim, explicit non-goals, and dispatch warnings for missing scope or authentication.
- remove stale marketing-style profile copy from pre-dispatch UX
  Current batch: the assessment builder now presents contract-driven language instead of implying unsupported depth from generic copy alone.

### Phase 2: Medium release build

- surface Medium artifact summaries and coverage clearly
- implement deterministic auth/session/API/input/authz validation adapters
- define Medium fixtures and case oracles
- benchmark Medium for precision, recall, repeatability, and evidence completeness

### Phase 3: Aggressive promotion

- add broader approved-depth checks without breaking the non-exploitative boundary
- add multi-role and workflow-aware deterministic coverage where authorized
- define the human-baseline comparison protocol

### Phase 4: Release gating

- encode the checklist as CI or release gates
- prevent unsupported profile claims
- require benchmark and evidence gates before profile promotion

## 8. Definition of Done

The backend is `10/10` only when:

1. the declared checklist is fully satisfied,
2. the supported profile claims are benchmark-backed,
3. the evidence contract survives real and failure-path runs,
4. the reports are generated from a trustworthy fact set,
5. and no critical domain remains “known weak but acceptable.”

Anything less can still be useful and impressive, but it is not honestly `10/10`.
