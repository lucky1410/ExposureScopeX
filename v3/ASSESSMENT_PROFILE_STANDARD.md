# Assessment Profile Standard

Status: design baseline for implementation and benchmark approval  
Methodology version: 1.0.0-draft  
Safety boundary: authorized, deterministic, non-destructive security testing

## 1. Purpose

Light, Medium, and Aggressive describe assessment depth and assurance, not how
long a tool is allowed to run. A deeper profile must include every applicable
test family from the profile below it. More requests, templates, screenshots,
or timeout budget do not by themselves create a deeper assessment.

ExposureScopeX must not describe a profile as a penetration test unless it
performs evidence-backed validation across the applicable OWASP WSTG test
families. Tool completion is execution telemetry, not a measure of security
coverage or accuracy.

## 2. Shared Analyst Workflow

Every profile follows the same controlled workflow:

1. Confirm authorization, rules of engagement, target boundaries, exclusions,
   testing window, credentials, permitted request classes, and stop conditions.
2. Create an immutable, versioned test plan and applicable-test denominator.
3. Establish unauthenticated and supplied authenticated contexts and prove
   their state without retaining plaintext secrets.
4. Inventory hosts, services, routes, APIs, parameters, roles, session state,
   technologies, and trust boundaries to the depth required by the profile.
5. Execute deterministic checks mapped to versioned WSTG and ASVS identifiers.
6. Validate candidate findings independently using bounded, non-destructive
   observations or safe canary requests permitted by the rules of engagement.
7. Normalize and deduplicate findings while retaining every original artifact.
8. Assign technical severity, confidence, affected asset, and a separate
   business-context status. Unknown business context must not be invented.
9. Verify evidence hashes, finding-to-evidence traceability, reproduction steps,
   and contradictory observations.
10. Publish Complete, Partial, Failed, or Cancelled results with explicit tested,
    not-tested, inconclusive, and failed coverage.

## 3. Profile Definitions

Nuclei coverage is profile-manifest driven. Each run resolves the exact paths
from the pinned template release, stores that inventory as immutable evidence,
and executes that same selector contract. Stage deadlines are watchdogs only;
they never establish or imply coverage. A timed-out inventory is incomplete and
must not be reported as completed coverage.

### Light - Exposure Baseline

Purpose: rapid, low-impact identification of externally observable exposure and
configuration risk. It is suitable for triage, frequent regression checks, and
pre-assessment reconnaissance. It is not a full penetration test.

- One supplied role plus unauthenticated comparison when credentials exist.
- Bounded host, service, TLS, HTTP, technology, route, API-description, cookie,
  header, metadata, and common exposure checks.
- Same-origin crawl and form/parameter inventory without submitting mutation
  forms or security payloads.
- Approved passive and non-intrusive signature checks.
- Independent evidence and report validation.
- No injection payloads, authorization boundary probes, business-logic
  workflows, credential attacks, file uploads, or state-changing requests.

### Medium - Verified Application Assessment

Purpose: analyst-equivalent, authenticated vulnerability assessment using safe,
non-destructive validation. Medium includes all Light coverage.

- Multiple supplied roles where available, with an authorization matrix.
- Deeper route, API, parameter, input-source, session, and workflow inventory.
- Safe canary and differential-response validation for injection, reflected
  output, redirects, path handling, error behavior, and server-side requests.
- Authentication, session lifecycle, CSRF, object/function authorization, API
  authorization, client-side, and cryptographic-control checks where applicable.
- Candidate findings require independent replay or corroboration before being
  presented as confirmed.
- Mutation checks are disabled unless individually classified as reversible and
  explicitly allowed by the rules of engagement.

### Aggressive - Comprehensive Controlled Assessment

Purpose: maximum approved breadth and depth while remaining non-destructive.
Aggressive includes all Medium coverage. The name refers to coverage and request
intensity, never permission to exploit or damage a target.

- Full supplied role matrix, workflow and trust-boundary traversal.
- Expanded endpoint, parameter, content-type, protocol, API, and service depth.
- Approved reversible state-transition checks with before/after evidence and
  cleanup verification when explicitly authorized.
- Concurrency, rate, and test-window controls remain mandatory.
- No persistence, destructive denial of service, credential theft, unrestricted
  data extraction, malware, lateral movement, or unapproved exploitation.

## 4. Coverage Matrix

| Test family | Light | Medium | Aggressive |
|---|---|---|---|
| Scope and authorization | Enforce | Enforce | Enforce |
| Attack-surface and route inventory | Bounded | Deep | Comprehensive |
| Service, TLS, HTTP and configuration | Baseline | Extended | Comprehensive |
| Authentication mapping | Observe supplied role | Validate flows | Multi-role and edge cases |
| Session management | Cookie/config review | Safe lifecycle validation | Expanded lifecycle validation |
| Authorization | Inventory only | Safe object/function checks | Full supplied-role matrix |
| Input validation | Parameter inventory | Safe canary/differential checks | Expanded encodings and contexts |
| Client-side security | Headers and inventory | Safe DOM/source-sink checks | Expanded browser workflows |
| API security | Discover schemas/routes | Authenticated endpoint checks | Multi-role and content-type depth |
| Business logic | Workflow inventory | Selected safe invariants | Approved reversible transitions |
| Evidence validation | Required | Required | Required |
| Analyst review gate | Exceptions only | Required for confirmed findings | Required for confirmed findings |

## 4.1 Current Implementation Boundary

The profile contract above is the promotion target. The current implementation
must report its actual capability rather than infer it from a selected profile
name, increased timeout, crawl budget, or template count.

| Profile | Current deterministic implementation | Release claim allowed today | Required promotion work |
|---|---|---|---|
| Light | Scope preflight, HTTP profiling, bounded service/TLS discovery, authenticated crawl, header assessment, pinned non-intrusive Nuclei baseline, evidence validation, and reporting | Exposure/configuration baseline only; not a full penetration test | Complete labelled Light fixture set, repeatability runs, negative controls, and approved benchmark gate |
| Medium | Light workflow plus deeper crawler/service/Nuclei budgets; GET-only application route/form/parameter/client-resource inventory; authenticated session-cookie control review; and published API-contract review | Expanded, evidence-backed non-destructive application assessment; not yet a verified application penetration test | Add deterministic, safe, independently replayed adapters for authentication, authorization, input validation, client-side behavior, and API test cases |
| Aggressive | Medium workflow plus the widest allowed crawler/service/Nuclei budgets and a GET-only route-level HTTP policy consistency review | Broadest currently available evidence-backed non-destructive assessment; not yet comprehensive controlled assessment | Add multi-role matrices, workflow coverage, individually authorized reversible checks, full evidence cleanup, and human-baseline benchmark comparison |

An assessment report must always display the resolved plan, applicable-case
coverage, completed checks, exceptions, and the release-eligibility result. A
profile is never promoted based solely on a successful tool exit status.

## 5. Completion and Quality Gates

A profile is Complete only when:

- every applicable required test case has a terminal successful result;
- authentication and role coverage match the immutable plan;
- no required tool or validator timed out, failed, or silently stopped;
- every confirmed finding has reproducible source evidence and valid hashes;
- every inapplicable test records a reason rather than disappearing;
- the report states the applicable, tested, passed, failed, inconclusive, and
  not-tested counts by test family; and
- the profile passes its approved labelled benchmark release gate.

The initial release targets are proposals subject to benchmark calibration:

| Gate | Light | Medium | Aggressive |
|---|---:|---:|---:|
| Precision | >= 0.95 | >= 0.95 | >= 0.95 |
| Recall on profile-applicable positives | >= 0.80 | >= 0.90 | >= 0.95 |
| Finding evidence completeness | 1.00 | 1.00 | 1.00 |
| Repeatability over three clean resets | >= 0.95 | >= 0.95 | >= 0.95 |
| Required-stage completion | 1.00 | 1.00 | 1.00 |

These thresholds cannot be claimed until the benchmark sample, confidence
interval, fixture version, target configuration, tool versions, and template
versions are published with the result.

## 6. Benchmark Rules

- Each fixture is immutable and identified by application version, image digest,
  configuration, security level, seed data, credentials/roles, and reset method.
- Ground truth identifies expected-positive and expected-negative cases using
  stable case IDs mapped to CWE, WSTG, ASVS, endpoint, role, and safe oracle.
- A detected case is a true positive only after its evidence satisfies the case
  oracle. A title or scanner signature alone is insufficient.
- Unknown, contradicted, or oracle-failing reports are false positives.
- Missing applicable positive cases are false negatives.
- Duplicate reports do not increase true positives and are measured separately.
- Accuracy is published only when the negative-case denominator is explicit.
- DVWA is one web-application fixture; API, authorization, configuration, TLS,
  negative-control, and real-world regression fixtures are also required.

### Aggressive Human-Baseline Gate

"Better than a human analyst" is a benchmark result, not a product label. The
Aggressive profile may use that claim only for a published benchmark in which
the platform and an approved panel of qualified analysts receive the same
targets, scope, credentials, seed state, safety restrictions, and elapsed-time
budget. Neither side receives the hidden ground truth.

The comparison publishes per test family and overall:

- independently confirmed true positives, false positives, and false negatives;
- precision, recall, F1, and severity-weighted recall;
- applicable-case coverage and unique attack-surface coverage;
- evidence completeness, reproducibility, and duplicate rate;
- elapsed analyst/runtime hours and time to first confirmed finding; and
- critical business-logic or authorization cases detected only by either side.

Aggressive passes this gate only when it meets all absolute Aggressive quality
gates, demonstrates statistically supported non-inferiority in precision and
superiority in recall or applicable-case coverage, produces complete forensic
evidence, and has no undisclosed critical false negatives. Results must state
the tested domains; success on a scanner-heavy fixture cannot be generalized to
business-logic, multi-role authorization, or novel-vulnerability assessment.

## 7. Implementation Sequence

1. Approve this profile and safety contract.
2. Create versioned methodology/test-case and fixture manifests.
3. Implement the benchmark scorer and CI release gate.
4. Map existing adapters to test cases and expose honest coverage gaps.
5. Implement missing deterministic Medium checks one test family at a time.
6. Validate Light, then Medium, then Aggressive against labelled fixtures.
7. Promote a profile only after its evidence, accuracy, and report gates pass.
