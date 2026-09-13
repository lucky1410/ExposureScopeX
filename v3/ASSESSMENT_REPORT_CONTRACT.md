# Assessment and Reporting Contract

Status: mandatory migration baseline  
Applies to: ExposureScopeX v3 and later  
Safety boundary: authorized, non-exploitative vulnerability assessment

This contract preserves the assessment, evidence, and reporting work completed in
the previous implementation. A scan is not considered production-ready merely
because its orchestration reaches 100 percent.

## 1. Light Assessment Profile

Light is a rapid, low-impact exposure baseline. It intentionally performs fewer
requests than Medium or Aggressive, but every planned Light stage must run to a
recorded terminal state.

| Order | Stage | Required outcome |
|---:|---|---|
| 1 | Authorization and scope preflight | Normalize the target, enforce allowlist and authorization, reject credentials embedded in URLs, and persist the immutable plan. |
| 2 | Reachability and HTTP profiling | Resolve the authorized target, record redirects, status, server metadata, technologies, and raw request/response evidence. |
| 3 | Passive discovery | Collect same-origin routes from approved passive sources with bounded result counts. |
| 4 | Safe crawling | Crawl same-origin public or authenticated routes with logout, reset, setup, delete, and other mutation routes excluded. |
| 5 | Service discovery | Perform bounded host and service identification appropriate to the target type. |
| 6 | TLS and security configuration | Validate TLS posture, response headers, cookie flags, exposed metadata, and common configuration weaknesses. |
| 7 | Nuclei baseline | Run the approved non-intrusive Light template policy to completion and preserve template-set identity, exclusions, statistics, output, and errors. |
| 8 | Browser evidence | Capture original Playwright screenshots of relevant pages and authenticated state where credentials were explicitly supplied. |
| 9 | Finding normalization | Parse successful output immediately, deduplicate findings, retain severity and confidence rationale, and link every finding to source evidence. |
| 10 | Evidence integrity gate | Verify source artifact and screenshot hashes, timestamps, target association, and finding traceability. |
| 11 | Report generation | Produce DOCX, PDF, and an evidence bundle for complete, partial, failed, and cancelled runs. |

Light must not perform exploitation, attack simulation, credential attacks,
destructive requests, persistence, data extraction, or unbounded active probing.

## 2. Completion Semantics

- `Complete` means every required stage succeeded and all finding evidence passed integrity checks.
- `Partial` means useful work completed but at least one required stage failed, timed out, was blocked, or lacks required evidence.
- `Failed` means execution could not produce a minimally valid assessment result. Any earlier findings and evidence must still be retained and reported.
- `Cancelled` means an operator stopped the run. Completed stages, findings, evidence, cancellation time, and the active stage must still be reported.
- Optional-stage failure never erases successful findings or prevents report generation.
- Progress is calculated from persisted stage states, never from elapsed-time estimation.
- A stage timeout is a bounded failure state, not permission to present the assessment as conclusive.

## 3. Evidence Requirements

Each tool run must retain:

- Tool name and version.
- Sanitized command or immutable adapter configuration.
- Start, finish, duration, attempt, exit state, and timeout budget.
- Original stdout, stderr, and structured output where available.
- A real terminal-output screenshot for human review, labelled as execution evidence.
- SHA-256, media type, byte size, capture timestamp, scan ID, stage ID, and target association.

Each finding must retain:

- The original source artifact and its SHA-256.
- A real browser screenshot of the observed state when visual evidence is applicable.
- The screenshot sidecar metadata and SHA-256.
- The exact tested URL or asset, observation time, tool/template identifier, and confidence basis.
- Reproduction steps that are safe, bounded, and sufficient for an authorized analyst to validate the observation.
- Concrete remediation guidance and a retest condition.

Terminal screenshots prove what a tool emitted; they do not independently prove a
vulnerability. Finding proof must be traceable to the source response/artifact and,
where applicable, the original browser capture. Generated or reconstructed images
are never admissible as forensic evidence.

## 4. Required Client Report Format

Every scan run produces a versioned report with the following order:

1. Cover page and confidentiality marking
2. Index
3. Document History
4. Point of Contact
5. Executive Summary
6. Project Scope
7. Profiling
8. Detailed Findings
9. Critical Risk Findings
10. High Risk Findings
11. Medium Risk Findings
12. Low Risk Findings
13. Informational Findings
14. Appendix A: Engagement Methodology
15. Appendix B: Risk Methodology
16. Appendix C: Testing Methodologies
17. Appendix D: Execution Coverage and Exceptions
18. Appendix E: Evidence Integrity Manifest

Finding sections must contain title, identifier, severity, confidence, affected
asset, description, business impact, technical evidence, original screenshot,
safe reproduction steps, remediation, references, evidence hashes, and retest
criteria. Empty severity sections may be summarized in the index but must not
contain fabricated findings.

The executive summary must clearly state whether the run is Complete, Partial,
Failed, or Cancelled. It must disclose coverage gaps and must not describe a
partial run as a clean result.

## 5. Report Outputs

- DOCX is the editable client deliverable.
- PDF is the fixed-layout client deliverable and must preserve the same content as DOCX.
- The evidence bundle contains original artifacts, original screenshots, sidecars, hashes, and a machine-readable manifest.
- Reports are generated idempotently per scan and format, with explicit versions and generation timestamps.
- Report generation failure is visible and retryable without rerunning completed scanner stages.
- Downloads expose a format selector and never substitute one format while using another file extension.

## 6. Accuracy and Release Gates

DVWA is an authorized integration fixture, not a universal accuracy benchmark.
Light releases must also pass versioned golden datasets containing expected
positives and negatives.

The release record must report:

- Precision, recall, F1 score, false-positive rate, and false-negative rate.
- Stage and template coverage.
- Finding-to-source-evidence coverage.
- Finding-to-original-screenshot coverage where applicable.
- DOCX, PDF, and evidence-bundle generation success.
- Repeatability across identical fixture resets.

No profile may be labelled industry-grade until its benchmark thresholds are
defined, measured, and passed in CI.

## 7. Migration Acceptance Checklist

- [ ] Light plan implements every stage in Section 1 with immutable versioning.
- [ ] Nuclei runs an approved Light policy and records live heartbeats and statistics.
- [ ] Authenticated Playwright coverage uses only explicitly provided test credentials.
- [ ] Successful findings survive later stage failure, timeout, cancellation, or ingestion errors.
- [ ] Every finding is linked to original source evidence and applicable original screenshots.
- [ ] Complete, partial, failed, blocked, and cancelled runs all generate reports.
- [ ] DOCX and PDF match the required structure in Section 4.
- [ ] Evidence bundles verify every included artifact hash.
- [ ] The UI exposes live stages, coverage exceptions, findings, evidence, and report formats.
- [ ] Benchmark results meet approved release thresholds.
