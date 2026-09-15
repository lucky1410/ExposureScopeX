# ExposureScopeX Canonical Backlog

**Reconciled:** 2026-09-09
**Current release:** 2.2.0
**Status source:** executable code, automated checks, and schema `018_operation_control_plane`

This is the current product backlog. `docs/BACKLOG.md` is historical story
evidence and must not be used as completion truth. Current product status is in
`docs/PRODUCT_STATUS.md`; documentation authority is in `docs/README.md`.

Status meanings:

- **Delivered:** operational end to end in the current self-hosted deployment.
- **Partial:** useful implementation exists, but the complete product workflow or production assurance is unfinished.
- **Next:** required for a dependable production security platform.
- **Later:** valuable after the Next work is complete.
- **Conditional:** requires an external adapter, cloud account, or production service to validate fully.

## P0 Architecture Baseline

- [ ] **P0 Governing reference architecture:** maintain the editable layered system view, current/target deployment mappings, capability boundary, trust boundaries, end-to-end transaction, delivery increments, and unresolved ADR decisions in `docs/REFERENCE_ARCHITECTURE.md`; architecture review is required before adding a service, queue, data store, model, scanner class, external trust boundary, or cloud dependency.
- [ ] **P0 Architecture contract tests:** enforce deterministic scan planning, forbidden exploitation utilities/templates, fail-closed scope at every boundary, tenant ownership, bounded stages, and evidence-gated report finality in unit, integration, and deployed journey tests.
- [ ] **P0 Evidence acquisition reliability:** make finding-specific Playwright capture network-equivalent to scanner execution, retry bounded connection failures, persist capture diagnostics, and prevent error-state images from satisfying evidence coverage.
- [ ] **P0 Report control plane:** guarantee terminal scans enqueue DOCX, PDF, and evidence bundles exactly once; add idempotent retry, queue timeout/recovery, stuck-job reconciliation, report versioning, and explicit Partial/Final evidence-gate state in API and UI.
- [ ] **P0 Profile specification:** version 1.0 executable Light, Medium, and Aggressive breadth/depth contracts and quality gates are published by the API; complete immutable persistence per scan, expected-duration calibration, saved-profile migration, and full acceptance-fixture coverage.
- [ ] **P0 Documentation-driven Nuclei profiles:** review the version-pinned official Nuclei documentation and derive measurable Light, Medium, and Aggressive template, protocol, headless, concurrency, rate, retry, timeout, and evidence policies; validate each profile against benchmark targets before release (ESX-043).
- [ ] **P0 Benchmark validation:** deterministic confusion-matrix, evidence, scope, execution-accounting, repeatability gates, CLI scoring, and a smoke fixture are implemented; add digest/commit-pinned OWASP Benchmark, crAPI, Juice Shop, WebGoat, DVWA, negative-control protocol-lab adapters, three-run CI matrices, historical score storage, and release trend UI before claiming industry benchmark certification.
- [ ] **P0 Architecture conformance:** reconcile architecture, threat model, data model, deployment, scan lifecycle, support matrix, and roadmap with executable code; CI must reject stale schema heads, forbidden capability claims, and undocumented boundary changes.
- [ ] **P0 Production reference architecture:** define single-node and Kubernetes topologies, trust zones, queue isolation, worker images, egress controls, secrets, immutable storage, observability, RPO/RTO, sizing, and failure-mode acceptance tests.

## Delivered

- [x] Assessment creation, flexible CSV intake, normalization, multi-asset storage, execution, cancellation, retry, deletion, and scan-scoped results
- [x] ASM target intake, flexible CSV normalization, discovery scans, cloud-source records, cancellation, findings, and target deletion
- [x] Domain, URL, IP, CIDR, ASN, repository, container image, cloud account, Kubernetes, Android, iOS, and MCP seed handling
- [x] Celery queue routing, per-organization quotas, priority, distributed execution leases, durable scan events, tool provenance, and stale-run recovery
- [x] Optional queue-specific worker pools plus a lower-memory shared local worker
- [x] Asset inventory, ownership, ports, DNS, TLS, technologies, headers, graph, drift, timeline, and assessment filters
- [x] Scan-scoped findings and vulnerability views with asset/source/severity/status filters and controlled status transitions
- [x] Investigation records with linked findings, notes, evidence, and timelines
- [x] MCP HTTP security assessment with advanced probes, authorization controls, cancellation, redacted exchanges, and finding normalization
- [x] Prowler and optional ScoutSuite CSPM adapters, cloud resource normalization, and CSPM finding ingestion
- [x] Container/repository scanning with Trivy, Syft, Grype, Gitleaks, SBOM generation, and normalized results
- [x] HTML, PDF, Markdown, SARIF, CSV, JSON, and evidence-bundle reports with immutable scope and SHA-256 integrity
- [x] Encrypted integrations for Slack, Teams, PagerDuty, Jira, Splunk, Elastic, GitHub SARIF, GreyNoise, and cloud sources
- [x] Role capabilities, organization ownership checks, scan authorization records, encrypted secrets, session rotation, rate limits, SSRF controls, and audit records
- [x] S3-compatible artifact storage, retention jobs, local cleanup, backup/restore scripts, metrics, alerts, Grafana, runtime health, and deployment verification
- [x] Dark/light themes, responsive navigation, collapsible sidebar, branded assets, favicon, global search, notifications, and runtime settings
- [x] Daily Nuclei template refresh without rebuilding images; official/community runtime templates are stored in a reusable Docker volume
- [x] Worker capability registry with fixed scanner/version discovery, heartbeats, queue/tool compatibility checks, dispatch rejection, and Operations visibility
- [x] Built-in and saved custom scan profiles, execution preview API/UI, and failed-run retry/clone foundations
- [x] Secret-safe execution manifests with redacted arguments, image/tool/template/wordlist/policy identities, artifact digests, and canonical manifest hashes
- [x] Stable finding identities and per-scan observations with comparable-scope reopen/resolve automation and legacy backfill
- [x] Asynchronous report generation with a dedicated queue, durable states, cancellation, bounded output, integrity checks, quota enforcement, and audit events
- [x] Recurring assessment schedules with IANA time zones, maintenance windows, missed-run policy, overlap prevention, pause/resume, and durable run history
- [x] Searchable organization audit log UI/API, CSV export, correlation IDs, and broad mutation coverage
- [ ] Canonical architecture conformance is being re-baselined against runtime behavior and the accepted deterministic-scanning and evidence-gate invariants.

## Next: Production Control Plane

- [x] **P0 Complete execution manifest:** artifact SHA-256 manifests, worker image/tool versions, Nuclei template commits, wordlist/policy identities, and redacted per-argument provenance are persisted.
- [x] **P0 Finding observation model:** stable identities and per-scan evidence observations are persisted and exposed with comparable-scope reopen/resolve transitions and historical backfill.
- [x] **P0 Lifecycle workflow:** assignment, comments, verification/retest, due dates, SLA, suppressions, risk acceptance, exceptions, approvals, expiry review, audit history, and operator workspace.
- [ ] **P0 Full journey tests:** a self-cleaning deployed API journey now covers auth, mixed CSV import, multi-asset scope, schedules, all report formats, real local scan dispatch, durable command provenance, cancel/retry, audit export, and delete; isolated-database, cross-tenant, browser, subprocess-race, and concurrent queue/load suites remain.
- [ ] **P0 Audit assurance:** append-only database enforcement, session-device detail, export/search UI, correlation IDs, and actor/tenant provenance are delivered; add audit-retention controls and automated mutation-coverage verification.
- [ ] **P0 Disaster recovery assurance:** automated backup restore drills, documented RPO/RTO, migration rollback rehearsal, off-host immutable backups, and release evidence.
- [x] **P1 Storage control plane:** tenant quota enforcement, artifact/report inventory, policy editing, disk alerts, separated cache/artifact accounting, and token-bound retention preview/safe cleanup UI are delivered.
- [ ] **P1 Signed scanner images:** split web, cloud, artifact/mobile, and report capabilities into smaller digest-pinned images with SBOMs and attestations.
- [ ] **P1 Report productization:** asynchronous generation, dedicated queue, durable state, retry policy, cancellation, limits, integrity, and audit are delivered; add branding/watermarking and scheduled delivery.

## Next: Practitioner Workflows

- [ ] **P1 Enterprise command dashboard and navigation:** deliver a professional, Seven AI-level product experience with a role-aware command center, progressive disclosure, interactive security visualizations, and consistent navigation across red-team, ASM, risk, and purple-team workflows. Acceptance requires configurable KPI/risk/exposure cards; live scan and worker health; severity, trend, attack-path, coverage, and remediation views with drill-down and cross-filtering; saved views and time ranges; global search and command palette; actionable empty/loading/error states; persistent context and breadcrumbs; responsive desktop/tablet/mobile layouts; keyboard navigation and WCAG 2.1 AA validation; reusable documented design-system components; and browser journey tests for the primary analyst and executive paths.
- [ ] **P0 Profile completion:** built-in light/medium/aggressive and saved custom profiles work; add immutable profile versions, dedicated stealth/MCP/CSPM presets, migration and cost history.
- [x] **P0 Execution preview completion:** target/tool/queue/policy, template, wordlist, adapter prerequisites, safety tier, exclusions, and confidence are exposed before dispatch.
- [ ] **P0 Recovery workspace completion:** retry and clone-draft foundations work; add targeted stage reruns, bounded automatic retries, configuration diff, and safe resume where supported.
- [x] **P1 Scheduling productization:** recurring scans, maintenance windows, time zones, missed-run policy, overlap prevention, pause/resume, and durable history are available through the assessment workspace and API.
- [ ] **P1 Differential scanning:** scan only changed assets where safe, compare observations, suppress unchanged noise, and alert on regressions.
- [ ] **P1 Asset governance:** tags, custom taxonomies, business criticality, owner/team directory, scope groups, exclusions, merge/split review, and aliases.
- [ ] **P1 Import review queue:** explain uncertain field mappings, preview normalized rows, correct ambiguous records, and retain source-line provenance.
- [ ] **P1 Business-logic testing:** authenticated journey recorder, roles/personas, invariants, test data, replay, state cleanup, and operator approval for actions.
- [ ] **P1 Manual testing workspace:** proxy/imported HTTP evidence, analyst notes, request/response annotations, manual findings, retest evidence, and chain-of-custody.
- [ ] **P1 Vulnerability intelligence:** CISA KEV, EPSS, exploit maturity, affected-version confidence, remediation availability, and risk-score transparency.

## Next: MCP And AI Security

- [ ] **P1 Programmatic mitigation blueprints for every vulnerability:** generate an implementation-ready remediation package for each surfaced finding, including indirect prompt injection and other AI/MCP failures. Select the blueprint from the affected technology, trust boundary, evidence, exploit path, and deployment context; provide concrete input/output validation code, system/developer prompt hardening, tool and resource allowlists, authorization checks, sandbox/egress policy, API gateway throttling, secret handling, logging, and detection rules where applicable. Every package must include exact target files or configuration surfaces, safe patch/config snippets, prerequisites, security tradeoffs, rollback guidance, unit/integration/adversarial regression tests, expected post-fix behavior, residual risk, confidence and applicability scores, standards mappings, and citations to immutable finding evidence. Generated changes remain operator-review gated, must never claim remediation until validation passes, and must redact secrets and unsafe payload details from exports.
- [ ] **P0 Saved MCP profiles and replay:** baseline, expanded, local-config, and destructive-lab profiles with non-secret reusable configuration.
- [ ] **P0 MCP prerequisite assistant:** validate auth, disposable task IDs, canaries, allowlisted tools/resources, and destructive-test consent before dispatch.
- [ ] **P1 MCP exchange inspector:** grouped conversations, request/response diffs, search, jump-to-finding, selected export, and redaction review.
- [ ] **P1 MCP coverage intelligence:** explain blocked, skipped, downgraded, and inconclusive checks with precise manual follow-up.
- [ ] **P1 MCP configuration scanner:** lint local stdio/server definitions for path hijacking, shell injection, inherited secrets, unsafe roots, and excessive permissions.
- [ ] **P1 Connected-agent testing:** cross-server confused-deputy, token audience, trust-boundary, prompt/tool propagation, and agent-chain simulation in an isolated lab.
- [ ] **P1 MCP report packs:** AppSec, platform, AI-safety, and executive views with protocol coverage and transcript summaries.
- [ ] **P1 Evidence-grounded AI:** citations to immutable evidence, prompt/version provenance, approval gates, hallucination evaluation, cost budgets, and tenant-safe retrieval.

## Later: Platform And Ecosystem

- [ ] **P2 Scoped Blue Team SOC AI integration:** preserve a versioned, tenant-aware extension point for the existing SOC AI platform, but do not place it on the current critical path. When prioritized, exchange authorized findings, evidence, ATT&CK context, detection coverage, incidents, and remediation state through authenticated, signed, idempotent contracts with replay protection, auditability, redaction, retries, dead-letter recovery, canonical cross-platform identifiers, and operator approval for response actions.
- [ ] OIDC/SAML SSO, MFA, SCIM, just-in-time provisioning, custom roles, service accounts, and emergency-access controls
- [ ] Organization onboarding, tenant feature flags, usage metering, billing, client workspaces, regional residency, and tenant retention policies
- [ ] Public API lifecycle: scoped API tokens, idempotency keys, cursor pagination, versioning policy, SDK generation, webhook signing, and deprecation telemetry
- [ ] Integration delivery rules, dead-letter/replay UI, Jira/ServiceNow bidirectional state sync, and scheduled Slack/Teams/email digests
- [ ] Compliance policy packs for PCI DSS, SOC 2, ISO 27001, NIST CSF/800-53, CIS, OWASP ASVS/API Top 10, and organization-specific controls
- [ ] Supply-chain policy packs, VEX ingestion, SBOM drift, SLSA/provenance verification, license policy, and dependency reachability
- [ ] Threat intelligence via STIX/TAXII, Censys, SecurityTrails, AbuseIPDB, CIRCL passive DNS, brand impersonation, leaked credentials, BGP, and C2 correlation
- [ ] Branded templates, scheduled delivery, executive narratives, period comparisons, legal evidence exports, and MSSP aggregate reporting
- [ ] Attack-path simulation with explainable graph edges, remediation what-if analysis, confidence, and evidence-backed executive narratives
- [ ] Plugin SDK with signed manifests, compatibility contracts, sandbox permissions, normalized evidence schemas, and operator approval
- [ ] Helm chart, external PostgreSQL/Redis support, autoscaling guidance, multi-region strategy, and Terraform deployment modules
- [ ] WCAG 2.1 AA audit, keyboard help, localization, PWA notifications, and mobile operations views

## Deliberately Not Prioritized

- Native replacements for mature open-source scanners solely to increase proprietary code
- Unattended exploitation, credential attacks, destructive MCP actions, or unrestricted payload generation
- GraphQL, Kafka/NATS, or microservice decomposition without measured scale or integration requirements
- Wireshark/aircrack-style packet or wireless tooling in the default web platform; these require separate privileged lab workers and a clear product use case
- A marketplace accepting arbitrary community code before signing, sandboxing, capability, provenance, and review controls exist

## Release Gate

A backlog item is Delivered only when its API and UI behavior are connected where applicable, authorization and tenant boundaries are enforced, cancellation/error states are graceful, evidence is normalized, documentation is updated, and automated tests cover success plus failure paths.
