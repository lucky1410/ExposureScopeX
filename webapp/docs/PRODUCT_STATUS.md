# ExposureScopeX Product Status

**Reviewed:** 2026-09-09
**Release:** 2.2.0
**Deployment posture:** controlled self-hosted use

## Product position

ExposureScopeX is a self-hosted exposure-management and security-assessment
platform. Its core is a normalized model for assessments, assets, scans,
findings, evidence, relationships, investigations, and reports. It orchestrates
mature open-source scanners instead of rebuilding them.

The platform is appropriate for authorized internal testing, labs, and
controlled practitioner evaluation. It is not yet an enterprise SaaS, an
unattended exploitation platform, or a replacement for specialist manual
penetration testing.

## Current capabilities

| Area | Status | Current behavior | Important remaining work |
|---|---|---|---|
| Assessments | Operational | Multi-target/CSV intake, preview, profiles, start, cancel, retry, clone, delete and scan-scoped results; deployed API journey verified | Browser journey and concurrent recovery assurance |
| ASM | Operational baseline | Target intake, cloud sources, discovery, scan-all, cancellation and findings | Differential alerting and ownership review |
| Assets and graph | Operational | Inventory, DNS, ports, TLS, headers, technologies, relations, drift and timeline | Merge/split governance and confidence review |
| Findings | Operational | Scan/assessment/asset filters, observations, workflow activities, historical backfill and comparable-scope reopen/resolve automation | Browser concurrency and lifecycle policy assurance |
| Scan operations | Operational | Queues, progress events, tool runs, canonical execution manifests, artifacts, worker capabilities, quotas, leases and recovery | Split signed scanner images and load assurance |
| MCP security | Operational baseline | Authenticated HTTP assessment, non-destructive probes, exchanges, cancellation and findings | Prerequisite assistant, replay profiles and connected-agent labs |
| Cloud/CSPM | Conditional | Prowler adapter and cloud normalization; ScoutSuite contract | Production-account validation and workload identity |
| Repository/image | Conditional | Gitleaks, Trivy, Syft, Grype, SBOM and normalized findings | Signed split worker images and registry auth UX |
| Kubernetes/mobile | Partial/conditional | Static Trivy-oriented artifact pipelines and dedicated queues | Upload UX, device/emulator dynamic tests and specialist adapters |
| Reports | Operational | Async HTML, PDF, Markdown, SARIF, CSV, JSON and evidence bundles with cancellation, quotas, integrity and audit | Branding, scheduled delivery and audience packs |
| Scheduling | Operational | Recurring assessment runs, time zones, maintenance windows, missed-run policy, overlap prevention, pause/resume and history | Notification/digest integrations |
| Audit and storage | Operational | Database-enforced append-only audit records, search/export, correlation IDs, session-device visibility/revocation, tenant usage, quotas, retention policy, cache separation, and token-bound cleanup preview | Audit-retention policy and automated mutation-coverage assurance |
| Integrations | Conditional | Encrypted Slack, Teams, PagerDuty, Jira, Splunk, Elastic, GitHub SARIF and GreyNoise settings | Replay, bidirectional sync and webhook lifecycle |
| AI analyst | Partial | Capability-aware guided analysis | Evidence grounding, evaluations, approvals and model provenance |
| Practitioner libraries | Reference-only | Recon, testing, privesc, malware, threat-intel, learning and resources | Keep separate from executable capabilities |

## Product guardrails

- A menu or catalog record is not proof that a capability executed.
- Active testing requires documented authorization and scope.
- Destructive tests, credential attacks and state-changing MCP probes require
  explicit approval and isolated environments; they are not default behavior.
- Conditional checks report `blocked`, `skipped`, `unavailable`, or
  `inconclusive`, never success.
- Results remain attributable to organization, assessment, scan, asset, tool
  run and evidence source where applicable.

## Completion standard

A feature is delivered only when connected behavior, tenant authorization,
safe defaults, cancellation, graceful failure, normalized evidence, provenance,
observability, documentation, and automated success/failure coverage exist.
Current priorities are tracked only in `../BACKLOG.md`.

## Verification baseline

As of 2026-09-09, 96 backend tests, 16 shell tests, frontend lint, the 38-route
production build, and the self-cleaning deployed API E2E journey pass. External
cloud accounts, mobile device farms, Kubernetes controllers, third-party
webhooks, browser concurrency and sustained load remain environment-dependent
or pending assurance; they are not represented as live-validated.
