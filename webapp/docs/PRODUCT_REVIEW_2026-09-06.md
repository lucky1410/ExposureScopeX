# ExposureScopeX Product Review

> Historical review snapshot. Current status is maintained in
> `PRODUCT_STATUS.md`; current work is maintained in `../BACKLOG.md`.

**Reviewed:** 2026-09-06
**Release:** 2.2.0
**Evidence:** executable routes, UI pages, services, 89 backend tests, container images, deployed schema `012_trust_control_plane`

## Executive Decision

ExposureScopeX is moving in the right direction. The strongest product decision is the shared normalized model for assets, scans, findings, relationships, evidence, and reports across ASM, assessments, MCP, cloud, repositories, images, mobile, and investigations. Authorization, cancellation, scheduling, provenance, and reporting are increasingly platform services rather than one-off module patches.

The current product is a credible self-hosted security operations and assessment platform for controlled internal use. It is not yet an enterprise SaaS or a substitute for specialist manual penetration testing. The next release should deepen lifecycle reliability and operator workflows rather than add many more scanners.

## Product Status

| Area | Status | What works now | Main remaining gap |
|---|---|---|---|
| Assessments | Operational | Multi-asset intake, CSV normalization, profiles, execution, stop, retry, delete, scoped findings | Saved/custom profiles, execution preview, scheduling, safe resume |
| ASM | Operational baseline | Targets, discovery, cloud sources, scans, cancellation, findings | Continuous scheduling, differential alerting, ownership review |
| Asset intelligence | Operational | Canonical identities, relations, graph, drift, timelines, ownership and technical evidence | Merge/split review, tags, criticality, aliases, import review queue |
| Findings/vulnerabilities | Operational baseline | Scan isolation, filters, status changes, suppressions, stable identities and per-scan observations | Automatic reopen/resolve, historical backfill, assignment/comments/SLA/retest lifecycle |
| Scan operations | Operational | Queue routing, quotas, priority, leases, worker capability registry, events, artifact hashes, provenance, work-unit progress, recovery | Complete wordlist/policy/argument manifest |
| MCP security | Advanced baseline | Stateful HTTP probes, redacted exchanges, findings, authorization and cancellation | Profiles/replay, prerequisite UX, config linting, connected-agent lab, rich reports |
| Cloud/CSPM | Conditional | Cloud sync plus Prowler and optional ScoutSuite normalization | Provider connection UX, short-lived identity validation, production adapter assurance |
| Repository/image | Operational baseline | Trivy, Syft, Grype, Gitleaks, SBOM and finding ingestion | VEX, policy packs, attestation/license/SBOM drift workflows |
| Mobile/Kubernetes runtime | Conditional | Static/specialized stages and bounded external-adapter contracts | Production dynamic controllers, device/lab orchestration and independent assurance |
| Investigations | Operational baseline | Cases, linked findings, evidence, notes, timeline | Assignment, collaboration, approvals, ticket synchronization |
| Reporting | Operational | Seven formats, scoped data, integrity hashes, evidence bundles | Async generation, branding, scheduled delivery, audience-specific packs |
| Integrations | Operational baseline | Encrypted provider configuration and test/dispatch adapters | Delivery policies, retries/dead letters, bidirectional workflow state |
| Security/tenancy | Strong self-hosted baseline | Roles, org scoping, scan authorization, sessions, SSRF/rate controls, secret encryption | SSO/MFA/SCIM, custom roles, complete audit verification, KMS rotation |
| Operations | Strong single-node baseline | Health, metrics, alerts, backups, retention, migration/deploy verification | Capability images, restore drills, HA/autoscaling and production SLO evidence |
| AI analyst | Early/partial | Guided analysis and capability-aware platform context | Evidence grounding, evaluations, approvals, budgets, prompt/model provenance |

## Direction Review

### Decisions to continue

- Keep PostgreSQL as the source of truth and Redis as replaceable execution infrastructure.
- Keep scanner adapters behind normalized evidence contracts rather than exposing raw tool output as the product model.
- Prefer mature open-source tools with pinned versions, safe presets, provenance, and graceful absence over weak native clones.
- Keep potentially destructive testing explicit, authorized, isolated, cancellable, and operator initiated.
- Preserve a memory-efficient local profile while offering isolated workers and Kubernetes Jobs for scaled deployments.

### Deviations to correct

- Capability breadth is growing faster than lifecycle depth. Do not add another scanner until findings, retries, schedules, manifests, and tests are stronger.
- Some UI modules communicate future capability more strongly than their backend depth. Mark conditional capabilities and prerequisites clearly.
- Planning documents previously mixed delivered work, duplicate ideas, and historical acceptance criteria. The canonical backlog now separates these.
- Phase-level completion is useful but not enough for exact per-target progress. Future adapters should emit target-level observations where tools support it.
- The broad worker image is practical locally but raises patching, storage, and blast-radius costs. Split signed capability images before large-scale deployment.

## Recommended Product Sequence

### Release 2.3: Trustworthy execution

1. Worker capability registry and complete execution manifests.
2. Stable finding observations and full lifecycle workflow.
3. Saved profiles, execution preview, failed-run recovery, and schedules.
4. Full integration, tenant-isolation, browser, cancellation, and load test journeys.
5. Storage control plane, restore drills, and signed capability images.

### Release 2.4: Practitioner depth

1. Asset governance and import review.
2. Business-logic and manual testing workspaces.
3. MCP replay, prerequisites, exchange analysis, configuration linting, and report packs.
4. Vulnerability intelligence using KEV, EPSS, exploit maturity, and remediation confidence.
5. Asynchronous branded and scheduled reporting.

### Release 3.x: Enterprise platform

1. SSO/MFA/SCIM, custom roles, service accounts, and tenant administration.
2. Public API/SDK/webhook lifecycle and workflow integrations.
3. Helm/Terraform, external data services, autoscaling, SLOs, and regional controls.
4. Compliance, supply-chain, threat-intelligence, MSSP, and evidence-grounded AI packs.

## Features Not Worth Adding Yet

GraphQL, Kafka/NATS, native rewrites of Prowler or Nuclei, unrestricted exploitation, wireless/packet-capture tooling in the standard worker, and an arbitrary-code plugin marketplace would increase complexity or risk without solving the present product bottlenecks. They should remain deferred until a measured customer or scale requirement exists.

## Completion Standard

“Implemented” means more than a menu or adapter stub. A feature must provide connected API/UI behavior where relevant, tenant and authorization enforcement, safe defaults, cancellation and failure behavior, normalized evidence, provenance, observability, documentation, and automated success/failure tests. Conditional integrations must state their prerequisites and must never report unavailable checks as successful.
