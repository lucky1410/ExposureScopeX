# ExposureScopeX Code and Architecture Review

> Historical review snapshot (2026-08-25). Keep this document as design and
> remediation evidence; do not use its open-item list as current scanner output.
> Revalidate releases through `SECURE_SDLC.md` and the required CI security gate.
> Superseded by `ARCHITECTURE_REVIEW_2026-09-06.md`.

Review date: 2026-08-25

## Current readiness

The platform has a working single-node foundation: authenticated multi-organization REST APIs, assessment and ASM intake, normalized assets, Celery/Redis execution, PostgreSQL persistence, scan cancellation, findings/assets/vulnerability views, integrations, and Docker Compose packaging. It is suitable for controlled development and internal evaluation, but it is not yet production-ready or a complete continuous ASM platform.

This review is based on the executable code, not roadmap labels.

## Resolved in this pass

- Added a tenant-scoped scan execution API and Scans workspace with assessment context, status, phase, percentage, timestamps, errors, worker task ID, recent logs, stop action, and scan-scoped findings navigation.
- Changed active scan execution from buffered output to incremental output parsing, persisted phase progress, recent logs, and dual scan/assessment progress events.
- Changed cancellation from force-killing the Celery task to cooperative child-process shutdown and final-state persistence.
- Added frontend refresh-token rotation. The 15-minute access token now refreshes against the configured 7-day refresh session instead of immediately logging the user out.
- Fixed middleware route matching that accidentally treated every route as public because all paths start with `/`.
- Split scan summaries from log detail so polling does not repeatedly transfer every historical raw log.
- Connected completed scan sessions to idempotent, tenant-scoped ingestion of discovered assets, ports, and findings for the exact assessment and scan.
- Upgraded Next.js from 14.2.15 to the vendor's patched 14.2.35 security release, removing the known critical middleware authorization-bypass exposure from the installed version.

## P0 - Required before production

### Scan authorization is modeled but not enforced

`scan_authorizations` exists, but assessment create/run and ASM scan endpoints do not require an active authorization record or explicit user attestation. Active scanning can be started without a platform-level scope gate.

Required work: authorization workflow, target/scope matching, expiry checks, role approval, immutable evidence, and enforcement in every active execution endpoint.

### WebSocket progress is unauthenticated

`/ws/scan/{scan_id}` accepts any client that knows an ID and does not verify organization ownership. The new Scans page uses tenant-scoped REST polling, but the WebSocket endpoint must be authenticated before it is used by the UI.

### Secrets and browser sessions need production hardening

Access and refresh tokens are stored in browser-readable storage. Refresh now functions correctly, but production should move refresh credentials to Secure, HttpOnly, SameSite cookies with CSRF protection, token revocation/rotation tracking, and a server-side logout endpoint.

## P1 - Required for a dependable operator platform

- No heartbeat-based reconciler marks orphaned Celery `queued`, `running`, or `cancelling` executions after worker loss or host restart.
- Local thread fallback scans are now reconciled after backend restart, but durable Celery executions still need heartbeat-based orphan detection and recovery.
- No database-backed scheduler or Celery Beat service provides recurring assessment/ASM scans, maintenance windows, or per-target cadence.
- Progress is phase-based rather than work-unit based. Batch scans need per-asset counters and weighted phase completion for a truthful aggregate percentage.
- Scan logs are stored in one database text field with a 50 KB tail. There is no append-only event/log table, searchable output, artifact manifest, or retention policy.
- Worker concurrency is fixed at two with no queue priority, per-organization quotas, fair scheduling, worker capability registry, or distributed scanner support.
- Worker tools are compiled from unpinned `@latest` sources, making builds slow and non-reproducible; use pinned versions or verified release artifacts in a separately versioned scanner base image.
- Result and Docker storage have no enforced retention, quota, archive, or disk-pressure controls; deleting an assessment cascades database rows but currently leaves its scan artifact directories on disk.
- RBAC values exist, but most mutation endpoints only require authentication and do not enforce admin/manager/analyst/viewer permissions.
- Audit coverage is partial. Assessment, scan, asset, finding, API-key, integration, and user mutations need consistent immutable audit events.
- Error handling lacks stable machine-readable error codes and correlation IDs across API, Celery task, subprocess, and UI layers.
- The test suite is far below production confidence: no API isolation suite, auth refresh tests, database integration tests, worker subprocess tests, cancellation race tests, or browser E2E suite.
- Next.js 14 is outside the currently maintained release lines; plan and regression-test a move to a supported Next.js 15/16 line for later 2026 security fixes.
- The pruned production dependency install still reports two high-severity advisories after the 14.2.35 patch. Resolve and verify these during the supported-major migration; a full registry audit requires explicit approval because it transmits the dependency inventory.

## P2 - Feature completeness gaps

- Scan profiles cannot be named, saved, versioned, shared, or scheduled from the UI.
- Nuclei template sources have no inventory, version pinning, trust policy, update status, rollback, custom-template editor, or per-scan template manifest.
- ASM relationships are heuristic; there is no durable evidence-backed asset relationship graph or merge/review workflow.
- Business-logic testing is configuration text, not a stateful workflow model with authentication journeys, roles, invariants, and replayable test cases.
- Findings lack complete assignment, comments, SLA, evidence history, duplicate/merge, risk acceptance, exception expiry, and ticket synchronization workflows.
- Reports are not yet a verified assessment deliverable pipeline with immutable artifact versions and download authorization.
- Cloud inventory needs production credential validation, least-privilege guidance, sync checkpoints, deletion reconciliation, and provider-specific integration tests.
- Threat intelligence, malware, privilege escalation, learning, and several utility pages are useful tool/resource surfaces but are not yet correlated operational workflows.
- There is no notification-rule engine, digesting, escalation policy, or reliable delivery/outbox pattern.
- There is no backup/restore workflow, disaster-recovery test, migration rollback procedure, observability stack, SLOs, or deployment upgrade validation.

## Recommended implementation order

1. Add full scan-ingestion integration and isolation tests, including DNS/TLS/technology timelines and report artifacts.
2. Enforce scan authorization and RBAC, then secure WebSocket/session handling.
3. Add stuck-task reconciliation, event/log persistence, storage retention, and scheduled scans.
4. Add trusted Nuclei template lifecycle management and artifact manifests.
5. Expand ASM relationship evidence, business workflows, findings lifecycle, and reporting.
6. Add integration, worker, security, and browser E2E suites before declaring production readiness.
