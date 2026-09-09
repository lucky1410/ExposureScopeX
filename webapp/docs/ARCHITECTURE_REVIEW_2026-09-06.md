# Architecture Direction Review

> Historical review snapshot. Current design is maintained in
> `ARCHITECTURE.md` and decisions are recorded in `adr/`.

**Reviewed:** 2026-09-06
**Decision:** Continue the current architecture with controlled decomposition.

## Assessment

The platform is moving in the right direction. A single normalized asset/finding/scan model now serves ASM, assessments, MCP, cloud, software supply chain, mobile, and reporting. Authorization, evidence, scheduling, and cancellation are platform services rather than module-specific patches. Optional adapters preserve deployment flexibility without pretending unavailable tools ran.

## Improvements completed in this review

- Added organization queue policy and distributed concurrency leases.
- Added optional queue-specific worker pools without increasing default local memory.
- Promoted scan events and tool runs from JSON/TSV-only summaries to indexed PostgreSQL records.
- Added runtime tool-version, scanner-image, command-hash, duration, output, and exit provenance.
- Replaced phase-only percentages with persisted target-aware work units.
- Corrected stale reconciliation so queued scans are not failed for legitimate waiting.
- Added redacted adapter/storage/isolation health checks and an operator configuration page.
- Added immutable report scope across scan, asset, severity, status, owner, and module/source.

## Remaining architectural risks

- The worker image is intentionally broad and large. Queue pools isolate runtime contention but still share one tool image; separate signed capability images are the next scaling optimization.
- Bash remains the scanner orchestration engine. Continue moving state transitions and argument construction into typed Python adapters without rewriting stable modules only for style.
- Report rendering is synchronous inside the API process. Very large reports should eventually move to a report queue with an outbox state machine.
- Redis priority plus tenant limits prevents starvation and noisy-neighbor saturation, but it is not strict weighted round-robin fairness.
- Dynamic mobile and live Kubernetes depth depends on external authorized controllers and their own assurance evidence.

## Guardrails

Do not add a scanner solely to increase the tool count. New modules must normalize evidence, declare prerequisites and safety tier, support cancellation, record provenance, and pass tenant-isolation and failure-path gates. PostgreSQL remains the source of truth; Redis and filesystem outputs remain replaceable execution infrastructure.
