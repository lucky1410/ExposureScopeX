# ADR 0001: Control Plane and Worker Separation

**Status:** Accepted
**Reviewed:** 2026-09-09

## Context

Security scanners are slow, failure-prone and more privileged than normal API
requests. Running them in web handlers creates timeouts and unsafe coupling.

## Decision

FastAPI owns identity, scope, planning and persistence. Celery workers execute
bounded scanner plans. PostgreSQL is authoritative; Redis transports work and
progress. Workers receive identifiers and validated configuration, not arbitrary
shell commands.

## Consequences

Scans survive browser disconnects and can be cancelled/recovered. Queue and
worker health become operational dependencies. Strong tenant and provenance
checks are required at both dispatch and ingestion.

## Alternatives

Synchronous API execution was rejected. Immediate microservice decomposition
was rejected until scale requires it.
