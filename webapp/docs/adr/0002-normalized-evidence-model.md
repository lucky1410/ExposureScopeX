# ADR 0002: Normalized Evidence Model

**Status:** Accepted
**Reviewed:** 2026-09-09

## Context

ASM, assessments, MCP, cloud and software scanners can rediscover the same
asset or issue. Module-specific stores create duplicates and cross-scan leakage.

## Decision

Use shared assets, relations, vulnerabilities, finding identities, findings and
per-scan observations. Preserve raw artifact/tool attribution. Reports bind to
explicit immutable scope.

## Consequences

Inventory can correlate across sources while scan detail remains isolated.
Deduplication keys and lifecycle transitions require careful migration and
backfill. Modules must not query global latest findings for scan views.
