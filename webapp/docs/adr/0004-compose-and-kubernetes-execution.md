# ADR 0004: Compose and Kubernetes Execution

**Status:** Accepted
**Reviewed:** 2026-09-09

## Context

Local practitioners need low operational overhead, while production scanners
need stronger isolation and queue scaling.

## Decision

Use one memory-efficient Compose worker by default, optional queue-specific
Compose pools, and per-scan Kubernetes Jobs for production isolation. Keep the
same planning/evidence contracts across executors.

## Consequences

Local use remains practical and production has an isolation path. The broad
shared image and incomplete control-plane Helm deployment limit current SaaS
readiness.
