# ADR 0003: Capability-Aware Open-Source Adapters

**Status:** Accepted
**Reviewed:** 2026-09-09

## Context

Mature scanners provide better coverage than shallow reimplementations, but
their binaries, licenses, credentials and output contracts vary.

## Decision

Pin supported tools in scanner images, expose a fixed catalog, advertise actual
worker capabilities/versions, validate prerequisites before dispatch, and parse
outputs into normalized evidence. Optional tools remain conditional adapters.

## Consequences

Coverage improves without pretending unavailable tools ran. Worker images are
large and require regular patching; signed split images remain a future control.
