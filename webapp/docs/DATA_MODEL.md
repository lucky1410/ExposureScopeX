# Data Model

**Schema head:** `015_scan_schedules`

Alembic migrations are the schema source of truth. This document describes
logical ownership and relationships; it deliberately avoids a hand-maintained
table count.

```text
Organization
  -> Users, sessions, API keys, authorizations, integrations, policies, profiles
  -> Assessments -> Scans -> Events, tool runs, artifacts
                 -> Schedules -> schedule run history
  -> Assets -> DNS, ports, TLS, technologies, headers, snapshots
  -> Asset relations, exposure events, attack paths
  -> Vulnerabilities
  -> Finding identities -> Findings -> Observations, activities
  -> Investigations -> linked findings, evidence, notes
  -> ASM targets, cloud sources, ASM findings
  -> MCP security runs
  -> Reports, notifications and audit events
```

## Ownership rules

- Organization is the primary tenant boundary.
- Every tenant-owned lookup includes organization scope directly or through a
  verified parent relationship.
- Assessment and scan identifiers define execution scope; asset identity alone
  must not cause findings from unrelated scans to appear in a scan view.
- Deleting a parent follows explicit service behavior and audit rules; callers
  must not assume database cascade semantics.

## Assets and observations

Normalized assets reduce duplicates across ASM and assessments. Canonical
values and types support domains, subdomains, URLs, IPs, CIDRs, images and cloud
resources, while assessment target metadata supports additional seed types.
Relations retain source/confidence metadata. Snapshots and exposure events
support drift without replacing current inventory.

Finding identities represent a stable issue concept. Findings represent the
current workflow object. Observations retain per-scan evidence so recurrence,
resolution and reopening can be reasoned about without copying global results.

## Runtime provenance

Scan events preserve lifecycle. Tool runs preserve status, timing and a
canonical secret-safe manifest containing redacted arguments and image, tool,
template, wordlist and policy identities. Worker capabilities record image
identity, queues, binaries, versions and heartbeat. Artifacts retain digest,
media type, storage location and scan/tool association. Secrets and raw
authorization credentials are not provenance fields.

## Schema changes

Every model change requires an Alembic migration, upgrade test, backup/restore
consideration and documentation update. Destructive changes require a staged
expand/migrate/contract approach. Production rollback normally restores a
backup or applies a corrective forward migration; application image rollback
does not automatically downgrade the database.
