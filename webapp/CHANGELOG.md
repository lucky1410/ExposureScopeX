# Changelog

All notable ExposureScopeX web-platform changes are recorded here. Historical
work before this file was introduced is summarized rather than reconstructed.

## Unreleased

### Control plane

- Added secret-safe canonical execution manifests with image, tool, template,
  wordlist, policy and artifact identities.
- Added comparable-scope finding reopen/resolve automation and legacy
  observation backfill without overwriting analyst dispositions.
- Added asynchronous report generation, cancellation, quota enforcement,
  integrity metadata, terminal errors and generation/export auditing.
- Added recurring assessment schedules with time zones, maintenance windows,
  missed-run behavior, overlap prevention and run history in the API and UI.
- Added searchable/exportable audit logs with correlation metadata and tenant
  storage usage, policy and quota controls.
- Fixed scan-filter initialization so deep-linked findings remain scoped to the
  selected scan instead of falling back to organization-wide results.
- Fixed generic CSV columns so mixed domain, IP, CIDR and URL rows are inferred
  from each value instead of being forced to the header's first inferred type.
- Fixed async assessment authorization for newly created multi-asset records.
- Added durable top-level orchestrator command records and post-write checks so
  terminal scans cannot silently omit command provenance.

### Verification

- Added a self-cleaning deployed-stack E2E journey covering authentication,
  flexible CSV intake, multi-asset assessment scope, scheduling, all seven
  report formats, authorized local scan execution, command provenance,
  cancellation, retry, audit export and deletion.
- Verified 94 backend tests, 16 shell tests, frontend lint and the 37-route
  production build.

### Documentation

- Added canonical documentation index, current product status, deployment,
  API, module, support, lifecycle, data-model, threat-model, runbook, release,
  contribution and architecture-decision documentation.
- Added configuration, operator workflow, CSV normalization, MCP assessment and
  reporting guides with explicit prerequisites and failure semantics.
- Reconciled documentation with schema `015_scan_schedules`, 60-minute
  access tokens, current navigation modules and runtime capability semantics.

## 2.2.0 - 2026-09

- Added normalized assessment/ASM intake and scan-scoped result workflows.
- Added durable scan orchestration, cancellation, retry, worker capability and
  provenance controls.
- Added MCP, CSPM, repository/image and report workflows with conditional
  capability reporting.
- Added finding lifecycle, integrations, operations, artifact storage,
  monitoring and secure deployment controls.
