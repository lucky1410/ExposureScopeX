# Operator User Guide

## First use

Start the platform with `docker compose up -d`, open the frontend, and bootstrap
the first administrator only on an empty deployment. Before active testing,
configure users, authorization scopes, API/provider keys, runtime policy and
integrations under Settings. Confirm required workers/tools in Operations.

## Create an assessment

1. Choose a primary target type and value or import a CSV.
2. Add/remove additional targets; one assessment may contain mixed normalized assets.
3. Select light, medium, aggressive or a saved custom profile.
4. Review execution preview: queue, tools, target count, limits and prerequisites.
5. Confirm authorization and start.
6. Follow Scans for work units, commands, output, artifacts, progress and ETA.
7. Cancel when required. Retry preserves the old run; clone draft allows editing.
8. Open Findings from the scan to retain `assessment_id` and `scan_id` filtering.

Light is a quick snapshot, medium balances coverage and duration, and aggressive
expands discovery/validation. Aggressive does not authorize destructive testing.

## ASM workflow

Add individual targets, import CSV, or configure a cloud source. Normalize and
review ownership before scanning. Use per-target scan for controlled validation
or scan-all only when every included target is authorized. ASM and assessment
discovery can correlate to common assets without combining their scan evidence.

## Findings and vulnerabilities

Global lists aggregate the organization. Use assessment, scan, asset, severity,
status and source filters for scoped review. Finding detail shows observations
and workflow activity. Status, assignment, SLA, suppression, risk acceptance and
retest actions should preserve comments and audit history.

## MCP security

Use a reachable HTTP MCP endpoint; from containers, a host service commonly uses
`host.docker.internal`. Supply authorization headers as secrets and validate
`tools/list` connectivity first. Choose non-destructive checks unless a disposable
lab and explicit consent exist. See [MCP security](MCP_SECURITY.md).

## Cloud, repository, image and mobile

These workflows are conditional. Configure least-privilege cloud identity,
repository/registry access or artifact/runtime adapter before launch. A static
Android/iOS artifact scan is not equivalent to dynamic device testing. Coverage
must show missing adapters as unavailable.

## Reports and cases

Generate reports from explicit assessment/scan/filter scope. Use evidence
bundles for machine-verifiable handoff and PDF/HTML for human delivery. Create a
case to collect selected findings, notes and evidence without changing original
scan records.

## Delete behavior

Delete only after checking report/evidence retention and integration references.
Cancellation and deletion are different: cancel stops work while retaining its
record; delete applies the endpoint's documented ownership/cascade behavior.
Back up before bulk removal.
