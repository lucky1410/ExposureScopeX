# Exposure Management Operating Model

This layer turns point-in-time assessments into a client-reviewable exposure
program. It is deliberately conservative: discovery does not establish
ownership, and a completed scan is not a claim that an environment is secure.

## Client Workflow

1. **Create a scoped assessment.** A declared root asset becomes an
   organization-level inventory record. Light mode is an external,
   non-destructive baseline.
2. **Discover and correlate.** Passive sources can add candidate assets and
   asset-to-asset relationships. A candidate is never automatically treated as
   customer-owned scope.
3. **Verify ownership.** An Analyst, Admin, or Owner records written
   authorization, a DNS attestation, or cloud-inventory attestation before an
   asset is marked verified. DNS and cloud connector records are auditable
   attestations in this release; they do not impersonate a native cloud API
   integration.
4. **Assess only approved scope.** Client-approved assets can be queued from
   the asset inventory. The `authorized_deep` product lane requires a scope
   file and Medium or Aggressive profile, but its current adapters remain
   non-exploitative until deeper checks are individually released.
5. **Operate continuously.** A monitor re-checks recorded authorization and
   validated scope every time before creating a run. It blocks instead of
   running if either condition is no longer valid.
6. **Review the evidence lifecycle.** New, observed, reopened, resolved,
   accepted-risk, and dismissed states retain timestamps and rationale.

## Dashboard And Operations

- `/dashboard` is the executive worklist: ownership review, priority findings,
  scheduled monitors, active assessments, and recent asset changes.
- `/assets` is the organization asset graph, including correlation and evidence
  record counts. It preserves the existing assessment-specific approval flow.
- `/operations` is the control room for monitoring, finding lifecycle,
  validation quality, integrations, and audit history.
- `/assessments/new` has separate External baseline and Authorized deep lanes.

## Roles And Auditability

- `viewer`: read-only access.
- `analyst`: create and operate assessments, asset review, monitors, finding
  decisions, and validation corpus registration.
- `admin` and `owner`: analyst capabilities plus connector configuration,
  monitor pause/resume, and audit-log access.

Ownership changes, monitor activation/dispatch/blocking, scan dispatch and
cancellation, finding decisions, corpus registration, and connector
configuration create immutable audit events. Technical scan evidence stays with
the assessment and report.

## Alerts And Connector Security

Webhook and SIEM deliveries use encrypted-at-rest endpoints and signing
secrets, HMAC-SHA-256 signatures, bounded retry through a durable outbox,
HTTPS-only production egress, no redirects, DNS resolution checks, and a
production hostname allowlist.

Connector `configuration` is intentionally non-sensitive metadata. Credential-
shaped keys are rejected there so that credentials can only be supplied through
an encrypted secret field.

Production configuration must set:

```text
EXPOSURE_INTEGRATION_ALLOWED_HOSTS=security.example.com,siem.example.com
EXPOSURE_INTEGRATION_PRIVATE_NETWORKS=
```

Only list private networks when a deliberately approved private delivery path
exists. Do not place tokens in endpoint URLs; the API rejects them.

## Validation Quality

Use `/validation-corpus-template.json` as the import shape for a versioned
validation corpus. The console calculates the observed false-positive rate only
from findings marked confirmed or rejected. It does not make a performance claim
about unvalidated or unseen findings.

## Start Or Upgrade

The exposure schema, runner, API, and web application changed together, so one
rebuild is required after pulling this release:

```powershell
docker compose -f .\v3\compose.yml up -d --build api runner web
```

Do not use `--force-recreate`. Migrations run when the API starts. Open
`http://localhost:3001/dashboard` after the services are healthy.

For the container-backed test suite:

```powershell
docker compose -f .\v3\compose.yml exec api python -m unittest discover -s tests -p "test_*.py"
```
