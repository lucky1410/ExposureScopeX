# ExposureScopeX Threat Model

**Reviewed:** 2026-09-09

## Assets to protect

- User identities, sessions, roles and organization boundaries
- Target authorization records and assessment scope
- Cloud, integration, repository and API credentials
- Scanner command plans and worker execution environment
- Findings, evidence, reports and investigation chain-of-custody
- PostgreSQL, Redis, artifact storage and backups

## Adversaries and misuse

- Unauthenticated internet attacker targeting the web/API edge
- Low-privilege user attempting cross-tenant access or privilege escalation
- Authorized user attempting out-of-scope or destructive scanning
- Malicious target returning payloads designed to exploit parsers or UI rendering
- Compromised scanner/tool/template or poisoned repository dependency
- Stolen integration credential or malicious webhook destination
- Operator mistake causing data loss, excessive resource use or secret exposure

## Principal threats and controls

| Threat | Primary controls | Residual risk/action |
|---|---|---|
| Cross-tenant data access | Organization-scoped dependencies, capability checks, opaque not-found behavior | Expand cross-tenant integration coverage |
| Session theft/replay | Short access lifetime, rotating refresh sessions, revocation, secure production cookies | Add enterprise MFA/SSO and anomaly detection |
| CSRF/CORS/host abuse | SameSite cookies, origin validation, exact CORS/trusted hosts | Verify every production proxy topology |
| SSRF and internal reach | Target validation, localhost alias controls, allowlists, egress segmentation | Workers intentionally need egress; enforce network policy |
| Command injection | Fixed tool catalog, validated arguments, no user shell | Continue parser/fuzz tests and argument manifests |
| Scanner escape | Non-root containers, dropped capabilities, no-new-privileges, Kubernetes Job isolation | Shared local worker has broader blast radius |
| Secret disclosure | Fernet encryption, redacted responses/evidence, no secret provenance | Prefer workload identity and external secret manager |
| Malicious output/XSS | Structured parsers, escaping, bounded output/download types | Treat every target string and report field as hostile |
| Supply-chain compromise | Pinned versions/revisions, dependency scanning, CodeQL, Renovate/Dependabot | Add signed images, SBOM attestations and template policy |
| Nuclei template abuse | Persistent curated sources, profile tags, runtime provenance | Community templates remain executable content; review/signing needed |
| Resource exhaustion | Rate limits, queue quotas, leases, time/memory/process/disk limits, retention | Add tenant storage quotas and disk-pressure admission control |
| Evidence tampering | SHA-256 artifacts/reports, immutable scope, audit records | Add off-host immutable evidence and signing |
| Destructive scan misuse | Authorization records, preview, safe defaults, guarded adapters | Human approval and isolated lab remain required |
| Backup loss/ransomware | Integrity-checked backup and optional off-host replication | Automate restore drills and immutability |

## Security assumptions

- Operators control and patch the host, database, Redis, ingress and object store.
- Targets are explicitly authorized; ExposureScopeX does not grant legal authority.
- Scanner tools and templates can contain vulnerabilities and must be treated as
  high-risk dependencies.
- Local Compose is a controlled deployment, not hostile-tenant isolation.
- Reference-only pages do not execute the tools they mention.

## Review triggers

Update this model when adding a new target type, scanner, template source,
credential, public endpoint, upload format, executor, plugin mechanism, tenant
role, report destination or data-retention behavior.
