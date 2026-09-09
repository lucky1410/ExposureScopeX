# ExposureScopeX Module Catalog

**Reviewed:** 2026-09-09

## Operational modules

| Module | UI route | Purpose | Primary backend families |
|---|---|---|---|
| Dashboard | `/dashboard` | Exposure posture, trends, change and risk | dashboard |
| ASM | `/asm` | Target inventory, discovery and cloud sync | asm |
| Assessments | `/assessments` | Plan and run scoped assessments | assessments |
| Scans | `/scans` | Work units, commands, artifacts, retry/cancel | assessments, operations |
| Operations | `/operations` | Queue, worker, capability and health | operations, settings |
| Assets | `/assets` | Normalized inventory and evidence | assets |
| Exposure Graph | `/attack-surface` | Relations, attack paths and drift | assets |
| Coverage | `/coverage` | Planned/performed/skipped visibility | assessments, operations |
| Vulnerabilities | `/vulnerabilities` | CVE-oriented records | vulnerabilities |
| Findings | `/findings` | Observations and remediation workflow | findings |
| MCP Security | `/mcp-security` | MCP protocol/security assessment | mcp-security |
| Cases | `/investigations` | Evidence, notes and linked findings | investigations |
| Reports | `/reports` | Scoped report generation and download | reports |
| Notifications | `/notifications` | Operational alerts | notifications |
| Integrations | `/settings/integrations` | Provider configuration and tests | integrations, settings |
| Settings | `/settings` | Users, keys, authorization and capacity | settings |

## Partial or conditional modules

| Capability | Status | Requirement or boundary |
|---|---|---|
| AI Analyst (`/ai-analyst`) | Partial | Provider/model configuration; evidence-grounded output remains backlog |
| Bug Hunting (`/bug-hunting`) | Mixed | Guarded utilities work; the page also contains practitioner guidance |
| Cloud/CSPM | Conditional | Authorized provider credentials and Prowler; ScoutSuite is optional external adapter |
| Repository/image | Conditional | Reachable repository/registry and worker scanner capabilities |
| Kubernetes artifacts | Conditional | Accessible manifests or repository; this is not a cluster pentest by default |
| Android/iOS | Partial | Static artifact/repository checks; no claim of device/emulator dynamic testing |
| Business logic | Partial | Discovery and workflow mapping; authenticated stateful testing requires operator-designed journeys |

## Reference-only modules

Recon & OSINT (`/recon`), Security Testing (`/security-testing`), Privilege
Escalation (`/privesc`), Malware Analysis (`/malware`), Threat Intelligence
(`/threat-intel`), Resources (`/resources`) and Learning (`/learning`) include
curated tools, techniques
and external references. Their presence does not mean ExposureScopeX executes
every named tool. Executable availability is listed in [Support matrix](SUPPORT_MATRIX.md).

## Shared platform services

All executable modules should use common intake normalization, authorization,
scan planning, execution policy, Celery routing, cancellation, evidence
ingestion, finding lifecycle, audit, artifact storage and reporting. New modules
must not create parallel asset/finding stores or module-specific global results.
