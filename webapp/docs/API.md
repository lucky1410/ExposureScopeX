# ExposureScopeX API

**Base path:** `/api/v1`
**Current schema:** runtime `/openapi.json`

FastAPI OpenAPI is the endpoint-level source of truth. Use `/docs` for request
and response schemas. This document defines conventions and endpoint families
rather than duplicating every generated field.

## Authentication and errors

Login returns access/refresh credentials and establishes the configured session
cookies. Access lifetime defaults to 60 minutes and refresh lifetime to seven
days. Refresh tokens rotate through persistent auth sessions; logout revokes the
session. Browser state-changing requests are protected by origin/CSRF controls.

Expected status codes include `400` invalid workflow, `401` unauthenticated,
`403` unauthorized, `404` absent tenant-owned resource, `409` state conflict,
`413` import/request too large, `422` validation, `429` rate limit and `503`
dependency/capability unavailable. Conditional scanners must return explicit
blocked/unavailable state rather than fabricated success.

## Endpoint families

| Prefix | Responsibilities |
|---|---|
| `/auth` | Register, login, refresh, logout and current user |
| `/dashboard` | Posture, methodology, trends, change feed, signals and graph summaries |
| `/assessments` | Import, CRUD, preview, profiles, schedules/history, capability catalog, scans, cancel, retry and clone |
| `/assets` | Filtered inventory, graph, drift, detail, ownership, ports, DNS, TLS, technology, headers, findings and timeline |
| `/vulnerabilities` | Vulnerability list/detail and linked findings |
| `/findings` | Filtered findings, statistics, observations, activities and lifecycle updates |
| `/asm` | Targets, CSV import, cloud sources, target/all scans, cancellation and ASM findings |
| `/mcp-security` | MCP run creation, history, detail, cancellation and deletion |
| `/investigations` | Cases, linked findings, evidence, notes and timeline |
| `/reports` | Async scoped generation, status, comparison, cancellation, download and deletion |
| `/integrations` | Encrypted provider CRUD, test and NVD synchronization |
| `/settings` | Runtime, storage policy/usage, audit search/export, execution policy, workers, API keys, users and authorizations |
| `/operations` | Queue/runtime summary and administrator Prometheus metrics |
| `/tools` | Guarded DNS, WHOIS, SSL, crt.sh, Wayback, header and Shodan utilities |
| `/ai` | Guided analyst chat |
| `/notifications` | Notification list and read state |
| `/resources` | Curated resources, categories and favorites |
| `/search` | Organization-scoped global search |

Outside `/api/v1`, `/health` is liveness, `/ready` is dependency/schema
readiness, and `/ws/scan/{scan_id}` streams authenticated progress. Durable
events remain available through scan execution APIs if WebSocket/pub-sub events
are missed.

## Filtering and isolation

List APIs use explicit query parameters for organization-owned data. Findings
and vulnerabilities support assessment, scan, asset, source, severity and
status scoping where applicable. Clients opening results from a scan should pass
both `assessment_id` and `scan_id`; global lists intentionally aggregate the
organization.

Identifiers are UUIDs. A missing resource from another organization is not
distinguished from a nonexistent resource. Pagination shapes and limits are
defined in OpenAPI; a stable public cursor/versioning contract remains backlog.

## Assessment creation

Assessment intake accepts a primary target plus additional normalized targets,
or a CSV import that creates one assessment containing all valid rows. Preview
should be called before launch for custom plans. Built-in modes are `light`,
`medium`, and `aggressive`; scan intents include passive, Nuclei, web, cloud and
API. Saved profiles store reusable non-secret configuration.

CSV import returns added, skipped and error outcomes. A zero-added import with
errors is failure, not success. Ambiguous field mapping is reported rather than
silently assigning unsafe target types.

## API lifecycle limitations

The current API is authenticated application API, not a finalized public SDK
contract. Scoped API tokens, idempotency keys, cursor pagination, signed
webhooks, formal deprecation policy and generated SDKs remain backlog items.
