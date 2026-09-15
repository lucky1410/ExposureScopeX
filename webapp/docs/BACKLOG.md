# ExposureScopeX — Product Backlog

> Historical proposal backlog reconciled on 2026-09-06. Completion truth is tracked in `../BACKLOG.md` and executable status APIs.

**Format:** Epic → Stories (Jira/Linear style)
**Version:** 2.2.0
**Last Updated:** September 2026
**Story Point Scale:** Fibonacci (1, 2, 3, 5, 8, 13)
**Status Values:** Done | In Progress | Ready | Backlog | Icebox

---

## EPIC-001: Production Infrastructure Hardening

**Goal:** Make the platform safe and operable in a real production environment.
**Priority:** P0 — Blocking all production deployments.
**Target Quarter:** Q3 2026

---

### ESX-001
**Title:** Celery scan execution wiring
**Priority:** P0 | **Estimate:** 5 | **Status:** Done

**Description:**
Originally, assessment creation wrote only a database record. The completed implementation now auto-dispatches a queue-routed Celery task with normalized targets, scan configuration, persisted task identity, cancellation, and durable execution telemetry.

**Acceptance Criteria:**
- `POST /api/v1/assessments/{id}/run` enqueues `run_scan` and returns `{"scan_id": "...", "celery_task_id": "..."}`
- `scans.status` transitions: `created` → `queued` → `running` → `completed | failed`
- Assessment list page shows a live spinner for running scans

---

### ESX-002
**Title:** Fernet encryption for cloud credentials
**Priority:** P0 | **Estimate:** 3 | **Status:** Done

**Description:**
`asm_cloud_sources.config` JSONB stores cloud provider credentials (AWS secret keys, GCP service account JSON, Azure client secrets). These must be encrypted at rest using Fernet (AES-128-CBC + HMAC-SHA256). The encryption key is derived from `SECRET_KEY` in environment config. Decrypt only at scan dispatch time.

**Acceptance Criteria:**
- `AsmCloudSource.config` stored as Fernet-encrypted bytes in the DB
- `pg_dump` of the DB does not reveal plaintext credentials
- Decrypted config available in Celery worker at scan time
- Existing plaintext records migrated via an Alembic migration

---

### ESX-003
**Title:** nginx TLS configuration and certificate provisioning
**Priority:** P0 | **Estimate:** 3 | **Status:** Ready

**Description:**
Add a `make certs` target that generates a self-signed certificate for dev. Document the Let's Encrypt acme.sh flow for production. Update `nginx/nginx.conf` to enable the HTTPS server block with the correct `ssl_certificate` and `ssl_certificate_key` paths. Redirect all HTTP traffic to HTTPS.

**Acceptance Criteria:**
- `make certs` generates a 10-year self-signed cert in `nginx/certs/`
- HTTPS server block listening on 443 with TLS 1.2 minimum
- HTTP port 80 responds 301 to HTTPS equivalent URL
- `DEPLOYMENT.md` covers production certificate responsibilities

---

### ESX-004
**Title:** slowapi rate limiting on FastAPI
**Priority:** P0 | **Estimate:** 2 | **Status:** Done

**Description:**
Add slowapi as a defence-in-depth rate limiter applied at the FastAPI layer. Configure default limits of 200 req/min and 2000 req/hour per IP using Redis as the storage backend. Apply a tighter limit of 5 req/min on all `/auth/` routes.

**Acceptance Criteria:**
- `429 Too Many Requests` returned when limits exceeded
- `X-RateLimit-*` headers present on all API responses
- Redis used as storage backend (not in-memory) so limits survive worker restarts

---

### ESX-005
**Title:** SSRF protection on ASM target inputs
**Priority:** P0 | **Estimate:** 3 | **Status:** Done

**Description:**
`POST /api/v1/asm/targets` accepts arbitrary target values. Implement a validator that resolves hostname targets to IP(s) and rejects any that fall into RFC-1918 (10/8, 172.16/12, 192.168/16), loopback (127/8), link-local (169.254/16), or cloud metadata (169.254.169.254) ranges. Also validate IPv4/IPv6 CIDR syntax.

**Acceptance Criteria:**
- 422 returned for `target_value: "169.254.169.254"`
- 422 returned for `target_value: "10.0.0.1"`
- 422 returned for `target_value: "localhost"`
- Valid public IPs and domains accepted normally
- Unit tests in `tests/test_ssrf_validation.py` cover all denylist cases

---

### ESX-006
**Title:** Audit logging on auth events and mutations
**Priority:** P0 | **Estimate:** 5 | **Status:** In Progress

**Description:**
The `audit_logs` table exists but is not written to by any API handler. Implement an `audit_log()` helper in `app/services/audit.py` and call it from: login, logout, failed login, token refresh, create/update/delete assessment, create/update finding status, create/update/delete asm_target, user management operations.

**Acceptance Criteria:**
- Every successful login produces an `audit_logs` row with `action="login"` and `ip_address`
- Every failed login produces a row with `action="login_failed"`
- Assessment create/run/delete produce rows with `entity_type="assessment"` and `entity_id`
- Finding status changes produce rows with `old_value` and `new_value` JSONB
- Audit writes never cause the parent request to fail (wrapped in try/except)

---

### ESX-007
**Title:** WebSocket real-time scan progress endpoint
**Priority:** P0 | **Estimate:** 5 | **Status:** Done

**Description:**
Implement `GET /ws/scan/{scan_id}` WebSocket endpoint in `app/main.py`. Subscribe to Redis pub/sub channel `scan:{scan_id}`. Forward all messages to the connected client. Auto-close on terminal events (`scan.completed`, `scan.failed`). Maintain a shared async Redis pool via `get_redis()` to avoid connection leaks.

**Acceptance Criteria:**
- Browser can connect to `ws://host/ws/scan/{uuid}` with a valid JWT
- Progress events appear in real time on the assessment detail page
- Connection auto-closes when scan completes or fails
- Disconnection by client does not cause a Redis subscription leak
- Load test: 10 simultaneous WebSocket connections do not degrade API response times

---

### ESX-008
**Title:** Multi-tenancy org_id enforcement audit
**Priority:** P0 | **Estimate:** 8 | **Status:** In Progress

**Description:**
Audit all 15 API route modules to verify every list query filters by `org_id == current_user.org_id`. Write an automated test that creates two organizations, seeds data in each, and asserts a user from Org A cannot retrieve Org B's data via any endpoint.

**Acceptance Criteria:**
- `grep -r "select.*from" app/api/` shows all queries include org_id filter
- `tests/test_org_isolation.py` passes for all 15 route modules
- No cross-org data returned for any endpoint in the test suite

---

### ESX-009
**Title:** Docker Compose production overrides file
**Priority:** P1 | **Estimate:** 2 | **Status:** Ready

**Description:**
Create `docker-compose.prod.yml` with production overrides: `SEED_DEMO_DATA=false`, `DEBUG=false`, nginx exposed on 80/443, healthcheck intervals tightened, `restart: unless-stopped` on all services, secrets via Docker secrets or env files excluded from version control.

**Acceptance Criteria:**
- `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` starts cleanly
- No demo data seeded in production mode
- All services restart automatically after VM reboot

---

## EPIC-002: Scan Execution Engine

**Goal:** Close the gap between UI-driven assessment creation and actual scan execution.
**Priority:** P0 | **Target Quarter:** Q3–Q4 2026

---

### ESX-010
**Title:** Scan cancellation endpoint
**Priority:** P1 | **Estimate:** 3 | **Status:** Backlog

**Description:**
Implement `POST /api/v1/scans/{scan_id}/cancel`. Revoke the Celery task using `celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")`. Update `scans.status = "cancelled"`. Propagate a final event to the WebSocket channel.

**Acceptance Criteria:**
- Cancel button appears on running scans in the UI
- `scans.status` = `cancelled` within 5 seconds of clicking Cancel
- Running subprocess (`exposurescopex.sh`) receives SIGTERM and exits
- WebSocket receives `{"event": "scan.cancelled"}` and closes

---

### ESX-011
**Title:** Real data importer startup hook
**Priority:** P1 | **Estimate:** 5 | **Status:** Done

**Description:**
The `real_data_importer.py` service reads existing `results/` directory output on backend startup and imports findings, assets, and ports into the DB using the parser modules (`nmap_parser.py`, `nuclei_parser.py`, `ssl_parser.py`, etc.). This allows existing CLI scans to surface in the web UI without re-scanning.

**Acceptance Criteria:**
- After `docker compose up`, existing results in `results/` appear in the assessments/findings UI
- Import is idempotent (running twice does not duplicate rows)
- Import failure does not prevent backend startup (warning log only)

---

### ESX-012
**Title:** Scan phase-level output viewer
**Priority:** P1 | **Estimate:** 3 | **Status:** Backlog

**Description:**
Display the `scans.raw_log` content on the assessment detail page, filterable by phase. Provide a "Download log" button that serves the raw text. Logs should be paginated for large outputs (> 10,000 lines).

**Acceptance Criteria:**
- Log viewer renders on assessment detail page with phase filter dropdown
- Download button serves `scan_{id}.log` as `Content-Disposition: attachment`
- Logs > 10,000 lines paginate with "load more" UX

---

### ESX-013
**Title:** CI exit code support in API
**Priority:** P2 | **Estimate:** 2 | **Status:** Backlog

**Description:**
Expose `GET /api/v1/assessments/{id}/ci-result` that returns `{"exit_code": 0|1|2}` based on the highest severity finding (2=CRITICAL, 1=HIGH, 0=clean). Intended for CI/CD pipeline integration.

**Acceptance Criteria:**
- Returns 2 if any CRITICAL findings exist in the assessment
- Returns 1 if no CRITICAL but HIGH findings exist
- Returns 0 if only MEDIUM/LOW/INFO findings exist
- Returns 0 for assessments with status != completed

---

### ESX-014
**Title:** Scan authorization gate for exploit phase
**Priority:** P0 | **Estimate:** 3 | **Status:** Backlog

**Description:**
Before dispatching a scan with the `exploit` phase enabled, the API must verify a `scan_authorizations` record exists for the target domain/IP pattern and has not expired. Block the dispatch with HTTP 403 if no valid authorization is found.

**Acceptance Criteria:**
- `POST /api/v1/assessments/{id}/run` with `phases: ["exploit"]` returns 403 without authorization
- Scan proceeds after `POST /api/v1/settings/scan-auth` creates a valid authorization
- Authorization records have `valid_until` expiry; expired records are treated as absent

---

## EPIC-003: ASM Module

**Goal:** Deliver a fully operational continuous Attack Surface Monitor.
**Priority:** P0 | **Target Quarter:** Q3 2026

---

### ESX-015
**Title:** CSV bulk target import
**Priority:** P1 | **Estimate:** 3 | **Status:** Backlog

**Description:**
`POST /api/v1/asm/targets/import` accepts a multipart CSV file with columns: `name,target_type,target_value,tags`. Validate each row through the SSRF validator, write to `asm_targets` with `source_type="csv"`, return a summary `{imported: N, skipped: M, errors: [...]}.

**Acceptance Criteria:**
- 1000-row CSV imports in < 10 seconds
- Invalid rows (private IPs, malformed CIDR) appear in `errors` array, not rejected wholesale
- Duplicate `target_value` rows skipped with `ON CONFLICT DO NOTHING`

---

### ESX-016
**Title:** Cloud source asset sync (AWS)
**Priority:** P1 | **Estimate:** 8 | **Status:** Backlog

**Description:**
Implement a Celery task `asm.tasks.sync_aws_source` that uses `boto3` to enumerate EC2 instances, ELBs, CloudFront distributions, Route53 records, and S3 bucket names from the configured AWS account. Write discovered assets to `asm_targets` with `source_type="aws"` and `cloud_account_id`.

**Acceptance Criteria:**
- `AsmCloudSource` with `provider="aws"` triggers sync on schedule
- Discovered EC2 instance public IPs and ELB DNS names appear in `asm_targets`
- S3 bucket names stored as `target_type="domain"` with `cloud_region` populated
- `asm_cloud_sources.status` = "ok" after successful sync; "error" with message on failure

---

### ESX-017
**Title:** ASM per-target scan trigger
**Priority:** P0 | **Estimate:** 5 | **Status:** In Progress

**Description:**
Implement the scan trigger for ASM targets. The `POST /api/v1/asm/targets/{id}/scan` endpoint should enqueue an ASM-specific Celery task (lighter than a full assessment scan) that runs DNS, SSL, HTTP headers, subdomain enumeration, and port checks. Results write to `asm_findings`.

**Acceptance Criteria:**
- `asm_targets.scan_status` transitions `idle` → `scanning` → `completed`
- `last_scan_summary` JSONB populated with `{findings_count, open_ports, subdomains_found}`
- `asm_findings` rows created with `source` indicating which check produced each finding
- Progress streamed to `/ws/scan/{target_id}` WebSocket

---

### ESX-018
**Title:** ASM continuous monitoring schedule (DB-backed)
**Priority:** P1 | **Estimate:** 5 | **Status:** Backlog

**Description:**
Replace the CLI cron-based scheduling with a DB-backed schedule using Celery Beat. Add a `scan_schedule` column to `asm_targets` (cron expression string). Celery Beat reads active schedules on startup and registers them as periodic tasks. When a scheduled run completes, diff results against the previous `last_scan_summary` and create notifications for new findings.

**Acceptance Criteria:**
- Setting `scan_schedule="0 6 * * *"` on a target triggers a daily 06:00 UTC scan
- New findings since the last scan generate a `notifications` row for the owning user
- Removing the schedule from the UI stops future Celery Beat executions

---

## EPIC-004: Reporting and Compliance

**Goal:** Produce deliverable-quality reports and compliance artifacts.
**Priority:** P1 | **Target Quarter:** Q4 2026

---

### ESX-019
**Title:** HTML report with Chart.js severity chart
**Priority:** P1 | **Estimate:** 3 | **Status:** Backlog

**Description:**
Implement `GET /api/v1/reports/{assessment_id}?format=html`. Generate a self-contained HTML report using the `reporting.sh` module's Chart.js template. Embed all chart data as inline JSON; no external CDN dependencies. Include executive summary, risk score, findings table, and asset inventory.

**Acceptance Criteria:**
- Report renders correctly offline (no internet access)
- Severity doughnut chart renders in both light and dark mode browser preferences
- Report file size < 5 MB for assessments with < 200 findings

---

### ESX-020
**Title:** SARIF 2.1 export
**Priority:** P1 | **Estimate:** 3 | **Status:** Backlog

**Description:**
Implement `GET /api/v1/reports/{assessment_id}?format=sarif`. Generate a SARIF 2.1 JSON document mapping findings to SARIF `result` objects with `ruleId` (CVE or nuclei template ID), `level`, `message`, and `locations`. Include tool metadata for ExposureScopeX and each sub-tool that contributed findings.

**Acceptance Criteria:**
- SARIF file validates against the official JSON schema at `schemas.json.schemastore.org/sarif-2.1.0.json`
- GitHub Advanced Security can ingest the SARIF file without errors
- `ruleId` maps correctly to nuclei template IDs and CVE IDs where available

---

### ESX-021
**Title:** PDF report via pandoc
**Priority:** P2 | **Estimate:** 2 | **Status:** Backlog

**Description:**
Add pandoc to the worker Docker image. Implement `GET /api/v1/reports/{assessment_id}?format=pdf`. Generate Markdown first, then convert via pandoc with a custom LaTeX template. Include a cover page with assessment name, target, date, and SecOps24 branding placeholder.

**Acceptance Criteria:**
- PDF generated in < 60 seconds for assessments with < 200 findings
- PDF passes pdfinfo validation (not corrupt)
- Cover page renders with assessment metadata

---

### ESX-022
**Title:** Compliance mapping (OWASP Top 10)
**Priority:** P2 | **Estimate:** 5 | **Status:** Backlog

**Description:**
Add an `owasp_category` field to the `findings` table. Populate it from nuclei template tags (A01–A10) and a manual mapping table for other sources. Add an OWASP Top 10 breakdown section to the HTML report.

**Acceptance Criteria:**
- nuclei findings with OWASP tags automatically categorized
- HTML report includes OWASP Top 10 bar chart
- CSV export includes `owasp_category` column

---

## EPIC-005: Multi-tenancy and RBAC

**Goal:** Make the platform safe for multiple organizations sharing one deployment.
**Priority:** P0 | **Target Quarter:** Q3–Q4 2026

---

### ESX-023
**Title:** RBAC enforcement on all write endpoints
**Priority:** P0 | **Estimate:** 5 | **Status:** Backlog

**Description:**
Implement role-check FastAPI dependencies: `require_role("admin")`, `require_role("manager")`, `require_role("analyst")`. Apply them to all mutation endpoints. Viewer role returns 403 on any POST/PUT/PATCH/DELETE.

**Acceptance Criteria:**
- `viewer` role: POST to any endpoint returns 403
- `analyst` role: cannot delete assessments (returns 403); can create and triage
- `manager` role: can delete assessments; cannot manage users
- `admin` role: all operations permitted

---

### ESX-024
**Title:** User management UI and API
**Priority:** P1 | **Estimate:** 5 | **Status:** Backlog

**Description:**
Implement `GET/POST/PUT/DELETE /api/v1/settings/users` for admin-only user management. Wire to the Settings → Users page. Allow admins to create users, change roles, deactivate accounts, and reset passwords.

**Acceptance Criteria:**
- Admin can create a new user and assign a role via the UI
- Deactivated users (`is_active=False`) cannot authenticate
- Password reset generates a secure one-time token (bcrypt hash stored, not plaintext)
- All user management actions produce audit_log entries

---

### ESX-025
**Title:** API key management
**Priority:** P1 | **Estimate:** 3 | **Status:** Backlog

**Description:**
Implement `GET/POST/DELETE /api/v1/settings/api-keys`. API keys authenticate to the same endpoints as JWT but bypass the browser login flow. Intended for CI/CD integration. Keys stored as bcrypt hashes in `api_keys` table. Scopes restrict which endpoints the key can call.

**Acceptance Criteria:**
- Key generation returns the plaintext key once; subsequent reads show only the hash prefix
- Expired keys (`valid_until`) return 401
- Scope enforcement: a key with scope `reports:read` cannot POST to `/assessments`

---

## EPIC-006: Integrations

**Goal:** Connect ExposureScopeX findings to existing security tooling.
**Priority:** P1 | **Target Quarter:** Q4 2026

---

### ESX-026
**Title:** Slack webhook notification on scan completion
**Priority:** P1 | **Estimate:** 3 | **Status:** Backlog

**Description:**
Implement Slack webhook delivery triggered on scan completion and when new CRITICAL/HIGH findings are detected. Use the `integrations.sh` injection-safe `jq --arg` payload builder pattern in the Python layer. Webhook URL stored in `settings` table per org.

**Acceptance Criteria:**
- Slack message includes: assessment name, target, scan duration, finding counts by severity, link to the assessment page
- Message delivered within 60 seconds of scan completion
- Webhook failures are retried 3 times with exponential backoff and logged to `audit_logs`

---

### ESX-027
**Title:** Splunk HEC integration
**Priority:** P2 | **Estimate:** 3 | **Status:** Backlog

**Description:**
Stream findings to Splunk HTTP Event Collector on assessment completion. Each finding becomes a discrete Splunk event with `sourcetype=exposurescopex:finding`. Include all finding fields as key=value pairs for Splunk field extraction.

**Acceptance Criteria:**
- `POST /api/v1/settings/integrations/splunk` configures HEC URL and token
- Test connection button validates the HEC endpoint and returns success/failure
- Each finding produces a distinct Splunk event within 5 minutes of scan completion

---

### ESX-028
**Title:** Jira ticket creation for critical findings
**Priority:** P2 | **Estimate:** 5 | **Status:** Backlog

**Description:**
Integrate with Jira Cloud API to auto-create tickets for CRITICAL and HIGH findings on scan completion. Map ExposureScopeX severity to Jira priority. Include finding title, description, evidence, and a link to the ExposureScopeX finding page in the ticket body.

**Acceptance Criteria:**
- Jira project and issue type configurable per org
- Duplicate detection: do not create a Jira ticket if one already exists for the same finding (check by finding title + target)
- Created Jira ticket URL stored in `findings.jira_url` column

---

## EPIC-007: AI Analyst

**Goal:** Make the Claude-powered AI Analyst module production-ready.
**Priority:** P1 | **Target Quarter:** Q4 2026

---

### ESX-029
**Title:** AI Analyst API endpoint
**Priority:** P1 | **Estimate:** 5 | **Status:** In Progress

**Description:**
The `app/api/v1/ai.py` router handles AI Analyst requests. Implement a `POST /api/v1/ai/analyze` endpoint that accepts a context payload (assessment summary, top findings, asset list) and calls the Anthropic Messages API (`claude-opus-4-6`) to generate a structured threat narrative, attack path hypotheses, and prioritized remediation advice. Stream the response via SSE.

**Acceptance Criteria:**
- Response streaming visible in the UI within 2 seconds of submission
- Response includes: executive summary, attack path narrative, top 5 prioritized remediations
- `ANTHROPIC_API_KEY` missing → 503 with user-friendly "AI Analyst not configured" message
- Token usage logged to `audit_logs` for cost tracking

---

### ESX-030
**Title:** Evidence-grounded analyst assistance
**Priority:** P2 | **Estimate:** 8 | **Status:** Backlog

**Description:**
Add optional post-scan assistance that explains findings, prioritizes remediation,
and drafts narratives from immutable evidence. It must remain isolated from scan
planning and execution and must never modify scanner facts.

**Acceptance Criteria:**
- Assistance is available only after normalized evidence is persisted
- Every generated claim cites finding and artifact identifiers
- Model, prompt version, inputs, output, and operator decision are auditable
- Generated content is clearly labelled and operator-review gated
- No AI configuration or response can alter targets, tools, templates, or scan actions

---

## EPIC-008: Developer Experience

**Goal:** Make the platform easy to develop, test, and contribute to.
**Priority:** P2 | **Target Quarter:** Q4 2026

---

### ESX-031
**Title:** Comprehensive test suite
**Priority:** P1 | **Estimate:** 8 | **Status:** In Progress

**Description:**
Expand `tests/` from the existing 15 CLI unit tests to include: FastAPI integration tests (pytest-asyncio + httpx), org isolation tests, rate limiting tests, WebSocket connection tests, and SSRF validation unit tests.

**Acceptance Criteria:**
- `pytest tests/` passes with ≥ 80% code coverage on backend `app/api/v1/`
- Org isolation test: Org A user cannot access Org B's assessments, findings, or targets
- SSRF test: all private IP ranges and loopback addresses rejected
- CI runs tests on every pull request

---

### ESX-032
**Title:** Makefile for common developer tasks
**Priority:** P2 | **Estimate:** 2 | **Status:** Done

**Description:**
`webapp/Makefile` targets: `make up`, `make down`, `make build`, `make certs`, `make migrate`, `make seed`, `make test`, `make logs`, `make shell-backend`, `make shell-worker`.

**Acceptance Criteria:**
- `make up` brings the full stack up with a single command
- `make certs` generates self-signed TLS cert for nginx
- `make test` runs backend pytest suite and returns non-zero on failure
- `make seed` idempotently seeds the AcmeCorp demo assessment

---

### ESX-033
**Title:** OpenAPI documentation completeness
**Priority:** P2 | **Estimate:** 3 | **Status:** Backlog

**Description:**
Audit all 15 route modules for missing Pydantic response models, missing `summary` and `description` fields on route decorators, and missing `tags`. Ensure `/docs` (Swagger UI) and `/redoc` render a complete, navigable API reference.

**Acceptance Criteria:**
- Every route has a `summary`, `description`, and `tags` annotation
- Every route has a typed `response_model` (no raw `dict` returns)
- `/redoc` renders without warnings about missing schema definitions

---

## EPIC-009: Application Security Platform Expansion

**Goal:** Evolve ExposureScopeX from infrastructure-led recon into a modular application-security platform with first-class web, API, mobile, analyst, and reporting workflows.
**Priority:** P1 | **Target Quarter:** Q4 2026–Q1 2027

---

### ESX-034
**Title:** First-class web application testing module
**Priority:** P1 | **Estimate:** 8 | **Status:** Backlog

**Description:**
Introduce a dedicated Web App module rather than overloading the generic assessment flow. The module should support authenticated and unauthenticated targets, site crawling, parameter discovery, content discovery, technology fingerprinting, misconfiguration validation, session handling checks, and business-flow-aware evidence collection. Expose scan profiles such as `quick`, `balanced`, `deep`, and `custom`.

**Acceptance Criteria:**
- New assessment type `web_application` is available in the UI and API
- Operators can configure auth mode, crawl depth, rate limit, wordlist size, and selected tools per run
- Results preserve page URL, parameter, method, evidence snippet, and source tool
- Findings page can filter by web route, parameter, and assessment-specific asset
- Failed runs can be edited and retried without creating duplicate assessments

---

### ESX-035
**Title:** First-class API security module
**Priority:** P1 | **Estimate:** 8 | **Status:** Backlog

**Description:**
Create an API Security module for REST, GraphQL, gRPC-web, and schema-driven testing. Support OpenAPI/Swagger URL import, file upload, Postman collection import, and live endpoint discovery from crawlers. Add checks for authentication drift, broken object/property authorization patterns, unsafe verbs, schema mismatches, excessive data exposure, rate-limit absence, and sensitive error disclosure.

**Acceptance Criteria:**
- New assessment type `api_application` is available in the UI and API
- OpenAPI URL, OpenAPI file, and Postman collection imports normalize into a common endpoint inventory
- Endpoint inventory stores method, path, auth requirement, tags, and schema source
- Findings can be filtered by endpoint, method, tag, and asset
- Custom API scan profiles can enable only selected checks and endpoint subsets

---

### ESX-036
**Title:** Android application security module
**Priority:** P2 | **Estimate:** 13 | **Status:** Backlog

**Description:**
Add an Android module that accepts APK and AAB uploads plus Play Store metadata where available. Perform static analysis for permissions, exported components, debuggable builds, embedded secrets, insecure network config, certificate pinning gaps, root detection gaps, and third-party SDK inventory. Reserve dynamic testing adapters for later phases.

**Acceptance Criteria:**
- New assessment type `android_application` accepts APK/AAB uploads
- File normalization extracts package name, version, signing cert metadata, and manifest inventory
- Findings preserve file path, class/component name, and evidence excerpt
- Reports include permissions matrix, exported components list, and SDK inventory summary
- Unsupported or malformed binaries fail gracefully with actionable errors

---

### ESX-037
**Title:** iOS application security module
**Priority:** P2 | **Estimate:** 13 | **Status:** Backlog

**Description:**
Add an iOS module that accepts IPA archives and extracted app bundles. Perform static analysis for ATS exceptions, entitlements, plist misconfigurations, hardcoded secrets, insecure URL schemes, excessive permissions, and third-party SDK inventory. Design the storage and parser layers so future dynamic instrumentation can plug in without schema redesign.

**Acceptance Criteria:**
- New assessment type `ios_application` accepts IPA uploads
- Normalization extracts bundle identifier, version, signing metadata, plist inventory, and entitlements
- Findings preserve plist key, binary path, class symbol, or entitlement source
- Reports include ATS posture, entitlement summary, and URL scheme inventory
- Unsupported archives fail gracefully and do not leave orphaned DB rows

---

### ESX-038
**Title:** Parameter discovery and content fuzzing module
**Priority:** P1 | **Estimate:** 8 | **Status:** Backlog

**Description:**
Add focused modules for parameter mining and content discovery so operators can run narrow follow-up scans without repeating full reconnaissance. The first implementation should integrate `ffuf` for content discovery and `arjun` for parameter discovery, with output normalized into routes, parameters, response fingerprints, and confidence scores.

**Acceptance Criteria:**
- Operators can launch standalone `content_discovery` and `parameter_discovery` runs against an existing asset or assessment
- `ffuf` results normalize discovered paths, status code, content length, and similarity fingerprint
- `arjun` results normalize parameter name, method, reflected behavior, and confidence
- Findings and assets can be filtered down to a single follow-up run
- Cancellation works cleanly for long-running fuzz jobs

---

### ESX-039
**Title:** Non-exploitative validation policy enforcement
**Priority:** P0 | **Estimate:** 8 | **Status:** Backlog

**Description:**
Enforce the product boundary that scan workers perform deterministic discovery and
non-exploitative validation only. Planning, dispatch, and worker execution must
reject exploit utilities, credential attacks, destructive template classes, and
AI-selected scan actions.

**Acceptance Criteria:**
- API and workers reject SQLMap, Hydra, Metasploit, and equivalent exploit utilities
- Unsafe Nuclei tags and templates are rejected before dispatch and again at execution
- Versioned profiles fully determine targets, tools, limits, retries, and timeouts
- Rejections produce auditable policy events without launching a process
- Historical/manual tool output can be imported only through a labelled, validated evidence workflow

---

### ESX-040
**Title:** Manual analyst workspace and Burp interoperability
**Priority:** P2 | **Estimate:** 8 | **Status:** Backlog

**Description:**
Create an analyst workspace that complements automation with manual workflows. Start with Burp import/export interoperability instead of attempting to embed Burp. Support ingest of site maps, request/response evidence, issue exports, and replay metadata so manual web testing can enrich the same asset and finding graph.

**Acceptance Criteria:**
- Analysts can import Burp issue exports and site map artifacts into an existing assessment
- Imported evidence is linked to the owning asset, route, parameter, and scan context where possible
- Findings UI clearly distinguishes automated findings from analyst-sourced findings
- Manual evidence can be included in HTML, PDF, and SARIF exports
- Import validation rejects malformed or oversized files gracefully

---

### ESX-041
**Title:** Unified reporting and drill-down evidence model
**Priority:** P1 | **Estimate:** 8 | **Status:** Backlog

**Description:**
Expand the reporting model so every module exposes consistent drill-down: run profile, tool plan, command timeline, output artifacts, asset-level findings, and module-specific summaries. Add narrative report sections for web app, API, Android, iOS, cloud, MCP, and container scans, with both executive and analyst views.

**Acceptance Criteria:**
- Every run stores a normalized command/evidence timeline viewable in the UI
- Reports group findings by module, asset, and run instead of blending historical assessments
- PDF and HTML reports include module-specific sections when relevant
- Findings can be filtered by assessment, scan run, asset, source tool, and module
- Scans page exposes summary progress, completed steps, pending steps, and per-tool outcomes

---

### ESX-042
**Title:** Third-party tool onboarding strategy and support matrix
**Priority:** P1 | **Estimate:** 5 | **Status:** Backlog

**Description:**
Create a formal support matrix for tool integrations to prevent platform sprawl and storage/performance regressions. Tools should be classified as `bundled`, `adapter_ready`, `import_only`, `manual_interop`, or `not_planned`. Initial decisions:

- Keep bundled and first-class: `nuclei`, `katana`, `subfinder`, `httpx`, `naabu`, `amass`, `waybackurls`, `assetfinder`, `gau`, `dnsx`, `nmap`, `masscan`, `trivy`, `gitleaks`, `syft`, `grype`, `prowler`
- Keep ScoutSuite, Hakrawler, and GoSpider as optional external adapters until maintained releases no longer require legacy dependency trees.
- Add next as high-value first-class or guarded adapters: `ffuf`, `arjun`, `nikto`, `ScoutSuite`
- Support via interoperability or import rather than deep embedding: `Burp`
- Keep import-only or external/manual, never executable by platform workers: `SQLMap`, `Wireshark`, `Hydra`, `Metasploit`, `John the Ripper`, `Aircrack-ng`

**Acceptance Criteria:**
- A machine-readable tool catalog exists with status, install strategy, module owner, and resource cost
- The worker image installs only `bundled` tools; adapter-ready tools are feature-flagged when missing
- UI clearly indicates whether a tool is bundled, optional, or import-only
- Storage controls prevent repeated cloning/downloading of template repos and wordlists
- Docs explain why some tools remain external/manual instead of embedded

---

### ESX-043
**Title:** Documentation-driven Nuclei profiles for Light, Medium, and Aggressive scans
**Priority:** P0 | **Estimate:** 13 | **Status:** Backlog (implementation deferred)

**Description:**
Review the official Nuclei documentation and the documentation shipped with the
version pinned by ExposureScopeX before changing scan behavior. Convert supported
Nuclei controls into explicit, versioned Light, Medium, and Aggressive execution
contracts rather than relying on arbitrary time limits or template counts. The
review must cover template selection and exclusions, protocols, workflows,
headless execution, severity and tag filters, concurrency, rate limits, retries,
request timeouts, host-error handling, statistics, result formats, template
signing, template updates, and resume behavior.

Light should provide a fast, non-destructive baseline with a documented minimum
coverage floor. Medium should broaden protocols and template families and increase
depth while remaining safe for authorized production-like environments.
Aggressive should maximize permitted non-exploitative coverage in isolated or
explicitly approved environments; it must not introduce exploitation, destructive
templates, credential attacks, denial-of-service checks, or AI-directed scanning.

**Acceptance Criteria:**
- The design cites the official documentation and records the Nuclei binary and template versions used to derive every setting
- Each mode has a machine-readable contract for included and excluded tags, severities, protocols, headless policy, workflows, concurrency, rate, retries, per-request timeout, host-error threshold, and total execution budget
- Mode differences are justified by coverage, target impact, runtime, and evidence quality rather than labels or arbitrary template counts
- Unsafe, intrusive, fuzzing, denial-of-service, credential, and exploit-oriented templates are denied by a shared policy enforced before dispatch and inside the worker
- Nuclei completion distinguishes successful coverage, zero matches, request errors, host skips, template exclusions, operator cancellation, and timeout without treating them as equivalent outcomes
- Benchmark runs use DVWA plus additional versioned vulnerable and clean fixtures, with expected findings, false positives, false negatives, precision, recall, F-score, runtime, requests, and error rate recorded per mode
- Regression gates prevent a profile release when required coverage falls below its baseline or error rate exceeds its documented tolerance
- Reports preserve the exact command policy, template-set identity, template exclusions, statistics, findings, source output, screenshots, and hashes for every run
- The UI explains what each mode will and will not test before dispatch and warns when authentication or another prerequisite limits expected coverage
- No implementation begins until the documentation review and profile specification are approved
