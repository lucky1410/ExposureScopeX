# ExposureScopeX — Product Requirements Document

> Product intent reconciled on 2026-09-10. Use `PRODUCT_STATUS.md`,
> `../BACKLOG.md`, `ARCHITECTURE.md`, and capability APIs for current behavior.

**Version:** 2.2.0
**Date:** August 2026
**Status:** Living Document — Q3 2026 Sprint
**Author:** SecOps24 Engineering
**Audience:** Engineering, Product, Leadership

---

## 1. Executive Summary

ExposureScopeX is an integrated Attack Surface Management (ASM) and security assessment platform that combines a battle-tested Bash CLI framework with a full-stack web application. It enables security teams to discover, inventory, and continuously monitor every externally reachable asset belonging to their organization — then execute structured penetration tests and vulnerability assessments against those assets from a single pane of glass.

The platform spans deterministic, non-exploitative security assessment: passive reconnaissance via public APIs, authorized subdomain and port discovery, bounded web and API checks, cloud misconfiguration detection, CVE correlation, immutable evidence, and professional reporting. Findings flow into a PostgreSQL-backed database with deduplication, severity triage, case management, and multi-format reporting. AI is restricted to evidence-grounded post-scan explanation, prioritization, and remediation assistance; it never plans or executes scans.

The web application (Next.js 15 frontend + FastAPI backend) surfaces these capabilities through an accessible UI built for daily use by security engineers, pentest leads, SOC analysts, and MSSP practitioners. Real-time scan progress via Redis pub/sub, durable PostgreSQL events, Celery task orchestration, and Docker Compose packaging make the platform operable from a laptop to a production cluster.

---

## 2. Problem Statement

### The Landscape

Modern organizations operate hybrid attack surfaces: cloud workloads (AWS, GCP, Azure), on-premises infrastructure, SaaS integrations, and an ever-expanding inventory of internet-exposed assets. The gap between what IT believes is exposed and what is actually discoverable by an adversary is consistently large.

Security teams face three compounding problems:

1. **Inventory drift** — New subdomains, cloud buckets, and API endpoints appear continuously without security review. No single system of record tracks the live attack surface.
2. **Tool sprawl** — Recon, scanning, and reporting require 15+ separate tools (subfinder, nmap, nuclei, nikto, dalfox, gowitness, etc.) with disconnected output formats. Operationalizing them takes weeks to script and maintain.
3. **Assessment lifecycle gaps** — Pentest workflows are manual: kick-off in a text editor, scanning via SSH to a VPS, findings in a spreadsheet, report in a Word document. There is no continuous feedback loop between assessments and the live attack surface.

### What ExposureScopeX Solves

| Problem | Solution |
|---|---|
| Unknown attack surface | ASM module continuously discovers assets from cloud APIs, DNS, crt.sh, and manual input |
| Tool sprawl | CLI framework orchestrates 30+ tools; web app provides unified UI |
| Manual reporting | Automated MD/HTML/PDF/SARIF report generation with Chart.js risk visualizations |
| No cross-scan baseline | SQLite findings DB with `ON CONFLICT` deduplication + `--diff` / `--baseline` modes |
| Siloed scanning | Celery task queue runs real scans; WebSocket streams progress to the browser |
| Analyst workload after scans | Evidence-grounded assistance can explain and prioritize results without controlling scanner execution |
| MSSP multi-tenancy | Org-scoped data model; every table carries `org_id` FK |

---

## 3. Target Users — Personas

### Persona A: Security Engineer (Internal Red Team)
- **Background:** 3–7 years in security, fluent in CLI tools, scripts their own recon pipelines
- **Goals:** Automate recurring ASM scans, get alerted on new attack surface additions, generate evidence for compliance reports
- **Pain points:** Maintaining a fragile bash pipeline of 15 tools; no persistent findings store; manual diff between scan runs
- **Usage pattern:** Schedules weekly scans via `--interval 168 --diff --slack`; reviews dashboard daily; triages findings in the Investigations module

### Persona B: Pentest Lead
- **Background:** Senior practitioner running structured engagements for clients or internal teams
- **Goals:** Kick off scoped assessments, run deterministic discovery, validation, and cloud phases, generate deliverable-quality reports
- **Pain points:** Context switching between tools; no phase-level progress visibility; PDF report generation is manual
- **Usage pattern:** Creates an Assessment via the UI, selects phases, monitors real-time progress via WebSocket, exports SARIF for the client's SIEM

### Persona C: SOC Analyst
- **Background:** Tier 1–2 analyst monitoring alerts, triaging findings
- **Goals:** Understand risk posture at a glance, investigate specific findings, escalate to cases
- **Pain points:** No single risk score; can't link a finding to an asset's full history; alert fatigue from noise
- **Usage pattern:** Reviews Dashboard risk score daily; opens high/critical findings; creates Investigation cases; uses AI Analyst for quick threat intel summaries

### Persona D: MSSP Practitioner
- **Background:** Manages 10–50 client organizations; needs efficient batch operations and per-client isolation
- **Goals:** Run bulk scans across client targets, produce branded reports, suppress known-good findings per client baseline
- **Pain points:** Shared tooling without client isolation; no per-client baseline for noise suppression; manual report generation per client
- **Usage pattern:** Uses `-f clients.txt --baseline --slack` for batch runs; organization isolation ensures no cross-client data leakage

---

## 4. Core Value Propositions

1. **Single platform, defensible assessment lifecycle** — Passive recon through non-exploitative validation and evidence-backed reporting; web UI and CLI are peers, not one a wrapper for the other.
2. **Zero-day-one value** — Demo data (AcmeCorp: 15 assets, 50 findings, 8 CVEs) lets evaluators experience the full workflow without running a real scan.
3. **Continuous ASM, not point-in-time** — Cron-based scheduling, `--diff` state diffing, and `--baseline` suppression turn a scan tool into a monitoring platform.
4. **Evidence-grounded intelligence** — Optional AI assists only after scanning with explanation, prioritization, and remediation drafts that cite immutable evidence and require operator review.
5. **Operator-grade security** — encrypted integration credentials, bcrypt password hashing, configurable short-lived access sessions with rotating refresh sessions, CSRF-protected HttpOnly cookies, nginx rate limiting, and persisted audit records.

---

## 5. Feature Requirements

### 5.1 Dashboard Module

| ID | Feature | Priority | Description | Acceptance Criteria |
|---|---|---|---|---|
| F-DASH-01 | Risk Score KPI | P0 | Aggregate risk score (0–100) computed from finding severity distribution | Score updates within 30s of a new finding being saved |
| F-DASH-02 | Findings Trend Chart | P0 | Time-series Chart.js chart of findings by severity over last 30 days | Chart renders correctly in both light/dark themes |
| F-DASH-03 | Asset Count Tiles | P0 | Live count of total assets, live hosts, open ports | Tile values match `/api/v1/dashboard` response |
| F-DASH-04 | Recent Activity Feed | P1 | Last 10 scan events, new findings, and case updates | Pulls from audit_logs and scans tables |
| F-DASH-05 | Top Vulnerabilities Widget | P1 | Top 5 critical/high findings across all assessments | Clicking a row navigates to the finding detail page |

### 5.2 ASM (Attack Surface Management) Module

| ID | Feature | Priority | Description | Acceptance Criteria |
|---|---|---|---|---|
| F-ASM-01 | Target Inventory | P0 | Add targets (domain/IP/CIDR/hostname) manually, via CSV upload, or from cloud sources | All three ingestion paths write to `asm_targets` table with correct `source_type` |
| F-ASM-02 | Cloud Source Discovery | P0 | Connect AWS/GCP/Azure accounts; enumerate compute, DNS, storage assets automatically | Cloud credentials encrypted at rest with Fernet; `asm_cloud_sources.status` reflects sync result |
| F-ASM-03 | ASM Scan Execution | P0 | Trigger DNS/SSL/HTTP headers/port/subdomain checks per target via Celery | `asm_targets.scan_status` transitions idle→scanning→completed; `last_scan_summary` JSONB populated |
| F-ASM-04 | ASM Findings Table | P0 | Display findings from `asm_findings` with severity filter, source filter, status triage | Findings link to parent target; status updates persist to DB |
| F-ASM-05 | SSRF / Input Validation | P0 | Block private RFC-1918 ranges, loopback, and metadata IPs in target inputs | POST /api/v1/asm/targets rejects 169.254.169.254, 10.x.x.x, 127.x.x.x with 422 |
| F-ASM-06 | Scope File Support | P1 | Upload a scope file; ASM respects wildcard/CIDR/exact-domain rules | Only in-scope targets trigger scans; out-of-scope targets shown with "out of scope" badge |
| F-ASM-07 | Continuous Monitoring Schedule | P1 | Per-target cron schedule for automatic re-scanning | Schedule stored in DB; Celery beat triggers at configured interval |

### 5.3 Assessments Module

| ID | Feature | Priority | Description | Acceptance Criteria |
|---|---|---|---|---|
| F-ASSESS-01 | Create Assessment | P0 | UI wizard: target, scan mode (light/medium/aggressive), phase selection, optional flags | Assessment record written to DB with status=created |
| F-ASSESS-02 | Celery Scan Dispatch | P0 | Creating an assessment enqueues a `worker.tasks.run_scan` Celery task | `scans.celery_task_id` populated; scan transitions queued→running |
| F-ASSESS-03 | Real-time Progress | P0 | WebSocket stream from Redis pub/sub channel `scan_progress:{scan_id}` | Browser receives phase name and 0–100 progress integer; UI shows live progress bar |
| F-ASSESS-04 | Scan Cancellation | P1 | Cancel a running scan from the UI; Celery task revoked | `scans.status` = cancelled; subprocess terminated cleanly |
| F-ASSESS-05 | Scan Authorization | P1 | Operator must provide written authorization before exploit phase runs | `scan_authorizations` record required; `-x` flag blocked without it |
| F-ASSESS-06 | Phase-level Output | P1 | View raw log output per phase in the assessment detail page | `scans.raw_log` streamed to UI; downloadable as .txt |
| F-ASSESS-07 | Result Parsing | P1 | Parsers ingest nuclei/nmap/nikto/ssl output into findings/assets/ports tables | parser modules in `backend/app/services/parsers/` process output files post-scan |

### 5.4 Assets, Vulnerabilities, Findings

| ID | Feature | Priority | Description | Acceptance Criteria |
|---|---|---|---|---|
| F-INV-01 | Asset Detail Page | P0 | Per-asset view: open ports, TLS cert, technologies, HTTP headers, DNS records | All related tables render; relationships loaded via SQLAlchemy selectin |
| F-INV-02 | Vulnerability Triage | P0 | Severity filter, status update (open/confirmed/false-positive/remediated), CVSS score | Status update writes to DB and creates audit_log entry |
| F-INV-03 | Finding Deduplication | P1 | `ON CONFLICT` upsert by (target, title, source) prevents duplicate rows | Running same scan twice does not double-count findings in the dashboard |
| F-INV-04 | CVE Correlation | P1 | `cvematch.sh` cross-references nmap/whatweb fingerprints with NVD API | `cve_matches.txt` populated; CVE IDs displayed on vulnerability rows |

### 5.5 Investigations (Cases) Module

| ID | Feature | Priority | Description | Acceptance Criteria |
|---|---|---|---|---|
| F-CASE-01 | Create Case | P0 | Link findings, assets, and notes into a named investigation | `investigations` table populated; finding FK list stored in JSONB |
| F-CASE-02 | Case Timeline | P1 | Chronological event log of all activity within a case | Events sourced from audit_logs filtered by entity_id |
| F-CASE-03 | Evidence Attachment | P2 | Upload screenshots, raw output files, and notes as evidence | Files stored in `results/` volume; metadata in DB |

### 5.6 Reporting

| ID | Feature | Priority | Description | Acceptance Criteria |
|---|---|---|---|---|
| F-RPT-01 | Markdown Report | P0 | Auto-generated executive + technical report in Markdown | `/api/v1/reports/{id}` returns rendered Markdown |
| F-RPT-02 | HTML Report with Charts | P0 | Chart.js-powered HTML report with severity pie, timeline, asset table | Report renderable without internet access |
| F-RPT-03 | SARIF Export | P1 | Static Analysis Results Interchange Format for SIEM/pipeline ingestion | SARIF file passes schema validation at sarifweb.azurewebsites.net |
| F-RPT-04 | PDF Export | P2 | PDF via pandoc; included in Docker worker image | PDF generated in < 60 seconds for assessments with < 200 findings |

### 5.7 Security & Infrastructure (Non-Functional)

| ID | Requirement | Priority | Description | Acceptance Criteria |
|---|---|---|---|---|
| NF-SEC-01 | TLS Termination | P0 | nginx handles TLS; self-signed for dev, Let's Encrypt for prod | All HTTP traffic on port 80 redirects 301 to 443 |
| NF-SEC-02 | Rate Limiting | P0 | 30 req/s general API, 5 req/min auth endpoints at nginx layer | 429 returned on burst; legitimate requests not throttled |
| NF-SEC-03 | Audit Logging | P0 | All auth events and data mutations write an `audit_logs` row | Login, logout, create/update/delete assessment all appear in audit_logs |
| NF-SEC-04 | Fernet Encryption | P0 | Cloud credentials in `asm_cloud_sources.config` encrypted with Fernet | Plaintext credentials not visible in DB dump |
| NF-SEC-05 | SSRF Protection | P0 | ASM target input validator blocks private IP ranges | 422 returned for RFC-1918 and link-local addresses |
| NF-SEC-06 | Session Expiry | P1 | Access tokens expire in 60 minutes by default; rotating refresh sessions in 7 days | Expired token returns 401; refresh rotates session credentials |
| NF-SEC-07 | Org Isolation | P0 | Every DB query scoped by `org_id`; no cross-tenant data leakage | Analyst in Org A cannot retrieve data belonging to Org B |
| NF-PERF-01 | API Response Time | P1 | p95 response time < 200ms for list endpoints under normal load | Measured with k6 at 50 concurrent users |
| NF-PERF-02 | Scan Concurrency | P1 | Worker supports ≥ 2 concurrent scans (`--concurrency=2`) | Two assessments running simultaneously do not interfere |

### 5.8 Scan Operations and Profiles

| ID | Feature | Priority | Description | Acceptance Criteria |
|---|---|---|---|---|
| F-OPS-01 | Execution Preview | P0 | Resolve target count, queue, tools, policy and prerequisites before dispatch | Preview performs no scan and reports unavailable requirements truthfully |
| F-OPS-02 | Saved Profiles | P0 | Save reusable non-secret custom scan configuration | Profiles are organization-scoped and deletable; secrets are never embedded |
| F-OPS-03 | Work-unit Progress | P0 | Persist planned, running, completed, failed, skipped and blocked work | Progress survives browser disconnect and does not remain at zero after work starts |
| F-OPS-04 | Command and Evidence Drill-down | P1 | Show tool status, version, bounded command/output and artifacts | Sensitive arguments/output are redacted and tied to one scan/tool run |
| F-OPS-05 | Recovery | P0 | Cancel, retry and clone failed configuration without overwriting history | Retry creates a new execution identity; terminal history remains immutable |
| F-OPS-06 | Capability Routing | P0 | Dispatch only to online workers with queue and required tools | Missing compatibility blocks dispatch with actionable detail |

### 5.9 MCP and AI Security

| ID | Feature | Priority | Description | Acceptance Criteria |
|---|---|---|---|---|
| F-MCP-01 | MCP Inventory | P0 | Discover protocol version, tools, resources, prompts and tasks | Inventory is redacted and unsupported capabilities are explicit |
| F-MCP-02 | Security Probes | P0 | Execute baseline/expanded non-destructive protocol, auth, input and isolation checks | HTTP and JSON-RPC semantics are evaluated separately; cancellation works |
| F-MCP-03 | MCP Evidence | P0 | Store request/response exchanges and normalized findings | Tokens are redacted; each exchange is attributable to check/run |
| F-MCP-04 | Destructive Safety | P0 | Prevent state-changing/tool execution without isolated-lab consent | Default profiles never invoke arbitrary advertised tools |
| F-AI-01 | Evidence-grounded Analysis | P1 | Generate analysis from tenant-owned immutable evidence | Claims cite evidence; model/prompt provenance and approval are retained |

### 5.10 Cloud and Software Supply Chain

| ID | Feature | Priority | Description | Acceptance Criteria |
|---|---|---|---|---|
| F-CLOUD-01 | CSPM Adapter | P0 | Execute Prowler with least-privilege provider identity | Missing credentials/provider capability reports blocked, never passed |
| F-CLOUD-02 | Cloud Normalization | P0 | Ingest resources, findings and relationships into shared models | Cloud records retain account, region, provider and source scan |
| F-SC-01 | Repository Security | P1 | Detect secrets, dependencies, vulnerabilities and SBOM | Checkout is bounded/cleaned and secret evidence is redacted |
| F-SC-02 | Image Security | P1 | Inventory packages and correlate vulnerabilities with Trivy/Syft/Grype | Registry failure and unsupported architecture are explicit |
| F-MOB-01 | Mobile Static Analysis | P1 | Analyze supported Android/iOS artifacts/repositories | UI labels static versus dynamic coverage and required adapters |

### 5.11 Reporting and Operations Assurance

| ID | Feature | Priority | Description | Acceptance Criteria |
|---|---|---|---|---|
| F-RPT-05 | Immutable Report Scope | P0 | Persist assessment/scan/asset/filter scope and digest | Regeneration cannot silently include unrelated historical findings |
| F-RPT-06 | Evidence Bundle | P1 | Export normalized evidence and checksums | Bundle excludes credentials and verifies SHA-256 content |
| F-OBS-01 | Runtime Operations | P0 | Expose readiness, queues, stale scans, workers, versions and capability | Admin metrics are authenticated and alerts cover disk/backup/queue health |
| F-DR-01 | Backup and Restore | P0 | Create checksummed backup and controlled restore | Quarterly isolated restore evidence meets documented RPO/RTO |

---

## 6. Current State vs. Target State

| Capability | Current State | Target State |
|---|---|---|
| Scan execution | Celery dispatches real scanner runs with queue routing, tenant quotas, cancellation, durable events, and tool provenance | Kubernetes-isolated execution and queue-specific pools for scaled production deployments |
| Cloud credentials | Integration secrets are encrypted at rest and decrypted only at the execution boundary | Prefer short-lived workload identity for every production cloud integration |
| TLS | nginx terminates configured TLS; local deployment remains loopback-bound by default | Managed certificates and external ingress are deployment responsibilities |
| Rate limiting | nginx and application controls protect authentication, API, and scan dispatch paths | Continuously tune limits from production telemetry and abuse testing |
| SSRF protection | Target and integration validators reject unsafe network destinations; explicit local MCP aliases are narrowly controlled | Maintain bypass tests as URL parsers and supported protocols evolve |
| Audit logging | Persisted auth, authorization, integration, scan, and mutation events with remaining endpoint coverage tracked as hardening work | All security-relevant mutations produce immutable audit rows |
| Progress | Tenant-scoped REST polling reads durable PostgreSQL events/tool runs plus weighted work units; Redis carries ephemeral worker signals | Add push delivery only with authenticated tenant ownership and replay semantics |
| Multi-tenancy | Organization filters, role capabilities, dispatch quotas, and tenant execution leases are enforced | Validate continuously with cross-tenant integration and load tests |

---

## 7. Success Metrics (KPIs)

| Metric | Target | Measurement |
|---|---|---|
| Time to first scan (new user) | < 10 minutes from `docker compose up` | User testing sessions |
| ASM discovery coverage | > 90% of subdomains found by manual research also found by ASM | Comparative benchmarks against crt.sh |
| Scan success rate | > 95% of queued scans reach `completed` status | `scans` table status distribution |
| False positive rate | < 10% of findings marked false positive within 30 days | `asm_findings.status` distribution |
| Mean time to triage | < 4 hours from finding creation to status update | Difference between `created_at` and last `audit_log` entry for the finding |
| Report generation time | < 2 minutes for assessments with < 100 findings | Timing in `reports.py` |
| Platform uptime | 99.5% for self-hosted single-node deployment | Docker healthcheck failure rate |

---

## 8. Out of Scope (v2.2.0)

- **SaaS billing and subscription management** — single-org self-hosted only in this release
- **SSO / SAML / OIDC** — planned for Q1 2027
- **Native mobile application** — browser-responsive web only
- **Exploitation and attack simulation** — credential attacks, exploit payload generation or execution, persistence, command-and-control, and autonomous attack simulation are outside the product boundary
- **Managed scanning infrastructure** — users provide their own compute
- **Compliance frameworks (SOC 2, PCI DSS, ISO 27001) as first-class reports** — planned for Q4 2026

---

## 9. Dependencies and Assumptions

### Technical Dependencies
- Docker Engine ≥ 24 and Docker Compose ≥ 2.20 on the host
- PostgreSQL 16 (provided via Docker image)
- Redis 7 (provided via Docker image)
- External intelligence API keys are optional but improve coverage: Shodan, VirusTotal, Censys, HIBP, and GitHub
- The bash framework tools (nmap, subfinder, nuclei, httpx, etc.) are either installed on the host or executed via the worker container image

### Assumptions
- The operator has legal authorization to scan all targets before triggering any active scan phase
- Cloud source credentials (AWS IAM, GCP service account, Azure service principal) are read-only and scoped to asset discovery APIs only
- The `results/` directory is bind-mounted into both the backend (read-only) and worker (read-write) containers
- Scan authorization is a policy control; the platform assumes the operator has verified authorization before enabling the `-x` exploit flag
