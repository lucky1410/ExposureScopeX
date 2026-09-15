# ExposureScopeX — Product Roadmap

> Planning document reconciled on 2026-09-10. Current status is in
> `PRODUCT_STATUS.md` and priorities are in `../BACKLOG.md`; quarter labels below
> retain historical planning context.

**Version:** 2.2.0
**Last Updated:** 2026-09-10
**Planning Horizon:** Q3 2026 — Q2 2027 (core), 2028+ (future bets)
**Maintainer:** SecOps24 Engineering

---

## Vision Statement

ExposureScopeX will become the standard platform for organizations that operate security programs at practitioner depth — teams that need more than a SaaS scanner dashboard but fewer than a full security operations center. Every organization should be able to stand up a continuously monitored, deterministic attack-surface assessment program in under an hour, from a single `docker compose up`. AI remains outside scanning and is limited to evidence-grounded post-scan analysis.

By 2027, ExposureScopeX evolves from a single-organization tool into a multi-tenant SaaS platform with a marketplace of integrations, SSO for enterprise customers, and AI-driven attack path analysis that connects external exposure directly to internal blast radius.

---

## Q3 2026 — Production Hardening and ASM Launch

**Theme:** Make what exists production-safe and ship the ASM module end-to-end.

### Goals

- Zero known security vulnerabilities in the web application layer
- ASM module fully operational: discovery → scan → findings → notifications
- Real scan execution wired from UI through Celery to the CLI framework
- Self-hosted single-org deployments supported with a documented upgrade path

### Features Shipping

| Feature | Story | Status |
|---|---|---|
| Celery scan execution | ESX-001 | Done |
| Fernet credential encryption | ESX-002 | Done |
| nginx TLS and loopback-safe local ingress | ESX-003 | Done; production certificates are deployment-owned |
| slowapi rate limiting | ESX-004 | Done |
| SSRF protection on ASM inputs | ESX-005 | Done |
| Audit logging (auth + mutations) | ESX-006 | Partial; completeness verification remains |
| Durable scan progress and events | ESX-007 | Done; REST replay replaced unauthenticated WebSocket dependence |
| Multi-tenancy org_id enforcement | ESX-008 | Done; continuous isolation tests remain |
| Docker Compose production controls | ESX-009 | Done for self-hosted single node |
| ASM per-target scan trigger | ESX-017 | Done |
| Makefile developer tasks | ESX-032 | Done |

### Success Criteria

| Metric | Target |
|---|---|
| All P0 security issues resolved | 100% of P0 stories Done by Sep 30 |
| ASM module live with at least one real cloud source | AWS sync operational |
| Self-hosted deployment documented end-to-end | `DEPLOYMENT.md` published |
| Zero unauthenticated endpoints that return org data | Verified by org isolation test suite |

---

## Q4 2026 — Scan Execution Engine, Real-Time Progress, Compliance Reports

**Theme:** Close the loop between scan initiation and actionable deliverables.

### Goals

- All deterministic, non-exploitative assessment phases end-to-end in the web UI
- Real-time scan progress visible in the browser from phase 1 through completion
- SARIF and HTML report generation operational for CI/CD and client delivery
- Integration layer: Slack, Splunk HEC, and Jira working

### Features Shipping

| Feature | Story | Quarter |
|---|---|---|
| Scan cancellation | ESX-010 | Delivered |
| Scan phase/tool output viewer | ESX-012 | Delivered |
| CI exit code API | ESX-013 | Pending |
| Scan authorization gate | ESX-014 | Delivered |
| CSV bulk target import | ESX-015 | Delivered for ASM and assessments |
| Cloud source sync (AWS/Azure/GCP) | ESX-016 | Delivered; credentials/provider access conditional |
| Assessment recurring scheduling | ESX-018 | Delivered backend and assessment workspace UI |
| HTML report | ESX-019 | Delivered |
| SARIF 2.1 export | ESX-020 | Delivered |
| PDF report | ESX-021 | Delivered with bounded ReportLab renderer |
| Slack webhook integration | ESX-026 | Delivered |
| Splunk HEC integration | ESX-027 | Delivered |
| AI Analyst streaming and evidence grounding | ESX-029 | Partial |
| Backend test suite and coverage gate | ESX-031 | Partial; 94 tests and deployed API E2E pass, coverage threshold/browser/load E2E pending |
| OpenAPI documentation audit | ESX-033 | Delivered for current routes; contract CI remains |

### Milestone: v2.3.0 Release (December 2026)

```
ExposureScopeX v2.3.0 — "Scan Engine"
- Celery-powered real scan execution from the web UI
- WebSocket real-time progress (phase + percentage)
- SARIF + HTML + PDF report export
- Slack and Splunk integrations
- AWS cloud source asset discovery
- Continuous ASM scheduling (DB-backed Celery Beat)
```

### Success Criteria

| Metric | Target |
|---|---|
| End-to-end scan from UI button to completed report | < 5 minutes for a light scan of a single domain |
| SARIF output ingested by GitHub Advanced Security | Zero errors on ingest |
| Slack notification delivered on scan completion | Within 60 seconds |
| p95 API response time under 50 concurrent users | < 200ms |
| Test suite coverage | ≥ 80% on `app/api/v1/` |

---

## Q1 2027 — Multi-Tenant SaaS Mode, SSO, Marketplace

**Theme:** Scale from single-org to multi-org hosted deployment.

### Goals

- Organization self-registration and onboarding flow
- SSO via SAML 2.0 and OIDC for enterprise customers
- API marketplace: third-party integrations installable per organization
- Kubernetes deployment reference architecture
- Usage metering for future SaaS billing

### Major Features

#### Multi-Tenant Onboarding

- **Self-service org creation**: Registration flow creates a new `organizations` row, seeds the admin user, and provisions isolated namespaces
- **Org slug routing**: `app.exposurescopex.io/{org-slug}/` routes to org-specific dashboard
- **Data isolation verification**: Automated isolation test suite runs in CI on every merge

#### SSO / SAML / OIDC

- **SAML 2.0 IdP integration**: Okta, Azure AD, and Google Workspace as identity providers
- **OIDC support**: Auth0, Cognito, Keycloak
- **SCIM provisioning**: Auto-provision users from IdP groups; map IdP groups to ExposureScopeX roles
- **Just-in-time (JIT) provisioning**: First SSO login creates user record automatically

#### Integration Marketplace (v1)

| Integration | Category | Priority |
|---|---|---|
| Slack | Notifications | P0 (shipping Q4 2026) |
| Microsoft Teams | Notifications | P1 |
| PagerDuty | Incident response | P1 |
| Jira Cloud | Ticketing | P1 (shipping Q4 2026) |
| ServiceNow | ITSM | P2 |
| Splunk | SIEM | P1 (shipping Q4 2026) |
| Elastic SIEM | SIEM | P2 |
| AWS Security Hub | Cloud native | P2 |
| GitHub Advanced Security | DevSecOps | P1 |
| GitLab Security | DevSecOps | P2 |

Each integration: installable per org, configurable via settings UI, credentials encrypted with Fernet.

#### Kubernetes Reference Architecture

```yaml
# Minimum production cluster (AWS EKS / GCP GKE / Azure AKS)
Nodes: 3x general-purpose (4 vCPU, 16 GB)
       2x compute-optimized (8 vCPU, 32 GB) — scan workers

Deployments:
  frontend:  2 replicas, HPA (cpu > 70%)
  backend:   3 replicas, HPA (rps > 100)
  worker:    2 replicas, KEDA (celery queue depth > 5)

StatefulSets:
  postgres:  1 primary + 1 read replica, PVC (100 GB gp3)
  redis:     sentinel mode (1 master + 2 replicas), PVC (10 GB)

Ingress: nginx-ingress + cert-manager (Let's Encrypt)
Secrets: AWS Secrets Manager / GCP Secret Manager / Vault
```

### Milestone: v3.0.0 Release (March 2027)

```
ExposureScopeX v3.0.0 — "Platform"
- Multi-tenant self-service onboarding
- SAML 2.0 + OIDC SSO
- Integration marketplace (10 integrations at launch)
- Kubernetes reference architecture + Helm chart
- Usage metering (API calls, scan minutes, assets tracked)
```

### Success Criteria

| Metric | Target |
|---|---|
| Org onboarding time (signup to first scan) | < 15 minutes |
| SSO login latency | < 2 seconds (excluding IdP) |
| Cross-tenant data isolation | Zero findings in automated isolation test |
| Kubernetes deployment reproducibility | `helm install` completes without manual intervention |

---

## Q2 2027 — Evidence-Grounded Risk Paths, Threat Intelligence Feeds

**Theme:** Move from finding enumeration to defensible risk-path correlation.

### Goals

- Evidence-grounded risk-path analysis connecting external findings to internal blast radius
- Live threat intelligence feed integration (MITRE ATT&CK, CVE feeds, threat actor TTPs)
- Post-scan AI assistance for explanation and remediation, never scan execution
- MSSP white-label reporting and bulk assessment management

### Major Features

#### AI-Powered Attack Path Analysis

Post-scan analysis derives risk paths from normalized assets, findings, and
immutable evidence without selecting or executing scanner actions:

- **Attack graph visualization**: D3.js force-directed graph showing the path from initial access (external finding) through lateral movement opportunities to crown-jewel assets
- **Confidence scoring**: Each attack path edge labeled with exploitability and impact confidence scores derived from CVSSv3 + contextual signals
- **"What if" simulation**: Operator can mark a finding as remediated and see how the attack graph changes
- **Executive narrative**: Auto-generated executive summary of the top 3 attack paths, written in plain English via Claude

#### Threat Intelligence Integration

- **MITRE ATT&CK mapping**: Every finding tagged with ATT&CK tactic and technique (T1190 Exploit Public-Facing Application, T1133 External Remote Services, etc.)
- **CVE feed subscription**: Daily NVD feed ingestion (supplementing the existing on-demand `cvematch.sh` lookups); alert when a new CVE matches a tracked asset's technology fingerprint
- **Threat actor TTP library**: Curated database of observed TTP chains for common threat actor groups; ASM findings matched against known initial access TTPs
- **OSINT enrichment**: Shodan, Censys, and GreyNoise context automatically pulled for each discovered IP asset

#### MSSP Bulk Management

- **Client workspace switcher**: MSSP admin can switch between client orgs from a single login
- **Bulk scheduling**: Apply a scan schedule to a tag-filtered set of targets across all client orgs
- **White-label reports**: Per-org report branding (logo, color scheme, contact details) configurable in org settings
- **Consolidated MSSP dashboard**: Cross-org risk score, open findings by client, scan completion status

### Milestone: v3.5.0 Release (June 2027)

```
ExposureScopeX v3.5.0 — "Intelligence"
- AI attack path graph (D3.js, Claude analysis)
- MITRE ATT&CK tagging on all findings
- CVE feed subscription with asset fingerprint matching
- Agent mode in the web UI
- MSSP white-label reporting and bulk management
```

### Success Criteria

| Metric | Target |
|---|---|
| Attack path analysis generation time | < 30 seconds for assessments with < 500 findings |
| CVE match accuracy | ≥ 85% true positive rate vs. manual NVD lookup |
| MITRE ATT&CK coverage | ≥ 70% of nuclei-sourced findings tagged with ATT&CK TTP |
| MSSP operator context-switch time (between clients) | < 3 seconds |

---

## Integration Roadmap

### Phase 1 — Q4 2026 (Notifications and SIEM)

```
Slack     ████████████ Done (design) → Shipping Q4 2026
Teams     ░░░░░░░░░░░░ Q4 2026
Splunk    ████████░░░░ In Progress → Shipping Q4 2026
PagerDuty ░░░░░░░░░░░░ Q4 2026
```

### Phase 2 — Q1 2027 (Ticketing and DevSecOps)

```
Jira        ░░░░░░░░░░░░ Q1 2027
ServiceNow  ░░░░░░░░░░░░ Q1 2027
GitHub GHAS ░░░░░░░░░░░░ Q1 2027
GitLab      ░░░░░░░░░░░░ Q1 2027
```

### Phase 3 — Q2 2027 (Cloud Native and Intelligence)

```
AWS Security Hub  ░░░░░░░░░░░░ Q2 2027
Elastic SIEM      ░░░░░░░░░░░░ Q2 2027
GreyNoise         ░░░░░░░░░░░░ Q2 2027
MITRE ATT&CK Nav  ░░░░░░░░░░░░ Q2 2027
```

### Integration Architecture

All integrations follow the same pattern established in `modules/integrations.sh`:

1. Credentials stored in `org_settings` table, encrypted with Fernet
2. Integration delivery triggered by domain events: `scan.completed`, `finding.created`, `finding.severity_changed`
3. Delivery via Celery task with 3-retry exponential backoff
4. Delivery status logged to `audit_logs` with payload hash (not plaintext credentials)
5. Test-connection endpoint validates credentials before saving

---

## Platform Evolution: From Tool to SaaS

| Dimension | v2.2.0 (Today) | v3.0.0 (Q1 2027) | v3.5.0 (Q2 2027) |
|---|---|---|---|
| Tenancy | Single organization | Multi-tenant self-service | MSSP white-label |
| Identity | JWT (email/password) | JWT + SAML/OIDC SSO | SSO + SCIM provisioning |
| Deployment | Docker Compose (single node) | Kubernetes (Helm chart) | Managed cloud hosting option |
| Integrations | Slack/Teams/Splunk (CLI) | 10-integration marketplace | 20+ integrations, webhook-based |
| AI | Outside scan execution | Evidence-cited analyst assistance | Risk-path graph + CVE intelligence |
| Reporting | MD/HTML/PDF/SARIF (CLI) | Web-generated, per-org branded | Compliance frameworks (PCI, SOC 2) |
| Billing | Self-hosted, free | Usage metering in place | SaaS subscription tiers |
| Support | GitHub Issues | Community + email | Enterprise SLA (business hours) |

---

## Future Bets — 2028 and Beyond

These are directional bets, not committed features. They will be re-evaluated based on market signals, customer feedback, and competitive landscape in 2027.

### Detection Collaboration Without Attack Simulation

Correlate immutable assessment evidence with authorized telemetry supplied by a
separate blue-team SOC platform. ExposureScopeX will exchange findings, ATT&CK
context, detection coverage, and remediation state, but will not execute breach
simulation, exploit payloads, credential attacks, or persistence techniques.

### Browser-Based IDE for Security Scripts

An in-browser editor (Monaco + WebAssembly) for writing and running custom nuclei templates, nmap NSE scripts, and Python reconnaissance modules. Templates saved to org library; results imported directly into the findings DB.

### Managed Scanning Infrastructure

Offer scan workers as a managed cloud service. Organizations connect their ExposureScopeX instance to SecOps24-managed worker pools hosted in multiple regions. This eliminates the need to maintain a scan server and enables concurrent scans at scale.

### Supply Chain Attack Surface

Track software dependencies (npm, PyPI, Maven, Go modules) alongside network assets. When a CVE is published for a dependency in use, automatically correlate it with the dependent service in the asset inventory and generate a finding.

### Deception and Honeypot Integration

Deploy low-interaction honeypots (HTTP, SSH, SMB) as decoy assets in the attack surface. When an adversary interacts with a honeypot, generate a real-time alert and automatically correlate the attacker's IP with ASM scan data.

### Natural Language Scan Builder

Accept plain-English scan instructions: "Check if our e-commerce site has any OWASP Top 10 vulnerabilities, skip the login page, and focus on the checkout flow." The AI Analyst translates the instruction into an assessment configuration and phase selection.
