# ExposureScopeX v3

ExposureScopeX v3 is a clean multi-agent red-team assessment platform
foundation. It is intentionally developed beside the legacy implementation
until migration is complete.

Read [PRODUCT_PROBLEM_STATEMENTS.md](PRODUCT_PROBLEM_STATEMENTS.md) first for
the canonical product problem, component boundaries, and the meaning of a
release decision.

## Runtime

The local stack has four services:

- `web`: operator interface
- `api`: control plane and read API
- `runner`: hosts independently scalable deterministic assessment agents
- `postgres`: system of record and durable work queue

Redis, Celery, nginx, Prometheus, Grafana, Elasticsearch, and queue-specific
worker replicas are not required for local development.

AI Assurance & Observability is hosted as a bounded module in `api`. Its active
v3 capability is pre-release AI evaluation, not runtime telemetry monitoring. It
is not another container and is not part of assessment-scan execution. Its
dedicated workspace is available at `http://localhost:3001/ai-evaluator`.

Customer-owned AI systems can be evaluated through the installable
[`client-runner`](client-runner/README.md), which runs beside a customer model,
RAG application, or agent and can submit a redacted signed result package. The
repository also includes a [GitHub Actions OIDC wrapper](github-actions/evaluate/README.md)
for secretless CI release checks.

## Start

```powershell
Copy-Item .\v3\.env.example .\v3\.env
docker compose -f .\v3\compose.yml up -d --build
docker compose -f .\v3\compose.yml ps
```

Open `http://localhost:3001`. The API health endpoint is
`http://localhost:8001/health`.

## Isolated DVWA verification lab

DVWA is deliberately excluded from the production stack. Start the optional
lab overlay with the base file so the runner and target share the isolated
`assessment_lab` network:

```powershell
docker compose -f .\v3\compose.yml -f .\v3\compose.lab.yml up -d dvwa-db dvwa runner
docker compose -f .\v3\compose.yml -f .\v3\compose.lab.yml exec runner python /opt/esx-lab/initialize-dvwa.py
```

Use `http://dvwa.lab.internal` as the assessment target and
`http://dvwa.lab.internal/login.php` as the login URL. The operator-only browser
view is published separately at `http://127.0.0.1:4281`; the scanner must use
the network alias, not host loopback. The initialization command waits for DVWA,
creates or resets its disposable database when setup is available, and verifies
the documented lab credentials `admin` / `password`. The overlay pins the target to
the English locale and low DVWA security level for reproducible validation.

## Assessment profiles

Profiles are defined by assessment depth and assurance, not tool runtime or
request volume. All profiles use the same authorization, evidence, validation,
coverage, and reporting contracts.

| Profile | Purpose | Validation depth |
| --- | --- | --- |
| Light | Rapid exposure baseline | Observable configuration, attack-surface and metadata checks; no security payload submission |
| Medium | Expanded non-destructive application assessment | Light plus GET-only route/form/parameter inventory, session-cookie review, and published API-contract review |
| Aggressive | Broad non-destructive assessment | Medium plus expanded approved-surface coverage and route-level policy consistency review |

The current v3 adapters implement only part of the long-term contracts. Larger
crawl, service, or template budgets do not alone make an assessment
industry-grade. Current Medium and Aggressive profiles add the evidence-backed
observational stages listed above; they do not yet perform multi-role,
payload-based, state-transition, or business-logic validation. Promotion
requires labelled benchmark results and complete methodology coverage. Nuclei
remains restricted to signed, non-intrusive templates; Aggressive means maximum
approved safe depth, not exploitation.

## Product boundary

- Scanning is deterministic and never controlled by AI.
- Exploitation, credential attacks, persistence, and destructive checks are
  prohibited.
- Every planned stage reaches a terminal status.
- Every run is reportable, including partial, cancelled, and failed runs.
- Findings require traceable source evidence before release.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the governing design,
[ASSESSMENT_FLOW.md](ASSESSMENT_FLOW.md) for the lifecycle, and
[ASSESSMENT_PROFILE_STANDARD.md](ASSESSMENT_PROFILE_STANDARD.md) for profile
definitions and release gates. See
[MEDIUM_MODE_SPEC.md](MEDIUM_MODE_SPEC.md) for the Medium implementation target
and promotion checklist. See
[BACKEND_10_10_CHECKLIST.md](BACKEND_10_10_CHECKLIST.md) for the backend release
quality definition. The bounded quality-assurance architecture and developer
smoke test are documented in [AI_EVALUATOR.md](AI_EVALUATOR.md).
