# ADR-001: Deterministic Multi-Agent Boundary

Status: accepted  
Date: 2026-09-10

## Decision

ExposureScopeX uses a deterministic, evidence-first execution plane for all
security assessment activity. Probabilistic AI services are isolated in an
analysis and assurance plane and cannot select targets, modify scope, configure
tools, dispatch scanners, validate their own output, or change original evidence.

## Logical layers

1. Analyst experience: web interface, API and client workflows.
2. Trust control plane: identity, authorization, scope, policy, approvals and audit.
3. Deterministic coordination: versioned execution DAG, durable work ledger,
   leases, retries, cancellation and terminal-state enforcement.
4. Specialist agent domains: ASM, DAST, API, SAST, SCA/SBOM, IAST import,
   secrets, infrastructure, cloud, container, IaC, configuration/passive audit,
   AI security/trust, risk correlation and purple assurance.
5. Execution adapters: sandboxed scanner and importer contracts. MCP is an
   optional connector, not the platform's security or orchestration boundary.
6. Data and evidence: PostgreSQL system of record, immutable artifacts,
   cryptographic integrity, provenance and retention controls.
7. Independent assurance: normalization, validation, benchmarking, confusion
   matrices, calibration, groundedness, trajectory, RAG and robustness evaluation.
8. Delivery: findings, risk paths, remediation, DOCX/PDF reports and evidence bundles.

## AI boundary

AI may summarize validated facts, explain evidence, propose remediation drafts,
perform approved AI-system evaluations and assist analysts. Every AI output must
retain model, prompt, input evidence, citations, confidence basis and human-review
state. AI outputs are advisory until independently validated.

LangChain, LangGraph, model routers and RAG frameworks may be used inside this
isolated plane when they provide measurable value. They are not foundational
platform dependencies and never become the authoritative workflow engine.

## Exclusions

- Adversarial simulation and exploitation are outside the current product scope.
- Scanner execution does not use generative AI.
- Agents cannot invoke one another directly or create unapproved work.
- MCP does not replace process isolation, authorization, schema validation or policy.
- Product contracts do not depend on AWS or another single cloud provider.
- SOC integration remains deferred and outside the current assessment critical path.

## Deployment

Local development may host multiple deterministic agents in one runner process.
Production deploys the same versioned contracts as isolated workloads with tenant,
resource, network and identity boundaries. Cloud implementations are replaceable;
logical agent, evidence and report contracts remain unchanged.

## Consequences

- Assessment results remain reproducible and auditable.
- AI innovation can proceed without weakening scanner or evidence integrity.
- Specialist agents can collaborate through governed, persisted handoffs.
- The platform requires explicit schemas and adapters rather than unrestricted
  agent conversations.
- New engines are not considered operational until they satisfy evidence,
  benchmark, failure-handling and reporting gates.

