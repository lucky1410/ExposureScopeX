# ExposureScopeX Architecture

**Verified against source:** 2026-09-10
**Schema head:** `018_operation_control_plane`

## Context

ExposureScopeX separates its control plane from scanner execution. The control
plane owns identity, authorization, scope, planning, scheduling, persistence,
normalization and reporting. Workers execute bounded plans with mature tools
and return evidence.

## Non-negotiable architecture invariants

1. **Deterministic scanning:** AI never selects targets, tools, payloads, templates,
   retries, timing, scope expansion, or scan actions. Versioned profiles and policy
   code produce the complete execution plan before dispatch.
2. **No exploitation:** workers do not perform credential attacks, exploit execution,
   destructive validation, persistence, command-and-control, or autonomous attack
   simulation. Forbidden utilities and template classes are rejected by backend
   planning and worker execution policy.
3. **Fail-closed scope:** authorization and normalized scope are checked at intake,
   dispatch, discovery-output aggregation, tool invocation, and ingestion. A failed
   scope control stops the affected work rather than widening access.
4. **Evidence before assurance:** each finding must map to an immutable source
   artifact and a valid finding-specific snapshot. Browser error pages, generated
   images, and generic terminal captures cannot satisfy finding proof.
5. **Completion is not finality:** a scan may complete with warnings, but its report
   remains Partial until the evidence release gate passes. Skipped and timed-out
   stages remain visible in coverage and reports.
6. **AI is post-scan only:** AI may explain completed evidence, prioritize risk,
   draft remediation, and correlate SOC feedback. AI output is labelled, cited to
   immutable evidence, tenant-isolated, and never treated as scanner truth.
7. **PostgreSQL is authoritative:** Redis, browser state, logs, and generated files
   are not the sole record of scan lifecycle, tenant ownership, or finding state.

```text
Browser
  -> nginx edge (optional TLS termination)
    -> Next.js frontend
    -> FastAPI control plane
       -> PostgreSQL: tenant state, inventory, lifecycle, provenance
       -> Redis: Celery, rate limits, progress pub/sub
       -> database or S3-compatible artifact storage
       -> scans-web / scans-api / scans-artifact / scans-cloud / scans-mobile
          -> local Compose worker or isolated Kubernetes Job
```

## Components

| Component | Responsibility | Persistent state |
|---|---|---|
| nginx | Edge routing, headers, limits and optional TLS | Certificates outside image |
| frontend | Next.js operator interface | Browser session state only |
| backend | FastAPI API, authorization, planning and normalization | PostgreSQL/artifacts |
| worker | Celery execution and scanner adapters | Per-scan evidence workspace |
| scheduler | Maintenance and scheduled control-plane tasks | PostgreSQL/Redis |
| PostgreSQL | Authoritative relational state | `postgres_data` volume |
| Redis | Queue, pub/sub, limits and transient coordination | `redis_data` volume with AOF |
| Nuclei runtime | Official/community template working sets | `nuclei_runtime` volume |

The default Compose deployment uses one broad worker to reduce memory. The
`worker-pools` profile separates queue contention while reusing the image.
Production Kubernetes can use per-scan Jobs for stronger isolation.

## Logical planes and contracts

| Plane | Owns | Must not own | Release contract |
|---|---|---|---|
| Experience | Role-aware UI, navigation, live status, evidence review | Authorization truth or scanner state | Primary analyst and executive journeys pass browser tests |
| Control | Identity, tenant policy, scope, profiles, orchestration, lifecycle | Raw tool execution | Every dispatch has an authorized immutable execution manifest |
| Execution | Bounded tool processes, cancellation, heartbeats, raw artifacts | User-defined commands, AI decisions, report finality | Every stage is policy-checked, timed, attributable, and terminal |
| Evidence | Artifact hashing, finding linkage, snapshots, retention, chain of custody | Risk narrative or synthetic proof | Every confirmed finding has verifiable source and visual evidence |
| Intelligence | Deterministic normalization, correlation, risk, post-scan AI assistance | Mutation of scanner facts | Derived claims cite immutable inputs and preserve provenance |
| Integration | SOC exchange, webhooks, exports, object storage | Cross-tenant trust or implicit response actions | Versioned, authenticated, idempotent contracts pass isolation tests |

Cross-plane communication uses identifiers and versioned schemas rather than
shared process memory. The control plane may request work, but only execution
policy can admit it. The evidence plane may downgrade report finality, and no
other plane can bypass that decision.

## Architecture acceptance gates

1. **Plan gate:** profile version, normalized targets, tool/template allowlists,
   scope decision, authorization, limits, and worker requirements are persisted.
2. **Dispatch gate:** tenant ownership, authorization validity, compatible worker,
   quota, and duplicate-dispatch protection pass in one controlled transition.
3. **Execution gate:** worker independently revalidates policy and scope; every
   stage has bounded retries, silence threshold, timeout, cancellation, and status.
4. **Ingestion gate:** parsers preserve source attribution, JSON-safe types,
   immutable artifact hashes, scan ownership, and idempotent observations.
5. **Evidence gate:** source artifact and original finding-specific capture are
   traceable; error-state, generic, synthetic, or unhashed evidence is rejected.
6. **Release gate:** terminal coverage, skipped/failed stages, evidence gaps,
   report integrity, and Partial/Final state are consistent across API, UI, and exports.

## Request and execution flow

1. The API authenticates the user and resolves organization capability.
2. Intake normalizes domain, URL, API, IP, CIDR, ASN, organization,
   repository, image, cloud account, Kubernetes, Android, iOS, MCP, file, or
   CSV seeds.
3. Planning merges a built-in mode, scan intents, saved profile, utilities and
   Nuclei tags.
4. Execution preview calculates target count, queue, tools, prerequisites,
   policy limits and estimates.
5. Authorization, scope, target policy, tenant quota and compatible-worker
   checks gate dispatch.
6. The database transaction creates scan and event state; Celery receives
   identifiers and bounded configuration.
7. A worker obtains a lease, creates a mode-0700 workspace, runs planned tools,
   and records versions, status, progress, bounded output and artifacts.
8. Parsers normalize assets, observations, findings and relationships while
   preserving tool-run attribution.
9. Terminal state is committed as completed, partial, failed or cancelled. Comparable
   completed scope drives finding reopen/resolve transitions.
10. Reports use immutable scan scope and execute asynchronously on the reports
    queue with durable status, cancellation, quota and integrity enforcement.
11. The evidence release gate evaluates source-artifact hashes and finding-specific
    captures. Only a passing gate can produce a Final forensic report.

## Profile and benchmark architecture

Light, Medium, and Aggressive are versioned breadth/depth contracts, not accuracy
labels. Their executable contracts define enumeration limits, port policy, crawl
depth and seed limits, Nuclei limits/concurrency/retries, headless behavior, and
bounded-stage policy. Every profile disables exploitation and autonomous agents.

Accuracy is measured separately by the deterministic benchmark plane in
`app.services.assessment_benchmark`:

```text
Pinned benchmark fixture + versioned ground truth
  -> deterministic profile execution
  -> normalized observations + source/evidence/screenshot hashes
  -> confusion matrix by category and overall
  -> precision, recall, F1, FPR, execution coverage, evidence and scope gates
  -> immutable scorecard + release pass/fail
```

The evaluator does not use AI. It rejects missing evidence, scope violations, and
unreported planned-stage outcomes independently of detection accuracy. Releases
must run each reset fixture at least three times and satisfy the profile's
repeatability-variance gate. Suite pins, adapter status, and the local scoring
command are maintained in [`../benchmarks/`](../benchmarks/README.md).

See [Scan lifecycle](SCAN_LIFECYCLE.md) for transitions and recovery.

## Trust boundaries

### Internet to edge

Default Compose ports bind to loopback. Production must terminate TLS and set
exact origins, trusted hosts, secure cookies and request limits.

### User to control plane

Resources are organization-scoped. Read and write capabilities are checked
separately. Session records support refresh rotation and logout revocation.
Security-relevant mutations emit audit records with correlation, actor, tenant,
route and outcome metadata. Append-only database enforcement remains hardening.

### Control plane to worker

Workers are privileged relative to targets because scanners need egress and
some require `NET_RAW`. User input must never become an arbitrary shell command.
Plans use fixed tool identifiers and validated arguments. Capability-aware
dispatch prevents required tools from reaching incompatible workers.

### Worker to target

Authorization records, scope, profile and safety tier constrain active behavior.
SSRF controls protect control-plane fetches but do not replace egress policy.
Kubernetes Jobs are non-root, tokenless, seccomp-confined, ingress-denied and
deadline-bound; `NET_RAW` is opt-in.

### Platform to third parties

Cloud accounts, webhooks, intelligence services, repositories and object
storage are conditional boundaries. Secrets are encrypted and redacted.
Production should prefer short-lived workload identity over static keys.

## Data and isolation

- PostgreSQL is authoritative; Redis is never the sole scan record.
- Tenant queries include organization predicates; cross-tenant tests are a
  release gate.
- Assets are reusable inventory. Assessment/scan links and finding observations
  preserve run-specific truth.
- Stable finding identities group recurrence; observations retain evidence.
- Reports bind immutable scope and SHA-256 integrity metadata.
- Local artifacts have retention; S3 keys are tenant-prefixed and can use
  server-side encryption.

See [Data model](DATA_MODEL.md) for entity relationships.

## Failure design

- `/health` is process liveness; `/ready` verifies dependencies and schema.
- Durable events reconstruct progress after Redis pub/sub loss.
- Celery task identity, cancellation flags, leases and stale-run recovery avoid
  permanently running scans after worker loss.
- Tool failures are isolated; unavailable optional adapters cannot report success.
- Queue limits, worker recycling, memory/time limits and per-scan disk policy
  bound resource consumption.
- Compose logs rotate; cache, images, volumes and artifacts are accounted separately.

## Observability

Operations exposes queue depth, scan state, tool progress, worker heartbeats,
versions and compatibility. Prometheus metrics and alert rules cover stale
scans, queue growth, readiness, disk pressure and backup age.

## Deployment forms

- **Local/controlled:** Docker Compose, shared worker, loopback ports.
- **Higher throughput:** Compose `worker-pools` profile.
- **Production isolation:** Kubernetes scanner Jobs plus managed PostgreSQL,
  Redis, object storage, ingress/TLS and monitoring. The repository includes
  scanner RBAC, not a complete production Helm platform.

## Deliberate constraints

- No arbitrary plugin execution or community-code marketplace.
- No exploitation, credential attacks, or destructive attack simulation.
- No AI participation in scan planning or execution.
- No claim of dynamic mobile-device testing from static artifact scans.
- No claim that a configured integration was successfully validated.
- No microservice/event-bus decomposition without measured need.

Architecture decisions are in [`adr/`](adr/README.md). Abuse cases and
mitigations are in [Threat model](THREAT_MODEL.md). The editable layered system
view and delivery increments are in
[Reference architecture](REFERENCE_ARCHITECTURE.md).
