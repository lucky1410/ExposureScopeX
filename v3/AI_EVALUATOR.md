# AI Assurance & Observability: Pre-release Evaluation

## Product boundary

AI Assurance & Observability is a standalone ExposureScopeX component for
testing AI models, RAG systems, and agent workflows before release. The active
v3 capability is pre-release evaluation; production telemetry observability is
an explicit future integration. It is not an assessment stage, does not accept
assessment or scan identifiers, and is never invoked automatically by Light,
Medium, or Aggressive vulnerability assessments.

The component cannot execute or configure scanners, alter original evidence,
or promote an unsupported security finding. The current evaluator runs inside the v3 API
deployment as one bounded modular-monolith module; it does not add another
service, queue, or agent mesh.

## Enterprise operating model

An evaluator result is an accountable release record, not an unqualified model
score. The production data boundary is:

```text
Organization workspace -> evaluation project -> approved dataset version
  -> immutable evaluation input + metrics -> report and audit events
```

- Every evaluator query, run, report, and download is organization-scoped.
- Workspace roles are `owner`, `admin`, `analyst`, and `viewer`. Owners and
  administrators create projects and approve datasets; analysts can register
  drafts and run evaluations; viewers are read-only.
- A dataset has a classification, source reference, SHA-256 source digest, and
  `draft`, `approved`, or `retired` lifecycle. A metric or semantic run is
  rejected unless its declared dataset version is approved in its project.
- Evaluations, generated reports, and evaluator audit events are append-only
  database records. Correcting a result means creating a new evaluation, never
  rewriting a release decision.
- The client shows the active workspace, role, dataset registry, approval
  state, report viewer, and deterministic replay result. It never shows raw
  customer labels, prompts, evidence, or trace content.

Any external AI system can be evaluated when it exports the versioned manifest
contract. A complex multi-agent system uses `subject_type: multi_agent_system`
and `integration_mode: trace_import`, with a redacted
event trace. The evaluator canonicalizes the redacted event list and rejects a
trace whose `content_sha256` does not match. This proves integrity of the
submitted trace, not independent origin authenticity. Live connectors that
invoke arbitrary client endpoints are not included. Version 1.3 provides one
bounded `http_json_v1` adapter with an exact approved endpoint, managed bearer
credential, and deployment egress policy. The current delivery layer also provides a
customer-executed runner for local development and CI, plus a secretless GitHub
Actions OIDC delivery path.

## Customer-operated runner and CI

The evaluator does not execute a customer's product, repository, model, or tool
chain. Instead, the customer installs a versioned `esx-eval` runner GitHub Release next to that system and
wraps it with the bounded `command_json_v1` protocol. The runner supplies local
test inputs to the wrapper and expects a predicted label plus confidence for
each case. It emits a canonical result package containing only the expected and
predicted labels, confidence values, execution metadata, and SHA-256 digests.

The package excludes prompts, model outputs, document content, source code,
environment variables, local command stderr, tool output, and secrets. The
platform cannot recover those values from its database or reports.

The compatibility-preserved `command_json_v1` client-runner package evaluates
classification and confidence only. `command_json_v2` can additionally submit
redaction-reviewed grounding, security, trajectory, RAG, robustness, judge
agreement, reproducibility, and cost-efficiency records. Every record is
schema-validated; it never accepts arbitrary free-text claims or traces.

For a local workstation or non-GitHub CI:

1. Download the tagged runner wheel from the official GitHub Release, verify `SHA256SUMS`, and run `gh attestation verify` against `lucky1410/ExposureScopeX` before installation. See `v3/client-runner/README.md` for the exact PowerShell commands.
2. Run `esx-eval keygen --private-key .\secrets\esx-evaluator.key`.
3. Register **only** the returned base64 public key in the AI Assurance UI and
   obtain owner/admin approval for the identity.
4. Run `esx-eval run --config esx-eval.json --out out\evaluation.json`.
5. Submit it with `esx-eval upload --api-url https://esx.example.com --package out\evaluation.json --response-out out\result.json`.

The approved public key verifies an Ed25519 signature. The private key is never
sent to ExposureScopeX, and a package UUID is accepted only once, preventing
replay from creating a second release decision. Disabling an identity is final;
key rotation requires registering a replacement.

For GitHub Actions, register and approve the exact `owner/repository` and the
exact pinned `workflow_ref` in the UI. The composite action in
`v3/github-actions/evaluate` asks GitHub for a short-lived OIDC token. The API
verifies GitHub's RSA signature and issuer, then binds the submission to the
approved repository, workflow, commit, and run ID. No ExposureScopeX API key or
long-lived signing key is put in GitHub Secrets. Its native workflow result is a
PR check; a GitHub App for organization installation and richer Check Run
annotations is deliberately a later integration, not a simulated feature.

## Governed live adapters

The `http_json_v1` adapter lets a client test a model or agent endpoint without
giving ExposureScopeX arbitrary access to its infrastructure. An owner or
administrator registers the exact endpoint and bearer token, then approves the
immutable configuration. Tokens are encrypted at rest and are never returned
by the API or displayed in the UI. Registering a replacement adapter is the
only way to rotate a token or change an endpoint.

ExposureScopeX sends a bounded batch with this contract:

```json
{
  "schema_version": "esx-live-evaluation-request-1.0",
  "request_id": "uuid",
  "cases": [{"case_id": "case-1", "input": {"message": "..."}}]
}
```

The client adapter must reply with exactly one result for each submitted case:

```json
{
  "schema_version": "esx-live-evaluation-response-1.0",
  "results": [{"case_id": "case-1", "predicted_label": "safe", "confidence": 0.98}]
}
```

Live runs score classification and confidence only. The evaluator retains the
labels, confidence values, timing, adapter identity, and request/response
SHA-256 digests, but not the case input or remote response body. Grounding,
security, RAG, robustness, and trajectory tests remain explicit manifest,
semantic-review, or redacted-trace workflows.

Production egress is fail-closed: set
`AI_EVALUATOR_ADAPTER_ALLOWED_HOSTS` to approved endpoint hostnames. HTTPS is
required, redirects and URL credentials are blocked, and private destinations
require an explicit CIDR in `AI_EVALUATOR_ADAPTER_PRIVATE_NETWORKS`. Local HTTP
is allowed only in development for controlled adapter integration tests.

Enterprise deployment still requires the surrounding controls that belong to
the customer environment: TLS, OIDC/SAML provisioning, a secret manager/KMS,
managed PostgreSQL backups, centralized audit export, retention policy, and
named approvers. Set `DEPLOYMENT_MODE=production`; startup then rejects
insecure cookies, development cryptographic keys, localhost CORS origins, and
the absence of independent dataset approval.
Use [`.env.production.example`](.env.production.example) as the non-secret
configuration checklist; place real values in the deployment secret manager.

## Architecture

```text
AI system outputs + labelled truth + traces + evidence
                          |
                          v
          AI Assurance Pre-release Evaluation
                |          |          |
                v          v          v
            Grounding   Security   Trajectory
              role      verdict     policy
                \          |          /
                 \         |         /
        Nine computed dimensions in eight quality areas
                          |
                          v
                Deterministic release gates
                          |
                          v
                  PASS / FAIL / INCONCLUSIVE
```

The three roles are logical modules in one process:

- `evidence_grounding` verifies claim support, evidence integrity, citations,
  hallucination proxies, and RAG faithfulness.
- `security_verdict` compares labelled attack and detection outcomes, including
  positive and negative controls.
- `trajectory_policy` evaluates required milestones, redundant actions, tool
  misuse, scope violations, and policy violations.

These roles produce nine computed dimensions, grouped into eight quality areas
rather than eight separate agents:

1. Classification confusion matrix, precision, recall, F1, FPR, and FNR.
2. Attack success, expected outcome accuracy, detection, and false detection.
3. Hallucination proxy, evidence grounding, integrity, and citation validity.
4. Confidence calibration through correctness Brier score and ECE.
5. RAG faithfulness, context precision, recall at K, reciprocal rank, and citations.
6. Trajectory coverage, efficiency, tool misuse, scope, and policy compliance.
7. Robustness across paraphrases, perturbations, and controlled repeats.
8. Cross-model agreement and repeated-run reproducibility, measured separately
   so either can block release.
9. Cost and efficiency: cost per case, tokens, requests, retries, tool calls,
   cache hits, fallbacks, timeout rate, and latency percentiles.

For a full pre-release gate, robustness must include all three variation types.
Confidence must satisfy both correctness Brier score and expected calibration
error. RAG must satisfy context precision, recall at K, faithfulness, and
citation validity. These are enforced by the server-owned policy rather than
being descriptive report fields.

## Two-layer decision model

The deterministic metric engine is authoritative. It accepts versioned labelled
data, calculates the metrics, applies a server-owned release policy, and returns:

- `pass` only when every required dimension is measurable and passes;
- `fail` when any measured required gate fails;
- `inconclusive` when no measured gate fails but required truth is missing.

The optional semantic judge grades claim entailment and nuanced trajectories.
Its output is advisory and must be referenced through a persisted semantic run
before the server imports its grades. A semantic run requiring human review
places an otherwise passing release decision on `inconclusive` hold.
Each claim verdict also emits a model-and-prompt-pinned judge decision that can
be combined with another independent judge for agreement measurement.

## Semantic judge controls

- Evidence content is accepted only with a matching SHA-256 digest.
- A matching content digest proves payload integrity, not source authenticity;
  production datasets still require governed provenance and approval.
- Claims can cite only evidence identifiers explicitly linked to that claim.
- Judge output must match a strict JSON schema and include every claim exactly once.
- Unknown citations, milestones, actions, and incoherent verdicts are rejected.
- Evidence and trajectory text are explicitly treated as untrusted data, not instructions.
- The model has no tools, scanner access, browser access, or outside retrieval.
- Producer model identifiers are mandatory; the requested and resolved judge
  models must be different from every producer model.
- The provider request uses `store: false` and records response, model, prompt,
  input-manifest, usage, and latency provenance without storing raw evidence in
  the audit manifest.
- Restricted data cannot use the external adapter. Internal data egress is
  disabled unless an administrator explicitly enables it.
- No API key is stored in evaluation results or returned to the UI.

## API

All management and report routes require an authenticated ExposureScopeX session:

- `GET /api/v3/evaluator` returns roles, boundaries, policy IDs, and semantic status.
- `GET /api/v3/evaluator/workspaces` lists the signed-in user's authorized
  evaluator workspaces. The selected workspace is passed as
  `X-ESX-Organization`.
- `GET /api/v3/evaluator/workspace` returns the selected workspace's projects
  and governed dataset registry.
- `POST /api/v3/evaluator/projects` creates an evaluation project.
- `POST /api/v3/evaluator/datasets` registers a source-hashed dataset as a
  draft; `POST /api/v3/evaluator/datasets/{dataset_id}/approve` approves it.
- `POST /api/v3/evaluator/live-adapters` registers an encrypted, draft
  `http_json_v1` endpoint; `/{adapter_id}/approve` approves it and
  `/{adapter_id}/disable` permanently disables it.
- `POST /api/v3/evaluator/live-runs` invokes one approved live adapter and
  persists a hash-only classification/calibration scorecard.
- `POST /api/v3/evaluator/client-identities` registers an Ed25519 public key;
  `/{identity_id}/approve` and `/{identity_id}/disable` govern its lifecycle.
- `POST /api/v3/evaluator/github-integrations` registers a pinned GitHub
  workflow; `/{integration_id}/approve` and `/{integration_id}/disable` govern
  its lifecycle.
- `POST /api/v3/evaluator/client-runs` is the only non-session evaluator route.
  It accepts either a package signed by an approved client identity or a package
  authenticated with an approved GitHub Actions OIDC assertion. It never accepts
  a caller-supplied organization ID, browser cookie, or forged provenance.
- `GET /api/v3/evaluator/audit-events` returns the owner/admin governance trail.
- `POST /api/v3/evaluations` scores and persists a labelled metric manifest.
- `GET /api/v3/evaluations` lists metric decisions.
- `GET /api/v3/evaluations/{evaluation_id}` returns a display-safe result
  scorecard, input counts, SHA-256 provenance, export inventory, and a fresh
  deterministic recomputation check. It does not return submitted label values
  or evidence text.
- `POST /api/v3/evaluations/{evaluation_id}/reports` generates immutable DOCX and PDF release-decision reports from a persisted metric evaluation.
- `GET /api/v3/evaluations/{evaluation_id}/reports/download/{docx|pdf}` verifies the stored file digest and downloads the requested report.
- `POST /api/v3/evaluator/semantic-runs` invokes the configured semantic judge.
- `GET /api/v3/evaluator/semantic-runs` lists semantic audit records.

External AI subjects declare `agent_id` and `subject_version`. Registered
ExposureScopeX agents are automatically pinned to their registry version. To
use semantic grades in a metric evaluation, supply `semantic_run_id` instead of
client-authored `claims` or `trajectory`; the server imports the stored grades
after verifying subject, version, dataset, and completion state.

## Evaluator reports

Each persisted metric evaluation can generate a DOCX and PDF report. The report
records the evaluated subject and version, evaluator and policy versions,
dataset version, release decision, required-dimension coverage, gate-by-gate
actual values and thresholds, role verdicts, measurable dimension results,
limitations, and SHA-256 digests of the immutable evaluation snapshot, original
input manifest, and calculated metrics. It does not rewrite source evidence or
claim scanner provenance. Generated files are retained under the evaluator
artifact root and their stored SHA-256 digest is verified before download.

Client-runner reports additionally identify the verified identity type and
fingerprint, package ID and digest, client runner version, execution digest, and
source-attestation digest. They do not include the client test cases or output.

Client-runner result packages support two compatibility-preserved contracts.
`command_json_v1` is limited to classification and confidence. `command_json_v2`
can submit the redacted metric records for grounding, attack/detection,
trajectory/policy, RAG, robustness, judge agreement, reproducibility, and cost
efficiency. Each
requested dimension must be present, is independently schema-validated, and is
release-gated server-side. The server rejects free-text evidence, prompts,
responses, tool payloads, and non-opaque references from v2 records even if a
caller bypasses the official runner.

The primary review surface is the in-product result page at
`/ai-evaluator/{evaluation_id}`. It presents the release gates, confusion
matrix, per-class metrics, calibration bins, role verdicts, input coverage, and
the stored-versus-recomputed metric digest. A `verified` recomputation proves
the stored metric values are reproducible from the immutable submitted manifest
with the same evaluator version. It does not prove that the submitted labels,
evidence grades, or dataset represent production behavior; those require
independently governed ground truth and representative test cases.

## Offline developer verification

The replay fixtures use synthetic text and require no model key, customer data,
network, assessment target, or scanner. From the repository root:

```powershell
docker compose -f .\v3\compose.yml exec api `
  python -m app.evaluation_cli `
  /app/benchmarks/evaluator/smoke-1.0.json

docker compose -f .\v3\compose.yml exec api `
  python -m app.evaluation_cli `
  /app/benchmarks/evaluator/multi-agent-smoke-1.0.json

docker compose -f .\v3\compose.yml exec api `
  python -m app.semantic_evaluation_cli `
  /app/benchmarks/evaluator/semantic-request-1.0.json `
  /app/benchmarks/evaluator/semantic-judge-pass-1.0.json
```

The deterministic fixture CLI returns `0` for pass, `1` for fail, and `2` for
inconclusive. The semantic replay CLI returns `0` when no human review flag is
raised and `1` when review is required.

## Optional live judge

The live adapter is disabled by default. Configure it only after data-egress,
model-independence, cost, and retention policy have been approved:

```dotenv
AI_EVALUATOR_PROVIDER=openai_responses
AI_EVALUATOR_MODEL=<pinned-independent-model-version>
AI_EVALUATOR_BASE_URL=https://api.openai.com/v1
AI_EVALUATOR_API_KEY=<secret>
AI_EVALUATOR_TIMEOUT_SECONDS=90
AI_EVALUATOR_ALLOW_INTERNAL_DATA=false
```

Production release requires a pinned judge model, a benchmarked prompt version,
negative and prompt-injection controls, calibrated thresholds, cross-model
agreement tests, repeated-run reproducibility, cost and latency budgets, and a
documented human-review workflow. Configuring a model alone does not satisfy
those release requirements.

## Client workflow

1. Choose the customer workspace and create a project for the subject or release train.
2. Register the versioned dataset source, including its classification, source
   reference, and SHA-256 digest. An authorized approver marks it approved.
3. Export the AI system's labelled outputs. For multi-agent systems, export the
   redacted trace event list and its canonical SHA-256 digest as well.
4. Upload the metric manifest. The evaluator blocks unknown, retired, or draft
   datasets before it calculates a score.
5. Review the interactive scorecard, measurement limits, release-gate trace,
   replay verification, and signed report exports. A pass is only evidence for
   the declared dataset and policy, never a blanket production guarantee.
