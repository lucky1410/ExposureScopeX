# ExposureScopeX Local AI Evaluation Runner

`esx-eval` is a **local-first pre-release evaluator** for a model, RAG
application, agent, or multi-agent system. It runs next to the AI system being
tested and prints results in the local terminal. A normal `run` command does
not connect to ExposureScopeX and does not upload prompts, model outputs, source
code, traces, environment variables, stderr, credentials, or results.

For a plain-language explanation of the evidence each local metric needs, see
[`PRE-D_EVIDENCE_GUIDE.md`](PRE-D_EVIDENCE_GUIDE.md). It separates the
organization's expected behavior from the redacted observations the application
emits and explains why a metric may be `NOT MEASURABLE`.

For labelled local AI and business decisions, start with
[`DECISION_EVALUATION.md`](DECISION_EVALUATION.md). It shows the direct local
endpoint and dataset contract used for accuracy, precision, recall, F1,
confidence, evidence-reference, and abstention checks. A ready-to-import
synthetic starter dataset is available at
[`examples/decision-evaluation.sample.json`](examples/decision-evaluation.sample.json).

Use the optional shared workflow only when a team wants ExposureScopeX to retain
a governed release decision and formal report.

## Recommended experience: evaluate local decisions

For a normal AI application, use the local setup page rather than writing an
adapter. **Decision evaluation** is the default: it imports labelled local
cases and calls one local endpoint that invokes the real product decision path.
That path can orchestrate any number of internal agents, tools, retrievers, and
models; PRE-D does not require a separate call for every internal agent.

```text
esx-eval setup --directory ./my-application-evaluation
```

The page opens only on `127.0.0.1`. It can scan a local repository for
framework, API-route, tool, retrieval, and observability hints without
exporting source content. The customer explicitly selects what is in scope,
then chooses a local decision API, generic JSON API, or loopback browser
journey. Decision setup imports a labelled dataset and maps response fields
without requiring users to type JSON paths. Generic API profiles remain
available for baseline checks, and browser journeys remain available for
protected UI coverage.

Discovery does not treat architecture documents, backlog items, comments, or
plain text as implemented technology. Each finding identifies whether it came
from an installed local package, a declared dependency, or a source import.
Those are static evidence levels, not proof that a capability executes at
runtime; the customer still confirms the evaluation scope.

The generated folder contains `esx-eval.json`, `discovery.json`,
`assurance-scope.json`, `risk-plan.json`, `PRE-D_EVIDENCE_REQUIREMENTS.md`,
and a local `README.md`. Read the generated evidence-requirements file before
running: it lists, for every score in that specific plan, what the team must
define, what the application must emit locally, and the minimum evidence needed
for a real result. A normal `run` automatically includes the confirmed scope
and plan in the Assurance Graph. Planned advanced checks are clearly shown as
`NOT MEASURABLE` until compatible redacted local evidence is available; the
runner never invents a score.

Before the first run, validate the actual local evidence source. This command
does not call the application or make a network request. It names the exact
missing field, control type, or case ID for every requested metric and writes
an optional local readiness report.

```text
esx-eval evidence-check --config ./esx-eval.json --out ./out/evidence-readiness.json
```

For a command-v2 adapter that reads advanced measurements from a local file,
include `--measurements ./full_metric_measurements.json`. For telemetry-backed
metrics, include `--telemetry ./out/telemetry.jsonl`. `READY TO COLLECT` means
the dataset and connection are valid but a real decision run still must return
observations. `EVIDENCE READY` means the supplied advanced local artifact meets
the schema and formula prerequisites; it still remains local and is scored only
after the decision run completes.

For the normal zero-adapter decision path, enter a loopback decision API URL,
import labelled cases, and select **Test local connection**. The setup page
sends one fixed harmless request, shows a value-redacted response structure,
and suggests label, confidence, evidence-ID, and abstention fields for the
customer to confirm. The decision endpoint receives
`{"case_id": "...", "input": {...}}` and returns a text label plus a numeric
confidence between `0` and `1`. See `DECISION_EVALUATION.md` for the complete
local contract.

The automatic connection check accepts loopback URLs only. A non-local staging
target remains an advanced, managed configuration: it requires HTTPS, mTLS,
and a signed test-tenant attestation before any evaluation request is sent.

Run the generated plan and open its self-contained local report:

```text
cd ./my-application-evaluation
esx-eval evidence-check --config ./esx-eval.json --out ./out/evidence-readiness.json
esx-eval run --config ./esx-eval.json --out ./out/evaluation.json
esx-eval view --report ./out/evaluation.local-report.html
```

The terminal report and HTML report never upload automatically. The HTML report
contains only derived, redacted evaluation data, not case prompts or raw model
responses.

## Advanced assurance workflow

Use these optional commands when a team prefers the individual local workflow
steps. Discovery never executes application code or calls an AI model. Most
users should use `esx-eval setup` instead.

```powershell
# Discover local technology and workflow hints. Source stays on this computer.
esx-eval discover --repository C:\work\my-ai-app --out .\discovery.json

# Review discovery.json and explicitly approve the relevant component IDs.
esx-eval scope --discovery .\discovery.json --include workflow-http-route-definitions-main-py agent-framework-langgraph --out .\assurance-scope.json

# Create a deterministic risk plan with an explanation for each selected area.
esx-eval plan --scope .\assurance-scope.json --out .\risk-plan.json

# Include confirmed scope and plan in the local Assurance Graph report.
esx-eval run --config .\esx-eval.json --out .\out\evaluation.json --discovery .\discovery.json --scope .\assurance-scope.json --plan .\risk-plan.json
```

The HTML report contains an **Assurance Graph** linking confirmed components,
local evidence, required metrics, and the reason no local result is a governed
release decision. Every metric card has a provenance state: `Verified` for
labelled comparisons or independently observed local events, `Declared` for
schema-valid evidence supplied by the target but not independently checked by
PRE-D, and `Missing` when the evidence is insufficient. Each card states its
score, why it received that state, its evidence source, and the next action.
All-zero cost, token, and latency evidence is retained but marked
`NON-REPRESENTATIVE`.

For decision evaluations, the report also shows dataset health, class
distribution, case-level outcomes, confusion matrix, per-class precision,
recall and F1, Brier score, calibration bins, and overconfident failures. An
ECE above `0.15` raises a calibration warning; fewer than five unique confidence
values raises a confidence-range warning. These warnings do not alter the
formula result, but prevent a structurally valid score from looking stronger
than its evidence.

### Browser journeys

For an application without an evaluation API, install the optional local browser
dependency and create declarative browser-action cases. Browser journeys are
loopback-only and must use approved test accounts; the runner never tests an
arbitrary remote application.

```powershell
py -m pip install "exposurescopex-eval-runner[browser]"
playwright install chromium
```

Use `adapter.type: "browser_journey"` and a loopback `base_url`. Browser mode
is a deterministic workflow check, not a model-quality score. Its local
scorecard measures declared workflow coverage: which journeys reached their
approved visible signal, which need assertion review, and which stopped at
session setup. It never converts a browser pass/fail result into a model label
or a synthetic confidence value.

For classification and confidence calibration, use the JSON API or local
adapter connection. The dataset needs at least two expected outcome classes,
and the application must return observed confidence values from `0` to `1`.
Constant confidence remains calculable but is visibly flagged because it cannot
show behavior across confidence levels. This prevents an all-pass browser plan
or a constant `1.0` value from appearing as a perfect AI-quality score. A
generated browser plan contains exactly the cases it states; selecting an HTTP
`release` profile does not create twelve hidden browser journeys.

Each `input.journey` can use `goto`, `fill`, `click`, `press`,
`wait_for_url`, `wait_for_text`, `wait_for_selector`, `wait_for_navigation`,
`wait_for_stable`, `assert_path`, `assert_title`, `expect_text`, or
`expect_visible`. Use an explicit wait or assertion after an SPA action rather
than relying on a generic page-load check.

For a protected local app, add an explicit `auth` object and mark only
post-login cases with `"requires_auth": true`. The runner reads a dedicated
test account from environment variables, saves an optional local session-state
file for reuse, and never writes credential values or cookies to a result,
report, audit log, or upload package.

For an identity-provider login, use `session_bootstrap` instead of `auth`, then
run `esx-eval browser-auth --config ./esx-eval.json`. The visible browser lets
the tester complete approved SSO and must return to the loopback application
before ESX saves a session. The saved state contains only local-application
cookies and local storage; identity-provider cookies are discarded.

```json
{
  "adapter": {
    "type": "browser_journey",
    "base_url": "http://127.0.0.1:3000",
    "session_state_path": ".esx/auth-session.json",
    "auth": {
      "login_path": "/login",
      "username_env": "ESX_TEST_USERNAME",
      "password_env": "ESX_TEST_PASSWORD",
      "username_selector": "input[name='email']",
      "password_selector": "input[name='password']",
      "submit_selector": "button[type='submit']",
      "success": {"type": "wait_for_text", "value": "Dashboard"}
    }
  },
  "dataset": {
    "cases": [{
      "case_id": "dashboard-ready-001",
      "requires_auth": true,
      "input": {"journey": [
        {"type": "goto", "path": "/dashboard"},
        {"type": "wait_for_text", "value": "Dashboard"},
        {"type": "assert_path", "path": "/dashboard"}
      ]},
      "expected_label": "pass"
    }]
  }
}
```

The local report distinguishes discovered components, customer-approved scope,
requested cases, executed pre-auth/authenticated cases, and measured dimensions.
An authenticated case blocked before session setup is reported as a **coverage
limitation**, excluded from quality scores, and never labelled as an application
failure. An executed browser assertion that does not match its approved signal
is labelled **assertion review**, not a confirmed product defect. Optional
screenshots remain only beside the local plan.

### Automatic local telemetry

For an application already emitting OpenTelemetry JSON, run a local collector
and point its test-environment OTLP JSON exporter at the printed loopback URL.
Provide the printed value as `X-ESX-Telemetry-Token`.

```powershell
esx-eval telemetry --out .\out\telemetry.jsonl
```

The collector accepts `/v1/traces` only on loopback. It retains only allowlisted
operational metadata: service, span name, selected `gen_ai` usage/tool fields,
and opaque `esx` identifiers. Prompts, outputs, documents, tool arguments,
credentials, and arbitrary attributes are discarded. Pass this file to
`run --telemetry` or `report --telemetry` to show evidence coverage in the
Assurance Graph. When the records contain a complete supported evidence set,
the runner derives its advanced metric inputs locally before it calculates the
report. Incomplete evidence remains `NOT MEASURABLE`; raw span count and browser
success never become an invented score. Locally observed tool, trajectory, and
agreement events can be verified as operational facts. Semantic assertions such
as claim entailment, groundedness, or attack outcomes remain target-declared
until PRE-D independently validates them. See `CONNECTORS.md` for OpenTelemetry,
Python, LangChain, and LangGraph integration paths. Use browser workflows for
protected UI coverage and local telemetry or an adapter for groundedness,
security behavior, agent trajectories, approved tool-use quality, RAG quality,
and provider cost metrics. The report explains the exact redacted evidence
required for every unmeasured dimension.

## Security boundary

The local setup page binds only to `127.0.0.1`. The built-in HTTP connector
accepts loopback targets only by default. A remote target must be explicitly
marked as `staging`, use HTTPS, and present a mutual-TLS client certificate;
plain remote HTTP, URL credentials, query secrets, and redirects are rejected.
Requests are identified with an
`X-ESX-Evaluation-Mode: local-pre-release` header, are limited to 500 cases by
default, and pause briefly between cases.

This is a secure-by-default baseline, not a sandbox. A run can still invoke a
real workflow and its tools. Use a dedicated test tenant, least-privilege test
credentials, safe test data, and an endpoint that rejects production actions.
Do not configure production systems as staging. Command adapters are trusted
local code and run with the invoking user's OS permissions unless they use the
optional container sandbox. A sandboxed adapter uses a digest-pinned image with
no network, no host mounts, a read-only filesystem, dropped Linux capabilities,
a non-root user, and CPU, memory, and process limits. It is intended for
offline adapters; it cannot call a local HTTP application because its network
is intentionally disabled.

Every run also appends redacted lifecycle metadata and hashes to a local audit
chain beside its output. Verify the chain with:

```powershell
esx-eval verify-audit --audit-log .\out\evaluation.audit.jsonl
```

The audit log intentionally contains no prompts, responses, source files, or
secrets. Its hash chain detects accidental or partial modification; it is not
immutable against an attacker who can rewrite the whole local log. Preserve its
tail hash in an approved external audit system for a tamper-evident anchor.

### Approved staging targets

A remote target is intentionally more strict than a loopback development run.
It must use mTLS and expose an HTTPS attestation endpoint on the same host. The
endpoint receives `X-ESX-Evaluation-Nonce` and returns this signed payload:

```json
{
  "schema_version": "esx-test-target-attestation-1.0",
  "nonce": "the request header value",
  "target_environment": "staging",
  "test_tenant_id": "opaque-test-tenant-id",
  "capabilities": [
    "test_tenant",
    "synthetic_data",
    "production_actions_disabled",
    "least_privilege_identity"
  ],
  "signature": {"algorithm": "ed25519", "value": "base64-signature"}
}
```

Sign the object without `signature` using the target's Ed25519 key. Configure
the corresponding public key and mTLS file paths in `esx-eval.json`. The runner
rejects the run before submitting cases if this proof is missing, stale/replayed
through the nonce check, malformed, or invalidly signed.

## Local-only quick start

These steps are all a colleague needs for a real local test. No Docker,
ExposureScopeX account, identity registration, key pair, or platform upload is
required.

Before starting, they need a local test copy of their application, an approved
test identity if the application requires login, and its local API URL. They do
not need an ExposureScopeX account, an adapter file, a GitHub integration, or
production data.

The commands below use Windows PowerShell. On macOS or Linux, use `python3`
instead of `py`, `cd` instead of `Set-Location`, and `./` paths instead of
`.\` paths.

1. Install Python 3.11 or later. On Windows, confirm it is available:

   ```powershell
   py --version
   ```

2. Download the `exposurescopex_eval_runner-<version>-py3-none-any.whl` asset
   and `SHA256SUMS` from the [ExposureScopeX releases page](https://github.com/lucky1410/ExposureScopeX/releases).
   Do not download `Source code (zip)` or install the entire platform.

3. Verify and install the downloaded wheel. Use the published runner version:

   ```powershell
   $version = "0.11.0"
   $wheel = "exposurescopex_eval_runner-$version-py3-none-any.whl"
   $expected = ((Get-Content .\SHA256SUMS | Where-Object { $_ -like "*$wheel" }) -split "\s+")[0].ToLower()
   $actual = (Get-FileHash ".\$wheel" -Algorithm SHA256).Hash.ToLower()
   if ($actual -ne $expected) { throw "Checksum verification failed. Do not install this file." }
   py -m pip install ".\$wheel"
   esx-eval --help
   ```

   On macOS or Linux, the equivalent install command is:

   ```bash
   python3 -m pip install ./exposurescopex_eval_runner-0.11.0-py3-none-any.whl
   ```

4. Start a local test copy of the AI application. It needs one endpoint that
   accepts `POST {"message": "..."}` and returns JSON with a text outcome and
   numeric confidence. Do not use production credentials, customer data, or a
   production endpoint.

   ```powershell
   # Example only: use the actual URL of the application being tested.
   # http://127.0.0.1:8000/evaluate
   ```

5. Start the guided local setup. It opens a page on a random `127.0.0.1` port.

   ```powershell
   esx-eval setup --directory .\my-application-evaluation
   ```

6. In the page, enter the local API URL and click **Test local connection**.
   Confirm the suggested outcome and confidence fields, choose an evaluation
   profile, review the scope, and click **Create local evaluation**. The page
   shows only a value-redacted response structure; it does not retain the API
   response. You do not need to create an adapter or type JSON paths.

7. Run the generated plan and open the local report:

   ```powershell
   Set-Location .\my-application-evaluation
   esx-eval run --config .\esx-eval.json --out .\out\evaluation.json
   esx-eval view --report .\out\evaluation.local-report.html
   ```

   The terminal shows each case and the calculated metrics. The HTML report,
   prompts, results, and source content remain on the local computer unless
   the team later chooses the separate signed-upload workflow.

### Advanced fallback: unsupported application contracts

Use this only when the application cannot expose the normal local JSON
endpoint, or when it needs advanced locally collected telemetry. Create a
one-case adapter starter, then follow the integration examples below:

```powershell
esx-eval init --directory .\my-agent-evaluation --agent-id support-agent --subject-version 2.4.0
Set-Location .\my-agent-evaluation
```

The system under test is the colleague's own product, not an agent supplied by
ExposureScopeX. It can be a Python function, local command, local model
wrapper, HTTP API, or the complete backend workflow of a multi-agent web app.
The adapter invokes that one entry point for every labelled case. Internal
planners, retrievers, tools, and handoffs remain inside the application.

A browser page or URL alone is not enough for the current runner to test. The
application needs either an existing local backend endpoint or a small
test-only local function/endpoint that invokes its ordinary workflow. Do not
expose that endpoint publicly and do not add production credentials to the
adapter.

For a Python web app, create the evaluation folder inside the application's
repository. Import the existing service or orchestration function that handles
one user request. The application team writes this small bridge because only
they know which function starts their real workflow:

```python
# In the customer's application, for example app/evaluation_bridge.py
from app.services.assistant_workflow import handle_user_message


def evaluate_message(message: str) -> dict[str, object]:
    run = handle_user_message(message, execution_mode="evaluation")
    return {
        "evaluation_label": "unsafe" if run.refused else "safe",
        "confidence": run.safety_confidence,
    }
```

Then `local_adapter.py` imports that bridge and calls it. `handle_user_message`,
`run.refused`, and `run.safety_confidence` are examples; replace them with the
application's actual names:

```python
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.evaluation_bridge import evaluate_message


def evaluate_case(case: dict[str, object]) -> tuple[str, float]:
    result = evaluate_message(str(case["input"]["message"]))
    return str(result["evaluation_label"]), float(result["confidence"])
```

For a JavaScript/TypeScript or separately deployed web app, create a private
local endpoint such as `POST /internal/evaluation/run-case`. That endpoint
calls the normal workflow, and the Python starter adapter calls it over
`localhost`. The protocol also supports a Node adapter: set the `command` in
`esx-eval.json` to `["node", "local_adapter.js"]`; it still receives one JSON
request on standard input and returns one JSON response on standard output.

For example, if the application exposes a local endpoint that accepts
`{"message": "..."}` and returns an evaluation-safe decision and confidence,
replace `evaluate_case()` with this pattern. Replace the URL, request shape,
and response field names with the colleague's real application contract:

```python
import json
import os
from urllib.request import Request, urlopen


def evaluate_case(case: dict[str, object]) -> tuple[str, float]:
    payload = json.dumps({"message": case["input"]["message"]}).encode("utf-8")
    request = Request(
        os.environ["MY_AGENT_EVALUATION_URL"],
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=60) as response:
        result = json.loads(response.read().decode("utf-8"))
    return str(result["evaluation_label"]), float(result["confidence"])
```

For the default benchmark, return `unsafe` when the application correctly
recognizes and refuses/blocks a disallowed request, and `safe` when it correctly
handles an allowed request. If the application does not expose a meaningful
decision or confidence, the colleague must add an evaluation mapping based on
their product policy; do not invent a confidence of `1.0`.

For full metrics, the adapter must generate the redacted measurements from the
application's local traces, retrieval records, tool telemetry, and provider
usage for that run. Manually filled example values only prove the integration;
they do not evaluate the real application.

After creating an adapter starter, replace every `REPLACE_WITH_*` value in
`esx-eval.json` with your own
   versioned, labelled cases. `expected_label` is the ground-truth answer your
   team has decided is correct. It is not generated by ExposureScopeX.

Run the advanced evaluation. Results, including every case, accuracy, precision,
   recall, F1, Brier score, calibration error, and every requested advanced
   metric print in the terminal. The runner writes a local-only result package
   and detailed derived report to `out`.

   ```powershell
   esx-eval run --config .\esx-eval.json --out .\out\evaluation.json
   ```

   Use `--summary-only` for a large dataset. The default prints every case so a
   developer can see exactly what was correct or incorrect.

   The detailed local reports are `out/evaluation.local-report.json` and
   `out/evaluation.local-report.html`. They contain the confusion matrix and
   each calculated result. Any advanced metric without the evidence needed to
   calculate it is labelled `not_measurable`; the runner never substitutes a
   guessed score.

## What local completion means

`COMPLETED LOCALLY` means the adapter ran and the terminal metrics were
calculated from the declared local labels. It is intentionally **not** a
platform pass/fail decision. In particular, an 8/8 local result is successful
local test execution, not a claim that eight examples prove release readiness.

The runner allows 1 to 10,000 cases. A one-case run is a connection smoke test,
not enough data to describe model quality. ExposureScopeX's optional governed
release policy requires at least 20 labelled cases and at least two ground-truth
classes. That threshold is never applied to a local-only run.

## Optional shared platform decision

Only use this section when a team deliberately wants a governed platform record,
release gate, and formal report. First add a `signing` object to `esx-eval.json`,
create a key, and register the resulting public key with a platform administrator:

```powershell
esx-eval keygen --private-key .\secrets\esx-evaluator.key
esx-eval run --config .\esx-eval.json --out .\out\evaluation.json --sign
esx-eval upload --api-url https://esx.example.com --package .\out\evaluation.json --response-out .\out\result.json
```

Signing and upload are separate on purpose. An unsigned local-only package is
rejected by `upload` with a clear explanation, rather than silently sending
anything to ExposureScopeX. A shared release decision with fewer than 20 cases
is `inconclusive`, because the release policy needs more evidence before it can
make a governed decision.

## Full metric evaluations

The default starter evaluates classification and confidence. Add `--full-metrics`
when the system can produce the redacted records for groundedness, security,
trajectory, approved tool-use quality, RAG, robustness, cross-judge agreement,
reproducibility, and cost/latency. The runner calculates all of those metrics
locally from those records. The protocol is documented in
[`ADAPTER_V2.md`](ADAPTER_V2.md). The runner keeps raw test data local; it only
writes opaque identifiers, labels, bounded scores, and hashes to its local
result package.

The included `examples/` fixture is for integration testing only. It uses
synthetic data and must not be represented as an evaluation of a real AI system.

## Development checkout only

Maintainers may install from this repository with:

```powershell
py -m pip install -e .\v3\client-runner
```

That is not the recommended customer distribution path. Customers should use a
versioned wheel and checksum from GitHub Releases.
