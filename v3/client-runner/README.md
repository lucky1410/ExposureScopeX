# ExposureScopeX Local AI Evaluation Runner

`esx-eval` is a **local-first pre-release evaluator** for a model, RAG
application, agent, or multi-agent system. It runs next to the AI system being
tested and prints results in the local terminal. A normal `run` command does
not connect to ExposureScopeX and does not upload prompts, model outputs, source
code, traces, environment variables, stderr, credentials, or results.

Use the optional shared workflow only when a team wants ExposureScopeX to retain
a governed release decision and formal report.

## Recommended experience: test an application workflow

For a normal AI web application, use the local setup page rather than writing
an adapter. It generates an editable, versioned test plan for one real
user-facing HTTP workflow. That workflow can orchestrate any number of
internal agents, tools, retrievers, and models; the runner does not require a
separate call for every internal agent.

```powershell
esx-eval setup --directory .\my-application-evaluation
```

The page opens only on `127.0.0.1`. It can optionally scan a local repository
for framework, API-route, and observability hints without exporting source
content. Then choose a `smoke`, `release`, or `red_team` baseline plan, enter
the application's local HTTP endpoint and response fields, and create the
plan. Every generated case remains editable in `esx-eval.json`; teams can add
their own product, domain, and organization-policy cases.

The built-in connector posts `{"message": "..."}` to the configured endpoint
and reads a decision label plus numeric confidence from configured JSON paths.
It accepts loopback URLs by default. A non-local staging endpoint requires the
explicit `allow_remote` choice in the setup page or generated config.

Run the generated plan and open its self-contained local report:

```powershell
Set-Location .\my-application-evaluation
esx-eval run --config .\esx-eval.json --out .\out\evaluation.json
esx-eval view --report .\out\evaluation.local-report.html
```

The terminal report and HTML report never upload automatically. The HTML report
contains only derived, redacted evaluation data, not case prompts or raw model
responses.

## Security boundary

The local setup page binds only to `127.0.0.1`. The built-in HTTP connector
accepts loopback targets only by default. A remote target must be explicitly
marked as `staging` and use HTTPS; plain remote HTTP, URL credentials, query
secrets, and redirects are rejected. Requests are identified with an
`X-ESX-Evaluation-Mode: local-pre-release` header, are limited to 500 cases by
default, and pause briefly between cases.

This is a secure-by-default baseline, not a sandbox. A run can still invoke a
real workflow and its tools. Use a dedicated test tenant, least-privilege test
credentials, safe test data, and an endpoint that rejects production actions.
Do not configure production systems as staging. Command adapters are trusted
local code and run with the invoking user's OS permissions.

## Local-only quick start

These steps are all a colleague needs for a real local test. No Docker,
ExposureScopeX account, identity registration, key pair, or platform upload is
required.

1. Install Python 3.11 or later. On Windows, confirm it is available:

   ```powershell
   py --version
   ```

2. Download the `exposurescopex_eval_runner-<version>-py3-none-any.whl` asset
   and `SHA256SUMS` from the [ExposureScopeX releases page](https://github.com/lucky1410/ExposureScopeX/releases).
   Do not download `Source code (zip)` or install the entire platform.

3. Verify and install the downloaded wheel. Replace `0.4.3` with the published
   runner version you downloaded:

   ```powershell
   $version = "0.4.3"
   $wheel = "exposurescopex_eval_runner-$version-py3-none-any.whl"
   $expected = ((Get-Content .\SHA256SUMS | Where-Object { $_ -like "*$wheel" }) -split "\s+")[0].ToLower()
   $actual = (Get-FileHash ".\$wheel" -Algorithm SHA256).Hash.ToLower()
   if ($actual -ne $expected) { throw "Checksum verification failed. Do not install this file." }
   py -m pip install ".\$wheel"
   esx-eval --help
   ```

4. Prefer `esx-eval setup --directory .\my-application-evaluation` for a
   standard HTTP application. Use the adapter starter below only when the
   application has no suitable HTTP endpoint or needs advanced local telemetry.
   It creates a one-case smoke-test folder; choose a larger `--case-count`
   whenever your team is ready to measure quality across representative cases
   and classes.

   ```powershell
   esx-eval init --directory .\my-agent-evaluation --agent-id support-agent --subject-version 2.4.0
   Set-Location .\my-agent-evaluation
   ```

5. Open `local_adapter.py`. Replace only `evaluate_case()` with the local call
   to the system under test. It receives one labelled test case and must return
   a predicted label plus a confidence between `0` and `1`.

   ```python
   def evaluate_case(case: dict[str, object]) -> tuple[str, float]:
       reply = my_local_agent(case["input"]["message"])
       return ("unsafe" if reply.blocked else "safe", reply.confidence)
   ```

   If the starter was created with `--full-metrics`, it also contains
   `full_metric_measurements.json`. Fill its named placeholders from local
   trace, evidence, RAG, security-test, repeat-run, and usage records. The
   adapter reads that file locally and rejects it until every placeholder is
   replaced.

### Connecting a full web application or multi-agent system

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

6. Replace every `REPLACE_WITH_*` value in `esx-eval.json` with your own
   versioned, labelled cases. `expected_label` is the ground-truth answer your
   team has decided is correct. It is not generated by ExposureScopeX.

7. Run the evaluation. Results, including every case, accuracy, precision,
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
trajectory and tool policy, RAG, robustness, cross-judge agreement,
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
