# ExposureScopeX Client Evaluation Runner

`esx-eval` executes a customer-owned adapter locally or in CI and sends only a
redacted result package to ExposureScopeX. It never uploads test inputs, model
outputs, tool output, source code, environment variables, stderr, or signing keys.

Two local adapter contracts are available:

- `command_json_v1` provides labelled classification and confidence results.
- `command_json_v2` additionally provides the redacted metric records required
  for grounding, security, trajectory, RAG, robustness, cross-judge agreement,
  repeat-run reproducibility, and cost and efficiency.

The runner sends one JSON object on standard input and expects one JSON object on
standard output. See [`ADAPTER_V2.md`](ADAPTER_V2.md) and `examples/`.

## Install a verified GitHub release

For customer workstations and CI, install a versioned release asset rather than a
source checkout. Each release publishes a wheel, `SHA256SUMS`, and a GitHub Actions
build-provenance attestation. The following PowerShell commands download version
`0.4.0`, check its SHA-256 before installation, and verify its GitHub provenance:

```powershell
$version = "0.4.0"
$tag = "esx-eval-runner-v$version"
$wheel = "exposurescopex_eval_runner-$version-py3-none-any.whl"
$release = "https://github.com/lucky1410/ExposureScopeX/releases/download/$tag"

Invoke-WebRequest "$release/$wheel" -OutFile $wheel
Invoke-WebRequest "$release/SHA256SUMS" -OutFile SHA256SUMS
$expected = ((Get-Content SHA256SUMS | Where-Object { $_ -like "*$wheel" }) -split "\s+")[0].ToLower()
$actual = (Get-FileHash $wheel -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $expected) { throw "Runner checksum verification failed. Do not install this file." }
gh attestation verify ".\$wheel" --repo lucky1410/ExposureScopeX
py -3.12 -m pip install ".\$wheel"
```

Do not install a release if either verification step fails. `gh attestation verify`
requires the GitHub CLI. Release assets become available after the maintainer
publishes the matching Git tag; see [`RELEASING.md`](RELEASING.md). GitHub supports
artifact attestations for public repositories on current plans, and for private or
internal repositories on GitHub Enterprise Cloud.

## Run a local evaluation

For local/other CI use, generate a key pair, register only the returned public key
in the AI Assurance workspace, and approve it before publishing a shared result:

```powershell
esx-eval keygen --private-key .\secrets\esx-evaluator.key
esx-eval run --config .\esx-eval.json --out .\out\evaluation.json
esx-eval upload --api-url https://esx.example.com --package .\out\evaluation.json --response-out .\out\result.json
```

GitHub Actions uses short-lived OIDC tokens instead. It does not need an
ExposureScopeX API key or a copied private signing key.

## Start a colleague evaluation

Create the starter folder in one command. It includes a balanced 20-case
dataset skeleton, adapter configuration, and a short local workflow guide:

```powershell
esx-eval init --directory .\my-agent-evaluation --agent-id support-agent --subject-version 2.4.0
```

For a RAG or agent release that needs every pre-release metric area, add
`--full-metrics` and optionally set `--subject-type rag` or
`--subject-type multi_agent_system`. The starter deliberately contains
placeholders: a colleague replaces them with their team-approved, versioned
benign and adversarial cases before running the evaluation.

## `command_json_v2` data boundary

The v2 adapter receives the same local test cases as v1 plus the requested
evaluation dimensions. It must return ordinary classification results and may
return a `measurements` object. ExposureScopeX accepts only the fields needed to
calculate the published metrics:

- claim, evidence, document, milestone, run, and judge identifiers;
- booleans, bounded numeric scores, controlled verdicts, and result labels;
- redacted trace-event metadata and a SHA-256 digest.

Prompts, source documents, retrieved text, answer text, chain-of-thought,
credentials, raw tool arguments/results, model output, and stderr are rejected
from metric fields and remain in the customer environment. Identifiers must be
opaque references such as `claim-014`, `doc-policy-02`, or `trace/run-431`.

Use the v2 fixture only to test plumbing, not to claim a real model passed:

```powershell
python .\v3\client-runner\examples\run_full_metrics_fixture.py `
  --identity-id <approved-identity-id> `
  --private-key .\secrets\esx-evaluator.key `
  --require-pass
```

Replace `<approved-identity-id>` with the **Runner identity ID** shown in the AI
AI Assurance workspace registry. The helper loads the included synthetic fixture,
signs it locally, submits it to `http://localhost:8001`, and prints a result URL.
It does not store private keys, test inputs, or model outputs in ExposureScopeX.

A real adapter should derive every metric record from its local labelled
benchmark, trace store, and evidence ledger.

## Full pre-release test packs

The supplied full-metric fixture proves runner plumbing only. For a real
release evaluation, copy
[`examples/full-metrics.http-bridge.template.json`](examples/full-metrics.http-bridge.template.json),
replace its two illustrative cases with a versioned labelled test pack, and
configure the team-owned endpoint through an environment variable:

```powershell
$env:ESX_LOCAL_ADAPTER_URL = "http://127.0.0.1:8080/esx-evaluation"
esx-eval run --config .\full-metrics.json --out .\out\evaluation.json
```

The endpoint receives the complete local v2 adapter request and must return the
v2 response described in [`ADAPTER_V2.md`](ADAPTER_V2.md). This supports a
model, RAG application, agent, or multi-agent gateway without adding an SDK or
giving ExposureScopeX access to the customer environment. `run` remains local:
the resulting package contains labels, bounded scores, opaque evidence IDs, and
digests, never prompts, outputs, source documents, tool payloads, or secrets.

Use all ten dimensions for a full pre-release decision. The release policy
gates calibration with both Brier score and ECE, RAG with context precision,
recall at K, faithfulness, and citations, and robustness with accuracy,
consistency, and all three variation types: paraphrase, perturbation, and
repeat. Publishing the signed redacted package with `esx-eval upload` is
optional and is only needed for a shared ExposureScopeX result, governance
trail, and platform-generated report.

Cost and efficiency records contain only per-case usage totals: provider- or
metered-cost in USD, tokens, requests, retries, tool calls, cache and fallback
flags, latency, and timeout status. They never contain provider credentials,
model output, prompts, or invoices. The policy gates cost per case, P95 latency,
timeout rate, and fallback rate without allowing a cheaper but unsafe system to
pass its quality or security gates.

## Development checkout only

Maintainers developing the runner itself may install it from the repository with
`python -m pip install -e .\v3\client-runner`. This is not the recommended customer
distribution path and does not replace release checksum or provenance verification.
