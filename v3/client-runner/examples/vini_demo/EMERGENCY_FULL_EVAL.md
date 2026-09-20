# Emergency VINI Full-Platform Evaluation Run

Use this when time is short and the goal is a defensible PRE-D report for the
whole VINI platform.

This does **not** mean every module magically has executable evidence. It means
PRE-D will:

- inventory the broad source surface and enrich it with OpenAPI when supplied,
- declare the full VINI module set in scope,
- execute every real evidence pack supplied,
- keep unreviewed/unbound modules visible as gaps,
- produce a report that answers: ship, do not ship, or insufficient evidence.

## Non-Negotiable Positioning

Do not say: "PRE-D evaluated every VINI behavior."

Say:

> PRE-D ran a full-platform evaluation attempt: it inventoried the broad VINI
> surface, executed the available evidence packs, and reported the rest as
> explicit gaps instead of hiding them.

If DLP/disposition/backend/browser evidence is supplied, the demo is strong
because it shows both executed failures and whole-platform coverage gaps.

## Minimum Inputs

```text
VINI_REPO=<path to local VINI repo>
VINI_BASE_URL=http://localhost
VINI_MANIFEST_SHA256=<value from GET /health manifest_sha256>
```

Optional but strongly preferred:

```text
VINI_OPENAPI=<path to local OpenAPI JSON export>
BACKEND_COMMAND_JSON=<path to backend-command.json>
BROWSER_ESX_CONFIG=<path to browser esx-eval.json>
DISPOSITION_ESX_CONFIG=<path to disposition esx-eval.json>
DLP_ESX_CONFIG=<path to dlp esx-eval.json>
```

## Build Workspace

PowerShell:

```powershell
$repo = "C:\path\to\local\vini"
$runner = "C:\path\to\ExposureScopeX\v3\client-runner"
$out = "C:\path\to\pred-output\vini-full-platform-eval"

python "$runner\examples\vini_demo\build_vini_demo.py" `
  --repo $repo `
  --base-url $env:VINI_BASE_URL `
  --version candidate-vini `
  --manifest-sha256 $env:VINI_MANIFEST_SHA256 `
  --backend-command $env:BACKEND_COMMAND_JSON `
  --browser-config $env:BROWSER_ESX_CONFIG `
  --disposition-config $env:DISPOSITION_ESX_CONFIG `
  --dlp-config $env:DLP_ESX_CONFIG `
  --confirm-inventory `
  --out $out `
  --replace
```

If OpenAPI or one optional config is unavailable, omit that flag. PRE-D will
still build a source-first plan and keep unbound execution evidence visible as a
gap.

## Run

```powershell
cd C:\path\to\pred-output\vini-full-platform-eval
esx-eval system preflight --plan .\vini-system-plan.json
esx-eval system approve --plan .\vini-system-plan.json
esx-eval system run --plan .\vini-system-plan.json --out .\runs\candidate-001 --history .\pred-history.sqlite
```

Use this after the first run only when every objective is reviewed and bound:

```powershell
esx-eval system preflight --plan .\vini-system-plan.json --require-whole-system
esx-eval system run --plan .\vini-system-plan.json --require-whole-system --out .\runs\candidate-strict-001 --history .\pred-history.sqlite
```

## Expected Result Under Current Evidence

The realistic first verdict is likely:

```text
insufficient_evidence
```

That is acceptable for the demo if the report also shows:

- source discovery totals, plus OpenAPI discovery totals when supplied,
- all declared modules in scope,
- backend/browser/DLP/disposition checks that actually executed,
- failing decision modules where applicable,
- blocked DLP or pipeline symptoms where applicable,
- all missing role/security/tenant/reliability checks as explicit gaps.

## Executive Message

> PRE-D did not just run isolated AI tests. It attempted a platform-level release
> evaluation: source/API inventory when available, build identity, backend
> tests, browser workflows, AI decision packs, and coverage gaps in one local
> report. The result is useful because it does not overclaim: executed evidence
> is scored, failing modules are named, and the remaining unreviewed platform
> surface is visible.

## Fastest Way To Make It Stronger

Add these before rerunning:

1. Role credentials for `admin`, `soc_lead`, `analyst`, `read_only`.
2. Tenant A/Tenant B fixtures for isolation checks.
3. Decision configs for governance, correlation, threat hunt, retrieval and response planner.
4. Health/queue counters for DLP status desync and job throughput checks.
5. Stable browser content assertions for every critical page.
