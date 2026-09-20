# VINI Demo Pack for PRE-D Local

This is a **target profile pack** for a VINI demo. It does not add VINI logic to
PRE-D core and it does not modify VINI source code.

Use it when you need a working demo that shows PRE-D can:

- discover a broad application surface from local source, with OpenAPI added
  when a live export is available,
- bind real evidence checks for backend tests, browser workflows and decision packs,
- preserve protected source-drift detection while allowing exact reviewed local commands,
- expose untouched modules as gaps instead of fake passes,
- produce an executive-readable system report.

## Inputs Needed

- Local VINI repository path.
- Optional local OpenAPI JSON export. PRE-D can draft a source-first
  evaluation plan without it, then enrich API coverage when `/api/openapi.json`
  is available.
- Local or staging base URL, for example `http://localhost`.
- Candidate identity, preferably the `/health` `manifest_sha256`.
- Optional existing PRE-D configs for browser, DLP and disposition evaluations.
- Optional backend JUnit command spec.

`backend-command.json` shape:

```json
{
  "id": "vini-backend-pytest",
  "command": ["python", "-m", "pytest", "--junitxml=C:/absolute/path/outside-vini/pred-backend-tests.xml"],
  "cwd": "../VINI/backend",
  "result_file": "C:/absolute/path/outside-vini/pred-backend-tests.xml",
  "timeout_seconds": 600
}
```

## Build the Demo Workspace

```text
python examples/vini_demo/build_vini_demo.py \
  --repo ../VINI \
  --base-url http://localhost \
  --version candidate-001 \
  --manifest-sha256 REVIEWED_HEALTH_MANIFEST_HASH \
  --backend-command ./backend-command.json \
  --browser-config ./browser/esx-eval.json \
  --disposition-config ./disposition/esx-eval.json \
  --dlp-config ./dlp/esx-eval.json \
  --confirm-inventory \
  --out ./vini-demo-workspace
```

Add `--openapi ./vini-openapi.json` when a live app export is available.

Then:

```text
cd ./vini-demo-workspace
esx-eval system preflight --plan ./vini-system-plan.json
esx-eval system approve --plan ./vini-system-plan.json
esx-eval system run --plan ./vini-system-plan.json --out ./runs/candidate-001 --history ./pred-history.sqlite
```

Use `--require-whole-system` only when every required objective is reviewed and
bound. For a live demo, it is acceptable and honest for the verdict to be
`insufficient_evidence` if only the demo subset is bound.

## Demo Positioning

Do not claim PRE-D fully evaluated VINI unless every objective is reviewed and
bound. The credible demo claim is:

> PRE-D scanned and inventoried the broad application surface, executed the
> reviewed evidence checks, identified failing/blocked areas, and reported the
> remaining system coverage gaps without inflating them.

## Safety

- Keep this workspace outside the VINI repository.
- Use disposable data and non-production integrations.
- Store credentials in environment variables, not in the plan.
- Protected profiles detect source drift, but they are not an OS sandbox.
- Trusted local commands are exact argv hashes; command changes require review.
