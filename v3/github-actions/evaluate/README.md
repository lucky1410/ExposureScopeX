# ExposureScopeX AI Assurance GitHub Actions integration

The composite action uses GitHub Actions OIDC. It sends no long-lived
ExposureScopeX secret to GitHub. Before enabling a workflow, an ExposureScopeX
owner or administrator must register and approve the exact repository and pinned
workflow reference in the AI Assurance workspace.

```yaml
name: AI assurance pre-release evaluation
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write

jobs:
  evaluate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-org/exposurescopex/v3/github-actions/evaluate@v1
        with:
          api-url: https://esx.example.com
          config: esx-eval.json
          oidc-audience: exposurescopex-evaluator
          require-pass: "true"
```

The workflow itself is a native GitHub check. A GitHub App for richer check-run
annotations and centralized installation is intentionally a later phase; it
requires app credentials, tenant installation flow, and webhook verification.
