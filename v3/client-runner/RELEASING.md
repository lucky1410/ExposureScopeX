# Releasing the ExposureScopeX Client Evaluation Runner

The customer runner is distributed only from a tagged GitHub Release. The release
workflow builds a wheel from the tag, records its SHA-256 in `SHA256SUMS`, creates a
GitHub Actions provenance attestation, and publishes both files as immutable release
assets.

## Maintainer checklist

1. Set the same release version in `pyproject.toml` and `esx_eval_runner/__init__.py`.
2. Run the runner and backend evaluator tests locally.
3. Commit the release changes and push the commit.
4. Create and push an exact tag such as `esx-eval-runner-v0.4.2`.
5. Review the `Release ESX Eval Runner` GitHub Actions run and the published assets.
6. Verify the downloaded wheel with both `SHA256SUMS` and `gh attestation verify` before announcing it.

The workflow rejects a tag whose version does not match `pyproject.toml`. Do not
replace release assets after publication. Publish a new patch version instead.

GitHub artifact attestations are supported for public repositories on current GitHub
plans. Private or internal repositories require GitHub Enterprise Cloud for this
provenance feature. For a supported repository, set the repository Actions variable
`ESX_ENABLE_GITHUB_ATTESTATIONS` to `true`; otherwise the workflow safely skips the
attestation step and publishes a private GitHub Release with a verified SHA-256
asset. Do not describe a release as provenance-verified unless the attestation step
completed successfully.
