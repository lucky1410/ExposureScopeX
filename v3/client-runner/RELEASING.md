# Releasing the ExposureScopeX Client Evaluation Runner

The customer runner is distributed only from a tagged GitHub Release. The release
workflow builds a wheel from the tag, records asset SHA-256 values in
`SHA256SUMS`, and publishes the wheel and Markdown guides as release assets.
GitHub Actions provenance attestation is optional, as described below.

## Maintainer checklist

1. Set the same release version in `pyproject.toml` and `esx_eval_runner/__init__.py`.
2. Update `README.md`, `RELEASE_NOTES.md`, and the linked guides. Run the complete
   runner suite and an installed-wheel CLI smoke check. Run backend evaluator
   tests when changing the shared backend contract.
3. Commit the release changes and push the commit.
4. Create and push an exact tag such as `esx-eval-runner-v0.12.0`.
5. Review the `Release ESX Eval Runner` GitHub Actions run and the published assets.
6. Verify the downloaded assets with `SHA256SUMS` before announcing them. Use
   `gh attestation verify` too when the attestation step is enabled and succeeds.

Release notes are published from `RELEASE_NOTES.md`; they must describe the
tested scope and current limitations, not imply whole-production certification.

The workflow rejects a tag whose version does not match `pyproject.toml`. Do not
replace release assets after publication. Publish a new patch version instead.

GitHub artifact attestations are supported for public repositories on current GitHub
plans. Private or internal repositories require GitHub Enterprise Cloud for this
provenance feature. For a supported repository, set the repository Actions variable
`ESX_ENABLE_GITHUB_ATTESTATIONS` to `true`; otherwise the workflow safely skips the
attestation step and publishes a private GitHub Release with a verified SHA-256
asset. Do not describe a release as provenance-verified unless the attestation step
completed successfully.
