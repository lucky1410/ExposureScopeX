# ExposureScopeX Secure SDLC

**Validated:** 2026-09-09. This is the current release-control policy. See
[Threat model](THREAT_MODEL.md), [release process](RELEASES.md), and
[contributing](../CONTRIBUTING.md).

This process applies to every application, scanner adapter, infrastructure change, and release.

## Required lifecycle

1. **Plan:** define security acceptance criteria, data classification, tenant boundaries, abuse cases, and rollback requirements. Update the threat model for new trust boundaries or active scanning behavior.
2. **Design:** prefer secure defaults, least privilege, explicit authorization, deny-by-default network access, and documented third-party trust. Review designs affecting authentication, cryptography, credentials, multi-tenancy, uploads, outbound requests, or command execution.
3. **Develop:** use a short-lived branch, peer review, pinned dependencies, parameterized commands, structured validation, and tests for success, failure, authorization, cancellation, and tenant isolation. Never commit `.env`, scan results, customer data, or credentials.
4. **Verify:** the required CI gate runs backend tests, frontend lint/build, SAST, SCA, secret detection, IaC/container checks, and SBOM generation. High or critical findings block merging unless a time-bound, owner-approved risk acceptance is recorded.
5. **Release:** tag an immutable reviewed commit. The release workflow builds in GitHub Actions, publishes an SBOM and signed provenance, and pushes immutable container digests. Production deploys consume digests, not mutable tags.
6. **Deploy:** migrate and test in staging, verify backup restoration and rollback, deploy through nginx/TLS with production validation enabled, run smoke tests, and use a canary or rolling rollout. Developers do not manually modify production containers.
7. **Operate:** centralize audit/security logs, alert on authentication and scan anomalies, back up PostgreSQL, test restoration quarterly, and monitor dependency/container advisories continuously.
8. **Respond:** follow `SECURITY.md` SLAs, rotate exposed credentials immediately, issue a patched release, document customer impact, and add a regression test or preventive gate.

## Enforcement

- Protect `main`; require pull requests, one security-aware approval, `required-gate`, and CodeQL.
- Block force pushes and branch deletion; require signed commits or vigilant mode where available.
- Enable GitHub private vulnerability reporting, secret scanning, push protection, and Dependabot alerts.
- Install the Renovate GitHub App for this repository; `renovate.json` tracks scanner versions that Dependabot cannot discover inside Docker build arguments. Scanner updates require Dependency Dashboard approval and the full compatibility gate.
- Run scheduled security workflows weekly and Dependabot weekly. Review critical alerts daily and all other alerts weekly.
- Run `make security` before requesting review and before every production tag.
- Review access, threat models, dependencies, base images, and recovery evidence quarterly.
- Require the repository's current Alembic head (`015_scan_schedules` at
  this review) and retain scan-event, worker-capability, artifact-manifest, and
  tool-provenance evidence from release verification.

## Patch and scanner maintenance

- Dependabot and the scheduled security workflow run weekly. The security owner triages critical alerts within one business day, high alerts within three business days, and other actionable alerts during the weekly maintenance window.
- Merge automated updates only after the full required gate passes. Deploy first to staging, run database migration plus rollback checks and a representative scan, then promote the same immutable image digest.
- Review pinned scanner releases and Nuclei/community template sources monthly. A version bump must retain command/output parser compatibility tests and record the upstream release or commit in the pull request.
- Never update or clone tool repositories per scan. Tool binaries are built into immutable images; a fresh persistent Nuclei volume is bootstrapped once at worker startup, then locked, success-stamped daily maintenance refreshes the managed official and explicitly configured community sources in place.
- A tool whose maintained release forces known vulnerable or unsupported dependencies is disabled or moved to an explicit external adapter. Do not suppress the advisory merely to preserve tool count.
- Regenerate and retain release SBOM/provenance, scan the final images, and publish patch evidence with every release. Rebuild unchanged application code when a base-image advisory is fixed upstream.
- Review exceptions weekly. Every exception needs an owner, affected component, compensating control, expiration date, and tracking issue; expired exceptions fail the release review.

## Production configuration

Set `ENVIRONMENT=production`, unique `SECRET_KEY`, `NEXTAUTH_SECRET`,
`POSTGRES_PASSWORD`, `REDIS_PASSWORD`, and `METRICS_BEARER_TOKEN`,
`SESSION_COOKIE_SECURE=true`, exact HTTPS origins/trusted hosts, and
`NGINX_BIND_ADDRESS=0.0.0.0` only on the intended reverse-proxy host. Terminate
trusted TLS at nginx or the platform load balancer. Keep database, Redis,
backend, and worker ports private.
