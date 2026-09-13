# Security posture and rollout requirements

## Current technical controls

- Local setup UI binds to `127.0.0.1` and requires an unpredictable per-run request token.
- HTTP evaluation defaults to loopback-only targets.
- Remote targets require explicit staging approval, HTTPS, and mutual TLS.
- Redirects, URL credentials, and URL query strings are rejected.
- HTTP evaluation traffic has case-count and pacing limits and an evaluation-mode header.
- Optional custom-adapter containers run without network or host mounts, with a read-only filesystem, a non-root user, dropped capabilities, and resource limits.
- Result packages and reports exclude raw case inputs and target responses.
- A local hash-chained audit log records redacted lifecycle metadata.
- GitHub release automation supports provenance attestation when the repository enables it.

## Required customer operating controls

- Use a dedicated test tenant, test identities, least-privilege credentials, and synthetic test data.
- Configure the target to reject production actions from the evaluation identity.
- Inject connector secrets from the organization's approved secret manager into environment variables at runtime.
- Store audit-tail hashes in a separate approved audit system for tamper-evident retention.
- Allow only approved staging endpoints and certificate authorities through enterprise egress controls.

## Not a certification

This project has not completed a third-party penetration test, SOC 2 assessment, ISO 27001 certification, or customer-specific security review. Those activities require an agreed scope, independent reviewers, operating evidence, and an authorized test environment. Do not claim certification before those steps are complete.
