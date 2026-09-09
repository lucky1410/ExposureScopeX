# Configuration Reference

`.env.example` is the exhaustive deployment template and `app/config.py` is the
validated backend source of truth. Restart affected services after changing
environment variables; rebuild only when a frontend build argument or image
content changes.

## Core and identity

| Setting group | Important variables | Notes |
|---|---|---|
| Database | `POSTGRES_*`, `DATABASE_URL`, `DATABASE_NULL_POOL` | Null pooling is useful for short-lived isolated jobs |
| Redis | `REDIS_URL`, `REDIS_PASSWORD` | Password in URL and server command must match |
| Environment | `ENVIRONMENT`, `DEBUG` | Production validation rejects unsafe defaults |
| Sessions | `SECRET_KEY`, token expiry, cookie secure/SameSite | Rotate refresh sessions; changing secret revokes tokens |
| Bootstrap | `ALLOW_PUBLIC_REGISTRATION`, `BOOTSTRAP_ADMIN_PASSWORD` | Public registration should remain off after first admin |
| Frontend | `NEXT_PUBLIC_API_URL`, `NEXTAUTH_URL`, `NEXTAUTH_SECRET` | Public URLs must use the deployed HTTPS origin |

## Networking and edge

`BACKEND_CORS_ORIGINS` is a JSON list of exact origins. Compose ports default to
loopback through `BACKEND_PORT`, `FRONTEND_PORT`, `NGINX_HTTP_PORT`,
`NGINX_HTTPS_PORT`, and `NGINX_BIND_ADDRESS`. Do not expose PostgreSQL, Redis or
workers. `HOST_UID`/`HOST_GID` align worker-owned result files with the host.

## Execution and capacity

- `WORKER_QUEUES` and per-pool concurrency select queue consumers.
- `STALE_SCAN_MINUTES` controls recovery detection.
- `DEFAULT_MAX_ACTIVE_SCANS_PER_ORG` and `DEFAULT_MAX_QUEUED_SCANS_PER_ORG`
  provide default tenant admission limits; runtime settings can override them.
- `ENFORCE_WORKER_CAPABILITIES` should remain true in production.
- `SCANNER_IMAGE_IDENTITY` should be an immutable digest in production.
- Retention defaults are controlled by `SCAN_ARTIFACT_RETENTION_DAYS` and
  `REPORT_RETENTION_DAYS`.

## Nuclei

Template directories live in the persistent runtime volume. Auto-refresh and
frequency use `NUCLEI_TEMPLATE_AUTOUPDATE` and
`NUCLEI_TEMPLATE_REFRESH_HOURS`. Additional repositories must be explicitly
approved. `NUCLEI_EXCLUDE_TAGS` defaults away from DoS, fuzz and intrusive
content. Code templates are disabled by default. Treat extra flags and template
repositories as security-sensitive executable configuration.

## Executors and adapters

`SCAN_EXECUTOR=process` uses the local worker. Kubernetes execution uses the
`SCAN_JOB_*` settings and keeps raw network capability disabled by default.
Mobile and Kubernetes runtime controllers use their adapter URL/API key pairs;
`RUNTIME_ADAPTER_ALLOWED_HOSTS` restricts destinations.

Prowler, ScoutSuite, Syft and Grype have binary and enable flags. Prowler, Syft
and Grype are enabled in the standard worker; ScoutSuite is optional. Provider
credentials are configured through encrypted organization settings rather than
committed environment files where possible.

## Artifacts, monitoring and backup

`ARTIFACT_STORAGE_BACKEND` is `database` or `s3`. S3 configuration includes
endpoint, region, bucket, prefix, optional key pair and server-side encryption.
Prefer workload identity. Metrics require a strong `METRICS_BEARER_TOKEN`.
Grafana credentials and port configure the optional monitoring profile.
`BACKUP_REPLICA_*` controls encrypted off-host backup replication.

## Optional intelligence and delivery

Anthropic, Shodan, VirusTotal, Censys, HIBP and GitHub credentials enable their
respective conditional capabilities. Slack, Teams, Splunk and syslog variables
support legacy/default delivery; organization integration records are preferred
for tenant-specific configuration.
