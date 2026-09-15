# ExposureScopeX Production Operations

**Validated:** 2026-09-10 against schema `018_operation_control_plane`.

Deployment steps are in [Deployment](DEPLOYMENT.md). Incident procedures,
including Docker disk pressure and stuck scans, are in [Runbooks](RUNBOOKS.md).

## Service objectives

- API availability target: 99.9% monthly for a multi-node deployment.
- Recovery point objective: 24 hours by default; use managed PostgreSQL continuous archiving for a 15-minute RPO.
- Recovery time objective: 4 hours, validated by a quarterly restore exercise.
- Scanner jobs are resumable by retry, not process checkpointing. Completed evidence is retained when cancellation is requested.

## Deployment and rollback

Run `make deploy`. The project-scoped deploy wrapper preserves rollback image tags, builds inputs, recreates services, verifies the migration head and readiness, and restores previous project images if interrupted. Production CI should publish digest-pinned images and promote the same digest from staging.

## Backup and restore

Run `make backup` daily and copy the SQL archive plus SHA-256 sidecar to encrypted off-host object storage with immutability enabled. Test with `CONFIRM_RESTORE=exposurescopex ./scripts/restore.sh backups/<file>.sql.gz` in an isolated environment every quarter. The restore command stops only ExposureScopeX application services and reapplies migrations.

Set `BACKUP_REPLICA_URI=s3://bucket/prefix` to make backup success depend on an encrypted off-host copy. `BACKUP_REPLICA_ENDPOINT_URL` supports maintained S3-compatible providers. The open-source MinIO server is intentionally not bundled because its final release line contains an unpatched storage path-traversal advisory; the application adapter remains S3-compatible.

## Artifact storage

The default `ARTIFACT_STORAGE_BACKEND=database` preserves local behavior. Production deployments should set it to `s3` and configure the `S3_*` variables. Prefer an IAM role or workload identity; static access keys are optional and must be supplied as a complete pair. Reports retain only metadata in PostgreSQL, are integrity-checked during download, and remote report/scan objects participate in explicit deletion and scheduled retention.

Settings -> Runtime & Capacity exposes tenant artifact/report usage, quota and
retention policy. Dispatch and report materialization reject new storage when
the quota is exhausted. Cache accounting remains separate because Docker build
cache is host-global and is not tenant evidence.

## Isolated execution

Set `SCAN_EXECUTOR=kubernetes` in the worker deployment and apply `deploy/kubernetes/scanner-rbac.yaml`. Configure `SCAN_JOB_IMAGE`, the runtime secret, scanner service account, namespace, and a ReadWriteMany results PVC. Each assessment scan then runs in a separate non-root Job with seccomp, dropped capabilities, CPU/memory/storage limits, no ingress, a deadline, and cooperative cancellation. Enable `SCAN_JOB_ALLOW_NET_RAW` only when raw-socket discovery is required and the cluster policy permits it. The controller service account can manage Jobs only; scanner Jobs do not receive Kubernetes API tokens.

## Runtime adapters

`MOBILE_DYNAMIC_ADAPTER_URL` and `KUBERNETES_RUNTIME_ADAPTER_URL` point to authorized internal controllers implementing `POST /v1/scan` with multipart artifact input and normalized JSON findings output. API keys are sent only to the configured controller. Without these settings the UI and evidence state clearly report runtime analysis as not configured; static analysis continues normally.

## Monitoring

Generate unique `METRICS_BEARER_TOKEN` and `GRAFANA_ADMIN_PASSWORD` values, then run `docker compose --profile monitoring up -d`. Grafana is bound to `127.0.0.1:3002`, anonymous access is disabled, Prometheus is internal-only, and alert rules cover availability, stale scans, queue backlog, and API errors.

## Retention

Run `make retention` daily after backup. Defaults are 30 days for filesystem results and 35 days for local backups. Override with `RESULT_RETENTION_DAYS` and `BACKUP_RETENTION_DAYS`. Compliance retention belongs in encrypted external object storage rather than the worker volume.

Docker build cache is host-global and is not project evidence. Inspect it with
`docker system df`; reclaim unused cache only when no build runs. Never prune
volumes as routine maintenance. PostgreSQL, Redis and Nuclei runtime volumes are
required state.

## Capacity and scaling

Queues isolate `scans-web`, `scans-api`, `scans-artifact`, `scans-cloud`, and `scans-mobile`. A default worker consumes every queue. Run `make worker-pools-up` to stop it and start queue-specific workers; `make worker-pools-down` restores the memory-efficient local worker. Organization limits are editable at Settings → Runtime & Capacity and enforced at dispatch and through expiring distributed execution leases.

The authenticated `/api/v1/operations/summary` endpoint exposes queue depth and scan state. `/api/v1/operations/metrics` exposes Prometheus text for administrators. Alert on stale active scans, queue growth, readiness failures, disk pressure above 80%, and backup age above 26 hours.

Scan detail reads current state from `scans` and durable history from `scan_events` and `scan_tool_runs`. Set `SCANNER_IMAGE_IDENTITY` to the deployed immutable digest so tool provenance identifies the exact runtime image.

The scheduler evaluates active assessment schedules every minute. It records
each dispatch, skip and failure, honors IANA time zones and maintenance windows,
applies missed-run policy, and prevents overlapping active runs. Pause a
schedule before maintenance rather than stopping Celery Beat globally.

Report requests enter `generating`, execute on the `reports` queue and finish as
`ready`, `failed`, or `cancelled`. Operators can inspect terminal errors and
cancel queued work; downloads are unavailable until integrity metadata exists.

## Incident checklist

1. Stop new dispatch while allowing safe cancellation of active scans.
2. Preserve database, audit logs, scan metadata and evidence hashes.
3. Rotate affected credentials and revoke sessions.
4. Roll back to a known image digest or restore PostgreSQL in isolation.
5. Run readiness, a representative authorized scan and report generation.
6. Document impact and add a regression test before reopening dispatch.
