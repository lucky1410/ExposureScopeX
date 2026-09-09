# ExposureScopeX Runbooks

## Service unavailable

1. Run `docker compose ps` from `webapp/`.
2. Check `docker compose logs --tail=100 backend worker postgres redis`.
3. Verify backend `/health` and `/ready` separately.
4. Confirm schema with `docker compose exec -T backend alembic current`.
5. Restart only the failed service. Do not rebuild unless source changed.

## Scan remains queued or at zero percent

1. Open Operations and confirm queue depth and online workers.
2. Confirm a worker advertises the required queue and tools.
3. Inspect scan detail events and pending work units.
4. Check worker logs for authorization, target policy, credential or capability blocks.
5. Cancel/retry only after identifying whether the stage is safe to repeat.

Never mark a stale scan completed manually. Recovery should preserve failed or
cancelled evidence and create a new identity for retry.

## Docker disk pressure

1. Run `docker system df`, `docker stats --no-stream`, and host `df -h`.
2. Distinguish build cache, unused images, volumes, logs and scan artifacts.
3. When no build runs, use `docker builder prune --all` with operator approval.
4. Use `docker image prune` for dangling images.
5. Apply `make retention` for project artifacts/backups according to policy.

Do not prune volumes or use `make clean`/`make reset` on retained data. Docker
build cache is global across projects. The Compose log driver is capped at
10 MiB with three files per container.

## Docker Desktop cannot start

Check host free space first. `Docker.raw` is sparse; compare `ls -lh` logical
size with `du -sh` physical usage. Inspect Docker Desktop diagnostics and logs
for `no space left on device`. Do not delete `Docker.raw`: it contains all local
containers, images and volumes. Repair/reinstall only the application bundle
while preserving Docker data, then reclaim cache through the running engine.

## Backup

Run `make backup`. Verify the `.sql.gz` and `.sha256` files exist and copy them
off-host. Database backup does not automatically include local scan result
directories, TLS keys, `.env`, or externally stored objects; back those up under
their own protected procedures.

## Restore

Restore is destructive. Use an isolated rehearsal first, validate checksum, and
record approval. The script requires:

```bash
CONFIRM_RESTORE=exposurescopex ./scripts/restore.sh BACKUP.sql.gz
```

Afterward verify migration head, tenant counts, a report download, worker
registration and a harmless authorized smoke scan.

## Compromised credential

1. Disable/revoke at the provider first.
2. Disable the ExposureScopeX integration or API key.
3. Revoke affected sessions if user credentials were involved.
4. Search audit records and scan evidence for use, without exposing the secret.
5. Rotate encryption/JWT secrets only with a migration plan; changing the
   encryption root can make stored credentials unreadable.

## Suspected cross-tenant exposure

Stop affected external access, preserve database/audit snapshots, revoke active
sessions, identify route and organization predicates, and treat the event as a
security incident. Do not delete records before evidence preservation.

## Failed deployment

`make deploy` retains rollback image tags but does not downgrade schema. Keep
the database backup, inspect readiness/migration failure, and either apply a
corrective forward migration or restore the approved backup with matching
images. Record the incident in release evidence.
