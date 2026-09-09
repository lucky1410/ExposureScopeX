#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
DEST=${1:-"$ROOT/backups"}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
ARCHIVE="$DEST/exposurescopex-$STAMP.sql.gz"
TEMP_DUMP="$ARCHIVE.sql.tmp"
mkdir -p "$DEST"
umask 077
trap 'rm -f "$TEMP_DUMP"' EXIT HUP INT TERM
cd "$ROOT"
docker compose exec -T postgres sh -c 'pg_dump --clean --if-exists --no-owner --no-privileges -U "$POSTGRES_USER" "$POSTGRES_DB"' > "$TEMP_DUMP"
test -s "$TEMP_DUMP"
gzip -9 -c "$TEMP_DUMP" > "$ARCHIVE"
gzip -t "$ARCHIVE"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"
else
  shasum -a 256 "$ARCHIVE" > "$ARCHIVE.sha256"
fi
if [ -n "${BACKUP_REPLICA_URI:-}" ]; then
  command -v aws >/dev/null 2>&1 || {
    echo "Backup replication requested but the AWS CLI is unavailable" >&2
    exit 1
  }
  set -- s3 cp
  if [ -n "${BACKUP_REPLICA_ENDPOINT_URL:-}" ]; then
    set -- --endpoint-url "$BACKUP_REPLICA_ENDPOINT_URL" "$@"
  fi
  aws "$@" "$ARCHIVE" "${BACKUP_REPLICA_URI%/}/$(basename "$ARCHIVE")" --sse "${BACKUP_REPLICA_SSE:-AES256}"
  aws "$@" "$ARCHIVE.sha256" "${BACKUP_REPLICA_URI%/}/$(basename "$ARCHIVE.sha256")" --sse "${BACKUP_REPLICA_SSE:-AES256}"
fi
rm -f "$TEMP_DUMP"
trap - EXIT HUP INT TERM
printf 'Backup created: %s\n' "$ARCHIVE"
