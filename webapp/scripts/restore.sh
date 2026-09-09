#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: CONFIRM_RESTORE=exposurescopex ./scripts/restore.sh BACKUP.sql.gz" >&2
  exit 2
fi
if [ "${CONFIRM_RESTORE:-}" != "exposurescopex" ]; then
  echo "Restore refused: set CONFIRM_RESTORE=exposurescopex" >&2
  exit 2
fi
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
BACKUP=$1
test -f "$BACKUP"
test -f "$BACKUP.sha256"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c "$BACKUP.sha256"
else
  shasum -a 256 -c "$BACKUP.sha256"
fi
gzip -t "$BACKUP"
cd "$ROOT"
docker compose stop backend worker scheduler
trap 'docker compose up -d backend worker scheduler' EXIT
gzip -dc "$BACKUP" | docker compose exec -T postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" "$POSTGRES_DB"'
docker compose up -d backend worker scheduler
docker compose exec -T backend alembic upgrade head
trap - EXIT
echo "Restore completed and migrations are at head"
