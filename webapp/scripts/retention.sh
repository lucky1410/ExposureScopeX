#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
RESULT_DAYS=${RESULT_RETENTION_DAYS:-30}
BACKUP_DAYS=${BACKUP_RETENTION_DAYS:-35}
find "$ROOT/../results" -type f -mtime "+$RESULT_DAYS" -delete 2>/dev/null || true
find "$ROOT/../results" -depth -type d -empty -delete 2>/dev/null || true
find "$ROOT/backups" -type f \( -name '*.sql.gz' -o -name '*.sha256' \) -mtime "+$BACKUP_DAYS" -delete 2>/dev/null || true
echo "Retention complete: results=${RESULT_DAYS}d backups=${BACKUP_DAYS}d"
