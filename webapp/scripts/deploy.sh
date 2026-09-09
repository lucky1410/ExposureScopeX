#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
for image in backend frontend worker; do
  if docker image inspect "exposurescopex-$image:latest" >/dev/null 2>&1; then
    docker image tag "exposurescopex-$image:latest" "exposurescopex-$image:rollback"
  fi
done
rollback() {
  echo "Deployment interrupted; restoring previous project images" >&2
  for image in backend frontend worker; do
    if docker image inspect "exposurescopex-$image:rollback" >/dev/null 2>&1; then
      docker image tag "exposurescopex-$image:rollback" "exposurescopex-$image:latest"
    fi
  done
  docker compose up -d --force-recreate
}
trap rollback INT TERM HUP
if ! docker compose build backend frontend worker; then rollback; exit 1; fi
if ! docker compose up -d --remove-orphans; then rollback; exit 1; fi
if ! docker compose exec -T backend alembic current; then rollback; exit 1; fi
if ! docker compose exec -T backend python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/ready')"; then rollback; exit 1; fi
docker compose ps
trap - INT TERM HUP
echo "ExposureScopeX deployment verified"
