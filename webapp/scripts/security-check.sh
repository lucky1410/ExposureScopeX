#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

echo "[1/6] Repository hygiene"
git diff --check
if git ls-files | grep -Eq '(^|/)\.env($|\.)|^config/exposurescopex\.conf$|^results/'; then
  echo "Sensitive runtime files are tracked by Git" >&2
  exit 1
fi

echo "[2/6] Backend tests"
docker run --rm -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$ROOT/webapp/backend/app:/app/app:ro" \
  -v "$ROOT/webapp/backend/tests:/app/tests:ro" exposurescopex-backend \
  python -m unittest discover -s tests -v

echo "[3/6] Frontend lint and audit"
(cd webapp/frontend && npm run lint && npm audit --audit-level=high)

echo "[4/6] Compose validation"
(cd webapp && docker compose config --quiet)

echo "[5/6] Filesystem vulnerabilities, secrets, and misconfigurations"
docker run --rm -v /tmp/exposurescopex-trivy:/root/.cache/trivy -v "$ROOT:/repo:ro" \
  aquasec/trivy:0.74.0 fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL \
  --ignore-unfixed --skip-dirs /repo/results --skip-dirs /repo/webapp/frontend/node_modules \
  --skip-dirs /repo/webapp/frontend/.next --exit-code 1 --no-progress /repo

for image in exposurescopex-backend exposurescopex-frontend exposurescopex-worker; do
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v /tmp/exposurescopex-trivy:/root/.cache/trivy aquasec/trivy:0.74.0 image \
    --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 \
    --no-progress "$image"
done

echo "[6/6] Git history secret scan"
docker run --rm -v "$ROOT:/repo:ro" zricethezav/gitleaks:v8.30.1 \
  detect --source=/repo --redact --no-banner

echo "All local security gates passed"
