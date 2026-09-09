# ExposureScopeX Deployment

**Verified:** 2026-09-09

## Supported deployment modes

- Docker Compose on a trusted workstation or single controlled host.
- Compose queue-specific worker pools for higher throughput.
- Kubernetes scanner Jobs for stronger scan isolation. The repository does not
  yet provide a complete production Helm deployment for the control plane.

## Prerequisites

- Docker Desktop/Engine with Compose v2
- At least 4 CPU cores, 12 GiB RAM and 40 GiB free disk for a basic local build
- More disk for scanner images, Nuclei templates, raw evidence and reports
- Authorization to test every configured target

The shared worker can consume up to 6 GiB; backend and frontend are limited to
1 GiB each. Queue-specific pools require materially more memory.

## Local installation

From `webapp/`:

```bash
cp .env.example .env
openssl rand -hex 32
docker compose up -d
docker compose ps
```

Put generated secrets into `.env` before any non-demo use. The backend applies
Alembic migrations through `head` on startup. Do not use `make clean` or
`make reset` on a system whose data must be preserved; both delete volumes.

Default loopback endpoints:

| Service | URL |
|---|---|
| Frontend | `http://127.0.0.1:3001` |
| Backend/OpenAPI | `http://127.0.0.1:8001/docs` |
| nginx HTTP | `http://127.0.0.1:8081` |
| nginx HTTPS | `https://127.0.0.1:8444` |
| Grafana, optional | `http://127.0.0.1:3002` |

Create or reactivate administrators through approved administration procedures;
the legacy default administrator is intentionally disabled by migration `009`.

## Configuration baseline

Production requires unique values for database, Redis, JWT/secret, NextAuth,
metrics and Grafana credentials. Also set:

- `ENVIRONMENT=production`
- `SESSION_COOKIE_SECURE=true`
- exact `ALLOWED_ORIGINS` and `TRUSTED_HOSTS`
- `NEXT_PUBLIC_API_URL` and `NEXTAUTH_URL` to public HTTPS origins
- `NGINX_BIND_ADDRESS` deliberately; default loopback is safest
- S3-compatible artifact settings when local database/file artifacts are unsuitable
- provider credentials or workload identity only for required conditional adapters

Never commit `.env`, cloud credentials, API keys, tokens, report artifacts or
scanner workspaces.

## Build and update behavior

`docker compose up -d` reuses existing images. It does not rebuild unless an
image is missing. Use `docker compose up -d --build` or `make deploy` only when
source/dependencies changed. BuildKit cache is shared by Docker across projects.

The worker image contains pinned scanners and is intentionally large. Nuclei
templates update in `nuclei_runtime`; they are not cloned into every scan.
Repository checkouts are deleted after scans unless
`EXPOSURESCOPEX_RETAIN_REPOSITORY_CHECKOUT=true`.

Safe storage inspection:

```bash
docker system df
docker stats --no-stream
docker compose ps
```

Safe cache reclamation when no build is running:

```bash
docker builder prune --all
docker image prune
```

Build cache removal affects rebuild speed for every Docker project. Never use
`docker system prune --volumes`, `docker compose down -v`, `make clean`, or
`make reset` as routine cleanup. See [runbooks](RUNBOOKS.md).

## TLS and ingress

Development certificates may be mounted under `nginx/certs`. Production should
terminate TLS at a managed ingress/load balancer or mount certificates from a
controlled secret mechanism. Require TLS 1.2+, secure cookies, HSTS after HTTPS
is confirmed, request-size limits and trusted proxy configuration. Certificate
issuance and renewal are operator responsibilities; no ACME automation is
currently shipped.

## Monitoring

```bash
make monitoring-up
```

This starts Prometheus and Grafana. Change the metrics bearer token and Grafana
administrator password first. Alert rules cover readiness, stale scans, queue
depth, disk pressure and backup age.

## Worker pools

Use the shared worker for local efficiency. For contention isolation:

```bash
make worker-pools-up
make worker-pools-down
```

Pools separate web, API/MCP, artifact, cloud, mobile and core queues but still
reuse one scanner image. Do not run shared and pooled workers unintentionally.

## Kubernetes scanner execution

Set `SCAN_EXECUTOR=kubernetes` and apply
`deploy/kubernetes/scanner-rbac.yaml`. Configure scanner image, namespace,
service account, secret, deadlines and ReadWriteMany result storage. Enable raw
network capability only for authorized jobs requiring it. See
`deploy/kubernetes/README.md`.

## Deployment verification and rollback

`make deploy` tags current project images as rollback candidates, builds
backend/frontend/worker, recreates services, confirms migration state and checks
readiness. It is a single-host convenience mechanism, not zero-downtime release
or database downgrade automation.

Back up before every migration. Restore the database and previous images if a
release fails; forward migrations may require a corrective migration because
automatic schema downgrade is not provided.
