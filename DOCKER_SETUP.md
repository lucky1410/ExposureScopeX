# Docker Setup

ExposureScopeX is Dockerized as a multi-container web platform. The canonical
Compose definition is [`webapp/docker-compose.yml`](webapp/docker-compose.yml);
the root `Dockerfile` builds only the advanced standalone scanner CLI.

## First Start

```bash
cd webapp
cp .env.example .env
docker compose up -d --build
docker compose ps
```

Open the UI at <http://localhost:3001>, the NGINX entry point at
<http://localhost:8081>, or API docs at <http://localhost:8001/docs>.

## Normal Operation

```bash
# Start or apply configuration without rebuilding images
docker compose up -d

# Rebuild after source, dependency, or Dockerfile changes
docker compose up -d --build

# Stop containers while retaining data
docker compose down
```

Do not run `docker compose down -v` unless permanent deletion of database,
queue, template, evidence, and monitoring volumes is intended.

## Optional Profiles

```bash
# Prometheus and Grafana
docker compose --profile monitoring up -d

# Dedicated capability worker pools
docker compose --profile worker-pools up -d
```

The default stack contains PostgreSQL, Redis, FastAPI, Next.js, NGINX, the
scheduler, and a scanner worker. Worker-pool profiles add isolated workers for
web, API, cloud, mobile, artifact, reporting, and core scan capabilities.

## Storage and Builds

Docker layer cache is shared by Docker Desktop across projects. ExposureScopeX
does not clone tool repositories on every normal start: tools are installed in
worker images, while mutable Nuclei templates and platform data use named
volumes. Use `docker system df` to inspect usage. Avoid global prune commands
unless their impact on every local Docker project is understood.

For deployment configuration, secrets, backups, health checks, and production
hardening, use [`webapp/docs/DEPLOYMENT.md`](webapp/docs/DEPLOYMENT.md) and
[`webapp/docs/OPERATIONS.md`](webapp/docs/OPERATIONS.md).
