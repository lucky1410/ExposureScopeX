.PHONY: help dev build up down logs migrate seed test security clean reset monitoring-up monitoring-down worker-pools-up worker-pools-down

# ExposureScopeX Web Application
# ================================

help: ## Show this help
	@echo "ExposureScopeX Web Application"
	@echo "=============================="
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

# Development
dev: ## Start all services in development mode with hot reload
	docker compose up --build

build: ## Build all Docker images
	docker compose build

up: ## Start all services in background
	docker compose up -d

down: ## Stop all services
	docker compose down

logs: ## Follow logs from all services
	docker compose logs -f

logs-backend: ## Follow backend logs
	docker compose logs -f backend

logs-frontend: ## Follow frontend logs
	docker compose logs -f frontend

logs-worker: ## Follow worker logs
	docker compose logs -f worker

# Database
migrate: ## Run database migrations
	docker compose exec backend alembic upgrade head

migrate-new: ## Create a new migration (usage: make migrate-new MSG="description")
	docker compose exec backend alembic revision --autogenerate -m "$(MSG)"

seed: ## Seed demo data
	docker compose exec backend python -m app.services.demo_data_service

# Testing
test-backend: ## Run backend tests in the production dependency image
	docker compose build backend
	docker run --rm -v "$(CURDIR)/backend/tests:/app/tests:ro" exposurescopex-backend python -m unittest discover -s tests -v

test-worker: ## Run scanner isolation and artifact safety tests
	cd worker && python3 -m unittest -v test_specialized_scan.py

test-shell: ## Run shell framework regression tests
	cd .. && bash tests/run_tests.sh

test-frontend: ## Lint and production-build the frontend
	cd frontend && npm run lint && npm run build

test: test-backend test-worker test-shell test-frontend ## Run all tests

security: ## Run local security, dependency, secret, and configuration gates
	./scripts/security-check.sh

backup: ## Create an integrity-checked PostgreSQL backup
	sh scripts/backup.sh

retention: ## Apply local result and backup retention
	sh scripts/retention.sh

monitoring-up: ## Start the optional Prometheus and Grafana profile
	docker compose --profile monitoring up -d prometheus grafana

monitoring-down: ## Stop the optional monitoring profile without deleting data
	docker compose --profile monitoring stop prometheus grafana

worker-pools-up: ## Replace the shared worker with queue-specific production pools
	docker compose stop worker
	docker compose --profile worker-pools up -d worker-web worker-api worker-artifact worker-cloud worker-mobile worker-core worker-report

worker-pools-down: ## Restore the single memory-efficient local worker
	docker compose --profile worker-pools stop worker-web worker-api worker-artifact worker-cloud worker-mobile worker-core worker-report
	docker compose up -d worker

deploy: ## Build, deploy, migrate, and verify with project-scoped rollback tags
	sh scripts/deploy.sh

# Maintenance
clean: ## Remove all containers, volumes, and images
	docker compose down -v --rmi all

reset: ## Reset database (drop + recreate + migrate + seed)
	docker compose down -v
	docker compose up -d postgres redis
	sleep 3
	docker compose up -d backend
	sleep 5
	docker compose exec backend alembic upgrade head

shell-backend: ## Open shell in backend container
	docker compose exec backend bash

shell-frontend: ## Open shell in frontend container
	docker compose exec frontend sh

shell-db: ## Open psql shell
	docker compose exec postgres psql -U exposurescopex

# Production
prod: ## Start in production mode
	docker compose -f docker-compose.yml up -d --build
