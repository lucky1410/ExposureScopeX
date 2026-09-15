from contextlib import asynccontextmanager
import csv
import hashlib
import io
import json
from pathlib import Path
from uuid import UUID
from urllib.parse import urlsplit

import asyncio
import os

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import ValidationError

from .auth import (
    Credentials,
    OwnerSetup,
    SESSION_COOKIE,
    create_session,
    current_user,
    password_digest,
    public_user,
    verify_password,
)
from .agent_contracts import registered_agent, registry_payload
from .db import connect, disconnect, pool, record_to_dict
from .evaluation import (
    EvaluationRequest,
    evaluation_input_summary,
    evaluate,
    evaluator_descriptor,
    verify_stored_evaluation,
)
from .evaluator_reporting import (
    EVALUATOR_REPORT_VERSION,
    EvaluationReportError,
    REPORT_EXTENSIONS,
    REPORT_MEDIA_TYPES,
    evaluation_source_sha256,
    evaluation_report_path,
    generate_evaluation_reports,
    get_evaluation_report,
    list_evaluation_reports,
)
from .evaluator_governance import (
    EvaluatorDatasetCreate,
    EvaluatorProjectCreate,
    approved_evaluator_dataset,
    evaluator_project,
    evaluator_workspace,
    record_evaluator_audit_event,
    require_evaluator_role,
)
from .live_evaluator_adapters import (
    AdapterInvocationError,
    EvaluatorLiveAdapterCreate,
    LiveAdapterEvaluationRequest,
    adapter_evaluation_payload,
    endpoint_sha256,
    invoke_live_adapter,
)
from .client_evaluator_runs import (
    ClientRunError,
    ClientRunnerPackage,
    EvaluatorClientIdentityCreate,
    EvaluatorGitHubIntegrationCreate,
    github_identity_fingerprint,
    github_integration_claims_match,
    package_evaluation_request,
    public_key_fingerprint,
    verify_ed25519_package,
    verify_github_actions_oidc,
)
from .methodology_cases import coverage_records
from .migrations import migrate
from .profiles import PLAN_VERSION, compile_plan
from .schemas import (
    AssetAssessmentStart,
    AssetDiscoveryRequest,
    Assessment,
    AssessmentAssetReview,
    AssessmentCreate,
    ExposureAssetReview,
    ExposureFindingLifecycleUpdate,
    ExposureMonitorCreate,
    ExposureMonitorUpdate,
    IntegrationCreate,
    PassiveInventoryRequest,
    ScanDetail,
    ScanStarted,
    ScopeFileValidationRequest,
    SubdomainAssessmentCreate,
    ValidationCorpusCreate,
)
from .asset_inventory import (
    DISCOVERY_SOURCE_CERTIFICATE_TRANSPARENCY,
    DISCOVERY_SOURCE_CLIENT_DECLARED,
    display_asset_status,
    target_for_discovered_hostname,
)
from .light_adapters import _passive_certificate_transparency
from .secrets import decrypt_secret, encrypt_secret
from .artifact_store import artifact_path
from .scope_files import parse_scope_file, scope_dispatch_error
from .subdomain_scope import approved_discovered_subdomains, target_for_subdomain
from .benchmark_manifest import (
    benchmark_release_eligibility,
    load_benchmark_manifest,
    map_observation_key,
)
from .benchmarking import BenchmarkObservation, score_vulnerability_benchmark
from .config import settings
from .methodology import profile_contract
from .methodology_cases import canonical_observation_key, observation_evidence_kinds
from .reporting import generate_scan_reports, report_status_for_scan
from .semantic_evaluator import (
    SEMANTIC_PROMPT_VERSION,
    OpenAIResponsesJudge,
    SemanticEvaluationRequest,
    SemanticJudgeError,
    run_semantic_evaluation,
    semantic_input_manifest,
    semantic_judge_descriptor,
)
from .exposure_management import (
    enqueue_integration_deliveries,
    exposure_workspace,
    record_exposure_audit_event,
    require_exposure_role,
    sync_assessment_asset,
    validate_integration_endpoint_url,
    workspace_assessment,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await connect()
    await migrate()
    yield
    await disconnect()


app = FastAPI(title="ExposureScopeX v3", version="3.0.0-alpha.1", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings().allowed_cors_origins,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-ESX-Organization"],
    allow_credentials=True,
)


def configured_semantic_judge() -> tuple[OpenAIResponsesJudge | None, dict]:
    configuration = settings()
    provider = configuration.ai_evaluator_provider.strip().lower()
    if provider in {"", "disabled", "none"}:
        return None, semantic_judge_descriptor(
            provider="disabled",
            model=None,
            configured=False,
            detail="Configure a provider and model to enable semantic judgement.",
        )
    if provider != "openai_responses":
        return None, semantic_judge_descriptor(
            provider=provider,
            model=configuration.ai_evaluator_model or None,
            configured=False,
            status="misconfigured",
            detail="Unsupported AI evaluator provider.",
        )
    try:
        judge = OpenAIResponsesJudge(
            api_key=configuration.ai_evaluator_api_key.get_secret_value(),
            model=configuration.ai_evaluator_model,
            base_url=configuration.ai_evaluator_base_url,
            timeout_seconds=configuration.ai_evaluator_timeout_seconds,
        )
    except ValueError as exc:
        return None, semantic_judge_descriptor(
            provider=provider,
            model=configuration.ai_evaluator_model or None,
            configured=False,
            status="misconfigured",
            detail=str(exc),
        )
    return judge, semantic_judge_descriptor(
        provider=provider,
        model=judge.model_name,
        configured=True,
        detail="Independent, tool-free structured semantic judge is ready.",
    )


@app.get("/health")
async def health() -> dict:
    value = await pool().fetchval("SELECT 1")
    return {"status": "ok", "database": value == 1}


@app.get("/api/v3/auth/setup-status")
async def setup_status() -> dict:
    count = await pool().fetchval("SELECT count(*) FROM users")
    return {"setup_required": count == 0}


@app.post("/api/v3/auth/setup", status_code=status.HTTP_201_CREATED)
async def setup_owner(payload: OwnerSetup, response: Response) -> dict:
    salt = os.urandom(16)
    digest = await asyncio.to_thread(password_digest, payload.password, salt)
    async with pool().acquire() as conn, conn.transaction():
        await conn.execute("LOCK TABLE users IN EXCLUSIVE MODE")
        count = await conn.fetchval("SELECT count(*) FROM users")
        if count:
            raise HTTPException(status_code=409, detail="Workspace is already initialized")
        row = await conn.fetchrow(
            """
            INSERT INTO users (email, display_name, password_hash, password_salt, role)
            VALUES ($1, $2, $3, $4, 'owner') RETURNING *
            """,
            payload.email,
            payload.display_name,
            digest,
            salt,
        )
        workspace = await conn.fetchrow(
            """
            INSERT INTO organizations (name, slug, owner_user_id)
            VALUES ($1, $2, $3)
            RETURNING id
            """,
            f"{payload.display_name} Workspace"[:160],
            f"org-{str(row['id']).replace('-', '')}",
            row["id"],
        )
        await conn.execute(
            """
            INSERT INTO organization_memberships (organization_id, user_id, role)
            VALUES ($1, $2, 'owner')
            """,
            workspace["id"],
            row["id"],
        )
        await conn.execute(
            """
            INSERT INTO evaluator_projects (organization_id, key, name, description, created_by)
            VALUES ($1, 'default', 'Default Evaluation Program', $2, $3)
            """,
            workspace["id"],
            "Default governed project created with the owner workspace.",
            row["id"],
        )
    await create_session(response, row["id"])
    return public_user(row)


@app.post("/api/v3/auth/login")
async def login(payload: Credentials, response: Response) -> dict:
    row = await pool().fetchrow("SELECT * FROM users WHERE email = $1 AND active = true", payload.email)
    if row is None or not await verify_password(
        payload.password, bytes(row["password_hash"]), bytes(row["password_salt"])
    ):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    await create_session(response, row["id"])
    return public_user(row)


@app.get("/api/v3/auth/me")
async def me(user: dict = Depends(current_user)) -> dict:
    return user


@app.get("/api/v3/agents")
async def list_agents(_: dict = Depends(current_user)) -> list[dict]:
    return registry_payload()


@app.get("/api/v3/evaluator")
async def get_evaluator(_: dict = Depends(current_user)) -> dict:
    _, semantic = configured_semantic_judge()
    return evaluator_descriptor(semantic_judge=semantic)


@app.get("/api/v3/evaluator/workspaces")
async def list_evaluator_workspaces(user: dict = Depends(current_user)) -> list[dict]:
    """List only organizations in which the signed-in user has evaluator access."""
    rows = await pool().fetch(
        """
        SELECT o.id, o.name, o.slug, m.role AS membership_role
        FROM organization_memberships m
        JOIN organizations o ON o.id = m.organization_id
        WHERE m.user_id = $1 AND o.active = true
        ORDER BY o.name
        """,
        user["id"],
    )
    return [dict(row) for row in rows]


@app.get("/api/v3/evaluator/workspace")
async def evaluator_workspace_overview(
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    projects = await pool().fetch(
        """
        SELECT id, key, name, description, status, created_at
        FROM evaluator_projects
        WHERE organization_id = $1
        ORDER BY status, name
        """,
        workspace["id"],
    )
    datasets = await pool().fetch(
        """
        SELECT d.id, p.key AS project_key, d.name, d.version, d.classification,
               d.source_sha256, d.source_reference, d.status, d.approved_at, d.created_at
        FROM evaluator_datasets d
        JOIN evaluator_projects p ON p.id = d.project_id
        WHERE p.organization_id = $1
        ORDER BY p.key, d.created_at DESC
        """,
        workspace["id"],
    )
    adapters = await pool().fetch(
        """
        SELECT a.id, p.key AS project_key, a.name, a.adapter_type, a.endpoint_sha256,
               a.status, a.approved_at, a.created_at
        FROM evaluator_live_adapters a
        JOIN evaluator_projects p ON p.id = a.project_id
        WHERE a.organization_id = $1
        ORDER BY p.key, a.created_at DESC
        """,
        workspace["id"],
    )
    client_identities = await pool().fetch(
        """
        SELECT i.id, p.key AS project_key, i.name, i.identity_type, i.key_fingerprint,
               i.status, i.approved_at, i.created_at
        FROM evaluator_client_identities i
        JOIN evaluator_projects p ON p.id = i.project_id
        WHERE i.organization_id = $1
        ORDER BY p.key, i.created_at DESC
        """,
        workspace["id"],
    )
    github_integrations = await pool().fetch(
        """
        SELECT g.id, p.key AS project_key, g.name, g.repository, g.workflow_ref,
               g.oidc_audience, g.status, g.approved_at, g.created_at
        FROM evaluator_github_integrations g
        JOIN evaluator_projects p ON p.id = g.project_id
        WHERE g.organization_id = $1
        ORDER BY p.key, g.created_at DESC
        """,
        workspace["id"],
    )
    return {
        "organization": {
            "id": workspace["id"],
            "name": workspace["name"],
            "slug": workspace["slug"],
            "membership_role": workspace["membership_role"],
        },
        "projects": [dict(row) for row in projects],
        "datasets": [dict(row) for row in datasets],
        "live_adapters": [dict(row) for row in adapters],
        "client_identities": [dict(row) for row in client_identities],
        "github_integrations": [dict(row) for row in github_integrations],
    }


@app.post("/api/v3/evaluator/projects", status_code=status.HTTP_201_CREATED)
async def create_evaluator_project(
    payload: EvaluatorProjectCreate,
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    require_evaluator_role(workspace, "owner", "admin")
    try:
        row = await pool().fetchrow(
            """
            INSERT INTO evaluator_projects (organization_id, key, name, description, created_by)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, organization_id, key, name, description, status, created_at
            """,
            workspace["id"], payload.key, payload.name, payload.description, workspace["user_id"],
        )
    except Exception as exc:
        if getattr(exc, "sqlstate", None) == "23505":
            raise HTTPException(status_code=409, detail="Evaluator project key already exists") from exc
        raise
    project = dict(row)
    await record_evaluator_audit_event(
        workspace, "evaluator_project_created", target_type="evaluator_project", target_id=project["id"],
        payload={"project_key": project["key"]},
    )
    return project


@app.post("/api/v3/evaluator/datasets", status_code=status.HTTP_201_CREATED)
async def register_evaluator_dataset(
    payload: EvaluatorDatasetCreate,
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    require_evaluator_role(workspace, "owner", "admin", "analyst")
    project = await evaluator_project(workspace, payload.project_key)
    try:
        row = await pool().fetchrow(
            """
            INSERT INTO evaluator_datasets (
              project_id, name, version, classification, source_sha256, source_reference, created_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, project_id, name, version, classification, source_sha256,
                      source_reference, status, created_at
            """,
            project["id"], payload.name, payload.version, payload.classification,
            payload.source_sha256, payload.source_reference, workspace["user_id"],
        )
    except Exception as exc:
        if getattr(exc, "sqlstate", None) == "23505":
            raise HTTPException(status_code=409, detail="Dataset version already exists for this project") from exc
        raise
    dataset = dict(row)
    await record_evaluator_audit_event(
        workspace, "evaluator_dataset_registered", target_type="evaluator_dataset", target_id=dataset["id"],
        payload={"project_key": project["key"], "dataset_version": dataset["version"], "classification": dataset["classification"]},
    )
    return dataset


@app.post("/api/v3/evaluator/datasets/{dataset_id}/approve")
async def approve_evaluator_dataset(
    dataset_id: UUID,
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    require_evaluator_role(workspace, "owner", "admin")
    draft = await pool().fetchrow(
        """
        SELECT d.id, d.created_by
        FROM evaluator_datasets d
        JOIN evaluator_projects p ON p.id = d.project_id
        WHERE d.id = $1 AND p.organization_id = $2 AND d.status = 'draft'
        """,
        dataset_id,
        workspace["id"],
    )
    if draft is None:
        raise HTTPException(status_code=404, detail="Draft dataset was not found in this workspace")
    if (
        settings().ai_evaluator_require_independent_approval
        and draft["created_by"] == workspace["user_id"]
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Independent approval is required; a different owner or administrator must approve this dataset",
        )
    row = await pool().fetchrow(
        """
        UPDATE evaluator_datasets d
        SET status = 'approved', approved_by = $2, approved_at = now()
        FROM evaluator_projects p
        WHERE d.id = $1 AND d.project_id = p.id AND p.organization_id = $3
          AND d.status = 'draft'
        RETURNING d.id, d.project_id, d.name, d.version, d.classification,
                  d.source_sha256, d.source_reference, d.status, d.approved_at
        """,
        dataset_id, workspace["user_id"], workspace["id"],
    )
    if row is None:
        raise HTTPException(status_code=409, detail="Dataset approval was changed concurrently; refresh and retry")
    dataset = dict(row)
    await record_evaluator_audit_event(
        workspace, "evaluator_dataset_approved", target_type="evaluator_dataset", target_id=dataset["id"],
        payload={"dataset_version": dataset["version"]},
    )
    return dataset


@app.post("/api/v3/evaluator/live-adapters", status_code=status.HTTP_201_CREATED)
async def register_evaluator_live_adapter(
    payload: EvaluatorLiveAdapterCreate,
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    """Register a replacement-only endpoint configuration with an encrypted bearer token."""
    require_evaluator_role(workspace, "owner", "admin")
    project = await evaluator_project(workspace, payload.project_key)
    try:
        row = await pool().fetchrow(
            """
            INSERT INTO evaluator_live_adapters (
              organization_id, project_id, name, adapter_type, endpoint_url, endpoint_sha256,
              credential_ciphertext, created_by
            ) VALUES ($1, $2, $3, 'http_json_v1', $4, $5, $6, $7)
            RETURNING id, project_id, name, adapter_type, endpoint_sha256, status, created_at
            """,
            workspace["id"], project["id"], payload.name, payload.endpoint_url,
            endpoint_sha256(payload.endpoint_url), encrypt_secret(payload.api_token.get_secret_value()), workspace["user_id"],
        )
    except Exception as exc:
        if getattr(exc, "sqlstate", None) == "23505":
            raise HTTPException(status_code=409, detail="Adapter name or endpoint is already registered for this project") from exc
        raise
    adapter = dict(row)
    adapter["project_key"] = project["key"]
    await record_evaluator_audit_event(
        workspace, "evaluator_live_adapter_registered", target_type="evaluator_live_adapter", target_id=adapter["id"],
        payload={"project_key": project["key"], "adapter_type": adapter["adapter_type"], "endpoint_sha256": adapter["endpoint_sha256"]},
    )
    return adapter


@app.post("/api/v3/evaluator/live-adapters/{adapter_id}/approve")
async def approve_evaluator_live_adapter(
    adapter_id: UUID,
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    require_evaluator_role(workspace, "owner", "admin")
    draft = await pool().fetchrow(
        """
        SELECT id, created_by FROM evaluator_live_adapters
        WHERE id = $1 AND organization_id = $2 AND status = 'draft'
        """,
        adapter_id, workspace["id"],
    )
    if draft is None:
        raise HTTPException(status_code=404, detail="Draft live adapter was not found in this workspace")
    if settings().ai_evaluator_require_independent_approval and draft["created_by"] == workspace["user_id"]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Independent approval is required; a different owner or administrator must approve this adapter",
        )
    row = await pool().fetchrow(
        """
        UPDATE evaluator_live_adapters
        SET status = 'approved', approved_by = $2, approved_at = now()
        WHERE id = $1 AND organization_id = $3 AND status = 'draft'
        RETURNING id, project_id, name, adapter_type, endpoint_sha256, status, approved_at
        """,
        adapter_id, workspace["user_id"], workspace["id"],
    )
    if row is None:
        raise HTTPException(status_code=409, detail="Live adapter approval was changed concurrently; refresh and retry")
    adapter = dict(row)
    await record_evaluator_audit_event(
        workspace, "evaluator_live_adapter_approved", target_type="evaluator_live_adapter", target_id=adapter["id"],
        payload={"adapter_type": adapter["adapter_type"], "endpoint_sha256": adapter["endpoint_sha256"]},
    )
    return adapter


@app.post("/api/v3/evaluator/live-adapters/{adapter_id}/disable")
async def disable_evaluator_live_adapter(
    adapter_id: UUID,
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    require_evaluator_role(workspace, "owner", "admin")
    row = await pool().fetchrow(
        """
        UPDATE evaluator_live_adapters
        SET status = 'disabled', disabled_by = $2, disabled_at = now()
        WHERE id = $1 AND organization_id = $3 AND status IN ('draft', 'approved')
        RETURNING id, project_id, name, adapter_type, endpoint_sha256, status, disabled_at
        """,
        adapter_id, workspace["user_id"], workspace["id"],
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Active live adapter was not found in this workspace")
    adapter = dict(row)
    await record_evaluator_audit_event(
        workspace, "evaluator_live_adapter_disabled", target_type="evaluator_live_adapter", target_id=adapter["id"],
        payload={"adapter_type": adapter["adapter_type"], "endpoint_sha256": adapter["endpoint_sha256"]},
    )
    return adapter


@app.post("/api/v3/evaluator/client-identities", status_code=status.HTTP_201_CREATED)
async def register_evaluator_client_identity(
    payload: EvaluatorClientIdentityCreate,
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    """Register only a public signing key. The corresponding private key stays with the client."""
    require_evaluator_role(workspace, "owner", "admin")
    project = await evaluator_project(workspace, payload.project_key)
    fingerprint = public_key_fingerprint(payload.public_key)
    try:
        row = await pool().fetchrow(
            """
            INSERT INTO evaluator_client_identities (
              organization_id, project_id, name, identity_type, public_key, key_fingerprint, created_by
            ) VALUES ($1, $2, $3, 'ed25519', $4, $5, $6)
            RETURNING id, project_id, name, identity_type, key_fingerprint, status, created_at
            """,
            workspace["id"], project["id"], payload.name, payload.public_key, fingerprint, workspace["user_id"],
        )
    except Exception as exc:
        if getattr(exc, "sqlstate", None) == "23505":
            raise HTTPException(status_code=409, detail="Client identity name or public key is already registered for this project") from exc
        raise
    identity = dict(row)
    identity["project_key"] = project["key"]
    await record_evaluator_audit_event(
        workspace, "evaluator_client_identity_registered", target_type="evaluator_client_identity", target_id=identity["id"],
        payload={"project_key": project["key"], "identity_type": "ed25519", "key_fingerprint": fingerprint},
    )
    return identity


@app.post("/api/v3/evaluator/client-identities/{identity_id}/approve")
async def approve_evaluator_client_identity(
    identity_id: UUID,
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    require_evaluator_role(workspace, "owner", "admin")
    identity_state = await pool().fetchrow(
        """
        SELECT id, project_id, name, identity_type, key_fingerprint, status, approved_at, created_by
        FROM evaluator_client_identities
        WHERE id = $1 AND organization_id = $2
        """,
        identity_id, workspace["id"],
    )
    if identity_state is None:
        raise HTTPException(status_code=404, detail="Client identity was not found in this workspace")
    if identity_state["status"] == "approved":
        # Approval is idempotent so a duplicate browser request is not reported as a false failure.
        return dict(identity_state)
    if identity_state["status"] == "disabled":
        raise HTTPException(status_code=409, detail="Disabled client identities cannot be approved; register a replacement identity")
    if settings().ai_evaluator_require_independent_approval and identity_state["created_by"] == workspace["user_id"]:
        raise HTTPException(status_code=422, detail="Independent approval is required; a different owner or administrator must approve this client identity")
    row = await pool().fetchrow(
        """
        UPDATE evaluator_client_identities
        SET status = 'approved', approved_by = $2, approved_at = now()
        WHERE id = $1 AND organization_id = $3 AND status = 'draft'
        RETURNING id, project_id, name, identity_type, key_fingerprint, status, approved_at
        """,
        identity_id, workspace["user_id"], workspace["id"],
    )
    if row is None:
        raise HTTPException(status_code=409, detail="Client identity approval was changed concurrently; refresh and retry")
    identity = dict(row)
    await record_evaluator_audit_event(
        workspace, "evaluator_client_identity_approved", target_type="evaluator_client_identity", target_id=identity["id"],
        payload={"identity_type": identity["identity_type"], "key_fingerprint": identity["key_fingerprint"]},
    )
    return identity


@app.post("/api/v3/evaluator/client-identities/{identity_id}/disable")
async def disable_evaluator_client_identity(
    identity_id: UUID,
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    require_evaluator_role(workspace, "owner", "admin")
    row = await pool().fetchrow(
        """
        UPDATE evaluator_client_identities
        SET status = 'disabled', disabled_by = $2, disabled_at = now()
        WHERE id = $1 AND organization_id = $3 AND status IN ('draft', 'approved')
        RETURNING id, project_id, name, identity_type, key_fingerprint, status, disabled_at
        """,
        identity_id, workspace["user_id"], workspace["id"],
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Active client identity was not found in this workspace")
    identity = dict(row)
    await record_evaluator_audit_event(
        workspace, "evaluator_client_identity_disabled", target_type="evaluator_client_identity", target_id=identity["id"],
        payload={"identity_type": identity["identity_type"], "key_fingerprint": identity["key_fingerprint"]},
    )
    return identity


@app.post("/api/v3/evaluator/github-integrations", status_code=status.HTTP_201_CREATED)
async def register_evaluator_github_integration(
    payload: EvaluatorGitHubIntegrationCreate,
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    """Trust one pinned GitHub Actions workflow without storing a GitHub secret."""
    require_evaluator_role(workspace, "owner", "admin")
    project = await evaluator_project(workspace, payload.project_key)
    audience = settings().ai_evaluator_github_oidc_audience
    try:
        row = await pool().fetchrow(
            """
            INSERT INTO evaluator_github_integrations (
              organization_id, project_id, name, repository, workflow_ref, oidc_audience, created_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, project_id, name, repository, workflow_ref, oidc_audience, status, created_at
            """,
            workspace["id"], project["id"], payload.name, payload.repository,
            payload.workflow_ref, audience, workspace["user_id"],
        )
    except Exception as exc:
        if getattr(exc, "sqlstate", None) == "23505":
            raise HTTPException(status_code=409, detail="GitHub integration name or workflow is already registered for this project") from exc
        raise
    integration = dict(row)
    integration["project_key"] = project["key"]
    await record_evaluator_audit_event(
        workspace, "evaluator_github_integration_registered", target_type="evaluator_github_integration", target_id=integration["id"],
        payload={"project_key": project["key"], "repository": integration["repository"], "workflow_ref": integration["workflow_ref"]},
    )
    return integration


@app.post("/api/v3/evaluator/github-integrations/{integration_id}/approve")
async def approve_evaluator_github_integration(
    integration_id: UUID,
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    require_evaluator_role(workspace, "owner", "admin")
    draft = await pool().fetchrow(
        """
        SELECT id, created_by FROM evaluator_github_integrations
        WHERE id = $1 AND organization_id = $2 AND status = 'draft'
        """,
        integration_id, workspace["id"],
    )
    if draft is None:
        raise HTTPException(status_code=404, detail="Draft GitHub integration was not found in this workspace")
    if settings().ai_evaluator_require_independent_approval and draft["created_by"] == workspace["user_id"]:
        raise HTTPException(status_code=422, detail="Independent approval is required; a different owner or administrator must approve this GitHub integration")
    row = await pool().fetchrow(
        """
        UPDATE evaluator_github_integrations
        SET status = 'approved', approved_by = $2, approved_at = now()
        WHERE id = $1 AND organization_id = $3 AND status = 'draft'
        RETURNING id, project_id, name, repository, workflow_ref, oidc_audience, status, approved_at
        """,
        integration_id, workspace["user_id"], workspace["id"],
    )
    if row is None:
        raise HTTPException(status_code=409, detail="GitHub integration approval was changed concurrently; refresh and retry")
    integration = dict(row)
    await record_evaluator_audit_event(
        workspace, "evaluator_github_integration_approved", target_type="evaluator_github_integration", target_id=integration["id"],
        payload={"repository": integration["repository"], "workflow_ref": integration["workflow_ref"]},
    )
    return integration


@app.post("/api/v3/evaluator/github-integrations/{integration_id}/disable")
async def disable_evaluator_github_integration(
    integration_id: UUID,
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    require_evaluator_role(workspace, "owner", "admin")
    row = await pool().fetchrow(
        """
        UPDATE evaluator_github_integrations
        SET status = 'disabled', disabled_by = $2, disabled_at = now()
        WHERE id = $1 AND organization_id = $3 AND status IN ('draft', 'approved')
        RETURNING id, project_id, name, repository, workflow_ref, oidc_audience, status, disabled_at
        """,
        integration_id, workspace["user_id"], workspace["id"],
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Active GitHub integration was not found in this workspace")
    integration = dict(row)
    await record_evaluator_audit_event(
        workspace, "evaluator_github_integration_disabled", target_type="evaluator_github_integration", target_id=integration["id"],
        payload={"repository": integration["repository"], "workflow_ref": integration["workflow_ref"]},
    )
    return integration


async def _approved_live_adapter(adapter_id: UUID, workspace: dict, project: dict) -> dict:
    row = await pool().fetchrow(
        """
        SELECT id, name, adapter_type, endpoint_url, endpoint_sha256, credential_ciphertext
        FROM evaluator_live_adapters
        WHERE id = $1 AND organization_id = $2 AND project_id = $3 AND status = 'approved'
        """,
        adapter_id, workspace["id"], project["id"],
    )
    if row is None:
        raise HTTPException(status_code=422, detail="Live adapter is not approved for this evaluator project")
    return dict(row)


@app.post("/api/v3/evaluator/live-runs", status_code=status.HTTP_201_CREATED)
async def run_live_adapter_evaluation(
    payload: LiveAdapterEvaluationRequest,
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    """Invoke one approved endpoint and retain score inputs plus hashes, never raw test prompts."""
    require_evaluator_role(workspace, "owner", "admin", "analyst")
    project = await evaluator_project(workspace, payload.project_key)
    dataset = await approved_evaluator_dataset(project["id"], payload.dataset_version)
    if dataset["classification"] == "restricted":
        raise HTTPException(status_code=422, detail="Restricted data cannot be sent to a live adapter")
    if dataset["classification"] == "internal" and not settings().ai_evaluator_allow_internal_data:
        raise HTTPException(status_code=422, detail="Internal data requires explicit live-adapter data approval in deployment configuration")
    adapter = await _approved_live_adapter(payload.adapter_id, workspace, project)
    try:
        api_token = decrypt_secret(bytes(adapter["credential_ciphertext"]))
    except RuntimeError as exc:
        await record_evaluator_audit_event(
            workspace, "evaluator_live_adapter_failed", target_type="evaluator_live_adapter", target_id=adapter["id"],
            payload={"code": "adapter_credential_unavailable", "retryable": False},
        )
        raise HTTPException(status_code=503, detail="Live adapter credential is unavailable; register a replacement adapter") from exc
    try:
        invocation = await asyncio.to_thread(
            invoke_live_adapter,
            adapter["endpoint_url"],
            api_token,
            payload.cases,
        )
    except AdapterInvocationError as exc:
        await record_evaluator_audit_event(
            workspace, "evaluator_live_adapter_failed", target_type="evaluator_live_adapter", target_id=adapter["id"],
            payload={"code": exc.code, "retryable": exc.retryable},
        )
        raise HTTPException(status_code=502, detail=f"Live adapter invocation failed: {exc.code}") from exc
    effective_payload = adapter_evaluation_payload(
        payload, invocation, adapter_name=adapter["name"], adapter_url_sha256=adapter["endpoint_sha256"]
    )
    evaluated_agent = registered_agent(effective_payload.agent_id)
    evaluator = registered_agent("ai_quality_evaluator")
    if evaluator is None:
        raise HTTPException(status_code=503, detail="Quality evaluator is unavailable")
    if evaluated_agent is not None and effective_payload.subject_version != evaluated_agent.version:
        raise HTTPException(status_code=422, detail="Registered agent version does not match subject_version")
    metrics = evaluate(effective_payload)
    row = await pool().fetchrow(
        """
        INSERT INTO agent_evaluations (
          name, evaluated_agent_id, evaluated_agent_version,
          evaluator_agent_id, evaluator_version, dataset_version,
          input_manifest, metrics, release_decision, created_by,
          organization_id, project_id, dataset_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10, $11, $12, $13)
        RETURNING *
        """,
        effective_payload.name,
        evaluated_agent.id if evaluated_agent is not None else effective_payload.agent_id,
        effective_payload.subject_version,
        evaluator.id,
        evaluator.version,
        effective_payload.dataset_version,
        effective_payload.model_dump_json(),
        json.dumps(metrics),
        metrics["release_decision"],
        workspace["user_id"], workspace["id"], project["id"], dataset["id"],
    )
    evaluation = dict(row)
    await record_evaluator_audit_event(
        workspace, "evaluator_live_adapter_completed", target_type="agent_evaluation", target_id=evaluation["id"],
        payload={
            "adapter_id": str(adapter["id"]), "adapter_type": adapter["adapter_type"],
            "case_count": len(payload.cases), "request_sha256": invocation.request_sha256,
            "response_sha256": invocation.response_sha256, "release_decision": evaluation["release_decision"],
        },
    )
    return evaluation


@app.get("/api/v3/evaluator/audit-events")
async def list_evaluator_audit_events(
    workspace: dict = Depends(evaluator_workspace),
) -> list[dict]:
    require_evaluator_role(workspace, "owner", "admin")
    rows = await pool().fetch(
        """
        SELECT event_type, target_type, target_id, payload, occurred_at,
               u.display_name AS actor_name, u.email AS actor_email
        FROM evaluator_audit_events ae
        JOIN users u ON u.id = ae.actor_id
        WHERE ae.organization_id = $1
        ORDER BY ae.occurred_at DESC
        LIMIT 100
        """,
        workspace["id"],
    )
    return [dict(row) for row in rows]


@app.get("/api/v3/evaluator/semantic-runs")
async def list_semantic_evaluation_runs(
    workspace: dict = Depends(evaluator_workspace),
) -> list[dict]:
    rows = await pool().fetch(
        """
        SELECT id, name, subject_id, subject_version, dataset_version,
               data_classification, provider, requested_model, prompt_version,
               status, result, error_code, error_detail, created_at, completed_at
        FROM semantic_evaluation_runs
        WHERE organization_id = $1
        ORDER BY created_at DESC
        LIMIT 100
        """,
        workspace["id"],
    )
    return [dict(row) for row in rows]


@app.post("/api/v3/evaluator/semantic-runs", status_code=status.HTTP_201_CREATED)
async def create_semantic_evaluation_run(
    payload: SemanticEvaluationRequest,
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    require_evaluator_role(workspace, "owner", "admin", "analyst")
    judge, descriptor = configured_semantic_judge()
    if judge is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=descriptor["detail"] or "Semantic judge is unavailable",
        )
    configuration = settings()
    project = await evaluator_project(workspace, payload.project_key)
    dataset = await approved_evaluator_dataset(project["id"], payload.dataset_version)
    if payload.data_classification != dataset["classification"]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Semantic request classification must match the approved dataset",
        )
    if payload.data_classification == "restricted":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Restricted evidence cannot be sent to an external semantic judge",
        )
    if (
        payload.data_classification == "internal"
        and not configuration.ai_evaluator_allow_internal_data
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Internal evidence egress is disabled by evaluator policy",
        )

    run = await pool().fetchrow(
        """
        INSERT INTO semantic_evaluation_runs (
          name, subject_id, subject_version, dataset_version,
          data_classification, provider, requested_model, prompt_version,
          input_manifest, created_by, organization_id, project_id, dataset_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13)
        RETURNING *
        """,
        payload.name,
        payload.subject_id,
        payload.subject_version,
        payload.dataset_version,
        payload.data_classification,
        judge.provider_name,
        judge.model_name,
        SEMANTIC_PROMPT_VERSION,
        semantic_input_manifest(payload),
        workspace["user_id"],
        workspace["id"],
        project["id"],
        dataset["id"],
    )
    try:
        result = await run_semantic_evaluation(payload, judge)
    except SemanticJudgeError as exc:
        failed = await pool().fetchrow(
            """
            UPDATE semantic_evaluation_runs
            SET status = 'failed', error_code = $2, error_detail = $3,
                completed_at = now()
            WHERE id = $1
            RETURNING *
            """,
            run["id"],
            exc.code,
            str(exc),
        )
        await record_evaluator_audit_event(
            workspace,
            "semantic_evaluation_failed",
            target_type="semantic_evaluation_run",
            target_id=failed["id"],
            payload={"code": exc.code, "retryable": exc.retryable},
        )
        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
                if exc.retryable
                else status.HTTP_502_BAD_GATEWAY
            ),
            detail={
                "run_id": str(failed["id"]),
                "code": exc.code,
                "message": str(exc),
                "retryable": exc.retryable,
            },
        ) from exc

    completed = await pool().fetchrow(
        """
        UPDATE semantic_evaluation_runs
        SET status = 'completed', result = $2::jsonb, completed_at = now()
        WHERE id = $1
        RETURNING *
        """,
        run["id"],
        result,
    )
    result = dict(completed)
    await record_evaluator_audit_event(
        workspace,
        "semantic_evaluation_completed",
        target_type="semantic_evaluation_run",
        target_id=result["id"],
        payload={"project_key": project["key"], "dataset_version": dataset["version"]},
    )
    return result


@app.get("/api/v3/evaluations")
async def list_evaluations(workspace: dict = Depends(evaluator_workspace)) -> list[dict]:
    rows = await pool().fetch(
        """
        SELECT id, name, evaluated_agent_id, evaluated_agent_version,
               evaluator_agent_id, evaluator_version, dataset_version,
               metrics, release_decision, created_at
        FROM agent_evaluations
        WHERE organization_id = $1
        ORDER BY created_at DESC
        LIMIT 100
        """,
        workspace["id"],
    )
    evaluations = [dict(row) for row in rows]
    if not evaluations:
        return []
    report_rows = await pool().fetch(
        """
        SELECT id, evaluation_id, report_format, renderer_version, source_sha256,
               content_sha256, storage_key, size_bytes, generated_at
        FROM evaluation_reports
        WHERE evaluation_id = ANY($1::uuid[]) AND renderer_version = $2
        ORDER BY generated_at DESC
        """,
        [item["id"] for item in evaluations], EVALUATOR_REPORT_VERSION,
    )
    reports_by_evaluation: dict[str, dict[str, dict]] = {}
    for row in report_rows:
        report = dict(row)
        reports_by_evaluation.setdefault(str(report["evaluation_id"]), {})[
            report["report_format"]
        ] = report
    for evaluation in evaluations:
        evaluation["reports"] = reports_by_evaluation.get(str(evaluation["id"]), {})
    return evaluations


@app.get("/api/v3/evaluations/{evaluation_id}")
async def evaluation_detail(
    evaluation_id: UUID,
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    """Return a display-safe evaluator scorecard with a deterministic replay check."""
    evaluation = await _stored_evaluation(evaluation_id, workspace["id"])
    input_manifest = evaluation["input_manifest"]
    metrics = evaluation["metrics"]
    if not isinstance(input_manifest, dict) or not isinstance(metrics, dict):
        raise HTTPException(status_code=409, detail="Stored evaluation record is malformed")
    reports = await list_evaluation_reports(evaluation_id)
    return {
        "id": evaluation["id"],
        "name": evaluation["name"],
        "evaluated_agent_id": evaluation["evaluated_agent_id"],
        "evaluated_agent_version": evaluation["evaluated_agent_version"],
        "evaluator_agent_id": evaluation["evaluator_agent_id"],
        "evaluator_version": evaluation["evaluator_version"],
        "dataset_version": evaluation["dataset_version"],
        "project_key": evaluation["project_key"],
        "dataset": evaluation["dataset"],
        "release_decision": evaluation["release_decision"],
        "created_at": evaluation["created_at"],
        "metrics": metrics,
        "input_summary": evaluation_input_summary(input_manifest),
        "calculation_assurance": verify_stored_evaluation(
            input_manifest, metrics, evaluation["evaluator_version"]
        ),
        "source_sha256": evaluation_source_sha256(evaluation),
        "reports": {
            report["report_format"]: {
                "content_sha256": report["content_sha256"],
                "size_bytes": report["size_bytes"],
                "generated_at": report["generated_at"],
            }
            for report in reports
        },
    }


async def _stored_evaluation(evaluation_id: UUID, organization_id: UUID) -> dict:
    row = await pool().fetchrow(
        """
        SELECT e.id, e.name, e.evaluated_agent_id, e.evaluated_agent_version,
               e.evaluator_agent_id, e.evaluator_version, e.dataset_version,
               e.input_manifest, e.metrics, e.release_decision, e.created_by, e.created_at,
               p.key AS project_key,
               jsonb_build_object(
                 'id', d.id, 'name', d.name, 'version', d.version,
                 'classification', d.classification, 'source_sha256', d.source_sha256,
                 'source_reference', d.source_reference, 'status', d.status,
                 'approved_at', d.approved_at
               ) AS dataset
        FROM agent_evaluations e
        JOIN evaluator_projects p ON p.id = e.project_id
        JOIN evaluator_datasets d ON d.id = e.dataset_id
        WHERE e.id = $1 AND e.organization_id = $2
        """,
        evaluation_id,
        organization_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Evaluation not found")
    return dict(row)


@app.post("/api/v3/evaluations/{evaluation_id}/reports", status_code=status.HTTP_201_CREATED)
async def generate_evaluation_report(
    evaluation_id: UUID,
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    require_evaluator_role(workspace, "owner", "admin", "analyst")
    evaluation = await _stored_evaluation(evaluation_id, workspace["id"])
    try:
        outputs = await generate_evaluation_reports(evaluation, workspace["user_id"])
    except EvaluationReportError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await record_evaluator_audit_event(
        workspace,
        "evaluation_report_generated",
        target_type="agent_evaluation",
        target_id=evaluation_id,
        payload={"renderer_version": EVALUATOR_REPORT_VERSION},
    )
    return {
        "evaluation_id": evaluation_id,
        "renderer_version": EVALUATOR_REPORT_VERSION,
        "outputs": outputs,
    }


@app.get("/api/v3/evaluations/{evaluation_id}/reports")
async def evaluation_report_inventory(
    evaluation_id: UUID,
    workspace: dict = Depends(evaluator_workspace),
) -> list[dict]:
    await _stored_evaluation(evaluation_id, workspace["id"])
    return await list_evaluation_reports(evaluation_id)


@app.get("/api/v3/evaluations/{evaluation_id}/reports/download/{report_format}")
async def download_evaluation_report(
    evaluation_id: UUID,
    report_format: str,
    workspace: dict = Depends(evaluator_workspace),
) -> FileResponse:
    evaluation = await _stored_evaluation(evaluation_id, workspace["id"])
    if report_format not in REPORT_MEDIA_TYPES:
        raise HTTPException(status_code=404, detail="Unsupported evaluator report format")
    report = await get_evaluation_report(evaluation_id, report_format)
    if report is None:
        raise HTTPException(status_code=404, detail="Generate the evaluator report before downloading it")
    path = evaluation_report_path(report["storage_key"])
    if not path.is_file():
        raise HTTPException(status_code=410, detail="Evaluator report file is missing from storage")
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise HTTPException(
            status_code=410,
            detail="Evaluator report file cannot be read from storage",
        ) from exc
    if hashlib.sha256(content).hexdigest() != report["content_sha256"]:
        raise HTTPException(status_code=409, detail="Evaluator report failed integrity verification")
    safe_name = "".join(
        character if character.isalnum() or character in "-_" else "-"
        for character in evaluation["name"]
    ).strip("-") or "ai-evaluation"
    extension = REPORT_EXTENSIONS[report_format]
    await record_evaluator_audit_event(
        workspace,
        "evaluation_report_downloaded",
        target_type="agent_evaluation",
        target_id=evaluation_id,
        payload={"format": report_format, "content_sha256": report["content_sha256"]},
    )
    # Evaluator reports are bounded scorecards. Returning the already
    # integrity-verified bytes avoids fragile cross-platform file streaming.
    return Response(
        content=content,
        media_type=REPORT_MEDIA_TYPES[report_format],
        headers={
            "Content-Disposition": (
                f'attachment; filename="{safe_name}-{evaluation_id}.{extension}"'
            ),
        },
    )


async def _resolve_client_run_identity(
    package: ClientRunnerPackage,
    authorization: str | None,
) -> tuple[dict, str, str, str, dict]:
    """Resolve a non-session client identity and return its active project boundary."""
    if package.signature is not None:
        if authorization:
            raise ClientRunError("ambiguous_authentication", "Submit either an Ed25519 signature or a GitHub OIDC token, not both", status_code=400)
        identity_id = package.signature.identity_id
        row = await pool().fetchrow(
            """
            SELECT i.id, i.name, i.public_key, i.key_fingerprint, i.project_id,
                   i.organization_id, i.created_by, p.key AS project_key
            FROM evaluator_client_identities i
            JOIN evaluator_projects p ON p.id = i.project_id
            WHERE i.id = $1 AND i.status = 'approved' AND p.status = 'active'
            """,
            identity_id,
        )
        if row is None:
            raise ClientRunError("client_identity_unavailable", "Client signing identity is not approved", status_code=403)
        identity = dict(row)
        if package.evaluation.project_key != identity["project_key"]:
            raise ClientRunError("client_project_mismatch", "Client signing identity is not approved for this evaluator project", status_code=403)
        if package.source.origin not in {"local", "other_ci"}:
            raise ClientRunError("client_source_mismatch", "Ed25519 client-runner packages must declare local or other_ci source provenance", status_code=422)
        verify_ed25519_package(package, identity["public_key"])
        return (
            identity,
            "ed25519",
            identity["name"],
            identity["key_fingerprint"],
            package.source.model_dump(mode="json"),
        )

    if not authorization or not authorization.startswith("Bearer "):
        raise ClientRunError("client_authentication_required", "A signed client package or GitHub Actions OIDC bearer token is required", status_code=401)
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise ClientRunError("client_authentication_required", "GitHub Actions OIDC bearer token is required", status_code=401)
    claims = await asyncio.to_thread(verify_github_actions_oidc, token)
    if package.source.origin != "github_actions":
        raise ClientRunError("github_source_required", "GitHub OIDC submissions must declare github_actions source provenance")
    repository = str(claims.get("repository") or "")
    workflow_ref = str(claims.get("workflow_ref") or "")
    row = await pool().fetchrow(
        """
        SELECT g.id, g.name, g.repository, g.workflow_ref, g.oidc_audience,
               g.project_id, g.organization_id, g.created_by, p.key AS project_key
        FROM evaluator_github_integrations g
        JOIN evaluator_projects p ON p.id = g.project_id
        WHERE p.key = $1 AND lower(g.repository) = lower($2) AND g.workflow_ref = $3
          AND g.status = 'approved' AND p.status = 'active'
        """,
        package.evaluation.project_key, repository, workflow_ref,
    )
    if row is None:
        raise ClientRunError("github_integration_unavailable", "No approved GitHub workflow is registered for this evaluator project", status_code=403)
    integration = dict(row)
    if integration["oidc_audience"] != settings().ai_evaluator_github_oidc_audience:
        raise ClientRunError("github_oidc_audience", "GitHub integration audience does not match the active deployment", status_code=403)
    github_integration_claims_match(claims, integration)
    claim_sha = str(claims.get("sha") or "")
    claim_run = str(claims.get("run_id") or "")
    if package.source.repository != repository or package.source.workflow_ref != workflow_ref:
        raise ClientRunError("github_source_mismatch", "Package GitHub repository or workflow does not match its OIDC identity", status_code=403)
    if package.source.commit_sha != claim_sha or package.source.external_run_id != claim_run:
        raise ClientRunError("github_source_mismatch", "Package commit or run identifier does not match its OIDC identity", status_code=403)
    source = {
        **package.source.model_dump(mode="json"),
        "github": {
            "repository": repository,
            "workflow_ref": workflow_ref,
            "sha": claim_sha,
            "run_id": claim_run,
            "event_name": str(claims.get("event_name") or ""),
            "ref": str(claims.get("ref") or ""),
        },
    }
    return (
        integration,
        "github_actions_oidc",
        integration["name"],
        github_identity_fingerprint(claims, integration),
        source,
    )


@app.post("/api/v3/evaluator/client-runs", status_code=status.HTTP_201_CREATED)
async def ingest_client_runner_evaluation(
    package: ClientRunnerPackage,
    authorization: str | None = Header(default=None),
) -> dict:
    """Ingest one replay-protected client evaluation without accepting raw test inputs."""
    try:
        identity, identity_type, identity_name, identity_fingerprint, source = await _resolve_client_run_identity(package, authorization)
        dataset = await approved_evaluator_dataset(identity["project_id"], package.evaluation.dataset_version)
        try:
            effective_payload = package_evaluation_request(
                package,
                identity_type=identity_type,
                identity_id=identity["id"],
                identity_name=identity_name,
                identity_fingerprint=identity_fingerprint,
            )
        except ValidationError as exc:
            raise ClientRunError("client_package_contract", "Client package cannot be converted into a valid evaluator contract") from exc
        evaluated_agent = registered_agent(effective_payload.agent_id)
        evaluator = registered_agent("ai_quality_evaluator")
        if evaluator is None:
            raise HTTPException(status_code=503, detail="Quality evaluator is unavailable")
        if evaluated_agent is not None and effective_payload.subject_version != evaluated_agent.version:
            raise ClientRunError("client_subject_version", "Registered agent version does not match subject_version")
        metrics = evaluate(effective_payload)
        package_digest = package.package_sha256()
        async with pool().acquire() as conn, conn.transaction():
            # A retry of the same client-issued UUID must never create two release decisions.
            await conn.execute("SELECT pg_advisory_xact_lock(hashtext($1))", str(package.package_id))
            already_received = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM evaluator_client_submissions WHERE package_id = $1)",
                package.package_id,
            )
            if already_received:
                raise ClientRunError("client_package_replayed", "This client-runner package was already received", status_code=409)
            row = await conn.fetchrow(
                """
                INSERT INTO agent_evaluations (
                  name, evaluated_agent_id, evaluated_agent_version,
                  evaluator_agent_id, evaluator_version, dataset_version,
                  input_manifest, metrics, release_decision, created_by,
                  organization_id, project_id, dataset_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10, $11, $12, $13)
                RETURNING *
                """,
                effective_payload.name,
                evaluated_agent.id if evaluated_agent is not None else effective_payload.agent_id,
                effective_payload.subject_version,
                evaluator.id,
                evaluator.version,
                effective_payload.dataset_version,
                effective_payload.model_dump(mode="json"),
                metrics,
                metrics["release_decision"],
                identity["created_by"], identity["organization_id"], identity["project_id"], dataset["id"],
            )
            evaluation = dict(row)
            await conn.execute(
                """
                INSERT INTO evaluator_client_submissions (
                  organization_id, project_id, evaluation_id, package_id, package_sha256,
                  auth_type, client_identity_id, github_integration_id, source_attestation
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
                """,
                identity["organization_id"], identity["project_id"], evaluation["id"], package.package_id,
                package_digest, identity_type,
                identity["id"] if identity_type == "ed25519" else None,
                identity["id"] if identity_type == "github_actions_oidc" else None,
                source,
            )
    except ClientRunError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": str(exc)}) from exc
    workspace = {"id": identity["organization_id"], "user_id": identity["created_by"]}
    await record_evaluator_audit_event(
        workspace,
        "evaluator_client_runner_ingested",
        target_type="agent_evaluation",
        target_id=evaluation["id"],
        payload={
            "project_key": package.evaluation.project_key,
            "dataset_version": package.evaluation.dataset_version,
            "identity_type": identity_type,
            "identity_fingerprint": identity_fingerprint,
            "package_sha256": package_digest,
            "release_decision": evaluation["release_decision"],
        },
    )
    return evaluation


@app.post("/api/v3/evaluations", status_code=status.HTTP_201_CREATED)
async def create_evaluation(
    payload: EvaluationRequest,
    workspace: dict = Depends(evaluator_workspace),
) -> dict:
    require_evaluator_role(workspace, "owner", "admin", "analyst")
    if payload.integration_mode == "live_adapter":
        raise HTTPException(
            status_code=422,
            detail="Live adapter provenance is server-owned; use the managed live-runs endpoint",
        )
    if payload.integration_mode == "client_runner":
        raise HTTPException(
            status_code=422,
            detail="Client-runner provenance is verified server-side; use the client-runs ingestion endpoint",
        )
    project = await evaluator_project(workspace, payload.project_key)
    dataset = await approved_evaluator_dataset(project["id"], payload.dataset_version)
    effective_payload = payload
    semantic_review_required = False
    semantic_result: dict | None = None
    if payload.semantic_run_id is not None:
        semantic_run = await pool().fetchrow(
            """
            SELECT id, subject_id, subject_version, dataset_version, status, result
            FROM semantic_evaluation_runs
            WHERE id = $1 AND organization_id = $2 AND project_id = $3 AND dataset_id = $4
            """,
            payload.semantic_run_id,
            workspace["id"],
            project["id"],
            dataset["id"],
        )
        if semantic_run is None:
            raise HTTPException(status_code=422, detail="Semantic evaluation run was not found")
        if semantic_run["status"] != "completed" or not semantic_run["result"]:
            raise HTTPException(status_code=409, detail="Semantic evaluation run is not complete")
        if semantic_run["subject_id"] != payload.agent_id:
            raise HTTPException(status_code=422, detail="Semantic run subject does not match")
        if semantic_run["dataset_version"] != payload.dataset_version:
            raise HTTPException(status_code=422, detail="Semantic run dataset does not match")
        if payload.subject_version != semantic_run["subject_version"]:
            raise HTTPException(status_code=422, detail="Semantic run version does not match")
        semantic_result = semantic_run["result"]
        semantic_review_required = bool(semantic_result.get("human_review_required"))
        effective_payload = EvaluationRequest.model_validate(
            {
                **payload.model_dump(mode="json"),
                "subject_version": semantic_run["subject_version"],
                "semantic_run_id": None,
                "claims": semantic_result.get("claim_grades") or [],
                "trajectory": semantic_result.get("trajectory_grade"),
            }
        )

    evaluated_agent = registered_agent(effective_payload.agent_id)
    evaluator = registered_agent("ai_quality_evaluator")
    if evaluator is None:
        raise HTTPException(status_code=503, detail="Quality evaluator is unavailable")
    if (
        evaluated_agent is not None
        and effective_payload.subject_version != evaluated_agent.version
    ):
        raise HTTPException(
            status_code=422,
            detail="Registered agent version does not match subject_version",
        )
    evaluated_version = effective_payload.subject_version
    metrics = evaluate(effective_payload)
    input_manifest = effective_payload.model_dump(mode="json")
    if payload.semantic_run_id is not None:
        semantic_provenance = (semantic_result or {}).get("provenance") or {}
        metrics["semantic_run_id"] = str(payload.semantic_run_id)
        metrics["semantic_assurance"] = {
            "human_review_required": semantic_review_required,
            "release_hold": semantic_review_required,
        }
        if semantic_review_required and metrics["release_decision"] == "pass":
            metrics["release_decision"] = "inconclusive"
            metrics["release_hold_reasons"] = ["semantic_human_review_required"]
        metrics["evaluator"]["ai_model_connected"] = True
        metrics["evaluator"]["semantic_judge"] = {
            "status": "used",
            "provider": semantic_provenance.get("provider"),
            "requested_model": semantic_provenance.get("requested_model"),
            "resolved_model": semantic_provenance.get("resolved_model"),
            "prompt_version": semantic_provenance.get("prompt_version"),
        }
        metrics["limitations"] = [
            limitation
            for limitation in metrics["limitations"]
            if "does not invoke the optional semantic judge" not in limitation
        ]
        metrics["limitations"].append(
            "Grounding and trajectory grades were imported from the referenced semantic run."
        )
        input_manifest["semantic_run_id"] = str(payload.semantic_run_id)
    row = await pool().fetchrow(
        """
        INSERT INTO agent_evaluations (
          name, evaluated_agent_id, evaluated_agent_version,
          evaluator_agent_id, evaluator_version, dataset_version,
          input_manifest, metrics, release_decision, created_by,
          organization_id, project_id, dataset_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10, $11, $12, $13)
        RETURNING *
        """,
        effective_payload.name,
        evaluated_agent.id if evaluated_agent is not None else effective_payload.agent_id,
        evaluated_version,
        evaluator.id,
        evaluator.version,
        effective_payload.dataset_version,
        input_manifest,
        metrics,
        metrics["release_decision"],
        workspace["user_id"],
        workspace["id"],
        project["id"],
        dataset["id"],
    )
    evaluation = dict(row)
    await record_evaluator_audit_event(
        workspace,
        "agent_evaluation_completed",
        target_type="agent_evaluation",
        target_id=evaluation["id"],
        payload={
            "project_key": project["key"],
            "dataset_version": dataset["version"],
            "release_decision": evaluation["release_decision"],
            "subject_type": effective_payload.subject_type,
            "integration_mode": effective_payload.integration_mode,
        },
    )
    return evaluation


@app.get("/api/v3/benchmarks/dvwa/scans/{scan_id}")
async def evaluate_dvwa_scan(
    scan_id: UUID,
    variant: str = "low",
    _: dict = Depends(current_user),
) -> dict:
    scan = await pool().fetchrow(
        """
        SELECT s.id, s.plan_version, a.mode::text AS mode, a.target
        FROM scans s JOIN assessments a ON a.id = s.assessment_id
        WHERE s.id = $1
        """,
        scan_id,
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    manifest_path = Path(settings().benchmark_root) / "dvwa" / "manifest.json"
    if not manifest_path.is_file():
        raise HTTPException(status_code=503, detail="DVWA benchmark manifest is unavailable")
    try:
        manifest, truth = load_benchmark_manifest(manifest_path, variant=variant, profile=scan["mode"])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    target_host = urlsplit(scan["target"]).hostname
    if target_host not in manifest["fixture"].get("target_hosts", []):
        raise HTTPException(status_code=422, detail="Scan target is not attributed to this benchmark fixture")

    rows = await pool().fetch(
        """
        SELECT f.id, f.severity, f.evidence, fa.canonical_observation_key,
               fa.validation_status, fa.evidence_integrity, fa.oracle_status
        FROM findings f
        LEFT JOIN finding_assurance fa ON fa.finding_id = f.id
        WHERE f.scan_id = $1
        ORDER BY f.created_at
        """,
        scan_id,
    )

    def observations(*, confirmed_only: bool) -> list[BenchmarkObservation]:
        result = []
        for row in rows:
            if row["severity"] == "info":
                continue
            if confirmed_only and not (
                row["validation_status"] == "confirmed"
                and row["evidence_integrity"] == "passed"
                and row["oracle_status"] == "passed"
            ):
                continue
            evidence = row["evidence"] or {}
            key = row["canonical_observation_key"] or canonical_observation_key(evidence)
            result.append(BenchmarkObservation(
                observation_id=str(row["id"]),
                case_id=map_observation_key(
                    manifest, key=key, variant=variant, profile=scan["mode"]
                ),
                evidence_kinds=observation_evidence_kinds(evidence),
            ))
        return result

    reported = score_vulnerability_benchmark(
        dataset_version=manifest["dataset_version"], profile=scan["mode"],
        truth_cases=truth, observations=observations(confirmed_only=False),
    )
    confirmed = score_vulnerability_benchmark(
        dataset_version=manifest["dataset_version"], profile=scan["mode"],
        truth_cases=truth, observations=observations(confirmed_only=True),
    )
    return {
        "scan_id": scan_id,
        "plan_version": scan["plan_version"],
        "fixture": manifest["fixture"],
        "variant": variant,
        "release_eligibility": benchmark_release_eligibility(manifest),
        "reported_findings_score": reported,
        "confirmed_findings_score": confirmed,
    }


@app.post("/api/v3/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response,
    esx_session: str | None = Cookie(default=None),
) -> Response:
    if esx_session:
        import hashlib

        await pool().execute(
            "DELETE FROM sessions WHERE token_hash = $1",
            hashlib.sha256(esx_session.encode()).hexdigest(),
        )
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.get("/api/v3/assessments", response_model=list[Assessment])
async def list_assessments(workspace: dict = Depends(exposure_workspace)) -> list[dict]:
    rows = await pool().fetch(
        "SELECT * FROM assessments WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 100",
        workspace["id"],
    )
    return [dict(row) for row in rows]


async def _asset_inventory_rows(organization_id: UUID, assessment_id: UUID | None = None) -> list[dict]:
    rows = await pool().fetch(
        """
        SELECT aa.*, a.name AS assessment_name, a.mode::text AS assessment_mode,
               latest.id AS latest_scan_id, latest.status::text AS latest_scan_status,
               latest.finished_at AS latest_scan_finished_at
        FROM assessment_assets aa
        JOIN assessments a ON a.id = aa.assessment_id
        LEFT JOIN LATERAL (
          SELECT s.id, s.status, s.finished_at
          FROM assessment_asset_scans aas
          JOIN scans s ON s.id = aas.scan_id
          WHERE aas.assessment_asset_id = aa.id
          ORDER BY s.created_at DESC
          LIMIT 1
        ) latest ON true
        WHERE a.organization_id = $1
          AND ($2::uuid IS NULL OR aa.assessment_id = $2)
        ORDER BY aa.last_seen_at DESC, aa.hostname
        LIMIT 1000
        """,
        organization_id, assessment_id,
    )
    result = []
    for row in rows:
        asset = dict(row)
        asset["client_status"] = display_asset_status(
            str(asset["ownership_status"]), str(asset["assessment_status"])
        )
        result.append(asset)
    return result


@app.get("/api/v3/assets")
async def list_assessment_assets(workspace: dict = Depends(exposure_workspace)) -> dict:
    """Return the reviewable asset inventory across all client assessments."""
    return {"assets": await _asset_inventory_rows(workspace["id"])}


@app.get("/api/v3/assessment-scans/dashboard")
async def assessment_scans_dashboard(workspace: dict = Depends(exposure_workspace)) -> dict:
    """Summarize inventory, evidence, coverage, and review work without inventing a risk score."""
    assets = await _asset_inventory_rows(workspace["id"])
    ownership = {state: 0 for state in ("client_declared", "candidate", "approved", "excluded")}
    assessment_status = {state: 0 for state in ("not_assessed", "approved_for_assessment", "queued", "assessed", "blocked")}
    for asset in assets:
        ownership[str(asset["ownership_status"])] += 1
        assessment_status[str(asset["assessment_status"])] += 1
    coverage_rows = await pool().fetch(
        """
        SELECT c.status, count(*)::integer AS count
        FROM scan_coverage c
        JOIN scans s ON s.id = c.scan_id
        JOIN assessments a ON a.id = s.assessment_id
        WHERE a.organization_id = $1
        GROUP BY c.status
        """, workspace["id"]
    )
    coverage = {str(row["status"]): int(row["count"]) for row in coverage_rows}
    finding_rows = await pool().fetch(
        """
        SELECT COALESCE(fa.validation_status, 'candidate') AS validation_status,
               f.severity, count(*)::integer AS count
        FROM findings f
        JOIN scans s ON s.id = f.scan_id
        JOIN assessments a ON a.id = s.assessment_id
        LEFT JOIN finding_assurance fa ON fa.finding_id = f.id
        WHERE f.severity <> 'info' AND a.organization_id = $1
        GROUP BY COALESCE(fa.validation_status, 'candidate'), f.severity
        """, workspace["id"]
    )
    findings = [dict(row) for row in finding_rows]
    attention = [
        asset for asset in assets
        if asset["ownership_status"] == "candidate" or asset["assessment_status"] == "blocked"
    ][:12]
    return {
        "summary": {
            "asset_count": len(assets),
            "ownership": ownership,
            "assessment_status": assessment_status,
            "coverage": coverage,
            "candidate_review_count": ownership["candidate"],
            "coverage_issue_count": sum(
                count for state, count in coverage.items()
                if state in {"failed", "timed_out", "blocked", "cancelled"}
            ),
        },
        "findings": findings,
        "recent_assets": assets[:10],
        "attention": attention,
    }


@app.get("/api/v3/exposure/dashboard")
async def exposure_dashboard(workspace: dict = Depends(exposure_workspace)) -> dict:
    """Return only persisted scope, asset, lifecycle, and coverage facts for the client dashboard."""
    asset_rows = await pool().fetch(
        """
        SELECT ownership_status, lifecycle_status, count(*)::integer AS count
        FROM exposure_assets WHERE organization_id = $1
        GROUP BY ownership_status, lifecycle_status
        """, workspace["id"],
    )
    assets = {"candidate": 0, "client_declared": 0, "verified": 0, "excluded": 0, "retired": 0}
    for row in asset_rows:
        if row["lifecycle_status"] == "retired":
            assets["retired"] += int(row["count"])
        else:
            assets[str(row["ownership_status"])] += int(row["count"])
    finding_rows = await pool().fetch(
        """
        SELECT lifecycle_status, severity, count(*)::integer AS count
        FROM exposure_findings WHERE organization_id = $1
        GROUP BY lifecycle_status, severity
        """, workspace["id"],
    )
    findings = [dict(row) for row in finding_rows]
    recent_events = await pool().fetch(
        """
        SELECT e.id, e.event_type, e.payload, e.occurred_at, a.hostname
        FROM exposure_asset_events e JOIN exposure_assets a ON a.id = e.asset_id
        WHERE e.organization_id = $1
        ORDER BY e.occurred_at DESC LIMIT 12
        """, workspace["id"],
    )
    monitors = await pool().fetch(
        """
        SELECT m.*, a.name AS assessment_name, a.target, ea.hostname
        FROM exposure_monitors m
        JOIN assessments a ON a.id = m.assessment_id
        LEFT JOIN exposure_assets ea ON ea.id = m.asset_id
        WHERE m.organization_id = $1
        ORDER BY m.next_run_at NULLS LAST, m.created_at DESC
        LIMIT 12
        """, workspace["id"],
    )
    return {
        "workspace": {"id": str(workspace["id"]), "name": workspace["name"], "role": workspace["membership_role"]},
        "assets": assets,
        "findings": findings,
        "recent_asset_events": [dict(row) for row in recent_events],
        "monitors": [dict(row) for row in monitors],
        "next_step": (
            "Review candidate ownership" if assets["candidate"] else
            "Create a recurring monitor for a verified target" if assets["verified"] or assets["client_declared"] else
            "Create a scoped assessment to establish your first declared asset"
        ),
    }


@app.get("/api/v3/exposure/assets")
async def list_exposure_assets(workspace: dict = Depends(exposure_workspace)) -> dict:
    rows = await pool().fetch(
        """
        SELECT ea.*, count(DISTINCT relation.id)::integer AS relationship_count,
               count(DISTINCT observation.id)::integer AS observation_count,
               latest.lifecycle_status AS latest_finding_status,
               latest.severity AS latest_finding_severity
        FROM exposure_assets ea
        LEFT JOIN exposure_asset_relations relation
          ON relation.source_asset_id = ea.id OR relation.target_asset_id = ea.id
        LEFT JOIN exposure_asset_observations observation ON observation.asset_id = ea.id
        LEFT JOIN LATERAL (
          SELECT lifecycle_status, severity FROM exposure_findings
          WHERE asset_id = ea.id ORDER BY last_seen_at DESC LIMIT 1
        ) latest ON true
        WHERE ea.organization_id = $1
        GROUP BY ea.id, latest.lifecycle_status, latest.severity
        ORDER BY ea.last_seen_at DESC, ea.hostname
        LIMIT 1000
        """, workspace["id"],
    )
    return {"assets": [dict(row) for row in rows]}


@app.patch("/api/v3/exposure/assets/{asset_id}/ownership")
async def update_exposure_asset_ownership(
    asset_id: UUID,
    payload: ExposureAssetReview,
    workspace: dict = Depends(exposure_workspace),
) -> dict:
    require_exposure_role(workspace, "owner", "admin", "analyst")
    if payload.verification_method != "written_authorization":
        connector_type = "dns_attestation" if payload.verification_method == "dns_attestation" else "cloud_inventory"
        connector = await pool().fetchval(
            """SELECT EXISTS(
                SELECT 1 FROM exposure_integrations
                WHERE organization_id = $1 AND integration_type = $2 AND status IN ('configured', 'active')
            )""", workspace["id"], connector_type,
        )
        if not connector:
            raise HTTPException(
                status_code=422,
                detail="Configure the matching DNS or cloud attestation connector before recording this verification method",
            )
    async with pool().acquire() as conn, conn.transaction():
        asset = await conn.fetchrow(
            """UPDATE exposure_assets
               SET ownership_status = $3, ownership_confidence = CASE WHEN $3 = 'verified' THEN 100 ELSE ownership_confidence END,
                   ownership_evidence = ownership_evidence || $4::jsonb,
                   reviewed_by = $5, reviewed_at = now(), last_verified_at = CASE WHEN $3 = 'verified' THEN now() ELSE last_verified_at END,
                   updated_at = now()
               WHERE id = $1 AND organization_id = $2 RETURNING *""",
            asset_id, workspace["id"], payload.ownership_status,
            {"method": payload.verification_method, "note": payload.note or ""}, workspace["user_id"],
        )
        if asset is None:
            raise HTTPException(status_code=404, detail="Asset not found in this workspace")
        event_type = "asset.ownership_verified" if payload.ownership_status == "verified" else "asset.excluded"
        event_payload = {"hostname": asset["hostname"], "method": payload.verification_method, "note": payload.note or ""}
        await conn.execute(
            """INSERT INTO exposure_asset_events (organization_id, asset_id, event_type, actor_id, payload)
               VALUES ($1, $2, $3, $4, $5::jsonb)""",
            workspace["id"], asset_id, event_type, workspace["user_id"], event_payload,
        )
        await enqueue_integration_deliveries(conn, workspace["id"], "asset.changed", event_payload)
        await conn.execute(
            """INSERT INTO exposure_audit_events (organization_id, actor_id, event_type, target_type, target_id, payload)
               VALUES ($1, $2, $3, 'exposure_asset', $4, $5::jsonb)""",
            workspace["id"], workspace["user_id"], event_type, asset_id, event_payload,
        )
    return dict(asset)


@app.get("/api/v3/exposure/findings")
async def list_exposure_findings(workspace: dict = Depends(exposure_workspace)) -> dict:
    rows = await pool().fetch(
        """
        SELECT ef.*, ea.hostname, ea.canonical_target
        FROM exposure_findings ef LEFT JOIN exposure_assets ea ON ea.id = ef.asset_id
        WHERE ef.organization_id = $1
        ORDER BY CASE ef.lifecycle_status WHEN 'open' THEN 1 WHEN 'needs_revalidation' THEN 2 ELSE 3 END,
                 CASE ef.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
                 ef.last_seen_at DESC
        LIMIT 1000
        """, workspace["id"],
    )
    return {"findings": [dict(row) for row in rows]}


@app.patch("/api/v3/exposure/findings/{finding_id}")
async def update_exposure_finding_lifecycle(
    finding_id: UUID,
    payload: ExposureFindingLifecycleUpdate,
    workspace: dict = Depends(exposure_workspace),
) -> dict:
    require_exposure_role(workspace, "owner", "admin", "analyst")
    async with pool().acquire() as conn, conn.transaction():
        row = await conn.fetchrow(
            """UPDATE exposure_findings
               SET lifecycle_status = $3, lifecycle_note = $4, updated_by = $5, updated_at = now(),
                   resolved_at = CASE WHEN $3 = 'resolved' THEN now() ELSE resolved_at END
               WHERE id = $1 AND organization_id = $2 RETURNING *""",
            finding_id, workspace["id"], payload.lifecycle_status, payload.note, workspace["user_id"],
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Finding not found in this workspace")
        event_payload = {"lifecycle_status": payload.lifecycle_status, "note": payload.note}
        await conn.execute(
            """INSERT INTO exposure_finding_events (organization_id, finding_id, event_type, actor_id, payload)
               VALUES ($1, $2, 'finding.lifecycle_updated', $3, $4::jsonb)""",
            workspace["id"], finding_id, workspace["user_id"], event_payload,
        )
        await conn.execute(
            """INSERT INTO exposure_audit_events (organization_id, actor_id, event_type, target_type, target_id, payload)
               VALUES ($1, $2, 'finding.lifecycle_updated', 'exposure_finding', $3, $4::jsonb)""",
            workspace["id"], workspace["user_id"], finding_id, event_payload,
        )
    return dict(row)


@app.post("/api/v3/exposure/monitors", status_code=status.HTTP_201_CREATED)
async def create_exposure_monitor(
    payload: ExposureMonitorCreate,
    workspace: dict = Depends(exposure_workspace),
) -> dict:
    require_exposure_role(workspace, "owner", "admin", "analyst")
    assessment = await workspace_assessment(workspace, payload.assessment_id)
    if not assessment["authorization_confirmed"]:
        raise HTTPException(status_code=422, detail="Recurring monitoring requires recorded written authorization")
    hostname = str(urlsplit(str(assessment["target"])).hostname or "").lower()
    async with pool().acquire() as conn, conn.transaction():
        asset = await conn.fetchrow(
            """SELECT id FROM exposure_assets WHERE organization_id = $1 AND hostname = $2""",
            workspace["id"], hostname,
        )
        row = await conn.fetchrow(
            """
            INSERT INTO exposure_monitors (organization_id, assessment_id, asset_id, cadence_hours, next_run_at, created_by)
            VALUES ($1, $2, $3, $4, now(), $5)
            ON CONFLICT (assessment_id) DO UPDATE SET cadence_hours = EXCLUDED.cadence_hours,
                status = 'active', next_run_at = now(), last_error = NULL, updated_at = now()
            RETURNING *
            """,
            workspace["id"], payload.assessment_id, asset["id"] if asset else None,
            payload.cadence_hours, workspace["user_id"],
        )
        await conn.execute(
            """INSERT INTO exposure_audit_events (organization_id, actor_id, event_type, target_type, target_id, payload)
               VALUES ($1, $2, 'monitor.enabled', 'assessment', $3, $4::jsonb)""",
            workspace["id"], workspace["user_id"], payload.assessment_id,
            {"cadence_hours": payload.cadence_hours},
        )
    return dict(row)


@app.patch("/api/v3/exposure/monitors/{monitor_id}")
async def update_exposure_monitor(
    monitor_id: UUID,
    payload: ExposureMonitorUpdate,
    workspace: dict = Depends(exposure_workspace),
) -> dict:
    require_exposure_role(workspace, "owner", "admin")
    row = await pool().fetchrow(
        """UPDATE exposure_monitors SET status = $3, updated_at = now()
           WHERE id = $1 AND organization_id = $2 RETURNING *""",
        monitor_id, workspace["id"], payload.status,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Monitor not found in this workspace")
    await record_exposure_audit_event(
        workspace, f"monitor.{payload.status}", target_type="monitor", target_id=monitor_id,
        payload={"assessment_id": str(row["assessment_id"])},
    )
    return dict(row)


@app.get("/api/v3/exposure/quality")
async def exposure_quality(workspace: dict = Depends(exposure_workspace)) -> dict:
    validation = await pool().fetch(
        """
        SELECT COALESCE(fa.validation_status, 'candidate') AS status, count(*)::integer AS count
        FROM findings f JOIN scans s ON s.id = f.scan_id
        JOIN assessments a ON a.id = s.assessment_id
        LEFT JOIN finding_assurance fa ON fa.finding_id = f.id
        WHERE a.organization_id = $1 AND f.severity <> 'info'
        GROUP BY COALESCE(fa.validation_status, 'candidate')
        """, workspace["id"],
    )
    counts = {"candidate": 0, "confirmed": 0, "rejected": 0, "inconclusive": 0}
    for row in validation:
        counts[str(row["status"])] = int(row["count"])
    measured = counts["confirmed"] + counts["rejected"]
    corpora = await pool().fetch(
        """
        SELECT c.*, count(cc.id)::integer AS case_count
        FROM validation_corpora c LEFT JOIN validation_corpus_cases cc ON cc.corpus_id = c.id
        WHERE c.organization_id = $1 GROUP BY c.id ORDER BY c.created_at DESC
        """, workspace["id"],
    )
    return {
        "validation": counts,
        "measured_validation_count": measured,
        "observed_false_positive_rate": (counts["rejected"] / measured) if measured else None,
        "rate_note": "This is a measured rejection rate among manually validated findings, not a claim about unreviewed findings.",
        "corpora": [dict(row) for row in corpora],
    }


@app.post("/api/v3/exposure/validation-corpora", status_code=status.HTTP_201_CREATED)
async def create_validation_corpus(
    payload: ValidationCorpusCreate,
    workspace: dict = Depends(exposure_workspace),
) -> dict:
    require_exposure_role(workspace, "owner", "admin", "analyst")
    async with pool().acquire() as conn, conn.transaction():
        corpus = await conn.fetchrow(
            """
            INSERT INTO validation_corpora (
              organization_id, name, version, classification, source_reference, source_sha256, created_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *
            """,
            workspace["id"], payload.name, payload.version, payload.classification,
            payload.source_reference, payload.source_sha256, workspace["user_id"],
        )
        await conn.executemany(
            """INSERT INTO validation_corpus_cases (corpus_id, case_key, expected_outcome, family, severity, metadata)
               VALUES ($1, $2, $3, $4, $5, $6::jsonb)""",
            [(corpus["id"], case.case_key, case.expected_outcome, case.family, case.severity, case.metadata) for case in payload.cases],
        )
        await conn.execute(
            """INSERT INTO exposure_audit_events (organization_id, actor_id, event_type, target_type, target_id, payload)
               VALUES ($1, $2, 'validation_corpus.registered', 'validation_corpus', $3, $4::jsonb)""",
            workspace["id"], workspace["user_id"], corpus["id"],
            {"name": payload.name, "version": payload.version, "case_count": len(payload.cases)},
        )
    return {**dict(corpus), "case_count": len(payload.cases)}


@app.post("/api/v3/exposure/integrations", status_code=status.HTTP_201_CREATED)
async def create_exposure_integration(
    payload: IntegrationCreate,
    workspace: dict = Depends(exposure_workspace),
) -> dict:
    require_exposure_role(workspace, "owner", "admin")
    if payload.endpoint_url:
        try:
            validate_integration_endpoint_url(payload.endpoint_url)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    if payload.integration_type in {"webhook", "siem"} and not payload.signing_secret:
        raise HTTPException(status_code=422, detail="Outbound integrations require a signing secret")
    async with pool().acquire() as conn, conn.transaction():
        row = await conn.fetchrow(
            """
            INSERT INTO exposure_integrations (
              organization_id, name, integration_type, status, endpoint_ciphertext, secret_ciphertext,
              event_types, configuration, created_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9)
            RETURNING id, name, integration_type, status, event_types, configuration, created_at
            """,
            workspace["id"], payload.name, payload.integration_type,
            "active" if payload.integration_type in {"webhook", "siem"} else "configured",
            encrypt_secret(payload.endpoint_url) if payload.endpoint_url else None,
            encrypt_secret(payload.signing_secret) if payload.signing_secret else None,
            payload.event_types, payload.configuration, workspace["user_id"],
        )
        await conn.execute(
            """INSERT INTO exposure_audit_events (organization_id, actor_id, event_type, target_type, target_id, payload)
               VALUES ($1, $2, 'integration.configured', 'integration', $3, $4::jsonb)""",
            workspace["id"], workspace["user_id"], row["id"],
            {"name": payload.name, "integration_type": payload.integration_type},
        )
    return dict(row)


@app.get("/api/v3/exposure/integrations")
async def list_exposure_integrations(workspace: dict = Depends(exposure_workspace)) -> dict:
    require_exposure_role(workspace, "owner", "admin")
    rows = await pool().fetch(
        """SELECT id, name, integration_type, status, event_types, configuration, created_at, updated_at
           FROM exposure_integrations WHERE organization_id = $1 ORDER BY created_at DESC""", workspace["id"]
    )
    deliveries = await pool().fetch(
        """SELECT status, count(*)::integer AS count FROM exposure_delivery_events
           WHERE organization_id = $1 GROUP BY status""", workspace["id"]
    )
    return {"integrations": [dict(row) for row in rows], "delivery_summary": [dict(row) for row in deliveries]}


@app.get("/api/v3/exposure/audit-events")
async def list_exposure_audit_events(workspace: dict = Depends(exposure_workspace)) -> dict:
    require_exposure_role(workspace, "owner", "admin")
    rows = await pool().fetch(
        """
        SELECT e.*, u.display_name AS actor_name
        FROM exposure_audit_events e LEFT JOIN users u ON u.id = e.actor_id
        WHERE e.organization_id = $1 ORDER BY e.occurred_at DESC LIMIT 250
        """, workspace["id"],
    )
    return {"events": [dict(row) for row in rows]}


@app.get("/api/v3/assessments/{assessment_id}/assets")
async def assessment_assets(assessment_id: UUID, workspace: dict = Depends(exposure_workspace)) -> dict:
    await workspace_assessment(workspace, assessment_id)
    return {"assessment_id": str(assessment_id), "assets": await _asset_inventory_rows(workspace["id"], assessment_id)}


@app.get("/api/v3/assessments/{assessment_id}/assets/export")
async def export_assessment_assets(assessment_id: UUID, workspace: dict = Depends(exposure_workspace)) -> Response:
    """Export the client-reviewable asset inventory without exposing raw evidence contents."""
    assets = await _asset_inventory_rows(workspace["id"], assessment_id)
    if not assets:
        await workspace_assessment(workspace, assessment_id)
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow([
        "Hostname", "Canonical target", "Asset type", "Ownership status",
        "Ownership confidence", "Assessment status", "Discovery sources",
        "First seen", "Last seen", "Latest scan status", "Review note",
    ])
    for asset in assets:
        writer.writerow([
            asset["hostname"], asset["canonical_target"], asset["asset_type"],
            asset["ownership_status"], asset["ownership_confidence"],
            asset["client_status"], "; ".join(asset.get("discovery_sources") or []),
            asset["first_seen_at"], asset["last_seen_at"],
            asset.get("latest_scan_status") or "not run", asset.get("review_note") or "",
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="assessment-assets-{assessment_id}.csv"'},
    )


async def _record_client_declared_asset(conn, assessment: dict) -> None:
    hostname = str(urlsplit(str(assessment["target"])).hostname or "").lower()
    if not hostname:
        raise ValueError("Assessment target does not have a hostname")
    asset = await conn.fetchrow(
        """
        INSERT INTO assessment_assets (
          assessment_id, hostname, canonical_target, asset_type, discovery_sources,
          discovery_evidence, ownership_status, ownership_confidence, assessment_status
        ) VALUES ($1, $2, $3, 'web_application', $4::jsonb, $5::jsonb,
                  'client_declared', 100, 'approved_for_assessment')
        ON CONFLICT (assessment_id, hostname) DO UPDATE
        SET canonical_target = EXCLUDED.canonical_target,
            last_seen_at = now(), updated_at = now()
        RETURNING *
        """,
        assessment["id"], hostname, assessment["target"],
        json.dumps([DISCOVERY_SOURCE_CLIENT_DECLARED]),
        json.dumps({"source": DISCOVERY_SOURCE_CLIENT_DECLARED, "target": assessment["target"]}),
    )
    await sync_assessment_asset(
        conn, assessment["organization_id"], dict(asset), actor_id=assessment.get("created_by")
    )


@app.get("/api/v3/scans")
async def list_scans(workspace: dict = Depends(exposure_workspace)) -> list[dict]:
    rows = await pool().fetch(
        """
        SELECT s.*, a.name AS assessment_name, a.target, a.mode,
               (SELECT count(*) FROM findings f WHERE f.scan_id = s.id AND f.severity <> 'info') AS finding_count,
               (SELECT count(*) FROM findings f WHERE f.scan_id = s.id AND f.severity = 'info') AS observation_count,
               (SELECT count(*) FROM artifacts ar WHERE ar.scan_id = s.id) AS artifact_count,
               COALESCE((
                 SELECT jsonb_agg(jsonb_build_object(
                   'id', sr.id,
                   'position', sr.position,
                   'adapter', sr.adapter,
                   'required', sr.required,
                   'status', sr.status,
                   'attempt', sr.attempt,
                   'timeout_seconds', sr.timeout_seconds,
                   'started_at', sr.started_at,
                   'finished_at', sr.finished_at,
                   'heartbeat_at', sr.heartbeat_at,
                   'live_output', sr.live_output,
                   'last_output_at', sr.last_output_at,
                   'output_sequence', sr.output_sequence,
                   'error_code', sr.error_code,
                   'error_detail', sr.error_detail
                 ) ORDER BY sr.position)
                 FROM stage_runs sr WHERE sr.scan_id = s.id
               ), '[]'::jsonb) AS stages,
               COALESCE((
                 SELECT floor(
                   100.0 * count(*) FILTER (WHERE sr.status IN (
                     'succeeded', 'failed', 'timed_out', 'skipped', 'blocked', 'cancelled'
                   )) / NULLIF(count(*), 0)
                 )::integer
                 FROM stage_runs sr WHERE sr.scan_id = s.id
               ), 0) AS progress_percent,
               (SELECT sr.adapter FROM stage_runs sr
                WHERE sr.scan_id = s.id AND sr.status = 'running'
                ORDER BY sr.position LIMIT 1) AS current_stage
        FROM scans s
        JOIN assessments a ON a.id = s.assessment_id
        WHERE a.organization_id = $1
        ORDER BY s.created_at DESC
        LIMIT 100
        """, workspace["id"]
    )
    return [dict(row) for row in rows]


@app.get("/api/v3/findings")
async def list_findings(workspace: dict = Depends(exposure_workspace)) -> list[dict]:
    rows = await pool().fetch(
        """
        SELECT f.*, a.name AS assessment_name, ar.sha256 AS evidence_sha256,
               ar.storage_key AS evidence_storage_key,
               fa.canonical_observation_key, fa.validation_status,
               fa.evidence_integrity, fa.oracle_status,
               fa.validation_artifact_id, fa.rationale AS assurance_rationale,
               fa.validated_at
        FROM findings f
        JOIN scans s ON s.id = f.scan_id
        JOIN assessments a ON a.id = s.assessment_id
        JOIN artifacts ar ON ar.id = f.source_artifact_id
        LEFT JOIN finding_assurance fa ON fa.finding_id = f.id
        WHERE a.organization_id = $1
        ORDER BY f.created_at DESC
        LIMIT 500
        """, workspace["id"]
    )
    return [dict(row) for row in rows]


@app.get("/api/v3/artifacts")
async def list_artifacts(workspace: dict = Depends(exposure_workspace)) -> list[dict]:
    rows = await pool().fetch(
        """
        SELECT ar.*, a.name AS assessment_name, sr.adapter
        FROM artifacts ar
        JOIN scans s ON s.id = ar.scan_id
        JOIN assessments a ON a.id = s.assessment_id
        LEFT JOIN stage_runs sr ON sr.id = ar.stage_run_id
        WHERE a.organization_id = $1
        ORDER BY ar.created_at DESC
        LIMIT 500
        """, workspace["id"]
    )
    return [dict(row) for row in rows]


@app.get("/api/v3/reports")
async def list_reports(workspace: dict = Depends(exposure_workspace)) -> list[dict]:
    rows = await pool().fetch(
        """
        SELECT r.*, s.assessment_id, a.name AS assessment_name, a.target, s.status AS scan_status
        FROM reports r
        JOIN scans s ON s.id = r.scan_id
        JOIN assessments a ON a.id = s.assessment_id
        WHERE a.organization_id = $1
        ORDER BY r.generated_at DESC
        LIMIT 100
        """, workspace["id"]
    )
    return [dict(row) for row in rows]


@app.get("/api/v3/reports/{scan_id}")
async def report_detail(scan_id: UUID, workspace: dict = Depends(exposure_workspace)) -> dict:
    row = await pool().fetchrow(
        """SELECT r.* FROM reports r JOIN scans s ON s.id = r.scan_id
           JOIN assessments a ON a.id = s.assessment_id
           WHERE r.scan_id = $1 AND a.organization_id = $2""", scan_id, workspace["id"]
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Report not generated")
    return dict(row)


@app.post("/api/v3/reports/{scan_id}/regenerate")
async def regenerate_report(scan_id: UUID, workspace: dict = Depends(exposure_workspace)) -> dict:
    require_exposure_role(workspace, "owner", "admin", "analyst")
    scan = await pool().fetchrow(
        """SELECT s.id, s.assessment_id, s.status::text AS status FROM scans s
           JOIN assessments a ON a.id = s.assessment_id
           WHERE s.id = $1 AND a.organization_id = $2""", scan_id, workspace["id"],
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] not in {"complete", "partial", "failed", "cancelled", "blocked"}:
        raise HTTPException(status_code=409, detail="Only terminal scans can regenerate reports")
    coverage = [dict(row) for row in await pool().fetch(
        "SELECT * FROM scan_coverage WHERE scan_id = $1 ORDER BY created_at, case_id",
        scan_id,
    )]
    report_status = report_status_for_scan(scan["status"])
    manifest = await generate_scan_reports(scan_id, scan["assessment_id"], report_status, coverage)
    row = await pool().fetchrow(
        """
        INSERT INTO reports (scan_id, status, manifest) VALUES ($1, $2, $3)
        ON CONFLICT (scan_id) DO UPDATE
        SET status = EXCLUDED.status, manifest = EXCLUDED.manifest, generated_at = now()
        RETURNING *
        """,
        scan_id, report_status, manifest,
    )
    await pool().execute(
        "INSERT INTO scan_events (scan_id, event_type, payload) VALUES ($1, 'report.regenerated', $2)",
        scan_id, {"schema_version": manifest["schema_version"], "status": report_status},
    )
    return dict(row)


@app.get("/api/v3/reports/{scan_id}/download/{report_format}")
async def download_report(
    scan_id: UUID,
    report_format: str,
    workspace: dict = Depends(exposure_workspace),
) -> FileResponse:
    kinds = {"docx": "report_docx", "pdf": "report_pdf", "evidence": "evidence_bundle"}
    media_types = {
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "pdf": "application/pdf", "evidence": "application/zip",
    }
    if report_format not in kinds:
        raise HTTPException(status_code=404, detail="Unsupported report format")
    row = await pool().fetchrow(
        """SELECT ar.storage_key, ar.sha256, a.name FROM artifacts ar JOIN scans s ON s.id = ar.scan_id
           JOIN assessments a ON a.id = s.assessment_id
           WHERE ar.scan_id = $1 AND ar.kind = $2 AND a.organization_id = $3
           ORDER BY ar.captured_at DESC LIMIT 1""",
        scan_id, kinds[report_format], workspace["id"],
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Requested report artifact is not available")
    path = artifact_path(row["storage_key"])
    if not path.is_file():
        raise HTTPException(status_code=410, detail="Report artifact is missing from storage")
    if hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]:
        raise HTTPException(status_code=409, detail="Report artifact failed integrity verification")
    safe_name = "".join(character if character.isalnum() or character in "-_" else "-" for character in row["name"]).strip("-") or "assessment"
    extension = "zip" if report_format == "evidence" else report_format
    return FileResponse(path, media_type=media_types[report_format], filename=f"{safe_name}-{scan_id}.{extension}")


@app.post("/api/v3/assessments", response_model=Assessment, status_code=status.HTTP_201_CREATED)
async def create_assessment(
    payload: AssessmentCreate,
    workspace: dict = Depends(exposure_workspace),
) -> dict:
    require_exposure_role(workspace, "owner", "admin", "analyst")
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=422, detail="Written authorization must be confirmed")
    if payload.authentication and urlsplit(payload.authentication.login_url).hostname != urlsplit(payload.target).hostname:
        raise HTTPException(status_code=422, detail="Authentication login URL must use the target hostname")
    async with pool().acquire() as conn, conn.transaction():
        row = await conn.fetchrow(
            """
            INSERT INTO assessments (
              name, target, mode, authorization_confirmed, service_tier, organization_id, created_by
            ) VALUES ($1, $2, $3::assessment_mode, $4, $5, $6, $7)
            RETURNING *
            """,
            payload.name,
            payload.target,
            payload.mode,
            payload.authorization_confirmed,
            payload.service_tier,
            workspace["id"],
            workspace["user_id"],
        )
        await _record_client_declared_asset(conn, dict(row))
        if payload.authentication:
            auth = payload.authentication
            await conn.execute(
                """
                INSERT INTO assessment_authentication (
                  assessment_id, login_url, username_ciphertext, password_ciphertext,
                  username_selector, password_selector, submit_selector
                ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                row["id"], auth.login_url, encrypt_secret(auth.username),
                encrypt_secret(auth.password), auth.username_selector,
                auth.password_selector, auth.submit_selector,
            )
        if payload.scope:
            scope = payload.scope.model_dump(mode="json")
            stored_scope = {key: value for key, value in scope.items() if key != "validation_token"}
            await conn.execute(
                """
                INSERT INTO assessment_scopes (
                  assessment_id, source_format, source_sha256, authorization_id,
                  authorization_expires_at, credential_reference, scope
                ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
                """,
                row["id"], stored_scope["source_format"], stored_scope["source_sha256"],
                stored_scope["authorization_id"], payload.scope.authorization_expires_at,
                stored_scope.get("credential_reference"), stored_scope,
            )
        await conn.execute(
            """INSERT INTO exposure_audit_events (organization_id, actor_id, event_type, target_type, target_id, payload)
               VALUES ($1, $2, 'assessment.created', 'assessment', $3, $4::jsonb)""",
            workspace["id"], workspace["user_id"], row["id"],
            {"target": payload.target, "mode": payload.mode, "service_tier": payload.service_tier},
        )
    return dict(row)


@app.post("/api/v3/scope-files/validate")
async def validate_scope_file(
    payload: ScopeFileValidationRequest,
    _: dict = Depends(current_user),
) -> dict:
    try:
        return parse_scope_file(payload.content, payload.filename)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v3/assessments/passive-inventory")
async def public_passive_inventory(
    payload: PassiveInventoryRequest,
    _: dict = Depends(current_user),
) -> dict:
    """Return a bounded CT inventory without contacting the target or authorizing active work."""
    hostname = str(urlsplit(payload.target).hostname or "").lower()
    inventory = await asyncio.to_thread(_passive_certificate_transparency, hostname, 100)
    return {
        "target": payload.target,
        "target_hostname": hostname,
        "inventory": inventory,
        "classification": "public_passive_inventory",
        "next_step": "Create an authorized Light assessment before any host is contacted or assessed.",
    }


@app.post("/api/v3/assessments/{assessment_id}/assets/discover")
async def discover_assessment_assets(
    assessment_id: UUID,
    payload: AssetDiscoveryRequest,
    workspace: dict = Depends(exposure_workspace),
) -> dict:
    """Add passive CT candidates to the inventory; this never contacts discovered hosts."""
    assessment = await pool().fetchrow(
        "SELECT id, target, organization_id FROM assessments WHERE id = $1 AND organization_id = $2",
        assessment_id, workspace["id"],
    )
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    parent_target = str(assessment["target"])
    hostname = str(urlsplit(parent_target).hostname or "").lower()
    inventory = await asyncio.to_thread(_passive_certificate_transparency, hostname, payload.limit)
    if inventory.get("status") != "completed":
        return {
            "assessment_id": str(assessment_id),
            "inventory": inventory,
            "created_or_refreshed": 0,
            "next_step": "Discovery did not complete. No asset ownership or security conclusion was made.",
        }

    evidence = {
        "source": DISCOVERY_SOURCE_CERTIFICATE_TRANSPARENCY,
        "query": inventory.get("query"),
        "parent_target": parent_target,
        "limitations": inventory.get("limitations"),
    }
    changed = 0
    async with pool().acquire() as conn, conn.transaction():
        for discovered_hostname in inventory.get("subdomains", []):
            if not isinstance(discovered_hostname, str):
                continue
            try:
                target = target_for_discovered_hostname(parent_target, discovered_hostname)
            except ValueError:
                continue
            asset = await conn.fetchrow(
                """
                INSERT INTO assessment_assets (
                  assessment_id, hostname, canonical_target, asset_type, discovery_sources,
                  discovery_evidence, ownership_status, ownership_confidence, assessment_status
                ) VALUES ($1, $2, $3, 'hostname', $4::jsonb, $5::jsonb,
                          'candidate', 35, 'not_assessed')
                ON CONFLICT (assessment_id, hostname) DO UPDATE
                SET last_seen_at = now(), updated_at = now(),
                    discovery_sources = CASE
                      WHEN assessment_assets.discovery_sources @> EXCLUDED.discovery_sources
                        THEN assessment_assets.discovery_sources
                      ELSE assessment_assets.discovery_sources || EXCLUDED.discovery_sources
                    END,
                    discovery_evidence = assessment_assets.discovery_evidence || EXCLUDED.discovery_evidence
                RETURNING *
                """,
                assessment_id, discovered_hostname.lower(), target,
                json.dumps([DISCOVERY_SOURCE_CERTIFICATE_TRANSPARENCY]), json.dumps(evidence),
            )
            await sync_assessment_asset(
                conn, workspace["id"], dict(asset), actor_id=workspace["user_id"], parent_hostname=hostname
            )
            changed += 1
        await conn.execute(
            """INSERT INTO exposure_audit_events (organization_id, actor_id, event_type, target_type, target_id, payload)
               VALUES ($1, $2, 'asset.discovery_completed', 'assessment', $3, $4::jsonb)""",
            workspace["id"], workspace["user_id"], assessment_id,
            {"source": DISCOVERY_SOURCE_CERTIFICATE_TRANSPARENCY, "candidate_count": changed},
        )
    return {
        "assessment_id": str(assessment_id),
        "inventory": inventory,
        "created_or_refreshed": changed,
        "next_step": "Review ownership evidence before approving any candidate for a safe assessment.",
        "assets": await _asset_inventory_rows(workspace["id"], assessment_id),
    }


@app.patch("/api/v3/assessments/{assessment_id}/assets/{asset_id}")
async def review_assessment_asset(
    assessment_id: UUID,
    asset_id: UUID,
    payload: AssessmentAssetReview,
    workspace: dict = Depends(exposure_workspace),
) -> dict:
    require_exposure_role(workspace, "owner", "admin", "analyst")
    if payload.ownership_status == "approved" and not payload.authorization_confirmed:
        raise HTTPException(
            status_code=422,
            detail="Confirm written authorization before approving a discovered asset for assessment",
        )
    if payload.ownership_status == "approved":
        next_assessment_status = "approved_for_assessment"
    else:
        next_assessment_status = "not_assessed"
    async with pool().acquire() as conn, conn.transaction():
        row = await conn.fetchrow(
            """
        UPDATE assessment_assets aa
        SET ownership_status = $3,
            assessment_status = $4,
            review_note = $5,
            reviewed_by = $6,
            reviewed_at = now(),
            updated_at = now()
        FROM assessments a
        WHERE aa.id = $1 AND aa.assessment_id = $2 AND a.id = aa.assessment_id
          AND a.organization_id = $7
          AND (aa.ownership_status <> 'client_declared' OR $3 = 'approved')
        RETURNING aa.*, a.organization_id
            """,
            asset_id, assessment_id, payload.ownership_status, next_assessment_status,
            payload.note, workspace["user_id"], workspace["id"],
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Assessment asset not found or cannot be changed")
        asset = dict(row)
        exposure_asset = await sync_assessment_asset(
            conn, workspace["id"], asset, actor_id=workspace["user_id"]
        )
        await conn.execute(
            """UPDATE exposure_assets
               SET ownership_status = $3, ownership_confidence = CASE WHEN $3 = 'verified' THEN 100 ELSE ownership_confidence END,
                   ownership_evidence = ownership_evidence || $4::jsonb,
                   reviewed_by = $5, reviewed_at = now(), last_verified_at = CASE WHEN $3 = 'verified' THEN now() ELSE last_verified_at END,
                   updated_at = now()
               WHERE id = $1 AND organization_id = $2""",
            exposure_asset["id"], workspace["id"],
            "verified" if payload.ownership_status == "approved" else "excluded",
            {"method": "written_authorization" if payload.ownership_status == "approved" else "client_review", "note": payload.note or ""},
            workspace["user_id"],
        )
        event_type = "asset.ownership_verified" if payload.ownership_status == "approved" else "asset.excluded"
        event_payload = {
            "hostname": asset["hostname"], "method": "written_authorization" if payload.ownership_status == "approved" else "client_review",
            "assessment_id": str(assessment_id),
        }
        await conn.execute(
            """INSERT INTO exposure_asset_events (organization_id, asset_id, event_type, actor_id, payload)
               VALUES ($1, $2, $3, $4, $5::jsonb)""",
            workspace["id"], exposure_asset["id"], event_type, workspace["user_id"], event_payload,
        )
        await enqueue_integration_deliveries(conn, workspace["id"], "asset.changed", event_payload)
        await conn.execute(
            """INSERT INTO exposure_audit_events (organization_id, actor_id, event_type, target_type, target_id, payload)
               VALUES ($1, $2, $3, 'exposure_asset', $4, $5::jsonb)""",
            workspace["id"], workspace["user_id"], event_type, exposure_asset["id"], event_payload,
        )
    asset["client_status"] = display_asset_status(
        str(asset["ownership_status"]), str(asset["assessment_status"])
    )
    return asset


async def _load_passive_subdomain_inventory(assessment_id: UUID, organization_id: UUID) -> tuple[dict, dict]:
    row = await pool().fetchrow(
        """
        SELECT a.id AS assessment_id, a.name AS assessment_name, a.target AS parent_target,
               a.mode::text AS parent_mode, s.id AS scan_id, s.status::text AS scan_status,
               ar.id AS artifact_id, ar.sha256 AS artifact_sha256, ar.storage_key
        FROM assessments a
        JOIN scans s ON s.assessment_id = a.id
        JOIN artifacts ar ON ar.scan_id = s.id
        WHERE a.id = $1 AND a.organization_id = $2 AND ar.kind = 'passive_subdomain_inventory'
        ORDER BY ar.captured_at DESC
        LIMIT 1
        """,
        assessment_id, organization_id,
    )
    if row is None:
        raise HTTPException(
            status_code=404,
            detail="No passive subdomain inventory is available. Complete a Light assessment first.",
        )
    result = dict(row)
    path = artifact_path(result["storage_key"])
    if not path.is_file():
        raise HTTPException(status_code=410, detail="The passive subdomain inventory artifact is missing")
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() != result["artifact_sha256"]:
        raise HTTPException(status_code=409, detail="The passive subdomain inventory failed integrity verification")
    try:
        inventory = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=409, detail="The passive subdomain inventory is not valid JSON") from exc
    if not isinstance(inventory, dict):
        raise HTTPException(status_code=409, detail="The passive subdomain inventory has an invalid format")
    return result, inventory


@app.get("/api/v3/assessments/{assessment_id}/passive-subdomains")
async def passive_subdomains(assessment_id: UUID, workspace: dict = Depends(exposure_workspace)) -> dict:
    source, inventory = await _load_passive_subdomain_inventory(assessment_id, workspace["id"])
    origin_rows = await pool().fetch(
        """
        SELECT o.hostname, o.child_assessment_id, c.name, c.target, c.status::text AS status,
               o.created_at
        FROM subdomain_assessment_origins o
        JOIN assessments c ON c.id = o.child_assessment_id
        WHERE o.parent_assessment_id = $1
        ORDER BY o.created_at DESC
        """,
        assessment_id,
    )
    assessments_by_host: dict[str, list[dict]] = {}
    for row in origin_rows:
        item = dict(row)
        hostname = item.pop("hostname")
        assessments_by_host.setdefault(hostname, []).append(item)
    names = [name for name in inventory.get("subdomains", []) if isinstance(name, str)]
    can_start = inventory.get("status") == "completed" and source["scan_status"] not in {"queued", "running"}
    return {
        "assessment_id": str(assessment_id),
        "parent_target": source["parent_target"],
        "scan_id": str(source["scan_id"]),
        "scan_status": source["scan_status"],
        "inventory_status": inventory.get("status"),
        "reason": inventory.get("reason"),
        "source": inventory.get("source"),
        "artifact_sha256": source["artifact_sha256"],
        "can_start": can_start,
        "subdomains": [
            {"hostname": name, "assessments": assessments_by_host.get(name, [])}
            for name in names
        ],
    }


async def _queue_assessment_scan(conn, assessment: dict) -> dict:
    scope_row = await conn.fetchrow(
        "SELECT scope FROM assessment_scopes WHERE assessment_id = $1", assessment["id"]
    )
    if scope_row:
        scope_error = scope_dispatch_error(dict(scope_row["scope"]), assessment["target"])
        if scope_error:
            raise HTTPException(status_code=403, detail=scope_error)
    active_scan = await conn.fetchrow(
        """
        SELECT id, status::text AS status FROM scans
        WHERE assessment_id = $1 AND status IN ('queued', 'running')
        ORDER BY created_at DESC LIMIT 1
        """,
        assessment["id"],
    )
    if active_scan is not None:
        raise HTTPException(
            status_code=409,
            detail=f"Assessment already has an active scan ({active_scan['status']}: {active_scan['id']})",
        )
    plan = compile_plan(assessment["mode"], assessment["target"])
    scan = await conn.fetchrow(
        """
        INSERT INTO scans (assessment_id, plan_version, plan)
        VALUES ($1, $2, $3::jsonb)
        RETURNING id, assessment_id, status, plan_version
        """,
        assessment["id"], PLAN_VERSION, plan,
    )
    await conn.executemany(
        """INSERT INTO stage_runs (scan_id, position, adapter, required, timeout_seconds)
           VALUES ($1, $2, $3, $4, $5)""",
        [
            (scan["id"], stage["position"], stage["adapter"], stage["required"], stage["timeout_seconds"])
            for stage in plan["stages"]
        ],
    )
    stage_ids = {
        row["adapter"]: row["id"]
        for row in await conn.fetch("SELECT id, adapter FROM stage_runs WHERE scan_id = $1", scan["id"])
    }
    await conn.executemany(
        """
        INSERT INTO scan_coverage (
          scan_id, stage_run_id, case_id, methodology_version, profile,
          family, adapter, title, required
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        """,
        [
            (
                scan["id"], stage_ids[record["adapter"]], record["case_id"],
                record["methodology_version"], record["profile"], record["family"],
                record["adapter"], record["title"], record["required"],
            )
            for record in coverage_records(plan)
        ],
    )
    await conn.execute("UPDATE assessments SET status = 'queued' WHERE id = $1", assessment["id"])
    await conn.execute(
        "INSERT INTO scan_events (scan_id, event_type, payload) VALUES ($1, 'scan.queued', $2)",
        scan["id"], {"plan_version": PLAN_VERSION},
    )
    return dict(scan)


@app.post("/api/v3/assessments/{assessment_id}/assets/{asset_id}/start", status_code=status.HTTP_202_ACCEPTED)
async def start_inventory_asset_assessment(
    assessment_id: UUID,
    asset_id: UUID,
    payload: AssetAssessmentStart,
    workspace: dict = Depends(exposure_workspace),
) -> dict:
    """Queue one approved exact-origin asset while retaining a parent assessment view."""
    require_exposure_role(workspace, "owner", "admin", "analyst")
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=422, detail="Confirm written authorization before assessment execution")
    async with pool().acquire() as conn, conn.transaction():
        asset = await conn.fetchrow(
            """
            SELECT aa.*, a.name AS parent_name, a.target AS parent_target,
                   a.mode::text AS parent_mode, a.authorization_confirmed AS parent_authorized
            FROM assessment_assets aa
            JOIN assessments a ON a.id = aa.assessment_id
            WHERE aa.id = $1 AND aa.assessment_id = $2 AND a.organization_id = $3
            FOR UPDATE OF aa, a
            """,
            asset_id, assessment_id, workspace["id"],
        )
        if asset is None:
            raise HTTPException(status_code=404, detail="Assessment asset not found")
        if not asset["parent_authorized"]:
            raise HTTPException(status_code=403, detail="The parent assessment has no recorded authorization")
        if asset["ownership_status"] not in {"client_declared", "approved"}:
            raise HTTPException(status_code=409, detail="Review and approve this candidate asset before assessment")

        if asset["canonical_target"] == asset["parent_target"]:
            scan_assessment = {
                "id": assessment_id,
                "mode": asset["parent_mode"],
                "target": asset["parent_target"],
            }
        else:
            child = await conn.fetchrow(
                """
                INSERT INTO assessments (
                  name, target, mode, authorization_confirmed, service_tier, organization_id, created_by
                ) VALUES ($1, $2, $3::assessment_mode, true, 'external_baseline', $4, $5)
                RETURNING *
                """,
                f"{str(asset['parent_name'])[:120]} / {asset['hostname']}", asset["canonical_target"],
                asset["parent_mode"], workspace["id"], workspace["user_id"],
            )
            scan_assessment = dict(child)

        scan = await _queue_assessment_scan(conn, scan_assessment)
        await conn.execute(
            """
            INSERT INTO assessment_asset_scans (assessment_asset_id, scan_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            """,
            asset_id, scan["id"],
        )
        await conn.execute(
            """
            UPDATE assessment_assets
            SET assessment_status = 'queued', updated_at = now()
            WHERE id = $1
            """,
            asset_id,
        )
        await conn.execute(
            """INSERT INTO exposure_audit_events (
                 organization_id, actor_id, event_type, target_type, target_id, payload
               ) VALUES ($1, $2, 'assessment.dispatched', 'scan', $3, $4::jsonb)""",
            workspace["id"], workspace["user_id"], scan["id"],
            {
                "assessment_id": str(scan_assessment["id"]),
                "parent_assessment_id": str(assessment_id),
                "asset_id": str(asset_id),
                "target": asset["canonical_target"],
                "plan_version": PLAN_VERSION,
            },
        )
    return {
        "assessment_id": str(assessment_id),
        "asset_id": str(asset_id),
        "scan_id": str(scan["id"]),
        "target": asset["canonical_target"],
        "status": scan["status"],
    }


@app.post("/api/v3/assessments/{assessment_id}/subdomain-assessments", status_code=status.HTTP_202_ACCEPTED)
async def start_approved_subdomain_assessments(
    assessment_id: UUID,
    payload: SubdomainAssessmentCreate,
    workspace: dict = Depends(exposure_workspace),
) -> dict:
    require_exposure_role(workspace, "owner", "admin", "analyst")
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=422, detail="Written authorization for the selected subdomains must be confirmed")
    source, inventory = await _load_passive_subdomain_inventory(assessment_id, workspace["id"])
    if source["scan_status"] in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="Wait for the parent assessment to finish before starting subdomain checks")
    try:
        hostnames = approved_discovered_subdomains(inventory, source["parent_target"], payload.hostnames)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    created: list[dict] = []
    async with pool().acquire() as conn, conn.transaction():
        parent = await conn.fetchrow(
            "SELECT * FROM assessments WHERE id = $1 AND organization_id = $2 FOR UPDATE",
            assessment_id, workspace["id"],
        )
        if parent is None:
            raise HTTPException(status_code=404, detail="Parent assessment not found")
        if not parent["authorization_confirmed"]:
            raise HTTPException(status_code=403, detail="Parent assessment is not authorized")
        for hostname in hostnames:
            target = target_for_subdomain(parent["target"], hostname)
            asset = await conn.fetchrow(
                """
                INSERT INTO assessment_assets (
                  assessment_id, hostname, canonical_target, asset_type, discovery_sources,
                  discovery_evidence, ownership_status, ownership_confidence, assessment_status,
                  reviewed_by, reviewed_at
                ) VALUES ($1, $2, $3, 'hostname', $4::jsonb, $5::jsonb,
                          'approved', 100, 'queued', $6, now())
                ON CONFLICT (assessment_id, hostname) DO UPDATE
                SET ownership_status = 'approved', ownership_confidence = 100,
                    assessment_status = 'queued', reviewed_by = $6, reviewed_at = now(),
                    last_seen_at = now(), updated_at = now()
                RETURNING *
                """,
                assessment_id, hostname, target,
                json.dumps([DISCOVERY_SOURCE_CERTIFICATE_TRANSPARENCY]),
                json.dumps({
                    "source": DISCOVERY_SOURCE_CERTIFICATE_TRANSPARENCY,
                    "source_artifact_id": str(source["artifact_id"]),
                    "source_artifact_sha256": source["artifact_sha256"],
                }),
                workspace["user_id"],
            )
            await sync_assessment_asset(
                conn, workspace["id"], dict(asset), actor_id=workspace["user_id"],
                parent_hostname=str(urlsplit(parent["target"]).hostname or "").lower(),
            )
            prefix = str(parent["name"])[: max(1, 157 - len(hostname))]
            child = await conn.fetchrow(
                """
                INSERT INTO assessments (
                  name, target, mode, authorization_confirmed, service_tier, organization_id, created_by
                ) VALUES ($1, $2, 'light'::assessment_mode, true, 'external_baseline', $3, $4)
                RETURNING *
                """,
                f"{prefix} / {hostname}", target, workspace["id"], workspace["user_id"],
            )
            child_assessment = dict(child)
            await conn.execute(
                """
                INSERT INTO subdomain_assessment_origins (
                  child_assessment_id, parent_assessment_id, source_artifact_id,
                  source_artifact_sha256, hostname, approved_by
                ) VALUES ($1, $2, $3, $4, $5, $6)
                """,
                child["id"], assessment_id, source["artifact_id"], source["artifact_sha256"], hostname, workspace["user_id"],
            )
            scan = await _queue_assessment_scan(conn, child_assessment)
            await conn.execute(
                """
                INSERT INTO assessment_asset_scans (assessment_asset_id, scan_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
                """,
                asset["id"], scan["id"],
            )
            await conn.execute(
                """INSERT INTO exposure_audit_events (
                     organization_id, actor_id, event_type, target_type, target_id, payload
                   ) VALUES ($1, $2, 'assessment.dispatched', 'scan', $3, $4::jsonb)""",
                workspace["id"], workspace["user_id"], scan["id"],
                {
                    "assessment_id": str(child["id"]),
                    "parent_assessment_id": str(assessment_id),
                    "asset_id": str(asset["id"]),
                    "target": target,
                    "plan_version": PLAN_VERSION,
                },
            )
            created.append({"assessment_id": str(child["id"]), "scan_id": str(scan["id"]), "hostname": hostname, "target": target})
    return {"parent_assessment_id": str(assessment_id), "created": created}


@app.post("/api/v3/assessments/preview")
async def preview_assessment(
    payload: AssessmentCreate,
    workspace: dict = Depends(exposure_workspace),
) -> dict:
    plan = compile_plan(payload.mode, payload.target)
    release_claims = {
        "light": "Exposure and configuration baseline only; not a full penetration test.",
        "medium": "Expanded evidence-backed non-destructive application assessment; not yet a verified application penetration test.",
        "aggressive": "Broadest currently available evidence-backed non-destructive assessment; not yet a comprehensive controlled assessment.",
    }
    non_goals = {
        "light": [
            "No injection payloads or state-changing requests",
            "No authorization probing or business-logic testing",
            "No credential attacks, file uploads, or exploitation",
        ],
        "medium": [
            "No exploitation payload chains or destructive validation",
            "No brute force or credential stuffing",
            "No unrestricted data extraction or AI-generated scanner decisions",
        ],
        "aggressive": [
            "No persistence, destructive denial of service, or malware",
            "No credential theft or unrestricted data extraction",
            "No unapproved exploitation outside authorized reversible checks",
        ],
    }
    warnings: list[str] = []
    if not payload.authorization_confirmed:
        warnings.append("Authorization must be confirmed before dispatch.")
    if payload.scope is None:
        warnings.append("No scope file supplied. Exact target origin will be the only enforced boundary.")
    if payload.authentication is None:
        warnings.append("No authenticated test session supplied. Findings will be limited to unauthenticated reachability and publicly accessible routes.")
    if payload.mode in {"medium", "aggressive"}:
        warnings.append("Current implementation for this profile is broader than Light, but some deeper validation families remain promotion targets rather than completed release claims.")
    if payload.service_tier == "authorized_deep":
        warnings.append("Authorized deep is a governed product lane. Current adapters remain non-exploitative until each deeper check is separately released and approved.")
    return {
        "plan_version": plan["version"],
        "target": plan["target"],
        "mode": plan["mode"],
        "safety_class": plan["safety_class"],
        "estimated_seconds": sum(stage["timeout_seconds"] for stage in plan["stages"]),
        "stages": plan["stages"],
        "coverage_contract": profile_contract(payload.mode),
        "current_claim": release_claims[payload.mode],
        "non_goals": non_goals[payload.mode],
        "warnings": warnings,
    }


@app.post(
    "/api/v3/assessments/{assessment_id}/scans",
    response_model=ScanStarted,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_scan(assessment_id: UUID, workspace: dict = Depends(exposure_workspace)) -> dict:
    require_exposure_role(workspace, "owner", "admin", "analyst")
    async with pool().acquire() as conn, conn.transaction():
        assessment = await conn.fetchrow(
            "SELECT * FROM assessments WHERE id = $1 AND organization_id = $2 FOR UPDATE", assessment_id, workspace["id"]
        )
        if assessment is None:
            raise HTTPException(status_code=404, detail="Assessment not found")
        if not assessment["authorization_confirmed"]:
            raise HTTPException(status_code=403, detail="Assessment is not authorized")
        scan = await _queue_assessment_scan(conn, dict(assessment))
        # Keep the client-declared root and its ordinary assessment lifecycle in one record.
        await conn.execute(
            """
            INSERT INTO assessment_asset_scans (assessment_asset_id, scan_id)
            SELECT id, $2 FROM assessment_assets
            WHERE assessment_id = $1 AND canonical_target = $3
            ON CONFLICT DO NOTHING
            """,
            assessment_id, scan["id"], assessment["target"],
        )
        await conn.execute(
            """
            UPDATE assessment_assets
            SET assessment_status = 'queued', updated_at = now()
            WHERE assessment_id = $1 AND canonical_target = $2
            """,
            assessment_id, assessment["target"],
        )
        await conn.execute(
            """INSERT INTO exposure_audit_events (
                 organization_id, actor_id, event_type, target_type, target_id, payload
               ) VALUES ($1, $2, 'assessment.dispatched', 'scan', $3, $4::jsonb)""",
            workspace["id"], workspace["user_id"], scan["id"],
            {"assessment_id": str(assessment_id), "target": assessment["target"], "plan_version": PLAN_VERSION},
        )
        return scan


@app.post("/api/v3/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: UUID, workspace: dict = Depends(exposure_workspace)) -> dict:
    require_exposure_role(workspace, "owner", "admin", "analyst")
    async with pool().acquire() as conn, conn.transaction():
        scan = await conn.fetchrow(
            """SELECT s.id, s.assessment_id, s.status::text AS status FROM scans s
               JOIN assessments a ON a.id = s.assessment_id
               WHERE s.id = $1 AND a.organization_id = $2 FOR UPDATE OF s""",
            scan_id, workspace["id"],
        )
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        if scan["status"] in {"complete", "partial", "failed", "cancelled"}:
            raise HTTPException(status_code=409, detail=f"Scan is already terminal: {scan['status']}")
        running_stage = await conn.fetchrow(
            """
            SELECT id, adapter, position
            FROM stage_runs
            WHERE scan_id = $1 AND status = 'running'
            ORDER BY position
            LIMIT 1
            """,
            scan_id,
        )
        reason = "Operator requested cancellation."
        if running_stage is None:
            cancelled = await conn.fetch(
                """
                UPDATE stage_runs
                SET status = 'cancelled', finished_at = now(),
                    error_code = 'OPERATOR_CANCELLED', error_detail = $2
                WHERE scan_id = $1 AND status = 'queued'
                RETURNING id, adapter
                """,
                scan_id, reason,
            )
            if cancelled:
                await conn.execute(
                    """
                    UPDATE scan_coverage
                    SET status = 'cancelled', finished_at = now(), reason = $2, updated_at = now()
                    WHERE stage_run_id = ANY($1::uuid[])
                    """,
                    [row["id"] for row in cancelled], reason,
                )
            await conn.execute(
                """
                UPDATE scans
                SET status = 'cancelled', finished_at = now(),
                    cancel_requested_at = COALESCE(cancel_requested_at, now()),
                    failure_reason = $2
                WHERE id = $1
                """,
                scan_id, reason,
            )
            await conn.execute(
                "UPDATE assessments SET status = 'cancelled' WHERE id = $1",
                scan["assessment_id"],
            )
            await conn.execute(
                """
                UPDATE assessment_assets aa
                SET assessment_status = 'blocked', updated_at = now()
                FROM assessment_asset_scans aas
                WHERE aas.scan_id = $1 AND aas.assessment_asset_id = aa.id
                """,
                scan_id,
            )
            await conn.execute(
                "INSERT INTO scan_events (scan_id, event_type, payload) VALUES ($1, 'scan.cancelled', $2)",
                scan_id,
                {"status": "cancelled", "reason": reason, "cancelled_stages": [str(row["adapter"]) for row in cancelled]},
            )
        else:
            await conn.execute(
                """
                UPDATE scans
                SET cancel_requested_at = COALESCE(cancel_requested_at, now()),
                    failure_reason = $2
                WHERE id = $1
                """,
                scan_id, reason,
            )
            await conn.execute(
                "INSERT INTO scan_events (scan_id, event_type, payload) VALUES ($1, 'scan.cancel_requested', $2)",
                scan_id,
                {"status": scan["status"], "reason": reason, "running_stage": running_stage["adapter"]},
            )
        await conn.execute(
            """INSERT INTO exposure_audit_events (
                 organization_id, actor_id, event_type, target_type, target_id, payload
               ) VALUES ($1, $2, $3, 'scan', $4, $5::jsonb)""",
            workspace["id"], workspace["user_id"],
            "scan.cancelled" if running_stage is None else "scan.cancellation_requested",
            scan_id,
            {"assessment_id": str(scan["assessment_id"]), "reason": reason},
        )
        existing_report = await conn.fetchrow("SELECT * FROM reports WHERE scan_id = $1", scan_id)
    if running_stage is None:
        coverage = [dict(row) for row in await pool().fetch(
            "SELECT * FROM scan_coverage WHERE scan_id = $1 ORDER BY created_at, case_id",
            scan_id,
        )]
        report_status = report_status_for_scan("cancelled")
        manifest = await generate_scan_reports(scan_id, scan["assessment_id"], report_status, coverage)
        row = await pool().fetchrow(
            """
            INSERT INTO reports (scan_id, status, manifest) VALUES ($1, $2, $3)
            ON CONFLICT (scan_id) DO UPDATE
            SET status = EXCLUDED.status, manifest = EXCLUDED.manifest, generated_at = now()
            RETURNING *
            """,
            scan_id, report_status, manifest,
        )
        return {"scan_id": str(scan_id), "status": "cancelled", "report": dict(row)}
    return {"scan_id": str(scan_id), "status": "cancellation_requested", "report": record_to_dict(existing_report)}


@app.get("/api/v3/scans/{scan_id}", response_model=ScanDetail)
async def scan_detail(scan_id: UUID, workspace: dict = Depends(exposure_workspace)) -> dict:
    scan = await pool().fetchrow(
        """SELECT s.* FROM scans s JOIN assessments a ON a.id = s.assessment_id
           WHERE s.id = $1 AND a.organization_id = $2""", scan_id, workspace["id"]
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    stages = await pool().fetch(
        "SELECT * FROM stage_runs WHERE scan_id = $1 ORDER BY position", scan_id
    )
    findings = await pool().fetch(
        """
        SELECT f.*, fa.canonical_observation_key, fa.validation_status,
               fa.evidence_integrity, fa.oracle_status, fa.rationale AS assurance_rationale,
               fa.validation_artifact_id, fa.validated_at
        FROM findings f
        LEFT JOIN finding_assurance fa ON fa.finding_id = f.id
        WHERE f.scan_id = $1 ORDER BY f.created_at
        """,
        scan_id,
    )
    coverage = await pool().fetch(
        "SELECT * FROM scan_coverage WHERE scan_id = $1 ORDER BY created_at, case_id",
        scan_id,
    )
    report = await pool().fetchrow("SELECT * FROM reports WHERE scan_id = $1", scan_id)
    result = dict(scan)
    result["stages"] = [dict(row) for row in stages]
    result["findings"] = [dict(row) for row in findings]
    result["coverage"] = [dict(row) for row in coverage]
    result["report"] = record_to_dict(report)
    return result
