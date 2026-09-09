"""MCP security assessment API with persisted, redacted protocol evidence."""

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db, require_permission
from app.models.mcp_security import McpSecurityRun
from app.models.user import User
from app.services.celery_app import celery_app, run_mcp_security_scan
from app.services.mcp_jobs import clear_mcp_cancel, encrypt_mcp_payload, request_mcp_cancel

router = APIRouter(prefix="/mcp-security", tags=["MCP Security"])


class McpRunRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    endpoint: HttpUrl
    bearer_token: str | None = Field(default=None, max_length=8192)
    allow_private: bool = False
    protocol_tests: bool = True
    authorization_confirmed: bool
    secondary_bearer_token: str | None = Field(default=None, max_length=8192)
    audience_mismatch_token: str | None = Field(default=None, max_length=8192)
    issuer_mismatch_token: str | None = Field(default=None, max_length=8192)
    approved_tool_name: str | None = Field(default=None, max_length=255)
    approved_tool_arguments: dict[str, Any] = Field(default_factory=dict)
    approved_resource_uri: str | None = Field(default=None, max_length=2048)
    approved_prompt_name: str | None = Field(default=None, max_length=255)
    test_task_id: str | None = Field(default=None, max_length=512)
    canary_url: HttpUrl | None = None
    cross_server_endpoint: HttpUrl | None = None
    cross_server_bearer_token: str | None = Field(default=None, max_length=8192)
    local_config_text: str | None = Field(default=None, max_length=65536)
    max_concurrency: int = Field(default=4, ge=1, le=8)
    enable_deep_tests: bool = False
    allow_mutation_tests: bool = False
    deep_authorization_confirmed: bool = False

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Assessment name cannot be blank")
        return normalized

    @model_validator(mode="after")
    def validate_execution_profile(self):
        if len(json.dumps(self.approved_tool_arguments, default=str)) > 65536:
            raise ValueError("Approved tool arguments cannot exceed 64 KiB")
        if (self.enable_deep_tests or self.allow_mutation_tests) and not self.deep_authorization_confirmed:
            raise ValueError("Deep and mutation tests require separate isolated-target authorization")
        if self.allow_mutation_tests and not self.test_task_id:
            raise ValueError("Mutation tests require a disposable test task ID")
        return self


class McpRunResponse(BaseModel):
    id: uuid.UUID
    name: str
    endpoint: str
    status: str
    overall_severity: str
    risk_score: int
    summary: dict[str, Any]
    inventory: dict[str, Any]
    findings: list[dict[str, Any]]
    exchanges: list[dict[str, Any]]
    error_message: str | None
    created_at: datetime
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class McpRunList(BaseModel):
    items: list[McpRunResponse]
    total: int
    page: int
    page_size: int


def _response(run: McpSecurityRun) -> McpRunResponse:
    return McpRunResponse.model_validate(run)


@router.post("/runs", response_model=McpRunResponse, status_code=status.HTTP_201_CREATED)
async def create_mcp_security_run(
    payload: McpRunRequest,
    current_user: User = Depends(require_permission("assessments:run")),
    db: AsyncSession = Depends(get_db),
):
    """Perform a non-destructive MCP protocol and capability assessment."""
    if not payload.authorization_confirmed:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Explicit authorization confirmation is required")
    if (payload.enable_deep_tests or payload.allow_mutation_tests) and not payload.deep_authorization_confirmed:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Deep and mutation tests require separate isolated-target authorization",
        )
    if payload.allow_mutation_tests and not payload.test_task_id:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Mutation tests require a disposable test task ID",
        )

    task_id = str(uuid.uuid4())
    run = McpSecurityRun(
        org_id=current_user.org_id,
        created_by=current_user.id,
        name=payload.name.strip(),
        endpoint=str(payload.endpoint),
        status="queued",
        summary={"progress": 0, "current_step": "queued", "task_id": task_id},
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    job_payload = {
        "endpoint": str(payload.endpoint),
        "bearer_token": payload.bearer_token,
        "allow_private": payload.allow_private,
        "protocol_tests": payload.protocol_tests,
        "profile": {
            "secondary_bearer_token": payload.secondary_bearer_token,
            "audience_mismatch_token": payload.audience_mismatch_token,
            "issuer_mismatch_token": payload.issuer_mismatch_token,
            "approved_tool_name": payload.approved_tool_name,
            "approved_tool_arguments": payload.approved_tool_arguments,
            "approved_resource_uri": payload.approved_resource_uri,
            "approved_prompt_name": payload.approved_prompt_name,
            "test_task_id": payload.test_task_id,
            "canary_url": str(payload.canary_url) if payload.canary_url else None,
            "cross_server_endpoint": str(payload.cross_server_endpoint) if payload.cross_server_endpoint else None,
            "cross_server_bearer_token": payload.cross_server_bearer_token,
            "local_config_text": payload.local_config_text,
            "max_concurrency": payload.max_concurrency,
            "enable_deep_tests": payload.enable_deep_tests,
            "allow_mutation_tests": payload.allow_mutation_tests,
        },
    }
    try:
        run_mcp_security_scan.apply_async(
            args=[str(run.id), encrypt_mcp_payload(job_payload)],
            task_id=task_id,
        )
    except Exception as exc:
        run.status = "failed"
        run.error_message = f"Could not queue MCP assessment: {type(exc).__name__}"
        run.completed_at = datetime.now(timezone.utc)
        await db.commit()
    return _response(run)


@router.get("/runs", response_model=McpRunList)
async def list_mcp_security_runs(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    filters = [McpSecurityRun.org_id == current_user.org_id]
    total = (await db.execute(select(func.count()).select_from(McpSecurityRun).where(and_(*filters)))).scalar() or 0
    rows = (await db.execute(
        select(McpSecurityRun).where(and_(*filters)).order_by(McpSecurityRun.created_at.desc())
        .offset((page - 1) * page_size).limit(page_size)
    )).scalars().all()
    return McpRunList(items=[_response(run) for run in rows], total=total, page=page, page_size=page_size)


@router.get("/runs/{run_id}", response_model=McpRunResponse)
async def get_mcp_security_run(
    run_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    run = (await db.execute(select(McpSecurityRun).where(and_(
        McpSecurityRun.id == run_id, McpSecurityRun.org_id == current_user.org_id,
    )))).scalar_one_or_none()
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "MCP security run not found")
    return _response(run)


@router.delete("/runs/{run_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_mcp_security_run(
    run_id: uuid.UUID,
    current_user: User = Depends(require_permission("scans:delete")),
    db: AsyncSession = Depends(get_db),
):
    run = (await db.execute(select(McpSecurityRun).where(and_(
        McpSecurityRun.id == run_id, McpSecurityRun.org_id == current_user.org_id,
    )))).scalar_one_or_none()
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "MCP security run not found")
    if run.status in {"queued", "running", "cancel_requested"}:
        request_mcp_cancel(str(run.id))
        task_id = (run.summary or {}).get("task_id")
        if task_id:
            celery_app.control.revoke(task_id, terminate=False)
    await db.delete(run)
    await db.commit()


@router.post("/runs/{run_id}/cancel", response_model=McpRunResponse)
async def cancel_mcp_security_run(
    run_id: uuid.UUID,
    current_user: User = Depends(require_permission("assessments:run")),
    db: AsyncSession = Depends(get_db),
):
    run = (await db.execute(select(McpSecurityRun).where(and_(
        McpSecurityRun.id == run_id, McpSecurityRun.org_id == current_user.org_id,
    )))).scalar_one_or_none()
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "MCP security run not found")
    if run.status not in {"queued", "running", "cancel_requested"}:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Run is already {run.status}")
    request_mcp_cancel(str(run.id))
    run.status = "cancel_requested"
    run.summary = {**(run.summary or {}), "current_step": "cancellation requested"}
    task_id = (run.summary or {}).get("task_id")
    if task_id and (run.summary or {}).get("progress", 0) == 0:
        celery_app.control.revoke(task_id, terminate=False)
        run.status = "cancelled"
        run.summary = {**(run.summary or {}), "current_step": "cancelled"}
        run.completed_at = datetime.now(timezone.utc)
        clear_mcp_cancel(str(run.id))
    await db.commit()
    await db.refresh(run)
    return _response(run)
