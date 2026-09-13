from __future__ import annotations

from typing import Literal
from uuid import UUID

from fastapi import Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from .auth import current_user
from .db import pool


WorkspaceRole = Literal["owner", "admin", "analyst", "viewer"]
DatasetClassification = Literal["synthetic", "public", "internal", "restricted"]


class GovernanceModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvaluatorProjectCreate(GovernanceModel):
    key: str = Field(pattern=r"^[a-z][a-z0-9-]{1,62}$")
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=1000)


class EvaluatorDatasetCreate(GovernanceModel):
    project_key: str = Field(pattern=r"^[a-z][a-z0-9-]{1,62}$")
    name: str = Field(min_length=2, max_length=160)
    version: str = Field(min_length=1, max_length=100)
    classification: DatasetClassification
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_reference: str = Field(min_length=1, max_length=512)


def require_evaluator_role(workspace: dict, *allowed: WorkspaceRole) -> None:
    if workspace["membership_role"] not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your workspace role does not permit this evaluator action",
        )


async def evaluator_workspace(
    user: dict = Depends(current_user),
    organization_id: UUID | None = Header(default=None, alias="X-ESX-Organization"),
) -> dict:
    """Resolve a member-authorized evaluator workspace for the current request."""
    if organization_id is None:
        row = await pool().fetchrow(
            """
            SELECT o.id, o.name, o.slug, m.role AS membership_role
            FROM organization_memberships m
            JOIN organizations o ON o.id = m.organization_id
            WHERE m.user_id = $1 AND o.active = true
            ORDER BY CASE m.role
              WHEN 'owner' THEN 1 WHEN 'admin' THEN 2 WHEN 'analyst' THEN 3 ELSE 4 END,
              m.joined_at
            LIMIT 1
            """,
            user["id"],
        )
    else:
        row = await pool().fetchrow(
            """
            SELECT o.id, o.name, o.slug, m.role AS membership_role
            FROM organization_memberships m
            JOIN organizations o ON o.id = m.organization_id
            WHERE m.user_id = $1 AND m.organization_id = $2 AND o.active = true
            """,
            user["id"],
            organization_id,
        )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No active evaluator workspace membership was found",
        )
    return {**dict(row), "user_id": user["id"]}


async def evaluator_project(workspace: dict, project_key: str) -> dict:
    row = await pool().fetchrow(
        """
        SELECT id, organization_id, key, name, description, status, created_at
        FROM evaluator_projects
        WHERE organization_id = $1 AND key = $2 AND status = 'active'
        """,
        workspace["id"],
        project_key,
    )
    if row is None:
        raise HTTPException(status_code=422, detail="Evaluator project is not active in this workspace")
    return dict(row)


async def approved_evaluator_dataset(project_id: UUID, version: str) -> dict:
    row = await pool().fetchrow(
        """
        SELECT id, project_id, name, version, classification, source_sha256,
               source_reference, status, approved_at
        FROM evaluator_datasets
        WHERE project_id = $1 AND version = $2 AND status = 'approved'
        """,
        project_id,
        version,
    )
    if row is None:
        raise HTTPException(
            status_code=422,
            detail="Dataset version is not approved for this evaluator project",
        )
    return dict(row)


async def record_evaluator_audit_event(
    workspace: dict,
    event_type: str,
    *,
    target_type: str,
    target_id: UUID | None = None,
    payload: dict | None = None,
) -> None:
    """Append non-sensitive governance provenance for an evaluator operation."""
    await pool().execute(
        """
        INSERT INTO evaluator_audit_events (
          organization_id, actor_id, event_type, target_type, target_id, payload
        ) VALUES ($1, $2, $3, $4, $5, $6::jsonb)
        """,
        workspace["id"],
        workspace["user_id"],
        event_type,
        target_type,
        target_id,
        payload or {},
    )
