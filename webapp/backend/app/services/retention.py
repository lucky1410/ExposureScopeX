"""Dry-run-first tenant retention with tamper-resistant confirmation tokens."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.assessment import Assessment
from app.models.report import ReportArtifact
from app.models.scan import Scan
from app.models.scan_runtime import OrganizationExecutionPolicy, ScanArtifact
from app.services.artifact_storage import delete_object

TOKEN_TTL_SECONDS = 15 * 60


async def retention_candidates(db: AsyncSession, org_id) -> dict:
    policy = await db.scalar(select(OrganizationExecutionPolicy).where(OrganizationExecutionPolicy.org_id == org_id))
    values = (policy.settings if policy else {}) or {}
    scan_days = int(values.get("scan_retention_days") or settings.SCAN_ARTIFACT_RETENTION_DAYS)
    report_days = int(values.get("report_retention_days") or settings.REPORT_RETENTION_DAYS)
    now = datetime.now(timezone.utc)
    scans = (await db.execute(
        select(ScanArtifact).join(Scan, Scan.id == ScanArtifact.scan_id).join(Assessment, Assessment.id == Scan.assessment_id)
        .where(Assessment.org_id == org_id, ScanArtifact.retained.is_(True), ScanArtifact.created_at < now - timedelta(days=scan_days))
        .order_by(ScanArtifact.id)
    )).scalars().all()
    reports = (await db.execute(
        select(ReportArtifact).where(ReportArtifact.org_id == org_id, ReportArtifact.created_at < now - timedelta(days=report_days))
        .order_by(ReportArtifact.id)
    )).scalars().all()
    return {
        "scan_days": scan_days,
        "report_days": report_days,
        "scan_artifacts": scans,
        "reports": reports,
    }


def _candidate_ids(candidates: dict) -> dict:
    return {
        "scan_artifact_ids": [str(row.id) for row in candidates["scan_artifacts"]],
        "report_ids": [str(row.id) for row in candidates["reports"]],
    }


def make_confirmation_token(org_id, candidates: dict, issued_at: int | None = None) -> str:
    payload = {"org_id": str(org_id), "issued_at": issued_at or int(time.time()), **_candidate_ids(candidates)}
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    signature = hmac.new(settings.SECRET_KEY.encode(), encoded, hashlib.sha256).hexdigest()
    return f"{encoded.hex()}.{signature}"


def verify_confirmation_token(token: str, org_id, candidates: dict) -> bool:
    try:
        encoded_hex, supplied = token.split(".", 1)
        encoded = bytes.fromhex(encoded_hex)
        expected = hmac.new(settings.SECRET_KEY.encode(), encoded, hashlib.sha256).hexdigest()
        payload = json.loads(encoded)
    except (ValueError, TypeError, json.JSONDecodeError):
        return False
    age = int(time.time()) - int(payload.get("issued_at", 0))
    return (
        hmac.compare_digest(supplied, expected)
        and payload.get("org_id") == str(org_id)
        and 0 <= age <= TOKEN_TTL_SECONDS
        and payload.get("scan_artifact_ids") == _candidate_ids(candidates)["scan_artifact_ids"]
        and payload.get("report_ids") == _candidate_ids(candidates)["report_ids"]
    )


def retention_preview(org_id, candidates: dict) -> dict:
    scan_bytes = sum(int(row.size_bytes or 0) for row in candidates["scan_artifacts"])
    report_bytes = sum(int(row.file_size or 0) for row in candidates["reports"])
    return {
        "scan_retention_days": candidates["scan_days"],
        "report_retention_days": candidates["report_days"],
        "scan_artifacts": {"count": len(candidates["scan_artifacts"]), "bytes": scan_bytes},
        "reports": {"count": len(candidates["reports"]), "bytes": report_bytes},
        "reclaimable_bytes": scan_bytes + report_bytes,
        "confirmation_token": make_confirmation_token(org_id, candidates),
        "expires_in_seconds": TOKEN_TTL_SECONDS,
    }


async def execute_retention(db: AsyncSession, candidates: dict) -> dict:
    object_errors: list[str] = []
    for report in candidates["reports"]:
        try:
            if report.storage_backend == "s3":
                delete_object(report.object_key)
            await db.delete(report)
        except Exception as exc:
            object_errors.append(f"report:{report.id}:{type(exc).__name__}")
    released = 0
    for artifact in candidates["scan_artifacts"]:
        provenance = artifact.provenance or {}
        try:
            if provenance.get("object_key"):
                delete_object(provenance["object_key"])
            artifact.retained = False
            released += 1
        except Exception as exc:
            object_errors.append(f"scan_artifact:{artifact.id}:{type(exc).__name__}")
    return {
        "scan_artifacts_released": released,
        "reports_deleted": len(candidates["reports"]) - sum(item.startswith("report:") for item in object_errors),
        "errors": object_errors,
    }
