"""Worker capability advertisement and capability-aware dispatch checks."""

from __future__ import annotations

import json
import os
import shutil
import socket
import time
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text

from app.config import settings
from app.models.scan_runtime import WorkerCapability
from app.services.open_source_catalog import OPEN_SOURCE_SCANNERS
from app.services.scan_provenance import _tool_version

_last_registration = 0.0
_BINARY_ALIASES = {"git_clone": "git", "mcp_audit": "python", "nuclei_templates": "nuclei", "scoutsuite": settings.SCOUTSUITE_BIN}


def _normalize_worker_name(worker_name: str | None) -> str:
    return (worker_name or socket.gethostname()).removeprefix("celery@")


def _template_commit(path: str) -> str | None:
    import subprocess

    try:
        result = subprocess.run(["git", "-C", path, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=3, check=False)
        return result.stdout.strip()[:64] or None
    except (OSError, subprocess.SubprocessError):
        return None


def capability_snapshot(worker_name: str | None = None) -> dict:
    """Build a bounded snapshot from fixed catalog entries, never user input."""
    capabilities: list[str] = []
    versions: dict[str, str] = {}
    for scanner in OPEN_SOURCE_SCANNERS:
        tool_id = scanner["id"]
        binary = _BINARY_ALIASES.get(tool_id, tool_id)
        location = shutil.which(binary)
        if not location:
            continue
        capabilities.append(tool_id)
        discovered = _tool_version(tool_id)
        if discovered:
            versions[tool_id] = discovered
    for name, path in (
        ("nuclei_templates_official", "/app/runtime/nuclei-templates"),
        ("nuclei_templates_community", "/app/runtime/nuclei-templates-community"),
    ):
        commit = _template_commit(path)
        if commit:
            versions[name] = commit
    return {
        "worker_name": _normalize_worker_name(worker_name),
        "image_identity": settings.SCANNER_IMAGE_IDENTITY,
        "queues": sorted({item.strip() for item in os.getenv("WORKER_QUEUES", "scans-web,scans-api,scans-artifact,scans-cloud,scans-mobile,scans,default").split(",") if item.strip()}),
        "capabilities": sorted(set(capabilities)),
        "versions": versions,
        "last_seen_at": datetime.now(timezone.utc),
    }


def register_worker_capabilities(worker_name: str | None = None, *, force: bool = False) -> dict | None:
    global _last_registration
    now = time.monotonic()
    if not force and now - _last_registration < 30:
        return None
    snapshot = capability_snapshot(worker_name)
    from app.services.celery_app import _get_sync_db

    db = _get_sync_db()
    try:
        db.execute(text(
            "INSERT INTO worker_capabilities (id,worker_name,image_identity,queues,capabilities,versions,status,last_seen_at,created_at,updated_at) "
            "VALUES (:id,:name,:image,CAST(:queues AS JSONB),CAST(:capabilities AS JSONB),CAST(:versions AS JSONB),'online',:seen,NOW(),NOW()) "
            "ON CONFLICT (worker_name) DO UPDATE SET image_identity=EXCLUDED.image_identity,queues=EXCLUDED.queues,"
            "capabilities=EXCLUDED.capabilities,versions=EXCLUDED.versions,status='online',last_seen_at=EXCLUDED.last_seen_at,updated_at=NOW()"
        ), {
            "id": str(uuid.uuid4()), "name": snapshot["worker_name"], "image": snapshot["image_identity"],
            "queues": json.dumps(snapshot["queues"]), "capabilities": json.dumps(snapshot["capabilities"]),
            "versions": json.dumps(snapshot["versions"]), "seen": snapshot["last_seen_at"],
        })
        db.commit()
        _last_registration = now
        return snapshot
    finally:
        db.close()


def mark_worker_offline(worker_name: str | None = None) -> None:
    from app.services.celery_app import _get_sync_db

    db = _get_sync_db()
    try:
        db.execute(text("UPDATE worker_capabilities SET status='offline',updated_at=NOW() WHERE worker_name=:name"), {"name": _normalize_worker_name(worker_name)})
        db.commit()
    finally:
        db.close()


async def compatible_workers(db, queue: str, tool_plan: list[dict]) -> list[WorkerCapability]:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.WORKER_CAPABILITY_TTL_SECONDS)
    workers = (await db.execute(select(WorkerCapability).where(
        WorkerCapability.status == "online", WorkerCapability.last_seen_at >= cutoff,
        WorkerCapability.queues.contains([queue]),
    ))).scalars().all()
    required = {item["tool_id"] for item in tool_plan if item.get("required")}
    return [worker for worker in workers if required.issubset(set(worker.capabilities or []))]
