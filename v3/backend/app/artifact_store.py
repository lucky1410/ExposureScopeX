from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from .config import settings
from .db import pool


def _safe(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-")[:100] or "artifact"


async def persist_bytes(
    stage: dict,
    content: bytes,
    *,
    kind: str,
    name: str,
    media_type: str,
    metadata: dict | None = None,
) -> dict:
    digest = hashlib.sha256(content).hexdigest()
    suffix = Path(name).suffix
    relative = Path(str(stage["scan_id"])) / f"{stage['position']:02d}-{_safe(Path(name).stem)}-{digest[:12]}{suffix}"
    destination = Path(settings().artifact_root) / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_bytes(content)
        os.replace(temporary, destination)
    captured_at = datetime.now(timezone.utc)
    artifact_id = await pool().fetchval(
        """
        INSERT INTO artifacts (
          scan_id, stage_run_id, kind, storage_key, media_type, sha256,
          size_bytes, captured_at, metadata
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
        ON CONFLICT (storage_key) DO UPDATE SET storage_key = EXCLUDED.storage_key
        RETURNING id
        """,
        stage["scan_id"], stage.get("id"), kind, relative.as_posix(), media_type,
        digest, len(content), captured_at, {"original": True, **(metadata or {})},
    )
    return {
        "id": artifact_id, "sha256": digest, "storage_key": relative.as_posix(),
        "path": destination, "size_bytes": len(content), "captured_at": captured_at,
    }


async def persist_json(stage: dict, payload: dict | list, *, kind: str, name: str, metadata: dict | None = None) -> dict:
    content = json.dumps(payload, indent=2, sort_keys=True, default=str).encode("utf-8")
    return await persist_bytes(stage, content, kind=kind, name=name, media_type="application/json", metadata=metadata)


async def persist_text(stage: dict, content: str, *, kind: str, name: str, metadata: dict | None = None) -> dict:
    return await persist_bytes(stage, content.encode("utf-8", errors="replace"), kind=kind, name=name, media_type="text/plain; charset=utf-8", metadata=metadata)


def artifact_path(storage_key: str) -> Path:
    root = Path(settings().artifact_root).resolve()
    candidate = (root / storage_key).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("Artifact path escapes configured storage root")
    return candidate
