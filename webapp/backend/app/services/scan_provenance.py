"""Idempotent persistence helpers for scan events and scanner invocations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import uuid
from datetime import datetime
from functools import lru_cache

from sqlalchemy import text

from app.config import settings


_VERSION_COMMANDS = {
    "nuclei": ["nuclei", "-version"], "subfinder": ["subfinder", "-version"],
    "httpx": ["httpx", "-version"], "dnsx": ["dnsx", "-version"],
    "naabu": ["naabu", "-version"], "katana": ["katana", "-version"],
    "nmap": ["nmap", "--version"], "trivy": ["trivy", "--version"],
    "syft": ["syft", "version"], "grype": ["grype", "version"],
    "gitleaks": ["gitleaks", "version"], "ffuf": ["ffuf", "-V"],
    "amass": ["amass", "-version"], "sqlmap": ["sqlmap", "--version"],
    "arjun": ["arjun", "--version"],
}

_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s'\"]+"),
    re.compile(r"(?i)((?:api[-_]?key|token|password|secret)[=:\s]+)[^\s'\"]+"),
    re.compile(r"(?i)(--(?:token|password|api-key|secret)\s+)[^\s'\"]+"),
    re.compile(r"(https?://)[^/@\s]+:[^/@\s]+@"),
)

_SENSITIVE_FLAGS = {
    "--api-key", "--apikey", "--authorization", "--password", "--secret",
    "--token", "-password", "-secret", "-token",
}
_INPUT_FLAGS = {
    "-w": "wordlist", "--wordlist": "wordlist",
    "-t": "template", "--template": "template", "--templates": "template",
    "-config": "configuration", "--config": "configuration",
}


def _redact(value: str | None, limit: int) -> str | None:
    if not value:
        return None
    redacted = value
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(r"\1[REDACTED]", redacted)
    return redacted[-limit:]


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _path_identity(value: str, kind: str) -> dict:
    """Describe scanner input material without persisting host-specific absolute paths."""
    path = os.path.realpath(os.path.expanduser(value))
    identity = {"kind": kind, "name": os.path.basename(path) or value, "exists": os.path.exists(path)}
    try:
        if os.path.isfile(path):
            digest = hashlib.sha256()
            size = 0
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    size += len(chunk)
                    digest.update(chunk)
            identity.update({"type": "file", "size_bytes": size, "sha256": digest.hexdigest()})
        elif os.path.isdir(path):
            head_path = os.path.join(path, ".git", "HEAD")
            if os.path.isfile(head_path):
                head = open(head_path, encoding="utf-8").read().strip()
                if head.startswith("ref: "):
                    ref_path = os.path.join(path, ".git", head[5:])
                    if os.path.isfile(ref_path):
                        head = open(ref_path, encoding="utf-8").read().strip()
                identity["revision"] = head[:128]
            identity["type"] = "directory"
    except OSError:
        identity["readable"] = False
    return identity


def build_tool_execution_manifest(
    raw_command: str,
    *,
    tool: str,
    output_file: str | None = None,
    scan_metadata: dict | None = None,
) -> dict:
    """Build a stable, secret-safe record of what was requested and executed."""
    redacted_command = _redact(raw_command, 16000) or ""
    try:
        argv = shlex.split(redacted_command)
    except ValueError:
        argv = redacted_command.split()

    safe_argv: list[str] = []
    inputs: list[dict] = []
    skip_secret = False
    for index, token in enumerate(argv):
        lowered = token.lower()
        if skip_secret:
            safe_argv.append("[REDACTED]")
            skip_secret = False
            continue
        if lowered in _SENSITIVE_FLAGS:
            safe_argv.append(token)
            skip_secret = True
            continue
        safe_argv.append(token)
        input_kind = _INPUT_FLAGS.get(lowered)
        if input_kind and index + 1 < len(argv):
            inputs.append(_path_identity(argv[index + 1], input_kind))
        else:
            for flag, kind in _INPUT_FLAGS.items():
                if lowered.startswith(f"{flag}="):
                    inputs.append(_path_identity(token.split("=", 1)[1], kind))
                    break

    metadata = scan_metadata or {}
    policy = metadata.get("execution_policy") or {}
    profile = metadata.get("profile") or {
        "mode": metadata.get("mode"),
        "target_type": metadata.get("target_type"),
        "utilities": metadata.get("utilities") or [],
        "nuclei_tags": metadata.get("nuclei_tags") or [],
    }
    manifest = {
        "schema_version": 1,
        "tool": tool,
        "argv": safe_argv,
        "command_sha256": hashlib.sha256(redacted_command.encode()).hexdigest() if redacted_command else None,
        "scanner_image": settings.SCANNER_IMAGE_IDENTITY,
        "profile_sha256": _canonical_hash(profile),
        "policy_sha256": _canonical_hash(policy),
        "inputs": inputs,
        "output_name": os.path.basename(output_file) if output_file else None,
    }
    manifest["manifest_sha256"] = _canonical_hash(manifest)
    return manifest


@lru_cache(maxsize=64)
def _tool_version(tool: str) -> str | None:
    command = _VERSION_COMMANDS.get(tool.lower())
    if not command:
        return None
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
        output = " ".join((result.stdout or result.stderr).split())
        return output[:255] or None
    except (OSError, subprocess.SubprocessError):
        return None


def _timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def append_scan_event(db, scan_id: str, event_type: str, *, status: str | None, phase: str | None,
                      progress: int | None, message: str | None = None, payload: dict | None = None) -> None:
    db.execute(
        text(
            "INSERT INTO scan_events (id,scan_id,event_type,status,phase,progress,message,payload,created_at,updated_at) "
            "VALUES (:id,:scan_id,:event_type,:status,:phase,:progress,:message,CAST(:payload AS JSONB),NOW(),NOW())"
        ),
        {
            "id": str(uuid.uuid4()), "scan_id": scan_id, "event_type": event_type,
            "status": status, "phase": phase, "progress": progress,
            "message": (message or "")[:4000] or None,
            "payload": json.dumps(payload or {}),
        },
    )


def persist_tool_runs(db, scan_id: str, runs: list[dict]) -> int:
    row = db.execute(
        text("SELECT scan_metadata FROM scans WHERE id=:scan_id"), {"scan_id": scan_id}
    ).fetchone()
    scan_metadata = dict(row[0] or {}) if row else {}
    persisted = 0
    for run in runs:
        raw_command = str(run.get("command") or "")
        command = _redact(raw_command, 16000)
        started_at = _timestamp(run.get("started_at"))
        completed_at = _timestamp(run.get("completed_at"))
        duration_ms = None
        if started_at and completed_at:
            duration_ms = max(0, int((completed_at - started_at).total_seconds() * 1000))
        execution_manifest = build_tool_execution_manifest(
            raw_command,
            tool=str(run.get("tool") or "unknown"),
            output_file=str(run.get("output_file") or "") or None,
            scan_metadata=scan_metadata,
        )
        provenance = {
            "command_sha256": execution_manifest["command_sha256"],
            "source": "tool_runs.tsv",
            "scanner_image": settings.SCANNER_IMAGE_IDENTITY,
            "execution_manifest": execution_manifest,
            "manifest_sha256": execution_manifest["manifest_sha256"],
        }
        result = db.execute(
            text(
                "INSERT INTO scan_tool_runs "
                "(id,scan_id,external_id,tool,tool_version,status,exit_code,command,output_file,output_excerpt,started_at,completed_at,duration_ms,provenance,created_at,updated_at) "
                "VALUES (:id,:scan_id,:external_id,:tool,:tool_version,:status,:exit_code,:command,:output_file,:output_excerpt,:started_at,:completed_at,:duration_ms,CAST(:provenance AS JSONB),NOW(),NOW()) "
                "ON CONFLICT (scan_id,external_id) DO UPDATE SET status=EXCLUDED.status,exit_code=EXCLUDED.exit_code,"
                "tool_version=COALESCE(EXCLUDED.tool_version,scan_tool_runs.tool_version),"
                "command=EXCLUDED.command,output_file=EXCLUDED.output_file,output_excerpt=COALESCE(EXCLUDED.output_excerpt,scan_tool_runs.output_excerpt),"
                "started_at=COALESCE(EXCLUDED.started_at,scan_tool_runs.started_at),completed_at=EXCLUDED.completed_at,"
                "duration_ms=EXCLUDED.duration_ms,provenance=EXCLUDED.provenance,updated_at=NOW()"
            ),
            {
                "id": str(uuid.uuid4()), "scan_id": scan_id,
                "external_id": str(run.get("id") or uuid.uuid4())[:255],
                "tool": str(run.get("tool") or "unknown")[:100],
                "tool_version": _tool_version(str(run.get("tool") or "unknown")),
                "status": str(run.get("status") or "unknown")[:20],
                "exit_code": run.get("exit_code"), "command": command,
                "output_file": str(run.get("output_file") or "")[:1000] or None,
                "output_excerpt": _redact(str(run.get("output_excerpt") or ""), 12000),
                "started_at": started_at, "completed_at": completed_at,
                "duration_ms": duration_ms,
                "provenance": json.dumps(provenance),
            },
        )
        persisted += max(result.rowcount or 0, 0)
    return persisted
