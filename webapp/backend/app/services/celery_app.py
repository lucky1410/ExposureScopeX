"""Celery application instance and task definitions.

Tasks in this file are discovered by the worker container.
The ASM scan task replaces the FastAPI BackgroundTask approach,
giving us retries, monitoring, and proper queue separation.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import selectors
import subprocess
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from celery import Celery
from celery.signals import heartbeat_sent, worker_ready, worker_shutdown
from celery.utils.log import get_task_logger

from app.config import settings
from app.services.assessment_runtime import (
    advance_execution_manifest,
    calculate_work_progress,
    execution_coverage_summary,
    finalize_execution_manifest,
)

logger = get_task_logger(__name__)


def _purge_runtime_web_auth_secrets(session_dir: str | None) -> list[str]:
    """Remove reusable session material before artifacts are sealed or archived."""
    removed: list[str] = []
    if not session_dir:
        return removed
    root = Path(session_dir).resolve()
    for name in ("web-auth-cookie.txt", "web-auth-storage-state.json"):
        for path in root.rglob(name):
            try:
                path.unlink()
                removed.append(str(path.relative_to(root)))
            except OSError:
                logger.warning("Could not purge runtime web-auth material: %s", path)
    return removed


def _seal_worker_evidence(
    session_dir: str | None,
    *,
    scan_id: str | None,
    task_id: str,
    command: list[str] | None,
    log_lines: list[str],
    status: str,
    exit_code: int | None,
) -> dict | None:
    """Write one append-only terminal-attempt transcript before artifact ingestion."""
    if not session_dir:
        return None
    evidence_dir = Path(session_dir).resolve() / "forensic"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    safe_task_id = re.sub(r"[^A-Za-z0-9._-]", "_", task_id)[:120]
    transcript_name = f"worker-transcript-{safe_task_id}.log"
    context_name = f"execution-context-{safe_task_id}.json"
    transcript = ("\n".join(log_lines) + "\n").encode("utf-8", errors="replace")
    transcript_hash = hashlib.sha256(transcript).hexdigest()
    context = {
        "scan_id": scan_id,
        "task_id": task_id,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "exit_code": exit_code,
        "command": command,
        "scanner_image": settings.SCANNER_IMAGE_IDENTITY,
        "transcript": transcript_name,
        "transcript_size_bytes": len(transcript),
        "transcript_sha256": transcript_hash,
    }
    terminal_screenshot = None
    try:
        with (evidence_dir / transcript_name).open("xb") as handle:
            handle.write(transcript)
            handle.flush()
            os.fsync(handle.fileno())
        with (evidence_dir / context_name).open("xb") as handle:
            handle.write(json.dumps(context, indent=2, sort_keys=True).encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        # A redelivered task must never overwrite evidence from the original attempt.
        return {"status": "already_sealed", "transcript": transcript_name, "sha256": transcript_hash}
    capture_script = Path("/app/worker/evidence_capture.py")
    if capture_script.is_file():
        screenshot = evidence_dir / f"terminal-snapshot-{safe_task_id}.png"
        try:
            subprocess.run([
                "python", str(capture_script), "terminal",
                "--transcript", str(evidence_dir / transcript_name),
                "--output", str(screenshot),
                "--scan-id", str(scan_id or "untracked"),
                "--task-id", task_id,
            ], check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            terminal_screenshot = screenshot.name
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning("Runtime terminal screenshot capture failed for scan=%s: %s", scan_id, exc)
    return {
        "status": "sealed", "transcript": transcript_name, "sha256": transcript_hash,
        "terminal_screenshot": terminal_screenshot,
    }


def _capture_finding_screenshots(
    session_dir: str | None, *, task_id: str, scan_id: str | None,
    assessment_id: str, org_id: str, target: str = "",
) -> dict:
    """Capture every unique web finding URL before result ingestion and report generation."""
    if not session_dir:
        return {"status": "unavailable", "requested": 0, "captured": 0}
    root = Path(session_dir).resolve()
    capture_script = Path("/app/worker/evidence_capture.py")
    if not root.is_dir() or not capture_script.is_file():
        return {"status": "capture_runtime_unavailable", "requested": 0, "captured": 0}
    from app.services.scan_result_ingestion import _collect_findings, _finding_evidence_key

    findings = _collect_findings(root, target)
    urls = sorted({
        str(item.get("url")).strip()
        for item in findings
        if str(item.get("url") or "").startswith(("http://", "https://"))
    })
    safe_task_id = re.sub(r"[^A-Za-z0-9._-]", "_", task_id)[:120]
    evidence_dir = root / "forensic" / f"finding-screenshots-{safe_task_id}"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    capture_env = {
        **os.environ,
        "EXPOSURESCOPEX_ORG_ID": org_id,
        "EXPOSURESCOPEX_ASSESSMENT_ID": assessment_id,
        "EXPOSURESCOPEX_SCAN_ID": str(scan_id or "untracked"),
        "EXPOSURESCOPEX_TASK_ID": task_id,
        "EXPOSURESCOPEX_SCANNER_IMAGE": settings.SCANNER_IMAGE_IDENTITY,
    }
    urls_file = evidence_dir / "finding-urls.txt"
    urls_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
    if urls:
        try:
            subprocess.run([
                "python", str(capture_script), "browser",
                "--urls-file", str(urls_file),
                "--output-dir", str(evidence_dir),
                "--limit", str(len(urls)),
            ], env=capture_env, check=True, timeout=max(90, len(urls) * 40 + 30), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning("Per-finding browser evidence capture failed: %s", exc)
    captured = 0
    for screenshot in evidence_dir.glob("playwright-*.png"):
        sidecar = screenshot.with_suffix(screenshot.suffix + ".json")
        try:
            metadata = json.loads(sidecar.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if metadata.get("capture_type") == "playwright_browser":
            captured += 1
    terminal_captured = 0
    terminal_failed = 0
    seen_finding_keys: set[str] = set()
    for index, finding in enumerate(findings, start=1):
        finding_key = _finding_evidence_key(finding)
        if finding_key in seen_finding_keys:
            continue
        seen_finding_keys.add(finding_key)
        source_label = str(finding.get("_artifact_path") or "")
        source_artifact = (root / source_label).resolve()
        if not source_label or not source_artifact.is_relative_to(root) or not source_artifact.is_file():
            terminal_failed += 1
            continue
        key_digest = hashlib.sha256(finding_key.encode()).hexdigest()[:12]
        terminal_screenshot = evidence_dir / f"finding-terminal-{index:03d}-{key_digest}.png"
        command = [
            "python", str(capture_script), "finding-terminal",
            "--source-artifact", str(source_artifact),
            "--source-label", source_label,
            "--output", str(terminal_screenshot),
            "--scan-id", str(scan_id or "untracked"),
            "--task-id", task_id,
            "--finding-key", finding_key,
        ]
        for term in (finding.get("template_id"), finding.get("url"), finding.get("title")):
            if term:
                command.extend(("--match", str(term)[:300]))
        try:
            subprocess.run(
                command, env=capture_env, check=True, timeout=30,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            terminal_captured += 1
        except (OSError, subprocess.SubprocessError) as exc:
            terminal_failed += 1
            logger.warning("Finding terminal evidence capture failed for %s: %s", finding_key[:120], exc)
    return {
        "status": "captured" if captured == len(urls) else "incomplete",
        "requested": len(urls), "captured": captured, "failed": len(urls) - captured,
        "finding_terminal_requested": len(seen_finding_keys),
        "finding_terminal_captured": terminal_captured,
        "finding_terminal_failed": terminal_failed,
    }


def _capture_tool_run_screenshots(
    session_dir: str | None, *, task_id: str, scan_id: str | None,
    assessment_id: str, org_id: str,
) -> dict:
    """Capture one real xterm image from each terminal tool-run output artifact."""
    if not session_dir:
        return {"status": "unavailable", "requested": 0, "captured": 0}
    root = Path(session_dir).resolve()
    registry = root / "tool_runs.tsv"
    capture_script = Path("/app/worker/evidence_capture.py")
    if not registry.is_file() or not capture_script.is_file():
        return {"status": "not_available", "requested": 0, "captured": 0}
    terminal_runs: dict[str, list[str]] = {}
    for raw in registry.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = raw.split("\t", 7)
        if len(fields) == 8 and fields[2] != "running":
            terminal_runs[fields[0]] = fields
    evidence_dir = root / "forensic" / f"tool-run-screenshots-{re.sub(r'[^A-Za-z0-9._-]', '_', task_id)[:120]}"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    capture_env = {
        **os.environ,
        "EXPOSURESCOPEX_ORG_ID": org_id,
        "EXPOSURESCOPEX_ASSESSMENT_ID": assessment_id,
        "EXPOSURESCOPEX_SCAN_ID": str(scan_id or "untracked"),
        "EXPOSURESCOPEX_TASK_ID": task_id,
        "EXPOSURESCOPEX_SCANNER_IMAGE": settings.SCANNER_IMAGE_IDENTITY,
    }
    captured = 0
    failed = 0
    for index, (run_id, fields) in enumerate(sorted(terminal_runs.items()), start=1):
        _, tool, status, _exit_code, _started, _completed, command_text, output_label = fields
        source = (root / output_label).resolve()
        if not output_label or not source.is_relative_to(root) or not source.is_file():
            failed += 1
            continue
        tool_slug = re.sub(r"[^A-Za-z0-9._-]", "_", tool)[:40]
        screenshot = evidence_dir / (
            f"tool-terminal-{index:03d}-{tool_slug}-{hashlib.sha256(run_id.encode()).hexdigest()[:10]}.png"
        )
        try:
            subprocess.run([
                "python", str(capture_script), "tool-terminal",
                "--source-artifact", str(source),
                "--source-label", output_label,
                "--output", str(screenshot),
                "--scan-id", str(scan_id or "untracked"),
                "--task-id", task_id,
                "--run-id", run_id,
                "--tool", tool,
                "--status", status,
                "--command", command_text,
            ], env=capture_env, check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            captured += 1
        except (OSError, subprocess.SubprocessError) as exc:
            failed += 1
            logger.warning("Tool terminal evidence capture failed for %s: %s", run_id, exc)
    return {
        "status": "captured" if captured == len(terminal_runs) else "incomplete",
        "requested": len(terminal_runs), "captured": captured, "failed": failed,
    }


@worker_ready.connect
def _advertise_worker(sender=None, **kwargs):
    try:
        from app.services.worker_capabilities import register_worker_capabilities
        register_worker_capabilities(getattr(sender, "hostname", None), force=True)
    except Exception:
        logger.exception("Worker capability registration failed")


@heartbeat_sent.connect
def _refresh_worker_advertisement(sender=None, **kwargs):
    try:
        from app.services.worker_capabilities import register_worker_capabilities
        register_worker_capabilities(getattr(sender, "hostname", None))
    except Exception:
        logger.warning("Worker capability heartbeat failed", exc_info=True)


@worker_shutdown.connect
def _retire_worker(sender=None, **kwargs):
    try:
        from app.services.worker_capabilities import mark_worker_offline
        mark_worker_offline(getattr(sender, "hostname", None))
    except Exception:
        logger.warning("Worker capability shutdown update failed", exc_info=True)

# ── App ───────────────────────────────────────────────────────────────────────

celery_app = Celery(
    "exposurescopex",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    # Serialisation
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    broker_connection_retry_on_startup=True,
    # Scans can run for many hours. Redis' one-hour default visibility window
    # otherwise redelivers the same unacknowledged task while it is still active.
    broker_transport_options={"visibility_timeout": 172800, "queue_order_strategy": "priority"},
    result_backend_transport_options={"visibility_timeout": 172800},
    # Timezone
    timezone="UTC",
    enable_utc=True,
    # Reliability
    task_acks_late=True,           # ack only after completion
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,  # one task at a time per worker slot
    # Retries
    task_max_retries=3,
    task_default_retry_delay=60,   # seconds
    # Result TTL
    result_expires=86400,          # 24 h
    # Queues
    task_default_queue="default",
    task_queues={
        "default": {"exchange": "default", "routing_key": "default"},
        "scans": {"exchange": "scans", "routing_key": "scans"},
        "scans-web": {"exchange": "scans-web", "routing_key": "scans-web"},
        "scans-api": {"exchange": "scans-api", "routing_key": "scans-api"},
        "scans-artifact": {"exchange": "scans-artifact", "routing_key": "scans-artifact"},
        "scans-cloud": {"exchange": "scans-cloud", "routing_key": "scans-cloud"},
        "scans-mobile": {"exchange": "scans-mobile", "routing_key": "scans-mobile"},
        "reports": {"exchange": "reports", "routing_key": "reports"},
    },
    task_routes={
        "app.services.celery_app.run_asm_scan": {"queue": "scans"},
        "app.services.celery_app.run_mcp_security_scan": {"queue": "scans-api"},
        "app.services.celery_app.generate_report_task": {"queue": "reports"},
    },
)


@celery_app.task(
    bind=True,
    name="app.services.celery_app.generate_report_task",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 2},
    soft_time_limit=570,
    time_limit=600,
)
def generate_report_task(self, report_id: str) -> dict:
    from app.services.report_jobs import materialize_report

    return asyncio.run(materialize_report(report_id))


@celery_app.task(name="app.services.celery_app.dispatch_due_scan_schedules", queue="default")
def dispatch_due_scan_schedules() -> dict:
    from app.services.scan_scheduler import dispatch_due_schedules

    return asyncio.run(dispatch_due_schedules())


@celery_app.task(name="app.services.celery_app.finding_lifecycle_maintenance", queue="default")
def finding_lifecycle_maintenance() -> dict:
    from app.services.finding_lifecycle import backfill_finding_observations, reopen_expired_suppressions

    return {
        "suppressions_reopened": asyncio.run(reopen_expired_suppressions()),
        "observations_backfilled": asyncio.run(backfill_finding_observations()),
    }


# ── Helpers (sync wrappers around async scan logic) ──────────────────────────

def _get_sync_db():
    """Return a synchronous SQLAlchemy session for use inside Celery tasks."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    # Convert asyncpg URL to psycopg2-style URL for sync access
    sync_url = settings.DATABASE_URL.replace("+asyncpg", "")
    engine = create_engine(sync_url, pool_pre_ping=True)
    Session = sessionmaker(bind=engine)
    return Session()


def _publish_progress(scan_id: str, event: str, payload: dict) -> None:
    """Publish a scan progress event to Redis for WebSocket delivery."""
    import json
    import redis

    try:
        r = redis.from_url(settings.REDIS_URL)
        message = json.dumps({"scan_id": scan_id, "event": event, **payload})
        r.publish(f"scan:{scan_id}", message)
    except Exception as exc:
        logger.warning("Redis publish failed: %s", exc)


def _update_scan_row(
    scan_id: str | None,
    *,
    status: str,
    current_phase: str | None = None,
    progress: int | None = None,
    error_message: str | None = None,
    raw_log: str | None = None,
    session_dir: str | None = None,
    extra_metadata: dict | None = None,
    manifest_status: str | None = None,
    manifest_message: str | None = None,
    completed: bool = False,
) -> None:
    """Best-effort scan row updates from task execution paths."""
    if not scan_id:
        return

    from sqlalchemy import text as sqla_text

    db = _get_sync_db()
    try:
        row = db.execute(
            sqla_text("SELECT scan_metadata,status,current_phase,progress FROM scans WHERE id=:id"),
            {"id": scan_id},
        ).fetchone()
        metadata = dict(row[0] or {}) if row else {}
        previous_status = row[1] if row else None
        previous_phase = row[2] if row else None
        previous_progress = row[3] if row else None
        if extra_metadata:
            metadata.update(extra_metadata)
        if current_phase:
            stage_status = manifest_status or {
                "failed": "failed",
                "cancelled": "cancelled",
                "timeout": "failed",
                "worker_lost": "failed",
            }.get(current_phase, "running")
            metadata = advance_execution_manifest(
                metadata,
                current_phase,
                status=stage_status,
                message=manifest_message or error_message,
            )
        if completed:
            metadata = finalize_execution_manifest(metadata, status)
        weighted_progress, work_units = calculate_work_progress(metadata, progress, status)
        telemetry = dict(metadata.get("telemetry") or {})
        telemetry["work_units"] = work_units
        metadata["telemetry"] = telemetry
        progress = weighted_progress

        params = {
            "id": scan_id,
            "status": status,
            "current_phase": current_phase,
            "progress": progress,
            "error_message": error_message,
            "raw_log": raw_log,
            "session_dir": session_dir,
            "scan_metadata": json.dumps(metadata),
            "completed_at": datetime.now(timezone.utc) if completed else None,
            "heartbeat_at": datetime.now(timezone.utc) if status in {"queued", "running"} else None,
        }
        db.execute(
            sqla_text(
                "UPDATE scans SET status=:status, current_phase=COALESCE(:current_phase, current_phase), "
                "progress=COALESCE(:progress, progress), error_message=:error_message, "
                "raw_log=COALESCE(:raw_log, raw_log), session_dir=COALESCE(:session_dir, session_dir), "
                "scan_metadata=CAST(:scan_metadata AS JSONB), completed_at=COALESCE(:completed_at, completed_at), "
                "heartbeat_at=COALESCE(:heartbeat_at, heartbeat_at), "
                "updated_at=NOW() WHERE id=:id"
            ),
            params,
        )
        if row and (previous_status, previous_phase, previous_progress) != (
            status, current_phase or previous_phase, progress if progress is not None else previous_progress
        ):
            from app.services.scan_provenance import append_scan_event

            append_scan_event(
                db, scan_id, "state_changed", status=status,
                phase=current_phase or previous_phase,
                progress=progress if progress is not None else previous_progress,
                message=error_message,
            )
        db.commit()
    finally:
        db.close()


@celery_app.task(bind=True, name="app.services.celery_app.run_mcp_security_scan")
def run_mcp_security_scan(self, run_id: str, encrypted_payload: str) -> dict:
    """Execute an MCP audit with encrypted credentials and cooperative cancellation."""
    from sqlalchemy import select

    from app.models.mcp_security import McpSecurityRun
    from app.services.mcp_jobs import clear_mcp_cancel, decrypt_mcp_payload, mcp_cancel_requested
    from app.services.mcp_security import (
        McpAuditCancelled,
        McpAuditError,
        McpExecutionProfile,
        run_mcp_audit,
    )

    db = _get_sync_db()
    try:
        run = db.get(McpSecurityRun, uuid.UUID(run_id))
        if not run:
            return {"status": "deleted", "run_id": run_id}
        if run.status in {"cancel_requested", "cancelled"} or mcp_cancel_requested(run_id):
            run.status = "cancelled"
            run.completed_at = datetime.now(timezone.utc)
            run.summary = {**(run.summary or {}), "progress": 0, "current_step": "cancelled"}
            db.commit()
            return {"status": "cancelled", "run_id": run_id}

        payload = decrypt_mcp_payload(encrypted_payload)
        run.status = "running"
        run.summary = {**(run.summary or {}), "progress": 2, "current_step": "validating endpoint"}
        db.commit()

        previous = db.execute(
            select(McpSecurityRun).where(
                McpSecurityRun.org_id == run.org_id,
                McpSecurityRun.endpoint == payload["endpoint"],
                McpSecurityRun.status == "completed",
                McpSecurityRun.id != run.id,
            ).order_by(McpSecurityRun.created_at.desc()).limit(1)
        ).scalar_one_or_none()
        profile_data = payload.get("profile") or {}
        estimated_steps = 30
        estimated_steps += int(profile_data.get("max_concurrency") or 4) if profile_data.get("secondary_bearer_token") else 0
        estimated_steps += 12 if profile_data.get("enable_deep_tests") else 0
        estimated_steps += 4 if profile_data.get("test_task_id") else 0
        estimated_steps += 3 if profile_data.get("cross_server_endpoint") else 0
        completed_steps = 0

        def on_exchange(name: str, _probe_count: int) -> None:
            nonlocal completed_steps
            completed_steps += 1
            if completed_steps % 2 and completed_steps < estimated_steps:
                return
            progress = min(95, max(3, int(completed_steps / max(estimated_steps, 1) * 95)))
            progress_db = _get_sync_db()
            try:
                progress_run = progress_db.get(McpSecurityRun, uuid.UUID(run_id))
                if progress_run:
                    progress_run.summary = {
                        **(progress_run.summary or {}),
                        "progress": progress,
                        "current_step": name,
                        "completed_steps": completed_steps,
                        "estimated_steps": estimated_steps,
                    }
                    progress_db.commit()
            finally:
                progress_db.close()

        result = asyncio.run(run_mcp_audit(
            payload["endpoint"],
            payload.get("bearer_token"),
            allow_private=bool(payload.get("allow_private")),
            protocol_tests=bool(payload.get("protocol_tests", True)),
            profile=McpExecutionProfile(**profile_data),
            previous_inventory=previous.inventory if previous else None,
            should_cancel=lambda: mcp_cancel_requested(run_id),
            on_exchange=on_exchange,
        ))

        db.expire_all()
        run = db.get(McpSecurityRun, uuid.UUID(run_id))
        if not run:
            return {"status": "deleted", "run_id": run_id}
        run.endpoint = result["endpoint"]
        run.status = "completed"
        run.overall_severity = result["overall_severity"]
        run.risk_score = result["risk_score"]
        run.summary = {**result["summary"], "progress": 100, "current_step": "completed"}
        run.inventory = result["inventory"]
        run.findings = result["findings"]
        run.exchanges = result["exchanges"]
        run.error_message = None
        run.completed_at = datetime.now(timezone.utc)
        db.commit()
        return {"status": "completed", "run_id": run_id}
    except McpAuditCancelled as exc:
        db.rollback()
        run = db.get(McpSecurityRun, uuid.UUID(run_id))
        if run:
            run.status = "cancelled"
            run.exchanges = exc.exchanges
            run.summary = {
                **(run.summary or {}),
                "current_step": "cancelled",
                "exchanges": len(exc.exchanges),
                "completed_steps": len(exc.exchanges),
            }
            run.completed_at = datetime.now(timezone.utc)
            db.commit()
        return {"status": "cancelled", "run_id": run_id}
    except (McpAuditError, ValueError) as exc:
        db.rollback()
        run = db.get(McpSecurityRun, uuid.UUID(run_id))
        if run:
            run.status = "failed"
            run.error_message = str(exc)[:1000]
            run.summary = {**(run.summary or {}), "current_step": "failed"}
            run.completed_at = datetime.now(timezone.utc)
            db.commit()
        return {"status": "failed", "run_id": run_id}
    except Exception as exc:
        logger.exception("MCP security scan failed: run=%s", run_id)
        db.rollback()
        run = db.get(McpSecurityRun, uuid.UUID(run_id))
        if run:
            run.status = "failed"
            run.error_message = f"MCP assessment failed safely: {type(exc).__name__}"
            run.summary = {**(run.summary or {}), "current_step": "failed"}
            run.completed_at = datetime.now(timezone.utc)
            db.commit()
        return {"status": "failed", "run_id": run_id}
    finally:
        try:
            clear_mcp_cancel(run_id)
        except Exception:
            logger.warning("Could not clear MCP cancellation flag: run=%s", run_id)
        db.close()


def _scan_row_state(scan_id: str | None) -> tuple[str | None, dict]:
    """Return the current scan status and metadata."""
    if not scan_id:
        return None, {}

    from sqlalchemy import text as sqla_text

    db = _get_sync_db()
    try:
        row = db.execute(
            sqla_text("SELECT status, scan_metadata FROM scans WHERE id=:id"),
            {"id": scan_id},
        ).fetchone()
        if not row:
            return None, {}
        return row[0], dict(row[1] or {})
    finally:
        db.close()


def _scan_cancel_requested(scan_id: str | None) -> bool:
    status, metadata = _scan_row_state(scan_id)
    return status == "cancelled" or bool((metadata or {}).get("cancel_requested"))


def _touch_scan_heartbeat(scan_id: str) -> None:
    """Refresh liveness without changing state owned by the isolated child."""
    from sqlalchemy import text as sqla_text

    db = _get_sync_db()
    try:
        db.execute(
            sqla_text("UPDATE scans SET heartbeat_at=NOW(), updated_at=NOW() WHERE id=:id"),
            {"id": scan_id},
        )
        db.commit()
    finally:
        db.close()


def _read_tool_runs(session_dir: str, *, include_output: bool = False) -> list[dict]:
    """Return the latest structured state for each scanner invocation."""
    status_file = Path(session_dir) / "tool_runs.tsv"
    if not status_file.is_file():
        return []
    runs: dict[str, dict] = {}
    try:
        for line in status_file.read_text(encoding="utf-8", errors="replace").splitlines():
            fields = line.split("\t")
            if len(fields) < 6:
                continue
            run_id, tool, status, exit_code, started_at, completed_at = fields[:6]
            command = fields[6] if len(fields) > 6 else None
            output_file = fields[7] if len(fields) > 7 else None
            output_excerpt = None
            if output_file and include_output:
                candidate = Path(output_file)
                if not candidate.is_absolute():
                    candidate = Path(session_dir) / candidate
                try:
                    session_root = Path(session_dir).resolve()
                    candidate = candidate.resolve()
                    if candidate.is_relative_to(session_root) and candidate.is_file():
                        output_excerpt = candidate.read_text(
                            encoding="utf-8", errors="replace"
                        )[-12000:]
                except OSError:
                    output_excerpt = None
            runs[run_id] = {
                "id": run_id,
                "tool": tool,
                "status": status,
                "exit_code": int(exit_code) if exit_code.isdigit() else None,
                "started_at": started_at or None,
                "completed_at": completed_at or None,
                "command": command or None,
                "output_file": output_file or None,
                "output_excerpt": output_excerpt,
            }
    except OSError as exc:
        logger.warning("Could not read tool execution state from %s: %s", status_file, exc)
    return list(runs.values())


def _read_scan_summary_files(session_dir: str) -> dict:
    """Return best-effort specialized and batch summaries plus a compact artifact manifest."""
    root = Path(session_dir)
    summary = {
        "specialized_summary": None,
        "batch_summary": None,
        "artifacts": [],
    }
    if not root.is_dir():
        return summary
    for name, key in (("specialized_summary.json", "specialized_summary"), ("batch_summary.json", "batch_summary")):
        candidate = root / name
        if not candidate.is_file():
            continue
        try:
            summary[key] = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            summary[key] = None
    try:
        summary["artifacts"] = sorted(
            str(path.relative_to(root))
            for path in root.rglob("*")
            if path.is_file()
        )[:500]
    except OSError:
        summary["artifacts"] = []
    return summary


def _claim_scan_execution(scan_id: str | None, task_id: str) -> tuple[bool, str]:
    """Atomically reject stale task IDs and terminal scan redeliveries."""
    if not scan_id:
        return True, "untracked"

    from sqlalchemy import text as sqla_text

    db = _get_sync_db()
    try:
        row = db.execute(
            sqla_text("SELECT status, celery_task_id FROM scans WHERE id=:id FOR UPDATE"),
            {"id": scan_id},
        ).fetchone()
        if not row:
            return False, "scan_not_found"
        status, assigned_task_id = row
        if status in {"completed", "partial", "failed", "cancelled"}:
            return False, f"already_{status}"
        if assigned_task_id and assigned_task_id != task_id:
            return False, "superseded_task"
        if not assigned_task_id:
            db.execute(
                sqla_text("UPDATE scans SET celery_task_id=:task_id WHERE id=:id"),
                {"id": scan_id, "task_id": task_id},
            )
            db.commit()
        return True, "claimed"
    finally:
        db.close()


_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_PHASE_MARKERS = (
    ("starting image reference preflight", "preflight", 2),
    ("starting image inventory", "image_inventory", 20),
    ("starting primary image vulnerability scan", "image_vulnerability", 48),
    ("starting secondary image sbom inventory", "image_sbom", 72),
    ("starting secondary image correlation", "image_correlation", 86),
    ("starting cloud account preflight", "preflight", 2),
    ("starting cloud inventory", "cloud_inventory", 18),
    ("starting primary cspm execution", "cspm_primary", 45),
    ("starting secondary posture validation", "cspm_secondary", 62),
    ("starting cloud iam analysis", "iam_analysis", 76),
    ("starting cloud compliance correlation", "compliance", 88),
    ("starting brand and seed preparation", "brand_seeds", 18),
    ("starting domain discovery", "domain_discovery", 45),
    ("starting repository discovery", "repo_discovery", 62),
    ("starting repository inventory", "repo_inventory", 15),
    ("starting secret scanning", "secrets", 40),
    ("starting dependency scanning", "dependencies", 65),
    ("generating software bill of materials", "sbom", 82),
    ("checking supply chain provenance", "provenance", 90),
    ("starting mcp discovery", "mcp_discovery", 15),
    ("starting mcp protocol testing", "mcp_protocol", 32),
    ("starting mcp authorization testing", "mcp_auth", 48),
    ("starting mcp inventory", "mcp_inventory", 62),
    ("starting mcp isolation testing", "mcp_isolation", 75),
    ("starting mcp semantic analysis", "mcp_semantic", 88),
    ("starting mcp drift analysis", "mcp_drift", 92),
    ("starting asn and bgp inventory", "asn_inventory", 15),
    ("starting prefix inventory", "prefix_inventory", 40),
    ("starting routing correlation", "routing_correlation", 70),
    ("starting passive reconnaissance", "passive_recon", 8),
    ("starting passive enumeration", "enumeration", 15),
    ("checking for potential subdomain takeovers", "enumeration_takeovers", 17),
    ("probing live hosts", "enumeration_live_hosts", 20),
    ("fetching historical urls", "enumeration_history", 23),
    ("starting dns reconnaissance", "dns_recon", 25),
    ("starting osint", "osint", 32),
    ("starting port scanning", "port_scan", 40),
    ("starting ssl/tls", "ssl_tls", 50),
    ("starting cloud security", "cloud", 57),
    ("starting web crawler", "crawler", 63),
    ("starting web application testing", "web_testing", 70),
    ("starting api security testing", "api_security", 76),
    ("capturing screenshots", "screenshots", 80),
    ("starting vulnerability scanning", "nuclei", 85),
    ("starting cve correlation", "cve_correlation", 90),
    ("generating report", "reporting", 95),
    ("session complete", "finalizing", 99),
)


def _scan_phase_from_line(line: str) -> tuple[str, int] | None:
    normalized = _ANSI_ESCAPE.sub("", line).lower()
    for marker, phase, progress in _PHASE_MARKERS:
        if marker in normalized:
            return phase, progress
    return None


def _scan_stage_outcome_from_line(line: str) -> tuple[str, str, str] | None:
    """Parse explicit stage outcomes emitted by the shell runner."""
    normalized = _ANSI_ESCAPE.sub("", line)
    match = re.search(
        r"\[stage-(start|completed|timeout|warning)\]\s+([a-z0-9_]+):\s*(.+)$",
        normalized,
        re.IGNORECASE,
    )
    if not match:
        return None
    status = {
        "start": "running",
        "completed": "completed",
        "timeout": "timed_out",
        "warning": "warning",
    }[match.group(1).lower()]
    return match.group(2).lower(), status, match.group(3).strip()


def _publish_assessment_progress(
    assessment_id: str,
    scan_id: str | None,
    event: str,
    payload: dict,
) -> None:
    """Publish to both stable scan and legacy assessment channels."""
    if scan_id:
        _publish_progress(scan_id, event, payload)
    if assessment_id != scan_id:
        _publish_progress(assessment_id, event, payload)


def _queue_terminal_document_report(
    assessment_id: str, org_id: str, scan_id: str | None, terminal_status: str,
) -> dict | None:
    """Queue the mandatory per-scan DOCX without changing the terminal outcome."""
    if not scan_id:
        return None
    try:
        from app.services.report_jobs import enqueue_automatic_scan_report

        return asyncio.run(enqueue_automatic_scan_report(
            assessment_id=assessment_id,
            org_id=org_id,
            scan_id=scan_id,
            terminal_status=terminal_status,
        ))
    except Exception:
        logger.exception("Could not queue automatic scan report: scan=%s", scan_id)
        return None


def _ingest_scan_results(
    *, org_id: str, assessment_id: str, scan_id: str, session_dir: str,
) -> dict:
    """Normalize all artifacts available at a terminal scan boundary."""
    from app.services.scan_result_ingestion import ingest_assessment_scan

    result = asyncio.run(ingest_assessment_scan(
        org_id=org_id,
        assessment_id=assessment_id,
        scan_id=scan_id,
        session_dir=session_dir,
    ))
    from app.services.eventing import dispatch_scan_exposure_events

    result["events_dispatched"] = asyncio.run(
        dispatch_scan_exposure_events(org_id, scan_id)
    )
    from app.services.artifact_storage import archive_scan_directory

    archived_key = archive_scan_directory(org_id, scan_id, session_dir)
    if archived_key:
        result["artifact_object_key"] = archived_key
    return result


def _preserve_terminal_scan_outputs(
    *, org_id: str, assessment_id: str, scan_id: str, session_dir: str,
    task_id: str, command: list[str] | None, log_lines: list[str],
    status: str, exit_code: int | None, target: str = "",
) -> dict:
    """Best-effort terminal preservation where one failed step cannot block another."""
    result = {
        "finding_screenshot_capture": None,
        "tool_screenshot_capture": None,
        "evidence_seal": None,
        "ingestion_result": None,
        "errors": [],
    }
    try:
        result["finding_screenshot_capture"] = _capture_finding_screenshots(
            session_dir, task_id=task_id, scan_id=scan_id,
            assessment_id=assessment_id, org_id=org_id, target=target,
        )
    except Exception as exc:
        result["errors"].append(f"Finding screenshot capture failed: {exc}"[:1000])
        logger.exception("Could not capture terminal finding evidence: scan=%s", scan_id)
    try:
        result["tool_screenshot_capture"] = _capture_tool_run_screenshots(
            session_dir, task_id=task_id, scan_id=scan_id,
            assessment_id=assessment_id, org_id=org_id,
        )
    except Exception as exc:
        result["errors"].append(f"Tool screenshot capture failed: {exc}"[:1000])
        logger.exception("Could not capture tool-run evidence: scan=%s", scan_id)
    try:
        _purge_runtime_web_auth_secrets(session_dir)
    except Exception as exc:
        result["errors"].append(f"Authentication secret purge failed: {exc}"[:1000])
        logger.exception("Could not purge terminal authentication secrets: scan=%s", scan_id)
    try:
        result["evidence_seal"] = _seal_worker_evidence(
            session_dir, scan_id=scan_id, task_id=task_id,
            command=command, log_lines=log_lines, status=status, exit_code=exit_code,
        )
    except Exception as exc:
        result["errors"].append(f"Evidence sealing failed: {exc}"[:1000])
        logger.exception("Could not seal terminal evidence: scan=%s", scan_id)
    try:
        result["ingestion_result"] = _ingest_scan_results(
            org_id=org_id, assessment_id=assessment_id, scan_id=scan_id,
            session_dir=session_dir,
        )
    except Exception as exc:
        result["errors"].append(f"Partial result ingestion failed: {exc}"[:1000])
        logger.exception("Could not ingest terminal scan artifacts: scan=%s", scan_id)
    return result


# ── Tasks ─────────────────────────────────────────────────────────────────────

@celery_app.task(
    name="app.services.celery_app.run_asm_scan",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    queue="scans",
)
def run_asm_scan(self, target_id: str, org_id: str) -> dict:
    """Run all ASM scan checks for a single AsmTarget (sync Celery task).

    Imports the async scan helpers and runs them inside asyncio.run().
    Results are written to asm_findings table and asm_targets.last_scan_summary.
    """
    import asyncio
    from app.api.v1.asm import _run_asm_scan as _async_scan

    task_id = self.request.id
    logger.info("ASM scan started: target=%s task=%s", target_id, task_id)
    _publish_progress(target_id, "scan.started", {"target_id": target_id, "task_id": task_id})

    try:
        asyncio.run(_async_scan(target_id, org_id))
        _publish_progress(target_id, "scan.completed", {"target_id": target_id})
        logger.info("ASM scan completed: target=%s", target_id)
        return {"status": "completed", "target_id": target_id}
    except Exception as exc:
        _publish_progress(target_id, "scan.failed", {"target_id": target_id, "error": str(exc)})
        logger.error("ASM scan failed: target=%s error=%s", target_id, exc)
        raise self.retry(exc=exc)


def _run_assessment_scan_impl(self, assessment_id: str, org_id: str, scan_id: str | None = None) -> dict:
    """Celery wrapper around the shared assessment scan execution path."""
    import os

    if settings.SCAN_EXECUTOR == "kubernetes" and os.getenv("EXSX_ISOLATED_JOB") != "1":
        if not scan_id:
            raise ValueError("Kubernetes scan isolation requires a persisted scan identifier")
        from app.services.kubernetes_executor import execute_in_kubernetes_job

        _update_scan_row(
            scan_id,
            status="queued",
            current_phase="isolated_dispatch",
            progress=1,
            extra_metadata={"executor": "kubernetes", "dispatch_task_id": self.request.id},
        )
        try:
            result = execute_in_kubernetes_job(
                assessment_id,
                org_id,
                scan_id,
                task_id=self.request.id,
                cancel_requested=lambda: _scan_cancel_requested(scan_id),
                heartbeat=lambda: _touch_scan_heartbeat(scan_id),
            )
            if result.get("status") == "cancelled":
                _update_scan_row(
                    scan_id,
                    status="cancelled",
                    current_phase="cancelled",
                    completed=True,
                    extra_metadata={"executor": "kubernetes", "job_name": result.get("job_name")},
                )
                _queue_terminal_document_report(assessment_id, org_id, scan_id, "cancelled")
            return result
        except Exception as exc:
            _update_scan_row(
                scan_id,
                status="failed",
                current_phase="isolated_dispatch_failed",
                completed=True,
                error_message=f"Isolated scan execution failed: {type(exc).__name__}",
                extra_metadata={"executor": "kubernetes"},
            )
            _queue_terminal_document_report(assessment_id, org_id, scan_id, "failed")
            raise
    return execute_assessment_scan(
        assessment_id,
        org_id,
        scan_id=scan_id,
        task_id=self.request.id,
    )


@celery_app.task(
    name="app.services.celery_app.run_assessment_scan",
    bind=True,
    max_retries=None,
)
def run_assessment_scan(self, assessment_id: str, org_id: str, scan_id: str | None = None) -> dict:
    """Acquire a distributed tenant slot before entering the scan executor."""
    from app.services.tenant_scheduling import acquire_execution_lease, release_execution_lease

    task_id = self.request.id
    if _scan_cancel_requested(scan_id):
        _update_scan_row(
            scan_id, status="cancelled", current_phase="cancelled",
            progress=0, completed=True,
            extra_metadata={"cancelled_while_queued": True},
        )
        _queue_terminal_document_report(assessment_id, org_id, scan_id, "cancelled")
        return {"status": "cancelled", "assessment_id": assessment_id, "scan_id": scan_id}
    scan_status, metadata = _scan_row_state(scan_id)
    ttl = int((metadata.get("execution_policy") or {}).get("timeout_seconds") or 7200) + 900
    if not acquire_execution_lease(org_id, task_id, ttl):
        _touch_scan_heartbeat(scan_id) if scan_id else None
        raise self.retry(countdown=min(60, 10 + int(self.request.retries or 0) * 2))
    try:
        try:
            from app.services.worker_capabilities import capability_snapshot

            worker = capability_snapshot(getattr(self.request, "hostname", None))
            worker["last_seen_at"] = worker["last_seen_at"].isoformat()
            _update_scan_row(
                scan_id,
                status=scan_status or "running",
                extra_metadata={"worker_manifest": worker},
            )
        except Exception:
            logger.warning("Could not persist worker manifest for scan=%s", scan_id, exc_info=True)
        return _run_assessment_scan_impl(self, assessment_id, org_id, scan_id)
    finally:
        try:
            release_execution_lease(org_id, task_id)
        except Exception:
            logger.warning("Could not release tenant execution lease: org=%s task=%s", org_id, task_id)


def execute_assessment_scan(
    assessment_id: str,
    org_id: str,
    *,
    scan_id: str | None = None,
    task_id: str | None = None,
    retry_cb=None,
) -> dict:
    """Invoke exposurescopex.sh and update platform scan state consistently."""
    import os
    import resource
    import signal
    import subprocess
    from sqlalchemy import text as sqla_text

    task_id = task_id or f"thread-{assessment_id[:8]}"
    claimed, claim_reason = _claim_scan_execution(scan_id, task_id)
    if not claimed:
        logger.warning(
            "Skipping assessment task: assessment=%s scan=%s task=%s reason=%s",
            assessment_id,
            scan_id,
            task_id,
            claim_reason,
        )
        return {
            "status": "ignored",
            "reason": claim_reason,
            "assessment_id": assessment_id,
            "scan_id": scan_id,
        }
    logger.info("Assessment scan started: assessment=%s task=%s scan=%s", assessment_id, task_id, scan_id)
    _publish_assessment_progress(
        assessment_id,
        scan_id,
        "assessment.scan.started",
        {"assessment_id": assessment_id, "scan_id": scan_id, "phase": "starting", "progress": 5},
    )
    if _scan_cancel_requested(scan_id):
        _update_scan_row(
            scan_id,
            status="cancelled",
            current_phase="cancelled",
            progress=0,
            completed=True,
            extra_metadata={"task_id": task_id, "org_id": org_id},
        )
        _queue_terminal_document_report(assessment_id, org_id, scan_id, "cancelled")
        _publish_assessment_progress(
            assessment_id,
            scan_id,
            "assessment.scan.cancelled",
            {"assessment_id": assessment_id, "scan_id": scan_id, "status": "cancelled", "phase": "cancelled"},
        )
        return {"status": "cancelled", "assessment_id": assessment_id, "scan_id": scan_id}

    _update_scan_row(
        scan_id,
        status="running",
        current_phase="starting",
        progress=5,
        extra_metadata={"task_id": task_id, "org_id": org_id},
    )

    db = _get_sync_db()
    try:
        db.execute(
            sqla_text("UPDATE assessments SET status='running', updated_at=NOW() WHERE id=:id"),
            {"id": assessment_id},
        )
        db.commit()

        row = db.execute(
            sqla_text("SELECT target, target_type, scan_mode, phases, flags FROM assessments WHERE id=:id"),
            {"id": assessment_id},
        ).fetchone()

        if not row:
            raise ValueError(f"Assessment {assessment_id} not found")

        target, target_type, scan_mode, phases, flags = row
        _update_scan_row(
            scan_id,
            status="running",
            current_phase="preflight",
            progress=2,
            manifest_status="completed",
            manifest_message="Assessment, target, and execution record validated",
        )
        imported_targets = list((flags or {}).get("_imported_targets") or [])
        target_count = max(1, len(imported_targets))
        from app.services.execution_policy import (
            estimate_remaining_seconds,
            resolve_execution_policy,
        )
        execution_policy = resolve_execution_policy(
            scan_mode or "medium",
            target_type,
            target_count=target_count,
        )
        scan_timeout = int(execution_policy["timeout_seconds"])
        output_dir = f"/app/results/{assessment_id}/{scan_id or task_id}"
        os.makedirs(output_dir, mode=0o700, exist_ok=True)
        os.chmod(output_dir, 0o700)
        command_target = target
        target_flag = "-d"
        batch_manifest = None
        if target_type == "file" and imported_targets:
            targets_file = os.path.join(output_dir, "imported_targets.txt")
            with open(targets_file, "w", encoding="utf-8") as handle:
                for item in imported_targets:
                    value = (item or {}).get("target")
                    if value:
                        handle.write(f"{value}\n")
            command_target = targets_file
            target_flag = "-f"
            batch_manifest = os.path.join(output_dir, "imported_targets.json")
            with open(batch_manifest, "w", encoding="utf-8") as handle:
                json.dump(imported_targets, handle)

        execution_type = "batch" if batch_manifest else target_type
        specialized_types = {"repository", "image", "mcp", "asn", "cloud_account", "organization", "kubernetes", "android", "ios", "batch"}
        if execution_type in specialized_types:
            cmd = [
                "python", "/app/worker/specialized_scan.py",
                "--type", execution_type,
                "--output", output_dir,
                "--mode", scan_mode or "medium",
            ]
            if batch_manifest:
                cmd.extend(["--manifest", batch_manifest])
            else:
                cmd.extend(["--target", command_target])
        else:
            cmd = [
                "bash", "/app/exposurescopex.sh",
                target_flag, command_target,
                "-m", scan_mode or "medium",
                "--auto",
                "--ci",
            ]

        phase_map = {
            "enum": "-e",
            "scan": "-s",
            "cloud": "-c",
            "report": "-r",
        }
        if execution_type not in specialized_types:
            for phase_key, cli_flag in phase_map.items():
                if (phases or {}).get(phase_key):
                    cmd.append(cli_flag)

        if execution_type not in specialized_types and (flags or {}).get("passive_only"):
            cmd.append("--passive-only")
        if execution_type not in specialized_types and (flags or {}).get("stealth"):
            cmd.append("--stealth")
        if execution_type not in specialized_types and (flags or {}).get("screenshots"):
            cmd.append("--screenshots")
        if execution_type not in specialized_types and (flags or {}).get("cve"):
            cmd.append("--cve")
        if execution_type not in specialized_types and (flags or {}).get("crawl"):
            cmd.append("--crawl")
        if execution_type not in specialized_types and (flags or {}).get("no_osint"):
            cmd.append("--no-osint")

        logger.info("Running: %s", " ".join(cmd))
        _update_scan_row(
            scan_id,
            status="running",
            current_phase="executing",
            progress=5,
            session_dir=output_dir,
            extra_metadata={
                "command": cmd,
                "target_count": target_count,
                "timeout_seconds": scan_timeout,
                "execution_policy": execution_policy,
            },
        )

        process_env = os.environ.copy()
        process_env["EXPOSURESCOPEX_RESULTS_DIR"] = output_dir
        process_env["EXPOSURESCOPEX_LOG_FILE"] = os.path.join(output_dir, "exposurescopex.log")
        process_env["EXPOSURESCOPEX_ORG_ID"] = org_id
        process_env["EXPOSURESCOPEX_ASSESSMENT_ID"] = assessment_id
        process_env["EXPOSURESCOPEX_SCAN_ID"] = str(scan_id or "untracked")
        process_env["EXPOSURESCOPEX_TASK_ID"] = task_id
        process_env["EXPOSURESCOPEX_SCANNER_IMAGE"] = settings.SCANNER_IMAGE_IDENTITY
        enabled_tools = sorted({
            str(item).strip().lower()
            for item in ((flags or {}).get("_requested_utilities") or [])
            if str(item).strip()
        })
        if enabled_tools:
            process_env["EXPOSURESCOPEX_ENABLED_TOOLS"] = ",".join(enabled_tools)
        process_env["EXPOSURESCOPEX_ACTIVE_VALIDATION"] = "true" if (flags or {}).get("allow_active_validation") else "false"
        encrypted_web_auth = (flags or {}).get("_web_auth_encrypted")
        if encrypted_web_auth:
            from app.services.encryption import decrypt_dict
            process_env["EXPOSURESCOPEX_WEB_AUTH_JSON"] = json.dumps(decrypt_dict(encrypted_web_auth))
        if execution_type in {"android", "ios", "kubernetes", "batch"}:
            from app.services.encryption import decrypt_dict

            integrations = db.execute(sqla_text(
                "SELECT provider,config FROM org_integrations WHERE org_id=:org_id AND is_active=TRUE "
                "AND provider IN ('mobile_dynamic','kubernetes_runtime')"
            ), {"org_id": org_id}).fetchall()
            env_names = {
                "mobile_dynamic": ("MOBILE_DYNAMIC_ADAPTER_URL", "MOBILE_DYNAMIC_API_KEY"),
                "kubernetes_runtime": ("KUBERNETES_RUNTIME_ADAPTER_URL", "KUBERNETES_RUNTIME_API_KEY"),
            }
            for integration in integrations:
                try:
                    config = decrypt_dict((integration.config or {}).get("_encrypted", ""))
                    url_name, key_name = env_names[integration.provider]
                    process_env[url_name] = str(config["url"])
                    process_env[key_name] = str(config["api_key"])
                except Exception:
                    logger.warning("Runtime adapter configuration could not be loaded: %s", integration.provider)

        def apply_process_limits() -> None:
            os.umask(0o077)
            resource.setrlimit(resource.RLIMIT_CPU, (int(execution_policy["cpu_seconds"]), int(execution_policy["cpu_seconds"])))
            resource.setrlimit(resource.RLIMIT_NOFILE, (int(execution_policy["max_open_files"]), int(execution_policy["max_open_files"])))
            resource.setrlimit(resource.RLIMIT_NPROC, (int(execution_policy["max_processes"]), int(execution_policy["max_processes"])))
            max_file = int(execution_policy["disk_mb"]) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_FSIZE, (max_file, max_file))

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=output_dir,
            bufsize=1,
            start_new_session=True,
            env=process_env,
            preexec_fn=apply_process_limits,
        )
        orchestrator_run_id = f"orchestrator-{task_id}"
        orchestrator_started_at = datetime.now(timezone.utc).isoformat()

        def persist_runtime_tool_runs(
            status: str,
            *,
            exit_code: int | None = None,
            completed_at: str | None = None,
            include_output: bool = False,
        ) -> list[dict]:
            child_runs = _read_tool_runs(actual_session_dir, include_output=include_output)
            orchestrator_run = {
                "id": orchestrator_run_id,
                "tool": "orchestrator",
                "status": status,
                "exit_code": exit_code,
                "started_at": orchestrator_started_at,
                "completed_at": completed_at,
                "command": " ".join(cmd),
                "output_file": None,
                "output_excerpt": "\n".join(log_lines)[-12000:] if include_output else None,
            }
            runs = [orchestrator_run, *child_runs]
            if scan_id:
                provenance_db = _get_sync_db()
                try:
                    from app.services.scan_provenance import persist_tool_runs

                    persisted = persist_tool_runs(provenance_db, scan_id, runs)
                    provenance_db.commit()
                    if persisted < len(runs):
                        raise RuntimeError(
                            f"Persisted {persisted} of {len(runs)} scan tool runs"
                        )
                finally:
                    provenance_db.close()
            return runs

        started_monotonic = time.monotonic()
        log_lines: deque[str] = deque(maxlen=2500)
        current_phase = "executing"
        current_progress = 5
        actual_session_dir = output_dir
        pending_output = ""
        last_heartbeat = started_monotonic
        last_output_monotonic = started_monotonic
        last_output_at = datetime.now(timezone.utc)
        stall_warning_seconds = max(60, int(os.getenv("SCAN_STALL_WARNING_SECONDS", "600")))
        artifact_bytes = 0
        output_selector = selectors.DefaultSelector()
        if proc.stdout:
            os.set_blocking(proc.stdout.fileno(), False)
            output_selector.register(proc.stdout, selectors.EVENT_READ)
        persist_runtime_tool_runs("running")

        def record_line(line: str) -> None:
            nonlocal actual_session_dir, current_phase, current_progress, last_output_monotonic, last_output_at
            clean_line = _ANSI_ESCAPE.sub("", line.rstrip())
            if clean_line:
                log_lines.append(clean_line)
                last_output_monotonic = time.monotonic()
                last_output_at = datetime.now(timezone.utc)
            session_match = re.search(r"\bSession:\s+(.+)$", clean_line)
            if session_match:
                candidate = session_match.group(1).strip()
                if candidate.startswith("/app/results/"):
                    actual_session_dir = candidate
                    _update_scan_row(scan_id, status="running", session_dir=actual_session_dir)
            stage_outcome = _scan_stage_outcome_from_line(clean_line)
            if stage_outcome:
                stage_id, stage_status, stage_message = stage_outcome
                _update_scan_row(
                    scan_id,
                    status="running",
                    current_phase=stage_id,
                    progress=current_progress,
                    manifest_status=stage_status,
                    manifest_message=stage_message,
                )
            phase_update = _scan_phase_from_line(clean_line)
            if phase_update and phase_update != (current_phase, current_progress):
                current_phase, current_progress = phase_update
                recent_log = "\n".join(log_lines)[-50000:]
                _update_scan_row(
                    scan_id,
                    status="running",
                    current_phase=current_phase,
                    progress=current_progress,
                    raw_log=recent_log,
                )
                _publish_assessment_progress(
                    assessment_id,
                    scan_id,
                    "assessment.scan.progress",
                    {
                        "assessment_id": assessment_id,
                        "scan_id": scan_id,
                        "status": "running",
                        "phase": current_phase,
                        "progress": current_progress,
                        "message": clean_line,
                    },
                )

        def terminate_process_group() -> tuple[str, int | None]:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                remaining, _ = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                remaining, _ = proc.communicate()
            return remaining or "", proc.returncode

        while True:
            if _scan_cancel_requested(scan_id):
                remaining, _ = terminate_process_group()
                if remaining:
                    log_lines.extend(remaining.splitlines())
                output_selector.close()
                db.execute(
                    sqla_text("UPDATE assessments SET status='cancelled', updated_at=NOW() WHERE id=:id"),
                    {"id": assessment_id},
                )
                db.commit()
                cancelled_at = datetime.now(timezone.utc).isoformat()
                cancelled_tool_runs = persist_runtime_tool_runs(
                    "cancelled",
                    exit_code=proc.returncode,
                    completed_at=cancelled_at,
                    include_output=True,
                )
                preservation = _preserve_terminal_scan_outputs(
                    org_id=org_id, assessment_id=assessment_id, scan_id=scan_id,
                    session_dir=actual_session_dir, task_id=task_id, command=cmd,
                    log_lines=log_lines, status="cancelled", exit_code=proc.returncode, target=target,
                )
                if preservation["errors"]:
                    log_lines.extend(preservation["errors"])
                _update_scan_row(
                    scan_id,
                    status="cancelled",
                    current_phase="cancelled",
                    progress=current_progress,
                    raw_log="\n".join(log_lines)[-50000:],
                    session_dir=actual_session_dir,
                    extra_metadata={
                        "task_id": task_id,
                        "exit_code": proc.returncode,
                        "cancelled": True,
                        "tool_runs": cancelled_tool_runs,
                        "ingestion_result": preservation["ingestion_result"],
                        "terminal_preservation_errors": preservation["errors"],
                        "evidence_seal": preservation["evidence_seal"],
                        "finding_screenshot_capture": preservation["finding_screenshot_capture"],
                    },
                    completed=True,
                )
                _queue_terminal_document_report(assessment_id, org_id, scan_id, "cancelled")
                _publish_assessment_progress(
                    assessment_id,
                    scan_id,
                    "assessment.scan.cancelled",
                    {"assessment_id": assessment_id, "scan_id": scan_id, "status": "cancelled", "phase": "cancelled", "progress": current_progress},
                )
                logger.info("Assessment scan cancelled: assessment=%s", assessment_id)
                return {"status": "cancelled", "assessment_id": assessment_id, "scan_id": scan_id}

            for key, _ in output_selector.select(timeout=1):
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if chunk:
                    pending_output += chunk.decode("utf-8", errors="replace")
                    complete_lines = pending_output.split("\n")
                    pending_output = complete_lines.pop()
                    for line in complete_lines:
                        record_line(line)

            if proc.poll() is not None:
                if pending_output:
                    record_line(pending_output)
                break

            elapsed = time.monotonic() - started_monotonic
            if time.monotonic() - last_heartbeat >= 10:
                tool_runs = _read_tool_runs(actual_session_dir)
                artifact_bytes = sum(
                    path.stat().st_size
                    for path in Path(output_dir).rglob("*")
                    if path.is_file()
                )
                quota_bytes = int(execution_policy["disk_mb"]) * 1024 * 1024
                if artifact_bytes > quota_bytes:
                    remaining, _ = terminate_process_group()
                    if remaining:
                        log_lines.extend(remaining.splitlines())
                    raise RuntimeError(
                        f"Scan artifact quota exceeded ({execution_policy['disk_mb']} MiB)"
                    )
                eta_seconds = estimate_remaining_seconds(
                    current_progress,
                    elapsed,
                    scan_timeout,
                )
                output_silence_seconds = max(0, int(time.monotonic() - last_output_monotonic))
                _update_scan_row(
                    scan_id,
                    status="running",
                    current_phase=current_phase,
                    progress=current_progress,
                    raw_log="\n".join(log_lines)[-50000:],
                    extra_metadata={
                        "last_heartbeat_at": datetime.now(timezone.utc).isoformat(),
                        "tool_runs": tool_runs,
                        "telemetry": {
                            "elapsed_seconds": int(elapsed),
                            "eta_seconds": eta_seconds,
                            "last_output_at": last_output_at.isoformat(),
                            "output_silence_seconds": output_silence_seconds,
                            "output_stalled": output_silence_seconds >= stall_warning_seconds,
                            "stall_warning_seconds": stall_warning_seconds,
                            "artifact_bytes": artifact_bytes,
                            "quota_bytes": quota_bytes,
                            "worker_pid": os.getpid(),
                        },
                    },
                )
                if scan_id and tool_runs:
                    provenance_db = _get_sync_db()
                    try:
                        from app.services.scan_provenance import persist_tool_runs

                        persist_tool_runs(provenance_db, scan_id, tool_runs)
                        provenance_db.commit()
                    finally:
                        provenance_db.close()
                last_heartbeat = time.monotonic()
            if elapsed > scan_timeout:
                remaining, _ = terminate_process_group()
                if remaining:
                    log_lines.extend(remaining.splitlines())
                raise subprocess.TimeoutExpired(
                    cmd=cmd, timeout=scan_timeout, output="\n".join(log_lines)
                )

        output_selector.close()

        artifact_bytes = sum(
            path.stat().st_size
            for path in Path(output_dir).rglob("*")
            if path.is_file()
        )
        quota_bytes = int(execution_policy["disk_mb"]) * 1024 * 1024
        if artifact_bytes > quota_bytes:
            raise RuntimeError(
                f"Scan artifact quota exceeded ({execution_policy['disk_mb']} MiB)"
            )

        exit_code = proc.returncode
        # The platform never launches the CLI in CI-gate mode, where 1/2 encode
        # finding severity. Here every non-zero exit indicates a scanner failure.
        final_status = "completed" if exit_code == 0 else "failed"
        execution_error = None if final_status == "completed" else (
            f"Scanner process exited with code {exit_code}. Review the final worker output for the failed prerequisite or utility."
        )
        ingestion_result = None
        ingestion_error = None
        finding_capture = _capture_finding_screenshots(
            actual_session_dir, task_id=task_id, scan_id=scan_id,
            assessment_id=assessment_id, org_id=org_id, target=target,
        )
        tool_capture = _capture_tool_run_screenshots(
            actual_session_dir, task_id=task_id, scan_id=scan_id,
            assessment_id=assessment_id, org_id=org_id,
        )
        _purge_runtime_web_auth_secrets(actual_session_dir)
        evidence_seal = _seal_worker_evidence(
            actual_session_dir,
            scan_id=scan_id,
            task_id=task_id,
            command=cmd,
            log_lines=log_lines,
            status=final_status,
            exit_code=exit_code,
        )
        if scan_id and actual_session_dir:
            _update_scan_row(
                scan_id,
                status="running",
                current_phase="ingesting_results",
                progress=98,
                raw_log="\n".join(log_lines)[-50000:],
                session_dir=actual_session_dir,
            )
            _publish_assessment_progress(
                assessment_id,
                scan_id,
                "assessment.scan.progress",
                {
                    "assessment_id": assessment_id,
                    "scan_id": scan_id,
                    "status": "running",
                    "phase": "ingesting_results",
                    "progress": 98,
                    "message": "Importing scan artifacts into the assessment",
                },
            )
            try:
                ingestion_result = _ingest_scan_results(
                    org_id=org_id,
                    assessment_id=assessment_id,
                    scan_id=scan_id,
                    session_dir=actual_session_dir,
                )
                _update_scan_row(
                    scan_id,
                    status="running",
                    current_phase="ingesting_results",
                    progress=98,
                    manifest_status="completed",
                    manifest_message="Artifacts normalized and persisted",
                )
                if (ingestion_result or {}).get("graph") is not None:
                    _update_scan_row(
                        scan_id,
                        status="running",
                        current_phase="attack_path",
                        progress=99,
                        manifest_status="completed",
                        manifest_message="Asset relationships and risk paths calculated",
                    )
            except Exception as exc:
                ingestion_error = f"Scan completed but result ingestion failed: {exc}"
                log_lines.append(ingestion_error)
                final_status = "failed"

        _, terminal_metadata = _scan_row_state(scan_id)
        provisional_status = final_status
        finalized_metadata = finalize_execution_manifest(terminal_metadata, provisional_status)
        coverage = execution_coverage_summary(finalized_metadata)
        child_tool_runs = _read_tool_runs(actual_session_dir)
        tool_exceptions = [
            run for run in child_tool_runs
            if run.get("status") in {"failed", "timed_out", "running"}
        ]
        evidence_incomplete = (
            (
                int((finding_capture or {}).get("requested") or 0) > 0
                and int((finding_capture or {}).get("captured") or 0)
                < int((finding_capture or {}).get("requested") or 0)
            )
            or (
                int((tool_capture or {}).get("requested") or 0) > 0
                and int((tool_capture or {}).get("captured") or 0)
                < int((tool_capture or {}).get("requested") or 0)
            )
        )
        if provisional_status == "completed" and (
            not coverage["complete"] or tool_exceptions or evidence_incomplete
        ):
            final_status = "partial"
            execution_error = (
                f"Assessment finished with coverage gaps: {coverage['successful']}/{coverage['planned']} "
                f"planned stages succeeded, {len(tool_exceptions)} tool exception(s), "
                f"and {int((finding_capture or {}).get('failed') or 0) + int((tool_capture or {}).get('failed') or 0)} "
                "evidence capture failure(s)."
            )

        db.execute(
            sqla_text("UPDATE assessments SET status=:status, updated_at=NOW() WHERE id=:id"),
            {"status": final_status, "id": assessment_id},
        )
        db.commit()

        final_tool_runs = persist_runtime_tool_runs(
            final_status,
            exit_code=exit_code,
            completed_at=datetime.now(timezone.utc).isoformat(),
            include_output=True,
        )
        _update_scan_row(
            scan_id,
            status=final_status,
            current_phase=(
                "completed" if final_status == "completed"
                else "completed_with_gaps" if final_status == "partial"
                else "failed"
            ),
            progress=100 if final_status in {"completed", "partial"} else 98,
            error_message=ingestion_error or execution_error,
            raw_log="\n".join(log_lines)[-50000:],
            session_dir=actual_session_dir,
            extra_metadata={
                "exit_code": exit_code,
                "ingestion_result": ingestion_result,
                "tool_runs": final_tool_runs,
                "evidence_seal": evidence_seal,
                "finding_screenshot_capture": finding_capture,
                "tool_screenshot_capture": tool_capture,
                "coverage": coverage,
                "tool_exceptions": tool_exceptions,
            },
            completed=True,
        )
        automatic_report = _queue_terminal_document_report(
            assessment_id, org_id, scan_id, final_status,
        )
        _publish_assessment_progress(
            assessment_id,
            scan_id,
            "assessment.scan.completed" if final_status in {"completed", "partial"} else "assessment.scan.failed",
            {"assessment_id": assessment_id, "scan_id": scan_id, "status": final_status, "phase": "completed" if final_status in {"completed", "partial"} else "failed", "progress": 100 if final_status in {"completed", "partial"} else 98, "exit_code": exit_code, "error": ingestion_error or execution_error, "coverage": coverage},
        )
        logger.info("Assessment scan %s: status=%s", assessment_id, final_status)
        return {
            "status": final_status,
            "assessment_id": assessment_id,
            "scan_id": scan_id,
            "exit_code": exit_code,
            "automatic_report": automatic_report,
        }

    except subprocess.TimeoutExpired as exc:
        preservation = None
        failed_phase = current_phase if "current_phase" in locals() else "unknown"
        if scan_id and "actual_session_dir" in locals() and "log_lines" in locals():
            preservation = _preserve_terminal_scan_outputs(
                org_id=org_id, assessment_id=assessment_id, scan_id=scan_id,
                session_dir=actual_session_dir, task_id=task_id,
                command=cmd if "cmd" in locals() else None, log_lines=log_lines,
                status="failed", exit_code=proc.returncode if "proc" in locals() else None,
                target=target if "target" in locals() else "",
            )
            if preservation["errors"]:
                log_lines.extend(preservation["errors"])
        if "persist_runtime_tool_runs" in locals():
            try:
                persist_runtime_tool_runs(
                    "failed",
                    exit_code=proc.returncode if "proc" in locals() else None,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    include_output=True,
                )
            except Exception:
                logger.warning("Could not persist timed-out orchestrator run for scan=%s", scan_id, exc_info=True)
        db.execute(
            sqla_text("UPDATE assessments SET status='failed', updated_at=NOW() WHERE id=:id"),
            {"id": assessment_id},
        )
        db.commit()
        _update_scan_row(
            scan_id,
            status="failed",
            current_phase="timeout",
            progress=100,
            error_message=f"Scan timed out during {failed_phase} after {scan_timeout} seconds",
            raw_log="\n".join(log_lines)[-50000:] if "log_lines" in locals() else None,
            session_dir=actual_session_dir if "actual_session_dir" in locals() else None,
            extra_metadata={
                "failed_phase": failed_phase,
                "failure_reason": "scan_timeout",
                "ingestion_result": preservation["ingestion_result"] if preservation else None,
                "terminal_preservation_errors": preservation["errors"] if preservation else [],
                "evidence_seal": preservation["evidence_seal"] if preservation else None,
                "finding_screenshot_capture": preservation["finding_screenshot_capture"] if preservation else None,
                "tool_screenshot_capture": preservation["tool_screenshot_capture"] if preservation else None,
            },
            completed=True,
        )
        _queue_terminal_document_report(assessment_id, org_id, scan_id, "failed")
        _publish_assessment_progress(assessment_id, scan_id, "assessment.scan.timeout", {"assessment_id": assessment_id, "scan_id": scan_id, "status": "failed", "phase": "timeout", "progress": 100})
        if retry_cb:
            raise retry_cb(exc=exc)
        raise

    except Exception as exc:
        preservation = None
        failed_phase = current_phase if "current_phase" in locals() else "unknown"
        if scan_id and "actual_session_dir" in locals() and "log_lines" in locals():
            preservation = _preserve_terminal_scan_outputs(
                org_id=org_id, assessment_id=assessment_id, scan_id=scan_id,
                session_dir=actual_session_dir, task_id=task_id,
                command=cmd if "cmd" in locals() else None, log_lines=log_lines,
                status="failed", exit_code=proc.returncode if "proc" in locals() else None,
                target=target if "target" in locals() else "",
            )
            if preservation["errors"]:
                log_lines.extend(preservation["errors"])
        if "persist_runtime_tool_runs" in locals():
            try:
                persist_runtime_tool_runs(
                    "failed",
                    exit_code=proc.returncode if "proc" in locals() else None,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    include_output=True,
                )
            except Exception:
                logger.warning("Could not persist failed orchestrator run for scan=%s", scan_id, exc_info=True)
        try:
            db.execute(
                sqla_text("UPDATE assessments SET status='failed', updated_at=NOW() WHERE id=:id"),
                {"id": assessment_id},
            )
            db.commit()
        except Exception:
            pass
        _update_scan_row(
            scan_id,
            status="failed",
            current_phase="failed",
            progress=100,
            error_message=f"Scan failed during {failed_phase}: {exc}",
            raw_log="\n".join(log_lines)[-50000:] if "log_lines" in locals() else None,
            session_dir=actual_session_dir if "actual_session_dir" in locals() else None,
            extra_metadata={
                "failed_phase": failed_phase,
                "failure_reason": type(exc).__name__,
                "ingestion_result": preservation["ingestion_result"] if preservation else None,
                "terminal_preservation_errors": preservation["errors"] if preservation else [],
                "evidence_seal": preservation["evidence_seal"] if preservation else None,
                "finding_screenshot_capture": preservation["finding_screenshot_capture"] if preservation else None,
                "tool_screenshot_capture": preservation["tool_screenshot_capture"] if preservation else None,
            },
            completed=True,
        )
        _queue_terminal_document_report(assessment_id, org_id, scan_id, "failed")
        _publish_assessment_progress(assessment_id, scan_id, "assessment.scan.failed", {"assessment_id": assessment_id, "scan_id": scan_id, "status": "failed", "phase": "failed", "progress": 100, "error": str(exc)})
        logger.error("Assessment scan failed: %s error=%s", assessment_id, exc)
        if retry_cb:
            raise retry_cb(exc=exc)
        raise
    finally:
        db.close()


@celery_app.task(
    name="app.services.celery_app.nvd_feed_sync_task",
    bind=True,
    max_retries=2,
    default_retry_delay=300,
    queue="default",
)
def nvd_feed_sync_task(self, org_id: str | None = None, days_back: int = 1) -> dict:
    """Daily Celery task: fetch NVD CVE feed and match against tracked assets.

    Scheduled via Celery Beat (see celery_app.conf.beat_schedule below) or
    triggered on-demand from the integrations API.

    Args:
        org_id:    Optional organisation UUID string for filtering.
        days_back: Number of days to query back in NVD (default 1 = yesterday).
    """
    import asyncio
    from app.services.threat_intel.nvd_feed import run_nvd_feed_sync

    task_id = self.request.id
    logger.info("NVD feed sync task started: task=%s org=%s", task_id, org_id)

    try:
        result = asyncio.run(
            run_nvd_feed_sync(org_id=org_id, days_back=days_back, db=None)
        )
        logger.info(
            "NVD feed sync task completed: cves=%d matches=%d",
            result.get("cves_fetched", 0),
            result.get("asset_matches", 0),
        )
        return result
    except Exception as exc:
        logger.error("NVD feed sync task failed: %s", exc)
        raise self.retry(exc=exc)


@celery_app.task(
    name="app.services.celery_app.nuclei_template_update_task",
    queue="default",
    soft_time_limit=1700,
    time_limit=1800,
)
def nuclei_template_update_task() -> dict:
    """Refresh managed Nuclei sources without cloning repositories per scan."""
    import subprocess

    command = ["/app/worker/entrypoint.sh", "update-templates"]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=1750,
        )
    except FileNotFoundError:
        return {"status": "unavailable", "reason": "worker updater is not installed"}
    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    if result.returncode != 0:
        raise RuntimeError(f"Nuclei template update failed: {output[-2000:]}")
    return {"status": "completed", "output": output[-4000:]}


# ── Celery Beat schedule ──────────────────────────────────────────────────────

celery_app.conf.beat_schedule = {
    "assessment-schedules": {
        "task": "app.services.celery_app.dispatch_due_scan_schedules",
        "schedule": 60,
        "options": {"queue": "default"},
    },
    "finding-lifecycle-daily": {
        "task": "app.services.celery_app.finding_lifecycle_maintenance",
        "schedule": 86400,
        "options": {"queue": "default"},
    },
    "nvd-feed-daily": {
        "task": "app.services.celery_app.nvd_feed_sync_task",
        "schedule": 86400,  # every 24 hours
        "kwargs": {"days_back": 1},
        "options": {"queue": "default"},
    },
    "runtime-maintenance": {
        "task": "app.services.celery_app.runtime_maintenance_task",
        "schedule": 300,
        "options": {"queue": "default"},
    },
    "nuclei-templates-daily": {
        "task": "app.services.celery_app.nuclei_template_update_task",
        "schedule": 86400,
        "options": {"queue": "default"},
    },
    "artifact-retention-daily": {
        "task": "app.services.celery_app.retention_maintenance_task",
        "schedule": 86400,
        "options": {"queue": "default"},
    },
}


@celery_app.task(
    name="app.services.celery_app.runtime_maintenance_task",
    queue="default",
)
def runtime_maintenance_task() -> dict:
    """Reconcile orphaned scans and expired finding suppressions."""
    import asyncio

    from app.services.assessment_runtime import reconcile_stale_scans
    from app.services.auth_sessions import purge_old_auth_sessions
    from app.services.finding_lifecycle import reopen_expired_suppressions
    from app.services.report_jobs import backfill_missing_scan_reports

    async def maintain_runtime() -> dict:
        stale_scans = await reconcile_stale_scans(settings.STALE_SCAN_MINUTES)
        reopened_findings = await reopen_expired_suppressions()
        purged_sessions = await purge_old_auth_sessions()
        report_backfill = await backfill_missing_scan_reports(limit=10)
        return {
            "stale_scans_reconciled": stale_scans,
            "expired_suppressions_reopened": reopened_findings,
            "expired_auth_sessions_purged": purged_sessions,
            "automatic_report_backfill": report_backfill,
        }

    return asyncio.run(maintain_runtime())


@celery_app.task(
    name="app.services.celery_app.retention_maintenance_task",
    queue="default",
    soft_time_limit=1700,
    time_limit=1800,
)
def retention_maintenance_task() -> dict:
    """Remove expired large artifacts while retaining normalized security records."""
    import shutil
    from datetime import timedelta
    from sqlalchemy import text as sqla_text

    now = datetime.now(timezone.utc)
    artifact_cutoff = now - timedelta(days=settings.SCAN_ARTIFACT_RETENTION_DAYS)
    report_cutoff = now - timedelta(days=settings.REPORT_RETENTION_DAYS)
    root = Path("/app/results").resolve()
    db = _get_sync_db()
    removed_directories = 0
    try:
        rows = db.execute(
            sqla_text(
                "SELECT id, session_dir, scan_metadata FROM scans "
                "WHERE status IN ('completed','partial','failed','cancelled') "
                "AND completed_at < :cutoff AND session_dir IS NOT NULL"
            ),
            {"cutoff": artifact_cutoff},
        ).fetchall()
        from app.services.artifact_storage import delete_object

        for scan_id, session_dir, scan_metadata in rows:
            candidate = Path(session_dir).resolve()
            if root in candidate.parents and candidate != root and candidate.exists():
                shutil.rmtree(candidate, ignore_errors=True)
                removed_directories += 1
            archived_key = (scan_metadata or {}).get("ingestion_result", {}).get("artifact_object_key")
            if archived_key:
                delete_object(archived_key)
            db.execute(
                sqla_text(
                    "UPDATE scans SET session_dir=NULL, "
                    "scan_metadata=jsonb_set(COALESCE(scan_metadata, '{}'::jsonb), "
                    "'{artifact_retention}', CAST(:retention AS jsonb), true) WHERE id=:id"
                ),
                {"id": scan_id, "retention": json.dumps({"retained": False, "removed_at": now.isoformat()})},
            )
        expired_reports = db.execute(
            sqla_text("SELECT id, storage_backend, object_key FROM report_artifacts WHERE created_at < :cutoff"),
            {"cutoff": report_cutoff},
        ).fetchall()
        reports_removed = 0
        for report_id, storage_backend, stored_key in expired_reports:
            if storage_backend == "s3":
                delete_object(stored_key)
            reports_removed += db.execute(
                sqla_text("DELETE FROM report_artifacts WHERE id=:id"), {"id": report_id}
            ).rowcount or 0
        db.commit()
        return {"status": "completed", "artifact_directories_removed": removed_directories, "reports_removed": reports_removed or 0}
    finally:
        db.close()


@celery_app.task(
    name="app.services.celery_app.delete_assessment_artifacts",
    queue="default",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 5},
)
def delete_assessment_artifacts(assessment_id: str, object_keys: list[str] | None = None) -> dict:
    """Delete one assessment artifact tree after its database transaction commits."""
    import os
    import shutil

    normalized_id = str(uuid.UUID(assessment_id))
    results_root = Path(os.getenv("EXPOSURESCOPEX_RESULTS_ROOT", "/app/results")).resolve()
    artifact_dir = (results_root / normalized_id).resolve()
    if artifact_dir.parent != results_root:
        raise ValueError("Artifact cleanup path escaped the configured results root")
    from app.services.artifact_storage import delete_object

    deleted_local = False
    if artifact_dir.exists():
        shutil.rmtree(artifact_dir)
        deleted_local = True
    deleted_objects = 0
    for key in object_keys or []:
        delete_object(key)
        deleted_objects += 1
    return {"assessment_id": normalized_id, "deleted": deleted_local, "objects_deleted": deleted_objects}


@celery_app.task(
    name="app.services.celery_app.sync_cloud_source",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
    queue="default",
)
def sync_cloud_source(self, source_id: str, org_id: str) -> dict:
    """Sync assets from a cloud provider into asm_targets.

    Steps:
        1. Fetch AsmCloudSource from DB.
        2. Decrypt config (Fernet-encrypted JSONB).
        3. Dispatch to provider-specific sync function (AWS / GCP / Azure).
        4. Upsert discovered assets into asm_targets (SELECT-first to avoid
           needing a unique constraint on org_id + target_value).
        5. Update source.last_sync, status, and last_sync_count.
    """
    import json as _json
    import uuid as _uuid
    from sqlalchemy import text as sqla_text

    from app.services.cloud_sync.aws import sync_aws_assets
    from app.services.cloud_sync.gcp import sync_gcp_assets
    from app.services.cloud_sync.azure_sync import sync_azure_assets
    from app.services.encryption import decrypt_dict

    logger.info("Cloud sync started: source=%s org=%s", source_id, org_id)

    db = _get_sync_db()
    try:
        # ── 1. Fetch source row ───────────────────────────────────────────────
        row = db.execute(
            sqla_text(
                "SELECT id, provider, config, is_active, created_by "
                "FROM asm_cloud_sources WHERE id=:id AND org_id=:org_id"
            ),
            {"id": source_id, "org_id": org_id},
        ).fetchone()

        if not row:
            raise ValueError(f"AsmCloudSource {source_id} not found for org {org_id}")

        if not row.is_active:
            logger.info("Cloud source %s is inactive, skipping sync", source_id)
            return {"status": "skipped", "reason": "inactive", "source_id": source_id}

        provider = row.provider
        raw_config = row.config          # JSONB already parsed to dict by psycopg2
        created_by = str(row.created_by)

        # ── 2. Decrypt config ─────────────────────────────────────────────────
        if isinstance(raw_config, dict) and raw_config.get("_encrypted"):
            config = decrypt_dict(raw_config["_encrypted"])
        else:
            config = raw_config or {}

        # ── 3. Dispatch to provider ───────────────────────────────────────────
        _dispatch = {
            "aws":   sync_aws_assets,
            "gcp":   sync_gcp_assets,
            "azure": sync_azure_assets,
        }
        if provider not in _dispatch:
            raise ValueError(f"Unsupported cloud provider: {provider!r}")

        result = _dispatch[provider](source_id, org_id, config)
        assets = result.get("assets", [])

        # ── 4. Upsert assets into asm_targets ─────────────────────────────────
        upserted = 0
        for asset in assets:
            target_value = (asset.get("target_value") or "").strip()
            if not target_value:
                continue

            # SELECT first — avoids relying on a unique constraint
            existing = db.execute(
                sqla_text(
                    "SELECT id FROM asm_targets "
                    "WHERE org_id=:org_id AND target_value=:target_value "
                    "LIMIT 1"
                ),
                {"org_id": org_id, "target_value": target_value},
            ).fetchone()

            tags_json = _json.dumps(asset.get("tags") or [])
            name = (asset.get("name") or target_value)[:255]
            target_type = asset.get("target_type") or "domain"
            cloud_region = asset.get("cloud_region")
            cloud_account_id = asset.get("cloud_account_id")

            if existing:
                db.execute(
                    sqla_text(
                        "UPDATE asm_targets "
                        "SET name=:name, source_type=:source_type, "
                        "    cloud_region=:cloud_region, "
                        "    cloud_account_id=:cloud_account_id, "
                        "    tags=:tags::jsonb, "
                        "    updated_at=NOW() "
                        "WHERE id=:id"
                    ),
                    {
                        "id": str(existing.id),
                        "name": name,
                        "source_type": provider,
                        "cloud_region": cloud_region,
                        "cloud_account_id": cloud_account_id,
                        "tags": tags_json,
                    },
                )
            else:
                db.execute(
                    sqla_text(
                        "INSERT INTO asm_targets "
                        "(id, org_id, created_by, name, target_value, target_type, "
                        " source_type, cloud_region, cloud_account_id, tags, "
                        " scan_status, created_at, updated_at) "
                        "VALUES "
                        "(:id, :org_id, :created_by, :name, :target_value, :target_type, "
                        " :source_type, :cloud_region, :cloud_account_id, :tags::jsonb, "
                        " 'idle', NOW(), NOW())"
                    ),
                    {
                        "id": str(_uuid.uuid4()),
                        "org_id": org_id,
                        "created_by": created_by,
                        "name": name,
                        "target_value": target_value[:500],
                        "target_type": target_type,
                        "source_type": provider,
                        "cloud_region": cloud_region,
                        "cloud_account_id": cloud_account_id,
                        "tags": tags_json,
                    },
                )
            upserted += 1

        # ── 5. Update source status ───────────────────────────────────────────
        db.execute(
            sqla_text(
                "UPDATE asm_cloud_sources "
                "SET last_sync=NOW(), status='ok', "
                "    status_message=:msg, last_sync_count=:count "
                "WHERE id=:id"
            ),
            {
                "id": source_id,
                "msg": f"Synced {upserted} assets from {provider}",
                "count": str(upserted),
            },
        )
        db.commit()

        logger.info(
            "Cloud sync completed: source=%s provider=%s assets=%d",
            source_id, provider, upserted,
        )
        return {
            "status": "ok",
            "source_id": source_id,
            "provider": provider,
            "count": upserted,
        }

    except Exception as exc:
        # Best-effort: mark the source as error so the UI can surface it
        try:
            from sqlalchemy import text as _sqla_text
            db.execute(
                _sqla_text(
                    "UPDATE asm_cloud_sources "
                    "SET status='error', status_message=:msg "
                    "WHERE id=:id"
                ),
                {"id": source_id, "msg": str(exc)[:500]},
            )
            db.commit()
        except Exception:
            pass
        logger.error("Cloud sync failed: source=%s error=%s", source_id, exc)
        raise self.retry(exc=exc)
    finally:
        db.close()
