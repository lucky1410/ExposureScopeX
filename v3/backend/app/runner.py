import asyncio
import hashlib
import json
import logging
import os
import platform
import signal
import socket
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen
from uuid import UUID

from .config import settings
from .db import connect, disconnect, pool
from .artifact_store import persist_bytes, persist_text
from .evidence_capture import terminal_evidence
from .execution_control import blocks_downstream
from .light_adapters import ADAPTERS
from .reporting import generate_scan_reports, report_status_for_scan
from .serialization import json_safe


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
LOGGER = logging.getLogger("exposurescopex.runner")
from .redaction import redact_text

TERMINAL_STAGE_STATUSES = {
    "succeeded",
    "failed",
    "timed_out",
    "skipped",
    "blocked",
    "cancelled",
}
SECURITY_HEADERS = {
    "content-security-policy": (
        "Content Security Policy is missing",
        "medium",
        "Define a restrictive Content-Security-Policy response header and validate it in report-only mode before enforcement.",
    ),
    "strict-transport-security": (
        "HTTP Strict Transport Security is missing",
        "medium",
        "Serve the application exclusively over HTTPS and add Strict-Transport-Security with an approved max-age.",
    ),
    "x-content-type-options": (
        "MIME sniffing protection is missing",
        "low",
        "Add X-Content-Type-Options: nosniff to applicable HTTP responses.",
    ),
    "x-frame-options": (
        "Clickjacking protection is missing",
        "low",
        "Set frame-ancestors in Content-Security-Policy; use X-Frame-Options for legacy client coverage.",
    ),
    "referrer-policy": (
        "Referrer policy is missing",
        "low",
        "Set an explicit Referrer-Policy appropriate for the application's navigation requirements.",
    ),
}

stop_requested = asyncio.Event()


class ScanCancellationRequested(RuntimeError):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def fetch_url(url: str) -> dict:
    request = Request(
        url,
        headers={"User-Agent": "ExposureScopeX/3.0 deterministic-assessment"},
        method="GET",
    )
    try:
        response = urlopen(request, timeout=settings().request_timeout_seconds)
    except HTTPError as exc:
        response = exc
    with response:
        body = response.read(256 * 1024)
        return {
            "requested_url": url,
            "final_url": response.geturl(),
            "status": response.status,
            "headers": {key.lower(): value for key, value in response.headers.items()},
            "body_preview": body[:4096].decode("utf-8", errors="replace"),
            "body_truncated": len(body) >= 256 * 1024,
            "observed_at": utcnow().isoformat(),
        }


async def claim_stage(owner: str) -> dict | None:
    async with pool().acquire() as conn, conn.transaction():
        row = await conn.fetchrow(
            """
            SELECT sr.*, s.assessment_id, a.target, a.mode::text AS mode, ass.scope AS scope
            FROM stage_runs sr
            JOIN scans s ON s.id = sr.scan_id
            JOIN assessments a ON a.id = s.assessment_id
            LEFT JOIN assessment_scopes ass ON ass.assessment_id = a.id
            WHERE sr.status = 'queued'
              AND s.cancel_requested_at IS NULL
              AND NOT EXISTS (
                SELECT 1 FROM stage_runs prior
                WHERE prior.scan_id = sr.scan_id
                  AND prior.position < sr.position
                  AND prior.status NOT IN (
                    'succeeded', 'failed', 'timed_out', 'skipped', 'blocked', 'cancelled'
                  )
              )
            ORDER BY sr.created_at, sr.position
            FOR UPDATE OF sr SKIP LOCKED
            LIMIT 1
            """
        )
        if row is None:
            return None
        await conn.execute(
            """
            UPDATE stage_runs
            SET status = 'running', attempt = attempt + 1, lease_owner = $2,
                lease_expires_at = now() + interval '2 minutes', heartbeat_at = now(),
                started_at = COALESCE(started_at, now())
            WHERE id = $1
            """,
            row["id"],
            owner,
        )
        await conn.execute(
            "UPDATE scans SET status = 'running', started_at = COALESCE(started_at, now()) WHERE id = $1",
            row["scan_id"],
        )
        await conn.execute(
            "UPDATE assessments SET status = 'running' WHERE id = $1",
            row["assessment_id"],
        )
        await conn.execute(
            """
            UPDATE scan_coverage
            SET status = 'running', started_at = COALESCE(started_at, now()),
                finished_at = NULL, reason = NULL, updated_at = now()
            WHERE stage_run_id = $1
            """,
            row["id"],
        )
        await conn.execute(
            "INSERT INTO scan_events (scan_id, event_type, payload) VALUES ($1, 'stage.started', $2)",
            row["scan_id"],
            {"stage_run_id": str(row["id"]), "adapter": row["adapter"]},
        )
        return dict(row)


async def recover_expired_leases() -> int:
    deadline_rows = await pool().fetch(
        """
        UPDATE stage_runs sr
        SET status = 'timed_out', finished_at = now(), lease_owner = NULL,
            lease_expires_at = NULL, error_code = 'ADAPTER_TIMEOUT',
            error_detail = 'The stage exceeded its persisted hard deadline and was closed by runner recovery.'
        FROM scans s
        WHERE sr.scan_id = s.id
          AND sr.status = 'running'
          AND sr.started_at IS NOT NULL
          AND sr.started_at + make_interval(secs => sr.timeout_seconds) <= now()
        RETURNING sr.scan_id, s.assessment_id, sr.id, sr.adapter
        """
    )
    for row in deadline_rows:
        LOGGER.warning(
            "Recovered overdue stage scan=%s stage=%s adapter=%s",
            row["scan_id"], row["id"], row["adapter"],
        )
        await pool().execute(
            """
            UPDATE scan_coverage
            SET status = 'timed_out', finished_at = now(),
                reason = 'The persisted hard deadline was exceeded.', updated_at = now()
            WHERE stage_run_id = $1
            """,
            row["id"],
        )
        await pool().execute(
            "INSERT INTO scan_events (scan_id, event_type, payload) VALUES ($1, 'stage.finished', $2)",
            row["scan_id"],
            {
                "stage_run_id": str(row["id"]),
                "adapter": row["adapter"],
                "status": "timed_out",
                "recovered": True,
            },
        )
        await finalize_if_terminal(row["scan_id"], row["assessment_id"])

    rows = await pool().fetch(
        """
        UPDATE stage_runs
        SET status = 'queued', lease_owner = NULL, lease_expires_at = NULL,
            error_code = 'LEASE_EXPIRED',
            error_detail = 'The previous runner stopped heartbeating; work was safely re-queued.'
        WHERE status = 'running' AND lease_expires_at < now()
        RETURNING scan_id, id, adapter
        """
    )
    for row in rows:
        await pool().execute(
            """
            UPDATE scan_coverage
            SET status = 'planned', started_at = NULL, finished_at = NULL,
                reason = 'Runner lease expired; work was re-queued.', updated_at = now()
            WHERE stage_run_id = $1
            """,
            row["id"],
        )
        await pool().execute(
            "INSERT INTO scan_events (scan_id, event_type, payload) VALUES ($1, 'stage.recovered', $2)",
            row["scan_id"],
            {"stage_run_id": str(row["id"]), "adapter": row["adapter"]},
        )
    return len(deadline_rows) + len(rows)


async def scan_cancel_requested(scan_id: UUID) -> bool:
    return bool(await pool().fetchval(
        "SELECT cancel_requested_at IS NOT NULL FROM scans WHERE id = $1",
        scan_id,
    ))


async def store_artifact(stage: dict, payload: dict) -> UUID:
    encoded = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    relative = Path(str(stage["scan_id"])) / f"{stage['position']:02d}-{stage['adapter']}-{digest[:12]}.json"
    destination = Path(settings().artifact_root) / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".tmp")
    temporary.write_bytes(encoded)
    os.replace(temporary, destination)
    return await pool().fetchval(
        """
        INSERT INTO artifacts (
          scan_id, stage_run_id, kind, storage_key, media_type, sha256,
          size_bytes, captured_at, metadata
        ) VALUES ($1, $2, 'raw_tool_output', $3, 'application/json', $4, $5, $6, $7)
        RETURNING id
        """,
        stage["scan_id"],
        stage["id"],
        relative.as_posix(),
        digest,
        len(encoded),
        utcnow(),
        {"adapter": stage["adapter"], "original": True},
    )


async def _block_downstream(conn, stage: dict, detail: str | None) -> list[dict]:
    reason = f"Blocked because scope preflight did not succeed: {detail or 'target validation failed'}"[:2000]
    rows = await conn.fetch(
        """
        UPDATE stage_runs
        SET status = 'blocked', finished_at = now(),
            error_code = 'UPSTREAM_SCOPE_PREFLIGHT_FAILED', error_detail = $3
        WHERE scan_id = $1 AND position > $2 AND status = 'queued'
        RETURNING id, adapter
        """,
        stage["scan_id"], stage["position"], reason,
    )
    if rows:
        await conn.execute(
            """
            UPDATE scan_coverage
            SET status = 'blocked', finished_at = now(), reason = $2, updated_at = now()
            WHERE stage_run_id = ANY($1::uuid[])
            """,
            [row["id"] for row in rows], reason,
        )
        await conn.execute(
            "INSERT INTO scan_events (scan_id, event_type, payload) VALUES ($1, 'stages.blocked', $2)",
            stage["scan_id"],
            {
                "cause_stage_run_id": str(stage["id"]),
                "cause_adapter": stage["adapter"],
                "blocked_stages": [str(row["adapter"]) for row in rows],
                "reason": reason,
            },
        )
    return [dict(row) for row in rows]


async def _cancel_pending_stages(conn, stage: dict, reason: str) -> list[dict]:
    rows = await conn.fetch(
        """
        UPDATE stage_runs
        SET status = 'cancelled', finished_at = now(),
            error_code = 'OPERATOR_CANCELLED', error_detail = $3
        WHERE scan_id = $1 AND position > $2 AND status = 'queued'
        RETURNING id, adapter
        """,
        stage["scan_id"], stage["position"], reason[:2000],
    )
    if rows:
        await conn.execute(
            """
            UPDATE scan_coverage
            SET status = 'cancelled', finished_at = now(), reason = $2, updated_at = now()
            WHERE stage_run_id = ANY($1::uuid[])
            """,
            [row["id"] for row in rows], reason[:2000],
        )
        await conn.execute(
            "INSERT INTO scan_events (scan_id, event_type, payload) VALUES ($1, 'stages.cancelled', $2)",
            stage["scan_id"],
            {
                "cause_stage_run_id": str(stage["id"]),
                "cause_adapter": stage["adapter"],
                "cancelled_stages": [str(row["adapter"]) for row in rows],
                "reason": reason[:2000],
            },
        )
    return [dict(row) for row in rows]


async def create_header_findings(stage: dict, artifact_id: UUID, result: dict) -> None:
    headers = result["headers"]
    for header, (title, severity, remediation) in SECURITY_HEADERS.items():
        if header in headers:
            continue
        identity = f"{stage['target']}|headers|{header}"
        fingerprint = hashlib.sha256(identity.encode()).hexdigest()
        await pool().execute(
            """
            INSERT INTO findings (
              scan_id, stage_run_id, source_artifact_id, fingerprint, title,
              severity, confidence, target, description, remediation, evidence
            ) VALUES ($1, $2, $3, $4, $5, $6, 95, $7, $8, $9, $10)
            ON CONFLICT (scan_id, fingerprint) DO NOTHING
            """,
            stage["scan_id"],
            stage["id"],
            artifact_id,
            fingerprint,
            title,
            severity,
            stage["target"],
            f"The {header} response header was absent from the observed response.",
            remediation,
            {
                "source_artifact_id": str(artifact_id),
                "requested_url": result["requested_url"],
                "status": result["status"],
                "observed_at": result["observed_at"],
            },
        )


async def execute_adapter(stage: dict) -> None:
    target = stage["target"]
    adapter = stage["adapter"]
    if adapter in ADAPTERS:
        execution = await ADAPTERS[adapter](stage)
    elif adapter in {"http_probe"}:
        result = await asyncio.to_thread(fetch_url, target)
        artifact_id = await store_artifact(stage, result)
        execution = {"command": "http-probe [AUTHORIZED_TARGET]", "transcript": json.dumps(result, indent=2)}
    elif adapter == "robots_discovery":
        result = await asyncio.to_thread(fetch_url, urljoin(target + "/", "robots.txt"))
        artifact_id = await store_artifact(stage, result)
        execution = {"command": "robots-discovery [AUTHORIZED_TARGET]", "transcript": json.dumps(result, indent=2)}
    elif adapter == "well_known_discovery":
        result = await asyncio.to_thread(
            fetch_url, urljoin(target + "/", ".well-known/security.txt")
        )
        artifact_id = await store_artifact(stage, result)
        execution = {"command": "well-known-discovery [AUTHORIZED_TARGET]", "transcript": json.dumps(result, indent=2)}
    else:
        raise RuntimeError(f"Adapter is not allowlisted: {adapter}")
    safe_transcript = redact_text(f"$ {execution['command']}\n{execution['transcript']}")
    transcript = await persist_text(stage, safe_transcript, kind="terminal_transcript", name=f"{adapter}-terminal.txt", metadata={"adapter": adapter, "command": execution["command"], "redacted": True})
    with tempfile.TemporaryDirectory(prefix="esx-terminal-") as temporary:
        screenshot_path = Path(temporary) / f"{adapter}-terminal.png"
        metadata = await terminal_evidence(transcript["path"], screenshot_path, str(stage["scan_id"]), adapter)
        if screenshot_path.is_file():
            await persist_bytes(stage, screenshot_path.read_bytes(), kind="terminal_screenshot", name=f"{adapter}-terminal.png", media_type="image/png", metadata={**metadata, "source_artifact_id": str(transcript["id"]), "source_transcript_sha256": transcript["sha256"]})


async def finish_stage(stage: dict, status: str, code: str | None = None, detail: str | None = None) -> None:
    async with pool().acquire() as conn, conn.transaction():
        await conn.execute(
            """
            UPDATE stage_runs
            SET status = $2::stage_status, finished_at = now(), lease_owner = NULL,
                lease_expires_at = NULL, error_code = $3, error_detail = $4
            WHERE id = $1
            """,
            stage["id"], status, code, detail,
        )
        await conn.execute(
            """
            UPDATE scan_coverage
            SET status = $2, finished_at = now(), reason = $3, updated_at = now()
            WHERE stage_run_id = $1
            """,
            stage["id"], "completed" if status == "succeeded" else status, detail,
        )
        await conn.execute(
            "INSERT INTO scan_events (scan_id, event_type, payload) VALUES ($1, 'stage.finished', $2)",
            stage["scan_id"],
            {"stage_run_id": str(stage["id"]), "adapter": stage["adapter"], "status": status},
        )
        if blocks_downstream(stage["adapter"], status):
            await _block_downstream(conn, stage, detail)


def _report_lock_key(scan_id: UUID) -> int:
    return int.from_bytes(hashlib.sha256(scan_id.bytes).digest()[:8], "big", signed=True)


async def finalize_if_terminal(scan_id: UUID, assessment_id: UUID) -> bool:
    lock_key = _report_lock_key(scan_id)
    async with pool().acquire() as lock_connection:
        acquired = await lock_connection.fetchval("SELECT pg_try_advisory_lock($1)", lock_key)
        if not acquired:
            LOGGER.info("Report finalization already active scan=%s", scan_id)
            return False
        try:
            return await _finalize_if_terminal_unlocked(scan_id, assessment_id)
        finally:
            await lock_connection.execute("SELECT pg_advisory_unlock($1)", lock_key)


async def _finalize_if_terminal_unlocked(scan_id: UUID, assessment_id: UUID) -> bool:
    rows = await pool().fetch(
        "SELECT position, adapter, required, status, error_code, error_detail FROM stage_runs WHERE scan_id = $1 ORDER BY position",
        scan_id,
    )
    if not rows or any(row["status"] not in TERMINAL_STAGE_STATUSES for row in rows):
        return False
    cancelled = any(row["status"] == "cancelled" for row in rows)
    required_failure = any(row["required"] and row["status"] != "succeeded" for row in rows)
    succeeded_count = sum(row["status"] == "succeeded" for row in rows)
    scan_status = "cancelled" if cancelled else "failed" if required_failure and succeeded_count == 0 else "partial" if required_failure else "complete"
    report_status = report_status_for_scan(scan_status)
    coverage = [dict(row) for row in await pool().fetch(
        "SELECT * FROM scan_coverage WHERE scan_id = $1 ORDER BY created_at, case_id",
        scan_id,
    )]
    if not coverage:
        coverage = [dict(row) for row in rows]
    await pool().execute("UPDATE scans SET status = $2::lifecycle_status, finished_at = now() WHERE id = $1", scan_id, scan_status)
    await pool().execute("UPDATE assessments SET status = $2::lifecycle_status WHERE id = $1", assessment_id, scan_status)
    try:
        manifest = await generate_scan_reports(scan_id, assessment_id, report_status, coverage)
    except Exception as exc:
        scan_status = "partial"
        report_status = report_status_for_scan(scan_status)
        await pool().execute("UPDATE scans SET status = 'partial', failure_reason = $2 WHERE id = $1", scan_id, f"Report generation failed: {exc}"[:2000])
        await pool().execute("UPDATE assessments SET status = 'partial' WHERE id = $1", assessment_id)
        manifest = json_safe({"schema_version": "2.5", "scan_id": str(scan_id), "generated_at": utcnow().isoformat(), "status": report_status, "execution_status": scan_status, "coverage": coverage, "report_error": f"{type(exc).__name__}: {exc}"[:2000], "outputs": {}})
    async with pool().acquire() as conn, conn.transaction():
        await conn.execute(
            """
            INSERT INTO reports (scan_id, status, manifest)
            VALUES ($1, $2, $3)
            ON CONFLICT (scan_id) DO UPDATE
            SET status = EXCLUDED.status, manifest = EXCLUDED.manifest, generated_at = now()
            """,
            scan_id,
            report_status,
            manifest,
        )
        await conn.execute(
            "INSERT INTO scan_events (scan_id, event_type, payload) VALUES ($1, 'scan.finished', $2)",
            scan_id,
            {"status": scan_status, "report_status": report_status},
        )
    return True


async def recover_missing_reports(limit: int = 10) -> int:
    rows = await pool().fetch(
        """
        SELECT s.id AS scan_id, s.assessment_id
        FROM scans s
        LEFT JOIN reports r ON r.scan_id = s.id
        WHERE r.scan_id IS NULL
          AND s.status::text IN ('complete', 'partial', 'failed', 'cancelled', 'blocked')
          AND EXISTS (SELECT 1 FROM stage_runs sr WHERE sr.scan_id = s.id)
          AND NOT EXISTS (
            SELECT 1 FROM stage_runs sr
            WHERE sr.scan_id = s.id
              AND sr.status::text NOT IN ('succeeded', 'failed', 'timed_out', 'skipped', 'blocked', 'cancelled')
          )
        ORDER BY COALESCE(s.finished_at, s.created_at) DESC
        LIMIT $1
        """,
        limit,
    )
    recovered = 0
    for row in rows:
        try:
            if await finalize_if_terminal(row["scan_id"], row["assessment_id"]):
                recovered += 1
        except Exception:
            LOGGER.exception("Failed to recover missing report scan=%s", row["scan_id"])
    return recovered


async def run_stage(stage: dict) -> None:
    LOGGER.info(
        "Starting stage scan=%s stage=%s adapter=%s attempt=%s timeout_seconds=%s",
        stage["scan_id"], stage["id"], stage["adapter"], stage["attempt"] + 1,
        stage["timeout_seconds"],
    )
    heartbeat = asyncio.create_task(heartbeat_stage(stage["id"]))
    try:
        if await scan_cancel_requested(stage["scan_id"]):
            raise ScanCancellationRequested("Cancellation was requested before stage execution began")
        async with asyncio.timeout(stage["timeout_seconds"]):
            await execute_adapter(stage)
    except ScanCancellationRequested as exc:
        await _store_failure_evidence(stage, "OPERATOR_CANCELLED", str(exc))
        await finish_stage(stage, "cancelled", "OPERATOR_CANCELLED", str(exc)[:2000])
        async with pool().acquire() as conn, conn.transaction():
            await _cancel_pending_stages(conn, stage, "Operator requested cancellation; remaining queued stages were not executed.")
    except TimeoutError:
        LOGGER.warning("Stage timed out scan=%s adapter=%s", stage["scan_id"], stage["adapter"])
        await _store_failure_evidence(stage, "ADAPTER_TIMEOUT", "Adapter exceeded its configured deadline")
        await finish_stage(stage, "timed_out", "ADAPTER_TIMEOUT", "Adapter exceeded its configured deadline")
    except (URLError, socket.timeout, OSError) as exc:
        await _store_failure_evidence(stage, "TARGET_UNREACHABLE", str(exc))
        await finish_stage(stage, "failed", "TARGET_UNREACHABLE", str(exc)[:2000])
    except Exception as exc:
        LOGGER.exception("Stage failed scan=%s adapter=%s", stage["scan_id"], stage["adapter"])
        await _store_failure_evidence(stage, "ADAPTER_ERROR", str(exc))
        await finish_stage(stage, "failed", "ADAPTER_ERROR", str(exc)[:2000])
    else:
        LOGGER.info("Stage succeeded scan=%s adapter=%s", stage["scan_id"], stage["adapter"])
        await finish_stage(stage, "succeeded")
    finally:
        heartbeat.cancel()
        try:
            await heartbeat
        except asyncio.CancelledError:
            pass
    await finalize_if_terminal(stage["scan_id"], stage["assessment_id"])


async def heartbeat_stage(stage_id: UUID) -> None:
    while True:
        await asyncio.sleep(20)
        result = await pool().execute(
            """
            UPDATE stage_runs
            SET heartbeat_at = now(), lease_expires_at = now() + interval '2 minutes'
            WHERE id = $1
              AND status = 'running'
              AND started_at + make_interval(secs => timeout_seconds) > now()
            """,
            stage_id,
        )
        if result.endswith("0"):
            LOGGER.warning("Stopped heartbeat renewal for terminal or overdue stage=%s", stage_id)
            return


async def _store_failure_evidence(stage: dict, code: str, detail: str) -> None:
    try:
        content = redact_text(f"Stage: {stage['adapter']}\nStatus: failed\nCode: {code}\nDetail: {detail[:4000]}\n")
        transcript = await persist_text(stage, content, kind="terminal_transcript", name=f"{stage['adapter']}-failure.txt", metadata={"adapter": stage["adapter"], "error_code": code, "redacted": True})
        with tempfile.TemporaryDirectory(prefix="esx-terminal-failure-") as temporary:
            screenshot_path = Path(temporary) / "failure.png"
            metadata = await terminal_evidence(transcript["path"], screenshot_path, str(stage["scan_id"]), stage["adapter"])
            if screenshot_path.is_file():
                await persist_bytes(stage, screenshot_path.read_bytes(), kind="terminal_screenshot", name=f"{stage['adapter']}-failure.png", media_type="image/png", metadata={**metadata, "source_artifact_id": str(transcript["id"]), "error_code": code})
    except Exception:
        pass


async def main() -> None:
    await connect()
    owner = f"{platform.node()}:{os.getpid()}"
    LOGGER.info("Runner started owner=%s", owner)
    loop = asyncio.get_running_loop()
    for signal_name in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signal_name, stop_requested.set)
    try:
        recovered_reports = await recover_missing_reports()
        if recovered_reports:
            LOGGER.info("Recovered missing terminal reports count=%s", recovered_reports)
        while not stop_requested.is_set():
            await recover_expired_leases()
            stage = await claim_stage(owner)
            if stage is None:
                try:
                    await asyncio.wait_for(stop_requested.wait(), settings().runner_poll_seconds)
                except TimeoutError:
                    pass
                continue
            await run_stage(stage)
    finally:
        LOGGER.info("Runner stopping owner=%s", owner)
        await disconnect()


if __name__ == "__main__":
    asyncio.run(main())
