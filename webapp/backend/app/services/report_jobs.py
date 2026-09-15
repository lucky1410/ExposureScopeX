"""Durable report materialization outside API request workers."""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import re
import zipfile
import uuid
from io import BytesIO, StringIO
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import func, not_, or_, select
from sqlalchemy.orm import selectinload

from app.config import settings
from app.database import async_session_factory
from app.models.asset import Asset
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.models.report import ReportArtifact
from app.models.scan import Scan
from app.models.scan_runtime import ScanArtifact, ScanToolRun
from app.schemas.report import ReportRequest
from app.services.artifact_storage import persist_report


AUTOMATIC_REPORT_NAMESPACE = uuid.UUID("965b860d-c682-46fd-a4f7-b8357bfd53e8")
AUTOMATIC_REPORT_STALE_AFTER = timedelta(minutes=15)
AUTOMATIC_REPORT_MAX_ATTEMPTS = 3
_SENSITIVE_RUNTIME_ARTIFACTS = {
    "web-auth-cookie.txt",
    "web-auth-storage-state.json",
}
logger = logging.getLogger(__name__)


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True, default=str).encode("utf-8")


def _redact_runtime_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    text = re.sub(
        r"(?i)(authorization\s*:\s*(?:bearer|token|basic)\s+)[^\s\"']+",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(r"(?i)(cookie\s*:\s*)[^\r\n]+", r"\1[REDACTED]", text)
    text = re.sub(
        r"(?i)(password|secret|api[_-]?key)(\s*[=:]\s*)[^\s,;\"']+",
        r"\1\2[REDACTED]",
        text,
    )
    return text


def generate_forensic_evidence_bundle(assessment, scan, tool_runs: list, scan_artifacts: list) -> bytes:
    """Package unchanged available source artifacts with tamper-evident provenance records."""
    payloads: dict[str, bytes] = {}
    payloads["records/scan.json"] = _json_bytes({
        "assessment_id": str(assessment.id),
        "assessment_name": assessment.name,
        "authorized_target": assessment.target,
        "scan_id": str(scan.id),
        "status": scan.status,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "session_dir": scan.session_dir,
        "scan_metadata": scan.scan_metadata or {},
    })
    payloads["records/tool-runs.json"] = _json_bytes([{
        "id": str(run.id),
        "external_id": run.external_id,
        "tool": run.tool,
        "tool_version": run.tool_version,
        "status": run.status,
        "exit_code": run.exit_code,
        "command": _redact_runtime_text(run.command),
        "output_file": run.output_file,
        "output_excerpt": _redact_runtime_text(run.output_excerpt),
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "duration_ms": run.duration_ms,
        "provenance": run.provenance or {},
    } for run in tool_runs])
    if scan.raw_log is not None:
        payloads["records/worker-log-database-record.txt"] = (
            _redact_runtime_text(scan.raw_log) or ""
        ).encode("utf-8", errors="replace")

    session_root = Path(scan.session_dir).resolve() if scan.session_dir else None
    artifact_index = []
    for artifact in scan_artifacts:
        artifact_name = Path(str(artifact.path)).name.lower()
        record = {
            "id": str(artifact.id), "path": artifact.path, "artifact_type": artifact.artifact_type,
            "mime_type": artifact.mime_type, "size_bytes": artifact.size_bytes, "sha256": artifact.sha256,
            "created_at": artifact.created_at, "retained": artifact.retained,
            "provenance": artifact.provenance or {}, "bundle_status": "metadata_only",
        }
        if artifact_name in _SENSITIVE_RUNTIME_ARTIFACTS:
            record["bundle_status"] = "excluded_sensitive_runtime_material"
            artifact_index.append(record)
            continue
        if session_root and session_root.is_dir():
            try:
                source = (session_root / artifact.path).resolve()
                if source.is_relative_to(session_root) and source.is_file():
                    original = source.read_bytes()
                    actual_hash = hashlib.sha256(original).hexdigest()
                    if actual_hash == artifact.sha256:
                        archive_path = artifact.path.replace("\\", "/")
                        payloads[f"artifacts/{archive_path}"] = original
                        record["bundle_status"] = "included_and_hash_verified"
                    else:
                        record["bundle_status"] = "source_hash_mismatch"
                        record["observed_sha256"] = actual_hash
            except OSError as exc:
                record["bundle_status"] = f"unavailable:{type(exc).__name__}"
        artifact_index.append(record)
    payloads["records/artifact-index.json"] = _json_bytes(artifact_index)

    manifest = {
        "format": "ExposureScopeX forensic evidence bundle",
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_id": str(scan.id),
        "integrity_model": "SHA-256 tamper-evident evidence package",
        "files": [
            {"path": name, "size_bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            for name, content in sorted(payloads.items())
        ],
        "limitations": (
            "SHA-256 detects changes after collection. For legal chain-of-custody requirements, configure immutable "
            "object storage, trusted timestamping, signer identity, and an external retention policy."
        ),
    }
    payloads["MANIFEST.json"] = _json_bytes(manifest)
    sums = "".join(
        f"{hashlib.sha256(content).hexdigest()}  {name}\n"
        for name, content in sorted(payloads.items())
    ).encode("ascii")
    payloads["SHA256SUMS"] = sums
    payloads["README.txt"] = (
        b"Original available scan artifacts and exact platform execution records. No screenshot or synthetic terminal "
        b"rendering is included. This archive may contain sensitive data and must remain access-controlled.\n"
    )

    archive = BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, content in sorted(payloads.items()):
            bundle.writestr(name, content)
    return archive.getvalue()


def automatic_report_id(scan_id: str | uuid.UUID, report_format: str = "docx") -> uuid.UUID:
    """Return a stable per-scan format ID so terminal retries cannot duplicate reports."""
    key = str(scan_id) if report_format == "docx" else f"{scan_id}:{report_format}"
    return uuid.uuid5(AUTOMATIC_REPORT_NAMESPACE, key)


def _automatic_report_needs_queue(report: ReportArtifact | None, now: datetime | None = None) -> bool:
    """Return whether an automatic report is missing or safe to retry."""
    if report is None:
        return True
    if report.status in {"ready", "cancelled"}:
        return False
    scope = report.scope or {}
    attempts = int(scope.get("generation_attempt") or 0)
    if attempts >= AUTOMATIC_REPORT_MAX_ATTEMPTS:
        return False
    if report.status == "failed":
        return True
    if report.status != "generating":
        return True
    queued_at = scope.get("queued_at")
    try:
        queued = datetime.fromisoformat(str(queued_at).replace("Z", "+00:00"))
        if queued.tzinfo is None:
            queued = queued.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        queued = report.updated_at or report.created_at
        if queued.tzinfo is None:
            queued = queued.replace(tzinfo=timezone.utc)
    return (now or datetime.now(timezone.utc)) - queued >= AUTOMATIC_REPORT_STALE_AFTER


def _terminal_report_needs_refresh(report: ReportArtifact | None, terminal_status: str) -> bool:
    """Refresh an earlier terminal snapshot when the same scan is later recovered."""
    if report is None or terminal_status == "historical":
        return False
    previous_status = str((report.scope or {}).get("terminal_status") or "")
    return terminal_status in {"completed", "partial", "recovered"} and previous_status != terminal_status


async def backfill_missing_scan_reports(limit: int = 10) -> dict[str, int]:
    """Queue a bounded set of historical terminal scans missing their DOCX."""
    candidates: list[tuple[uuid.UUID, uuid.UUID, uuid.UUID]] = []
    async with async_session_factory() as db:
        rows = (await db.execute(
            select(Scan.id, Assessment.id, Assessment.org_id)
            .join(Assessment, Assessment.id == Scan.assessment_id)
            .where(Scan.status.in_(["completed", "partial", "failed", "cancelled"]))
            .order_by(Scan.completed_at.desc().nullslast(), Scan.created_at.desc())
            .limit(max(25, limit * 5))
        )).all()
        report_ids = [
            automatic_report_id(scan_id, report_format)
            for scan_id, _, _ in rows
            for report_format in ("docx", "pdf", "evidence")
        ]
        existing = {
            report.id: report for report in (await db.execute(
                select(ReportArtifact).where(ReportArtifact.id.in_(report_ids))
            )).scalars().all()
        } if report_ids else {}
        now = datetime.now(timezone.utc)
        for scan_id, assessment_id, org_id in rows:
            if any(
                _automatic_report_needs_queue(existing.get(automatic_report_id(scan_id, report_format)), now)
                for report_format in ("docx", "pdf", "evidence")
            ):
                candidates.append((scan_id, assessment_id, org_id))
                if len(candidates) >= limit:
                    break

    queued = 0
    failed = 0
    for scan_id, assessment_id, org_id in candidates:
        try:
            await enqueue_automatic_scan_report(
                scan_id=str(scan_id),
                assessment_id=str(assessment_id),
                org_id=str(org_id),
                terminal_status="historical",
            )
            queued += 1
        except Exception:
            failed += 1
            logger.exception("Automatic report backfill failed for scan %s", scan_id)
    return {"examined": len(rows), "queued": queued, "failed": failed}


async def enqueue_automatic_scan_report(
    *, assessment_id: str, org_id: str, scan_id: str, terminal_status: str,
) -> dict:
    """Create or requeue the automatic DOCX, PDF, and forensic evidence reports."""
    reports = []
    for report_format in ("docx", "pdf", "evidence"):
        try:
            reports.append(await _enqueue_automatic_scan_report_format(
                assessment_id=assessment_id,
                org_id=org_id,
                scan_id=scan_id,
                terminal_status=terminal_status,
                report_format=report_format,
            ))
        except Exception as exc:
            logger.exception("Could not queue %s report for scan %s", report_format, scan_id)
            reports.append({"status": "failed", "format": report_format, "error": str(exc)[:500]})
    primary = reports[0]
    return {**primary, "reports": reports}


async def _enqueue_automatic_scan_report_format(
    *, assessment_id: str, org_id: str, scan_id: str, terminal_status: str, report_format: str,
) -> dict:
    report_uuid = automatic_report_id(scan_id, report_format)
    async with async_session_factory() as db:
        report = await db.get(ReportArtifact, report_uuid)
        force_refresh = _terminal_report_needs_refresh(report, terminal_status)
        if report and not force_refresh and not _automatic_report_needs_queue(report):
            return {"id": str(report.id), "status": report.status, "filename": report.filename}

        assessment = await db.scalar(select(Assessment).where(
            Assessment.id == uuid.UUID(assessment_id), Assessment.org_id == uuid.UUID(org_id)
        ))
        scan = await db.scalar(select(Scan).where(
            Scan.id == uuid.UUID(scan_id), Scan.assessment_id == uuid.UUID(assessment_id)
        ))
        if not assessment or not scan:
            raise ValueError("Automatic report scope is no longer available")

        payload = ReportRequest(
            assessment_id=assessment.id,
            scan_id=scan.id,
            format=report_format,
            title=f"{assessment.name} scan execution report",
        )
        safe_name = "".join(char if char.isalnum() or char in "-_" else "_" for char in assessment.name).strip("_")
        extension = "zip" if report_format == "evidence" else report_format
        filename = f"scan_report_{safe_name or assessment.id}_{str(scan.id)[:8]}.{extension}"
        previous_scope = dict(report.scope or {}) if report else {}
        scope = {
            "request": payload.model_dump(mode="json"),
            "automatic": True,
            "terminal_status": terminal_status,
            "queued_at": datetime.now(timezone.utc).isoformat(),
            "generation_attempt": int(previous_scope.get("generation_attempt") or 0) + 1,
        }
        if report:
            report.status = "generating"
            report.scope = scope
            report.file_size = 0
            report.sha256 = "0" * 64
            report.content = None
            report.object_key = None
        else:
            next_version = (await db.scalar(select(func.coalesce(func.max(ReportArtifact.version), 0) + 1).where(
                ReportArtifact.assessment_id == assessment.id, ReportArtifact.format == report_format
            ))) or 1
            report = ReportArtifact(
                id=report_uuid,
                org_id=assessment.org_id,
                assessment_id=assessment.id,
                created_by=assessment.created_by,
                title=payload.title,
                format=report_format,
                filename=filename,
                media_type={
                    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "pdf": "application/pdf",
                    "evidence": "application/zip",
                }[report_format],
                status="generating",
                version=next_version,
                file_size=0,
                sha256="0" * 64,
                storage_backend="database",
                scope=scope,
            )
            db.add(report)
        metadata = dict(scan.scan_metadata or {})
        automatic_reports = dict(metadata.get("automatic_reports") or {})
        automatic_reports[report_format] = {
            "id": str(report.id), "status": "generating", "format": report_format, "filename": filename,
        }
        metadata["automatic_reports"] = automatic_reports
        if report_format == "docx":
            metadata["automatic_report"] = automatic_reports[report_format]
        scan.scan_metadata = metadata
        await db.commit()

        from app.services.celery_app import generate_report_task

        try:
            task = generate_report_task.apply_async(args=[str(report.id)], queue="reports")
            report.scope = {**scope, "task_id": task.id}
        except Exception as exc:
            # The document is mandatory. If dispatch is unavailable, materialize
            # it inline rather than allowing the scan to close without a report.
            report.scope = {**scope, "dispatch_warning": f"Report worker unavailable: {type(exc).__name__}"}
            await db.commit()
            try:
                result = await materialize_report(str(report.id))
                return {"id": str(report.id), "status": result["status"], "filename": filename}
            except Exception as fallback_exc:
                return {"id": str(report.id), "status": "failed", "filename": filename, "error": str(fallback_exc)[:500]}
        await db.commit()
        return {"id": str(report.id), "status": report.status, "filename": filename}


async def materialize_report(report_id: str) -> dict:
    """Render and persist one queued report, recording terminal state reliably."""
    async with async_session_factory() as db:
        report = await db.get(ReportArtifact, uuid.UUID(report_id))
        if not report:
            return {"status": "missing", "report_id": report_id}
        if report.status == "cancelled":
            return {"status": "cancelled", "report_id": report_id}
        if report.status == "ready":
            return {"status": "ready", "report_id": report_id}
        try:
            payload = ReportRequest.model_validate((report.scope or {}).get("request") or {})
            assessment = await db.scalar(
                select(Assessment)
                .options(selectinload(Assessment.organization), selectinload(Assessment.created_by_user))
                .where(Assessment.id == report.assessment_id, Assessment.org_id == report.org_id)
            )
            if not assessment:
                raise ValueError("Assessment is no longer available")

            selected_scan = None
            if payload.scan_id:
                selected_scan = await db.scalar(select(Scan).where(
                    Scan.id == payload.scan_id, Scan.assessment_id == assessment.id
                ))
                if not selected_scan:
                    raise ValueError("Selected scan is no longer available")
            tool_runs = []
            scan_artifacts = []
            if selected_scan:
                tool_runs = (await db.execute(
                    select(ScanToolRun).where(ScanToolRun.scan_id == selected_scan.id)
                    .order_by(ScanToolRun.started_at.asc().nulls_last(), ScanToolRun.created_at.asc())
                )).scalars().all()
                scan_artifacts = (await db.execute(
                    select(ScanArtifact).where(ScanArtifact.scan_id == selected_scan.id)
                    .order_by(ScanArtifact.path.asc())
                )).scalars().all()

            assets_query = select(Asset).where(Asset.assessment_id == assessment.id)
            if payload.asset_ids:
                assets_query = assets_query.where(Asset.id.in_(payload.asset_ids))
            if payload.owners:
                assets_query = assets_query.where(Asset.owner.in_(payload.owners))
            assets = (await db.execute(assets_query)).scalars().all()

            findings_query = select(Finding).where(Finding.assessment_id == assessment.id)
            if selected_scan:
                findings_query = findings_query.where(Finding.scan_id == selected_scan.id)
            if payload.asset_ids:
                findings_query = findings_query.where(Finding.asset_id.in_(payload.asset_ids))
            if payload.severities:
                findings_query = findings_query.where(Finding.severity.in_(payload.severities))
            if payload.statuses:
                findings_query = findings_query.where(Finding.status.in_(payload.statuses))
            if payload.modules:
                findings_query = findings_query.where(or_(
                    Finding.source.in_(payload.modules),
                    Finding.evidence_metadata["module"].astext.in_(payload.modules),
                ))
            if payload.owners:
                findings_query = findings_query.join(Asset, Asset.id == Finding.asset_id).where(Asset.owner.in_(payload.owners))
            findings = (await db.execute(findings_query)).scalars().all()

            from app.api.v1.reports import (
                _compare_findings, _generate_html_report, _generate_markdown_report,
                _generate_pdf_report, _generate_sarif_report, _serialize_finding,
            )

            comparison = None
            if payload.baseline_scan_id:
                baseline = await db.scalar(select(Scan).where(
                    Scan.id == payload.baseline_scan_id, Scan.assessment_id == assessment.id
                ))
                if not baseline:
                    raise ValueError("Baseline scan is no longer available")
                baseline_findings = (await db.execute(select(Finding).where(Finding.scan_id == baseline.id))).scalars().all()
                comparison = _compare_findings(findings, baseline_findings)

            severity_counts = {key: 0 for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
            for finding in findings:
                severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            scope = {
                "scan_id": str(payload.scan_id) if payload.scan_id else None,
                "baseline_scan_id": str(payload.baseline_scan_id) if payload.baseline_scan_id else None,
                "asset_ids": [str(item) for item in payload.asset_ids], "severities": payload.severities,
                "statuses": payload.statuses, "owners": payload.owners, "modules": payload.modules,
                "asset_count": len(assets), "finding_count": len(findings),
            }
            if payload.format == "html":
                content = _generate_html_report(assessment, assets, findings, severity_counts, payload, scope).encode()
            elif payload.format == "pdf":
                if selected_scan:
                    from app.services.scan_document_report import generate_scan_pdf

                    content = generate_scan_pdf(assessment, selected_scan, assets, findings, tool_runs)
                else:
                    content = _generate_pdf_report(assessment, assets, findings, severity_counts, scope)
            elif payload.format == "docx":
                if not selected_scan:
                    raise ValueError("DOCX scan reports require a selected scan")
                from app.services.scan_document_report import generate_scan_docx

                content = generate_scan_docx(assessment, selected_scan, assets, findings, tool_runs)
            elif payload.format == "markdown":
                content = _generate_markdown_report(assessment, assets, findings, severity_counts, scope).encode()
            elif payload.format == "sarif":
                content = _generate_sarif_report(assessment, findings).encode()
            elif payload.format == "csv":
                buffer = StringIO()
                writer = csv.DictWriter(buffer, fieldnames=["id", "scan_id", "asset_id", "severity", "status", "title", "url", "source", "template_id", "description", "evidence", "remediated_at"])
                writer.writeheader(); writer.writerows(_serialize_finding(item) for item in findings)
                content = buffer.getvalue().encode()
            elif payload.format == "evidence" and selected_scan:
                content = generate_forensic_evidence_bundle(
                    assessment, selected_scan, tool_runs, scan_artifacts
                )
            else:
                evidence = {
                    "assessment": {"id": str(assessment.id), "name": assessment.name, "target": assessment.target},
                    "scan": {"id": str(selected_scan.id), "status": selected_scan.status, "metadata": selected_scan.scan_metadata or {}} if selected_scan else None,
                    "assets": [{"id": str(item.id), "value": item.value, "type": item.asset_type, "live": item.is_live} for item in assets],
                    "findings": [_serialize_finding(item) for item in findings], "comparison": comparison, "scope": scope,
                }
                encoded = json.dumps(evidence, indent=2, default=str).encode()
                if payload.format == "json":
                    content = encoded
                else:
                    archive = BytesIO()
                    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
                        bundle.writestr("evidence.json", encoded)
                        bundle.writestr("SHA256SUMS", f"{hashlib.sha256(encoded).hexdigest()}  evidence.json\n")
                        bundle.writestr("README.txt", "Normalized ExposureScopeX evidence bundle. Raw secrets and credentials are intentionally excluded.\n")
                    content = archive.getvalue()

            size_limit = 250 * 1024 * 1024 if settings.ARTIFACT_STORAGE_BACKEND == "s3" else 25 * 1024 * 1024
            if len(content) > size_limit:
                raise ValueError(f"Generated report exceeds the {size_limit // 1024 // 1024} MiB artifact limit")
            from app.models.scan_runtime import OrganizationExecutionPolicy

            policy = await db.scalar(select(OrganizationExecutionPolicy).where(OrganizationExecutionPolicy.org_id == report.org_id))
            quota_bytes = int((((policy.settings if policy else {}) or {}).get("storage_quota_bytes")) or 50 * 1024 ** 3)
            used_bytes = await db.scalar(select(func.coalesce(func.sum(ReportArtifact.file_size), 0)).where(
                ReportArtifact.org_id == report.org_id, ReportArtifact.status == "ready")) or 0
            scan_bytes = await db.scalar(select(func.coalesce(func.sum(ScanArtifact.size_bytes), 0)).select_from(ScanArtifact)
                .join(Scan, Scan.id == ScanArtifact.scan_id).join(Assessment, Assessment.id == Scan.assessment_id)
                .where(Assessment.org_id == report.org_id, ScanArtifact.retained.is_(True))) or 0
            if int(used_bytes) + int(scan_bytes) + len(content) > quota_bytes:
                raise ValueError("Organization artifact quota would be exceeded by this report")
            await db.refresh(report)
            if report.status == "cancelled":
                return {"status": "cancelled", "report_id": report_id}
            storage_backend, object_key, database_content = persist_report(
                str(report.org_id), str(report.id), report.filename, content, report.media_type
            )
            report.status = "ready"; report.file_size = len(content); report.sha256 = hashlib.sha256(content).hexdigest()
            original_scope = dict(report.scope or {})
            report.storage_backend = storage_backend; report.object_key = object_key; report.content = database_content
            report.scope = {**original_scope, **scope}
            if selected_scan and original_scope.get("automatic"):
                metadata = dict(selected_scan.scan_metadata or {})
                automatic_reports = dict(metadata.get("automatic_reports") or {})
                automatic_reports[report.format] = {
                    "id": str(report.id), "status": "ready", "format": report.format,
                    "filename": report.filename, "sha256": report.sha256,
                }
                metadata["automatic_reports"] = automatic_reports
                if report.format == "docx":
                    metadata["automatic_report"] = automatic_reports[report.format]
                selected_scan.scan_metadata = metadata
            await db.commit()
            return {"status": "ready", "report_id": report_id, "size_bytes": len(content)}
        except Exception as exc:
            report.status = "failed"
            report.scope = {**(report.scope or {}), "error": str(exc)[:500]}
            if "selected_scan" in locals() and selected_scan and (report.scope or {}).get("automatic"):
                metadata = dict(selected_scan.scan_metadata or {})
                automatic_reports = dict(metadata.get("automatic_reports") or {})
                automatic_reports[report.format] = {
                    "id": str(report.id), "status": "failed", "format": report.format,
                    "filename": report.filename, "error": str(exc)[:500],
                }
                metadata["automatic_reports"] = automatic_reports
                if report.format == "docx":
                    metadata["automatic_report"] = automatic_reports[report.format]
                selected_scan.scan_metadata = metadata
            await db.commit()
            raise
