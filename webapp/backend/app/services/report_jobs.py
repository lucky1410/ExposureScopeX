"""Durable report materialization outside API request workers."""

from __future__ import annotations

import csv
import hashlib
import json
import zipfile
import uuid
from io import BytesIO, StringIO

from sqlalchemy import func, or_, select

from app.config import settings
from app.database import async_session_factory
from app.models.asset import Asset
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.models.report import ReportArtifact
from app.models.scan import Scan
from app.schemas.report import ReportRequest
from app.services.artifact_storage import persist_report


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
            assessment = await db.scalar(select(Assessment).where(
                Assessment.id == report.assessment_id, Assessment.org_id == report.org_id
            ))
            if not assessment:
                raise ValueError("Assessment is no longer available")

            selected_scan = None
            if payload.scan_id:
                selected_scan = await db.scalar(select(Scan).where(
                    Scan.id == payload.scan_id, Scan.assessment_id == assessment.id
                ))
                if not selected_scan:
                    raise ValueError("Selected scan is no longer available")

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
                content = _generate_pdf_report(assessment, assets, findings, severity_counts, scope)
            elif payload.format == "markdown":
                content = _generate_markdown_report(assessment, assets, findings, severity_counts, scope).encode()
            elif payload.format == "sarif":
                content = _generate_sarif_report(assessment, findings).encode()
            elif payload.format == "csv":
                buffer = StringIO()
                writer = csv.DictWriter(buffer, fieldnames=["id", "scan_id", "asset_id", "severity", "status", "title", "url", "source", "template_id", "description", "evidence", "remediated_at"])
                writer.writeheader(); writer.writerows(_serialize_finding(item) for item in findings)
                content = buffer.getvalue().encode()
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
            from app.models.scan_runtime import OrganizationExecutionPolicy, ScanArtifact

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
            report.storage_backend = storage_backend; report.object_key = object_key; report.content = database_content; report.scope = scope
            await db.commit()
            return {"status": "ready", "report_id": report_id, "size_bytes": len(content)}
        except Exception as exc:
            report.status = "failed"
            report.scope = {**(report.scope or {}), "error": str(exc)[:500]}
            await db.commit()
            raise
