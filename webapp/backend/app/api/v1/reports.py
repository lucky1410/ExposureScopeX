"""Report endpoints: list, generate, download."""

import asyncio
import hashlib
import html
import csv
import json
import uuid
import zipfile
from io import BytesIO, StringIO
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db, require_permission
from app.config import settings
from app.models.assessment import Assessment
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.report import ReportArtifact
from app.models.scan import Scan
from app.models.user import User
from app.schemas.report import ReportRequest, ReportResponse
from app.services.artifact_storage import delete_object, load_report, persist_report
from app.services.audit import AuditEvent, write_audit

router = APIRouter(prefix="/reports", tags=["Reports"])


def _finding_key(finding: Finding) -> str:
    return "|".join([
        str(finding.asset_id or ""),
        str(finding.source or ""),
        str(finding.template_id or finding.title),
        str(finding.url or ""),
    ])


def _serialize_finding(finding: Finding) -> dict:
    return {
        "id": str(finding.id),
        "scan_id": str(finding.scan_id) if finding.scan_id else None,
        "asset_id": str(finding.asset_id) if finding.asset_id else None,
        "severity": finding.severity,
        "status": finding.status,
        "title": finding.title,
        "description": finding.description,
        "url": finding.url,
        "source": finding.source,
        "template_id": finding.template_id,
        "evidence": finding.evidence,
        "remediated_at": finding.remediated_at.isoformat() if finding.remediated_at else None,
    }


def _compare_findings(current: list[Finding], baseline: list[Finding]) -> dict:
    current_map = {_finding_key(item): item for item in current}
    baseline_map = {_finding_key(item): item for item in baseline}
    current_keys = set(current_map)
    baseline_keys = set(baseline_map)
    changed = []
    for key in sorted(current_keys & baseline_keys):
        before, after = baseline_map[key], current_map[key]
        if before.severity != after.severity or before.status != after.status:
            changed.append({
                "key": key,
                "title": after.title,
                "before": {"severity": before.severity, "status": before.status},
                "after": {"severity": after.severity, "status": after.status},
            })
    return {
        "new": [_serialize_finding(current_map[key]) for key in sorted(current_keys - baseline_keys)],
        "resolved": [_serialize_finding(baseline_map[key]) for key in sorted(baseline_keys - current_keys)],
        "unchanged": len(current_keys & baseline_keys) - len(changed),
        "changed": changed,
        "summary": {
            "new": len(current_keys - baseline_keys),
            "resolved": len(baseline_keys - current_keys),
            "unchanged": len(current_keys & baseline_keys) - len(changed),
            "changed": len(changed),
        },
    }


def _response(report: ReportArtifact) -> ReportResponse:
    created_at = report.created_at.isoformat()
    return ReportResponse(
        id=str(report.id),
        assessment_id=report.assessment_id,
        title=report.title,
        format=report.format,
        filename=report.filename,
        status=report.status,
        download_url=f"/api/v1/reports/{report.id}/download" if report.status == "ready" else None,
        generated_at=created_at if report.status == "ready" else None,
        created_at=created_at,
        file_size=report.file_size,
        version=report.version,
        sha256=report.sha256,
        scope=report.scope or {},
        error=(report.scope or {}).get("error"),
    )


@router.get("", response_model=list[ReportResponse])
async def list_reports(
    assessment_id: uuid.UUID | None = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all generated reports for the user's organization."""
    query = select(ReportArtifact).where(ReportArtifact.org_id == current_user.org_id)
    if assessment_id:
        query = query.where(ReportArtifact.assessment_id == assessment_id)
    reports = (await db.execute(query.order_by(ReportArtifact.created_at.desc()))).scalars().all()
    return [_response(report) for report in reports]


@router.post("", response_model=ReportResponse, status_code=status.HTTP_201_CREATED, include_in_schema=False)
@router.post("/generate", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def generate_report(
    payload: ReportRequest,
    current_user: User = Depends(require_permission("reports:generate")),
    db: AsyncSession = Depends(get_db),
):
    """Generate a new report for an assessment."""
    # Verify assessment exists and belongs to user's org
    result = await db.execute(
        select(Assessment).where(
            and_(
                Assessment.id == payload.assessment_id,
                Assessment.org_id == current_user.org_id,
            )
        )
    )
    assessment = result.scalar_one_or_none()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found"
        )

    requested_scan_ids = [item for item in (payload.scan_id, payload.baseline_scan_id) if item]
    if requested_scan_ids:
        found_scan_ids = set((await db.execute(select(Scan.id).where(
            Scan.id.in_(requested_scan_ids), Scan.assessment_id == assessment.id
        ))).scalars().all())
        if found_scan_ids != set(requested_scan_ids):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "One or more report scans were not found in this assessment")

    now = datetime.now(timezone.utc)
    extension = {"html": "html", "pdf": "pdf", "docx": "docx", "sarif": "sarif.json", "markdown": "md", "csv": "csv", "json": "json", "evidence": "zip"}[payload.format]
    media_type = {
        "html": "text/html; charset=utf-8", "pdf": "application/pdf", "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "markdown": "text/markdown; charset=utf-8",
        "sarif": "application/sarif+json", "csv": "text/csv; charset=utf-8", "json": "application/json", "evidence": "application/zip",
    }[payload.format]
    safe_name = "".join(char if char.isalnum() or char in "-_" else "_" for char in assessment.name).strip("_")
    next_version = (await db.scalar(select(func.coalesce(func.max(ReportArtifact.version), 0) + 1).where(
        ReportArtifact.assessment_id == assessment.id, ReportArtifact.format == payload.format
    ))) or 1
    report = ReportArtifact(
        org_id=current_user.org_id, assessment_id=assessment.id, created_by=current_user.id,
        title=payload.title or f"{assessment.name} {payload.format.upper()} report", format=payload.format,
        filename=f"report_{safe_name or assessment.id}_{now.strftime('%Y%m%d_%H%M%S')}.{extension}",
        media_type=media_type, status="generating", version=next_version, file_size=0, sha256="0" * 64,
        storage_backend="database", scope={"request": payload.model_dump(mode="json")},
    )
    db.add(report)
    await db.flush()
    # Commit the outbox row before publishing so a fast worker cannot consume
    # an ID that is still invisible outside this transaction.
    await db.commit()
    await db.refresh(report)
    from app.services.celery_app import generate_report_task
    try:
        task = generate_report_task.apply_async(args=[str(report.id)], queue="reports")
        report.scope = {**report.scope, "task_id": task.id}
    except Exception as exc:
        report.status = "failed"
        report.scope = {**report.scope, "error": f"Report worker unavailable: {type(exc).__name__}"}
    await db.flush()
    await write_audit(db, event=AuditEvent.REPORT_GENERATE, user_id=str(current_user.id), org_id=str(current_user.org_id),
        resource_type="report", resource_id=str(report.id), details={"format": payload.format, "status": report.status})
    await db.refresh(report)
    return _response(report)

    # Legacy inline materialization is retained temporarily for migration safety;
    # all API calls return through the durable queue path above.
    selected_scan = None
    if payload.scan_id:
        selected_scan = await db.scalar(
            select(Scan).where(
                Scan.id == payload.scan_id,
                Scan.assessment_id == assessment.id,
            )
        )
        if not selected_scan:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found in this assessment")

    # Load data for report
    assets_query = select(Asset).where(Asset.assessment_id == assessment.id)
    if payload.asset_ids:
        assets_query = assets_query.where(Asset.id.in_(payload.asset_ids))
    if payload.owners:
        assets_query = assets_query.where(Asset.owner.in_([item[:255] for item in payload.owners]))
    assets_q = await db.execute(assets_query)
    assets = assets_q.scalars().all()

    findings_query = select(Finding).where(Finding.assessment_id == assessment.id)
    if selected_scan:
        findings_query = findings_query.where(Finding.scan_id == selected_scan.id)
    if payload.asset_ids:
        findings_query = findings_query.where(Finding.asset_id.in_(payload.asset_ids))
    normalized_severities = [item.upper() for item in payload.severities]
    if any(item not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} for item in normalized_severities):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid report severity scope")
    if normalized_severities:
        findings_query = findings_query.where(Finding.severity.in_(normalized_severities))
    if payload.statuses:
        findings_query = findings_query.where(Finding.status.in_([item[:20] for item in payload.statuses]))
    if payload.modules:
        modules = [item[:100] for item in payload.modules]
        findings_query = findings_query.where(or_(
            Finding.source.in_(modules),
            Finding.evidence_metadata["module"].astext.in_(modules),
        ))
    if payload.owners:
        findings_query = findings_query.join(Asset, Asset.id == Finding.asset_id).where(
            Asset.owner.in_([item[:255] for item in payload.owners])
        )
    findings_q = await db.execute(findings_query)
    findings = findings_q.scalars().all()
    comparison = None
    if payload.baseline_scan_id:
        if not selected_scan:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "baseline_scan_id requires scan_id")
        baseline_scan = await db.scalar(
            select(Scan).where(
                Scan.id == payload.baseline_scan_id,
                Scan.assessment_id == assessment.id,
            )
        )
        if not baseline_scan:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Baseline scan not found in this assessment")
        baseline_findings = (
            await db.execute(select(Finding).where(Finding.scan_id == baseline_scan.id))
        ).scalars().all()
        comparison = _compare_findings(findings, baseline_findings)

    # Severity counts
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    now = datetime.now(timezone.utc)
    report_scope = {
        "scan_id": str(selected_scan.id) if selected_scan else None,
        "baseline_scan_id": str(payload.baseline_scan_id) if payload.baseline_scan_id else None,
        "asset_ids": [str(item) for item in payload.asset_ids],
        "severities": normalized_severities,
        "statuses": payload.statuses,
        "owners": payload.owners,
        "modules": payload.modules,
        "asset_count": len(assets),
        "finding_count": len(findings),
    }
    ext_map = {"html": "html", "pdf": "pdf", "docx": "docx", "sarif": "sarif.json", "markdown": "md", "csv": "csv", "json": "json", "evidence": "zip"}
    ext = ext_map.get(payload.format, "html")
    safe_name = "".join(char if char.isalnum() or char in "-_" else "_" for char in assessment.name).strip("_")
    filename = f"report_{safe_name or assessment.id}_{now.strftime('%Y%m%d_%H%M%S')}.{ext}"

    # Build report content (HTML)
    media_types = {
        "html": "text/html; charset=utf-8",
        "pdf": "application/pdf",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "markdown": "text/markdown; charset=utf-8",
        "sarif": "application/sarif+json",
        "csv": "text/csv; charset=utf-8",
        "json": "application/json",
        "evidence": "application/zip",
    }
    if payload.format == "html":
        html_report = _generate_html_report(assessment, assets, findings, severity_counts, payload, report_scope)
        content = html_report.encode("utf-8")
    elif payload.format == "pdf":
        content = _generate_pdf_report(assessment, assets, findings, severity_counts, report_scope)
    elif payload.format == "markdown":
        content = _generate_markdown_report(assessment, assets, findings, severity_counts, report_scope).encode("utf-8")
    elif payload.format == "sarif":
        content = _generate_sarif_report(assessment, findings).encode("utf-8")
    elif payload.format == "csv":
        buffer = StringIO()
        writer = csv.DictWriter(buffer, fieldnames=["id", "scan_id", "asset_id", "severity", "status", "title", "url", "source", "template_id", "description", "evidence", "remediated_at"])
        writer.writeheader()
        writer.writerows(_serialize_finding(item) for item in findings)
        content = buffer.getvalue().encode("utf-8")
    else:
        evidence_payload = {
            "assessment": {"id": str(assessment.id), "name": assessment.name, "target": assessment.target},
            "scan": {
                "id": str(selected_scan.id),
                "status": selected_scan.status,
                "metadata": selected_scan.scan_metadata or {},
            } if selected_scan else None,
            "assets": [{"id": str(item.id), "value": item.value, "type": item.asset_type, "live": item.is_live} for item in assets],
            "findings": [_serialize_finding(item) for item in findings],
            "comparison": comparison,
            "scope": report_scope,
            "generated_at": now.isoformat(),
        }
        encoded = json.dumps(evidence_payload, indent=2, default=str).encode("utf-8")
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
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Generated report exceeds the {size_limit // 1024 // 1024} MiB artifact limit",
        )

    next_version = (
        await db.scalar(
            select(func.coalesce(func.max(ReportArtifact.version), 0) + 1).where(
                ReportArtifact.assessment_id == assessment.id,
                ReportArtifact.format == payload.format,
            )
        )
    ) or 1
    report_id = uuid.uuid4()
    try:
        storage_backend, stored_key, database_content = await asyncio.to_thread(
            persist_report,
            str(current_user.org_id),
            str(report_id),
            filename,
            content,
            media_types[payload.format],
        )
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Artifact storage is unavailable") from exc
    report = ReportArtifact(
        id=report_id,
        org_id=current_user.org_id,
        assessment_id=assessment.id,
        created_by=current_user.id,
        title=payload.title or f"{assessment.name} {payload.format.upper()} report",
        format=payload.format,
        filename=filename,
        media_type=media_types[payload.format],
        status="ready",
        version=next_version,
        file_size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        storage_backend=storage_backend,
        object_key=stored_key,
        content=database_content,
        scope=report_scope,
    )
    db.add(report)
    try:
        await db.flush()
    except Exception:
        if stored_key:
            try:
                await asyncio.to_thread(delete_object, stored_key)
            except Exception:
                pass
        raise
    await db.refresh(report)
    return _response(report)


@router.get("/compare")
async def compare_scans(
    current_scan_id: uuid.UUID,
    baseline_scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scans = (
        await db.execute(
            select(Scan, Assessment)
            .join(Assessment, Assessment.id == Scan.assessment_id)
            .where(
                Scan.id.in_([current_scan_id, baseline_scan_id]),
                Assessment.org_id == current_user.org_id,
            )
        )
    ).all()
    by_id = {scan.id: (scan, assessment) for scan, assessment in scans}
    if current_scan_id not in by_id or baseline_scan_id not in by_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "One or both scans were not found")
    if by_id[current_scan_id][0].assessment_id != by_id[baseline_scan_id][0].assessment_id:
        raise HTTPException(status.HTTP_409_CONFLICT, "Scans must belong to the same assessment")
    current = (await db.execute(select(Finding).where(Finding.scan_id == current_scan_id))).scalars().all()
    baseline = (await db.execute(select(Finding).where(Finding.scan_id == baseline_scan_id))).scalars().all()
    return {
        "assessment_id": str(by_id[current_scan_id][0].assessment_id),
        "current_scan_id": str(current_scan_id),
        "baseline_scan_id": str(baseline_scan_id),
        **_compare_findings(current, baseline),
    }


@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Download a generated report."""
    try:
        normalized_id = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    report = await db.scalar(
        select(ReportArtifact).where(
            ReportArtifact.id == normalized_id,
            ReportArtifact.org_id == current_user.org_id,
        )
    )
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Report not found"
        )

    if report.status != "ready":
        raise HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail="Report is still being generated",
        )

    from fastapi.responses import Response

    try:
        content = await asyncio.to_thread(load_report, report.storage_backend, report.object_key, report.content)
    except FileNotFoundError:
        raise HTTPException(status.HTTP_410_GONE, "Report artifact is no longer available")
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Artifact storage is unavailable") from exc
    if hashlib.sha256(content).hexdigest() != report.sha256:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Report integrity verification failed")

    await write_audit(db, event=AuditEvent.REPORT_EXPORT, user_id=str(current_user.id), org_id=str(current_user.org_id),
        resource_type="report", resource_id=str(report.id), details={"format": report.format, "sha256": report.sha256})

    return Response(
        content=content,
        media_type=report.media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{report.filename}"',
            "ETag": f'"{report.sha256}"',
            "X-Content-SHA256": report.sha256,
        },
    )


@router.post("/{report_id}/cancel", response_model=ReportResponse)
async def cancel_report(report_id: uuid.UUID, current_user: User = Depends(require_permission("reports:delete")), db: AsyncSession = Depends(get_db)):
    report = await db.scalar(select(ReportArtifact).where(
        ReportArtifact.id == report_id, ReportArtifact.org_id == current_user.org_id
    ))
    if not report:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    if report.status != "generating":
        raise HTTPException(status.HTTP_409_CONFLICT, "Only a generating report can be cancelled")
    task_id = (report.scope or {}).get("task_id")
    if task_id:
        from app.services.celery_app import celery_app
        celery_app.control.revoke(task_id, terminate=False)
    report.status = "cancelled"
    report.scope = {**(report.scope or {}), "cancelled_at": datetime.now(timezone.utc).isoformat()}
    await write_audit(db, event="report.cancel", user_id=str(current_user.id), org_id=str(current_user.org_id),
        resource_type="report", resource_id=str(report.id))
    await db.flush(); await db.refresh(report)
    return _response(report)


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(
    report_id: uuid.UUID,
    current_user: User = Depends(require_permission("reports:delete")),
    db: AsyncSession = Depends(get_db),
):
    report = await db.scalar(
        select(ReportArtifact).where(
            ReportArtifact.id == report_id,
            ReportArtifact.org_id == current_user.org_id,
        )
    )
    if not report:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    if report.storage_backend == "s3":
        try:
            await asyncio.to_thread(delete_object, report.object_key)
        except Exception as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Artifact storage is unavailable") from exc
    await db.delete(report)


def _generate_html_report(assessment, assets, findings, severity_counts, payload, scope) -> str:
    """Generate an HTML report with Chart.js visualizations."""
    assessment_name = html.escape(assessment.name)
    assessment_target = html.escape(assessment.target)
    assessment_type = html.escape(assessment.target_type)
    assessment_mode = html.escape(assessment.scan_mode)
    assessment_status = html.escape(assessment.status)
    scope_text = "; ".join(_report_scope_lines(scope))
    findings_html = ""
    for f in sorted(findings, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x.severity)):
        color_map = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#2563eb",
            "INFO": "#6b7280",
        }
        color = color_map.get(f.severity, "#6b7280")
        findings_html += f"""
        <div class="finding" style="border-left: 4px solid {color}; padding: 12px; margin: 8px 0; background: #1e1e2e; border-radius: 4px;">
            <span style="color: {color}; font-weight: bold;">[{f.severity}]</span>
            <strong>{html.escape(f.title)}</strong>
            <p style="color: #94a3b8; margin: 4px 0;">{html.escape(f.description or '')}</p>
            {f'<code style="color: #38bdf8;">{html.escape(f.url)}</code>' if f.url else ''}
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ExposureScopeX Report - {assessment_name}</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px; }}
        h1 {{ color: #38bdf8; }} h2 {{ color: #818cf8; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin: 20px 0; }}
        .stat {{ background: #1e293b; padding: 16px; border-radius: 8px; text-align: center; }}
        .stat .value {{ font-size: 2em; font-weight: bold; color: #38bdf8; }}
        .chart-container {{ max-width: 400px; margin: 20px auto; }}
        table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #1e293b; color: #38bdf8; }}
    </style>
</head>
<body>
    <h1>ExposureScopeX Security Assessment Report</h1>
    <p><strong>Assessment:</strong> {assessment_name}</p>
    <p><strong>Target:</strong> {assessment_target} ({assessment_type})</p>
    <p><strong>Scan Mode:</strong> {assessment_mode}</p>
    <p><strong>Status:</strong> {assessment_status}</p>
    <p><strong>Applied scope:</strong> {html.escape(scope_text)}</p>

    {'<h2>Executive Summary</h2><p>This report summarizes the security assessment findings for <strong>' + assessment_target + '</strong>. A total of <strong>' + str(len(findings)) + '</strong> findings were identified across <strong>' + str(len(assets)) + '</strong> assets.</p>' if payload.executive_summary else ''}

    <div class="stats">
        <div class="stat"><div class="value">{len(assets)}</div><div>Assets</div></div>
        <div class="stat"><div class="value">{len(findings)}</div><div>Findings</div></div>
        <div class="stat"><div class="value" style="color:#dc2626">{severity_counts.get('CRITICAL', 0)}</div><div>Critical</div></div>
        <div class="stat"><div class="value" style="color:#ea580c">{severity_counts.get('HIGH', 0)}</div><div>High</div></div>
        <div class="stat"><div class="value" style="color:#ca8a04">{severity_counts.get('MEDIUM', 0)}</div><div>Medium</div></div>
    </div>

    <h2>Assets ({len(assets)})</h2>
    <table>
        <tr><th>Value</th><th>Type</th><th>Live</th></tr>
        {''.join(f'<tr><td>{html.escape(a.value)}</td><td>{html.escape(a.asset_type)}</td><td>{"Yes" if a.is_live else "No"}</td></tr>' for a in assets)}
    </table>

    <h2>Findings ({len(findings)})</h2>
    {findings_html}

    <hr style="border-color: #334155; margin-top: 40px;">
    <p style="color: #64748b; text-align: center;">Generated by ExposureScopeX v2.2.0</p>
</body>
</html>"""


def _report_scope_lines(scope: dict) -> list[str]:
    labels = {"scan_id": "Scan", "asset_ids": "Assets", "severities": "Severities", "statuses": "Statuses", "owners": "Owners", "modules": "Modules"}
    lines = []
    for key, label in labels.items():
        value = scope.get(key)
        if value:
            rendered = ", ".join(map(str, value)) if isinstance(value, list) else str(value)
            lines.append(f"{label}: {rendered}")
    return lines or ["All assessment data"]


def _generate_pdf_report(assessment, assets, findings, severity_counts, scope=None) -> bytes:
    """Generate a bounded, text-only PDF without interpreting report content as HTML."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"ExposureScopeX report - {assessment.name}",
    )
    styles = getSampleStyleSheet()
    story = [
        Paragraph("ExposureScopeX Security Assessment Report", styles["Title"]),
        Spacer(1, 5 * mm),
        Paragraph(f"<b>Assessment:</b> {html.escape(assessment.name)}", styles["BodyText"]),
        Paragraph(f"<b>Target:</b> {html.escape(assessment.target)}", styles["BodyText"]),
        Paragraph(f"<b>Status:</b> {html.escape(assessment.status)}", styles["BodyText"]),
        Paragraph(f"<b>Applied scope:</b> {html.escape('; '.join(_report_scope_lines(scope or {})))}", styles["BodyText"]),
        Spacer(1, 4 * mm),
        Paragraph("Summary", styles["Heading2"]),
    ]
    summary = [
        ["Assets", "Findings", "Critical", "High", "Medium", "Low"],
        [
            str(len(assets)),
            str(len(findings)),
            str(severity_counts.get("CRITICAL", 0)),
            str(severity_counts.get("HIGH", 0)),
            str(severity_counts.get("MEDIUM", 0)),
            str(severity_counts.get("LOW", 0)),
        ],
    ]
    table = Table(summary, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17324d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([table, Spacer(1, 5 * mm), Paragraph("Findings", styles["Heading2"])])
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for finding in sorted(findings, key=lambda item: severity_order.get(item.severity, 5)):
        story.append(Paragraph(
            f"<b>[{html.escape(finding.severity)}] {html.escape(finding.title)}</b>",
            styles["Heading3"],
        ))
        if finding.description:
            story.append(Paragraph(html.escape(finding.description), styles["BodyText"]))
        if finding.url:
            story.append(Paragraph(f"URL: {html.escape(finding.url)}", styles["BodyText"]))
        story.append(Spacer(1, 2 * mm))
    if not findings:
        story.append(Paragraph("No findings were recorded for this assessment.", styles["BodyText"]))

    document.build(story)
    return buffer.getvalue()


def _generate_markdown_report(assessment, assets, findings, severity_counts, scope) -> str:
    """Generate a Markdown report."""
    lines = [
        f"# ExposureScopeX Security Report - {assessment.name}",
        "",
        f"**Target:** {assessment.target} ({assessment.target_type})",
        f"**Mode:** {assessment.scan_mode}",
        f"**Status:** {assessment.status}",
        f"**Applied scope:** {'; '.join(_report_scope_lines(scope))}",
        "",
        "## Summary",
        "",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total Assets | {len(assets)} |",
        f"| Total Findings | {len(findings)} |",
        f"| Critical | {severity_counts.get('CRITICAL', 0)} |",
        f"| High | {severity_counts.get('HIGH', 0)} |",
        f"| Medium | {severity_counts.get('MEDIUM', 0)} |",
        f"| Low | {severity_counts.get('LOW', 0)} |",
        f"| Info | {severity_counts.get('INFO', 0)} |",
        "",
        "## Assets",
        "",
        "| Value | Type | Live |",
        "|-------|------|------|",
    ]
    for a in assets:
        lines.append(f"| {a.value} | {a.asset_type} | {'Yes' if a.is_live else 'No'} |")

    lines.extend(["", "## Findings", ""])
    for f in sorted(findings, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x.severity)):
        lines.append(f"### [{f.severity}] {f.title}")
        if f.description:
            lines.append(f"\n{f.description}")
        if f.url:
            lines.append(f"\n**URL:** `{f.url}`")
        lines.append("")

    lines.append("\n---\n*Generated by ExposureScopeX v2.2.0*")
    return "\n".join(lines)


def _generate_sarif_report(assessment, findings) -> str:
    """Generate a SARIF 2.1.0 report."""
    import json

    rules = []
    results = []
    seen_rules = set()

    for f in findings:
        rule_id = f.template_id or f.title.lower().replace(" ", "-")
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            level_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "none"}
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.title},
                "defaultConfiguration": {"level": level_map.get(f.severity, "warning")},
                "properties": {"severity": f.severity},
            })

        results.append({
            "ruleId": rule_id,
            "message": {"text": f.description or f.title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.url or assessment.target}
                }
            }] if f.url or assessment.target else [],
            "properties": {"severity": f.severity, "status": f.status},
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ExposureScopeX",
                    "version": "2.2.0",
                    "informationUri": "https://github.com/exposurescopex",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)
