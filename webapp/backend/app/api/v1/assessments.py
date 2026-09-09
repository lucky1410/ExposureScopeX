"""Assessment CRUD and rescan endpoints."""

import csv
import io
import logging
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.dependencies import get_current_user, get_db, require_permission, require_role
from app.models.assessment import Assessment
from app.models.asset import Asset
from app.models.scan import Scan
from app.models.report import ReportArtifact
from app.models.scan_runtime import OrganizationExecutionPolicy, OrganizationScanProfile, ScanArtifact, ScanSchedule, ScanScheduleRun
from app.models.user import User
from app.schemas.assessment import (
    AssessmentCreate,
    AssessmentImportResponse,
    AssessmentList,
    AssessmentResponse,
    AssessmentScanResponse,
    ScanExecutionList,
    ScanExecutionResponse,
    ExecutionPreviewResponse,
    ScanProfileResponse,
    SavedScanProfileCreate,
    SavedScanProfileResponse,
    ScanScheduleCreate,
    ScanScheduleResponse,
    ScanScheduleUpdate,
)
from app.services.asset_inventory import build_seed_metadata, normalize_target
from app.services.assessment_runtime import build_scan_metadata
from app.services.capability_catalog import get_capability_catalog
from app.services.intake_parser import parse_csv_row
from app.services.open_source_catalog import build_tool_plan
from app.services.scan_authorization import AuthorizationCoverage, require_scan_authorization
from app.services.scan_planning import build_scan_plan
from app.services.scan_profiles import get_scan_profile
from app.services.validation import ValidationError as TargetValidationError
from app.services.audit import write_audit

router = APIRouter(prefix="/assessments", tags=["Assessments"])
logger = logging.getLogger(__name__)


def _valid_timezone(value: str) -> str:
    try:
        ZoneInfo(value)
    except ZoneInfoNotFoundError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unknown IANA timezone") from exc
    return value


def _summarize_import_name(file_name: str | None, imported_targets: list[dict]) -> tuple[str | None, str | None]:
    if not imported_targets:
        return None, None

    base_name = (file_name or "Imported targets").rsplit(".", 1)[0].replace("_", " ").replace("-", " ").strip()
    if not base_name:
        base_name = "Imported targets"

    type_counts = Counter(item["target_type"] for item in imported_targets if item.get("target_type"))
    description = f"{len(imported_targets)} normalized targets imported from CSV"
    if type_counts:
        detail = ", ".join(f"{count} {kind}" for kind, count in sorted(type_counts.items()))
        description = f"{description} ({detail})"
    return base_name.title(), description


def _dedupe_imported_targets(imported_targets: list[dict]) -> tuple[list[dict], int]:
    unique_targets: list[dict] = []
    seen_keys: set[str] = set()
    skipped = 0

    for item in imported_targets:
        normalized_target = normalize_target(item["target"], item["target_type"])
        if normalized_target.canonical_key in seen_keys:
            skipped += 1
            continue

        unique_targets.append(
            {
                **item,
                "target": normalized_target.normalized_value,
                "target_type": normalized_target.target_type,
                "canonical_key": normalized_target.canonical_key,
                "root_domain": normalized_target.root_domain,
                "parent_key": normalized_target.parent_key,
            }
        )
        seen_keys.add(normalized_target.canonical_key)

    return unique_targets, skipped


def _build_batch_target_label(imported_targets: list[dict]) -> str:
    first_target = imported_targets[0]["target"]
    if len(imported_targets) == 1:
        return first_target
    return f"{first_target} (+{len(imported_targets) - 1} more)"


async def _create_assessment_assets(db: AsyncSession, assessment: Assessment, imported_targets: list[dict]) -> None:
    now = datetime.now(timezone.utc)
    for item in imported_targets:
        seed = build_seed_metadata(item["target"], item["target_type"], source="assessment_import", stage="confirmed")
        raw = item.get("raw") or {}
        owner = next((
            str(value).strip()
            for key, value in raw.items()
            if str(key).strip().lower().replace(" ", "_") in {"owner", "team", "business_unit", "asset_owner"}
            and str(value).strip()
        ), None)
        db.add(
            Asset(
                assessment_id=assessment.id,
                asset_type=item["target_type"],
                value=item["target"],
                canonical_key=item.get("canonical_key") or seed.get("canonical_key"),
                root_domain=item.get("root_domain") or seed.get("root_domain"),
                owner=owner,
                ownership_status="confirmed" if owner else "unattributed",
                first_seen=now,
                last_seen=now,
                is_live=True,
                metadata_={
                    "imported": True,
                    "seed": seed,
                    "canonical_key": item.get("canonical_key"),
                    "root_domain": item.get("root_domain"),
                    "parent_key": item.get("parent_key"),
                    "name": item.get("name"),
                    "description": item.get("description"),
                    "tags": item.get("tags", []),
                    "raw": raw,
                },
            )
        )


async def _dispatch_assessment_scan(
    assessment: Assessment,
    db: AsyncSession,
    authorization: AuthorizationCoverage,
) -> Scan:
    """Create a scan row and dispatch work for an assessment."""
    # Serialize dispatch decisions per tenant so concurrent API requests cannot
    # race past queue and concurrency limits.
    await db.execute(
        select(func.pg_advisory_xact_lock(func.hashtext(str(assessment.org_id))))
    )
    policy = await db.scalar(
        select(OrganizationExecutionPolicy).where(
            OrganizationExecutionPolicy.org_id == assessment.org_id
        )
    )
    max_active = policy.max_active_scans if policy else settings.DEFAULT_MAX_ACTIVE_SCANS_PER_ORG
    max_queued = policy.max_queued_scans if policy else settings.DEFAULT_MAX_QUEUED_SCANS_PER_ORG
    quota_bytes = int(((policy.settings if policy else {}) or {}).get("storage_quota_bytes") or 50 * 1024 ** 3)
    retained_bytes = await db.scalar(select(func.coalesce(func.sum(ScanArtifact.size_bytes), 0)).select_from(ScanArtifact)
        .join(Scan, Scan.id == ScanArtifact.scan_id).join(Assessment, Assessment.id == Scan.assessment_id)
        .where(Assessment.org_id == assessment.org_id, ScanArtifact.retained.is_(True))) or 0
    report_bytes = await db.scalar(select(func.coalesce(func.sum(ReportArtifact.file_size), 0)).where(
        ReportArtifact.org_id == assessment.org_id)) or 0
    if int(retained_bytes) + int(report_bytes) >= quota_bytes:
        raise HTTPException(status.HTTP_507_INSUFFICIENT_STORAGE, "Organization artifact quota reached; adjust retention or storage policy before starting another scan")
    counts = dict((await db.execute(
        select(Scan.status, func.count(Scan.id))
        .join(Assessment, Assessment.id == Scan.assessment_id)
        .where(
            Assessment.org_id == assessment.org_id,
            Scan.status.in_(["queued", "running"]),
        )
        .group_by(Scan.status)
    )).all())
    if int(counts.get("running", 0)) >= max_active:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Organization active-scan limit reached ({max_active}); wait for a running scan to finish",
        )
    if int(counts.get("queued", 0)) >= max_queued:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Organization queued-scan limit reached ({max_queued}); cancel or wait for queued work",
        )
    scan_metadata = build_scan_metadata(
        assessment_id=str(assessment.id),
        scan_mode=assessment.scan_mode,
        target_type=assessment.target_type,
        phases=assessment.phases or {},
        flags=assessment.flags or {},
    )
    scan_metadata["authorization"] = authorization.as_evidence()
    scan = Scan(
        assessment_id=assessment.id,
        status="queued",
        current_phase="queued",
        progress=0,
        scan_metadata=scan_metadata,
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    assessment.status = "running"
    await db.flush()
    await db.refresh(scan)
    await db.refresh(assessment)

    # Make the execution visible before Celery can consume it. Without this,
    # a fast worker can race the request transaction and fail to find the scan.
    scan.current_phase = "dispatching"
    await db.commit()

    try:
        from app.services.celery_app import run_assessment_scan
        from app.services.worker_capabilities import compatible_workers

        queue = str((scan.scan_metadata or {}).get("execution_policy", {}).get("queue") or "scans-web")
        workers = await compatible_workers(db, queue, (scan.scan_metadata or {}).get("tool_plan") or [])
        if settings.ENFORCE_WORKER_CAPABILITIES and not workers:
            raise RuntimeError(f"No online worker advertises the required capabilities for {queue}")
        task = run_assessment_scan.apply_async(
            args=[str(assessment.id), str(assessment.org_id), str(scan.id)],
            queue=queue,
            priority=policy.priority if policy else 5,
        )
        task_id = task.id
    except Exception as exc:
        logger.exception("Could not dispatch assessment scan %s", scan.id)
        scan.status = "failed"
        scan.current_phase = "dispatch_failed"
        scan.error_message = f"Could not submit scan to the worker: {exc}"
        scan.completed_at = datetime.now(timezone.utc)
        assessment.status = "failed"
        scan.scan_metadata = {
            **(scan.scan_metadata or {}),
            "dispatch": {"transport": "celery", "error": str(exc)},
        }
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The scan worker is unavailable. The assessment was saved and can be started again.",
        ) from exc

    scan.celery_task_id = task_id
    scan.current_phase = "dispatched"
    scan.scan_metadata = {
        **(scan.scan_metadata or {}),
        "dispatch": {
            "task_id": task_id,
            "transport": "celery",
            "queue": queue,
            "compatible_workers": [worker.worker_name for worker in workers],
        },
    }
    await db.flush()
    return scan


def _scan_cancel_metadata(scan: Scan) -> dict:
    metadata = dict(scan.scan_metadata or {})
    metadata["cancel_requested"] = True
    metadata["cancel_requested_at"] = datetime.now(timezone.utc).isoformat()
    return metadata


def _scan_execution_response(
    scan: Scan,
    assessment: Assessment,
    *,
    include_log: bool,
) -> ScanExecutionResponse:
    scan_data = AssessmentScanResponse.model_validate(scan).model_dump()
    if not include_log:
        scan_data["raw_log"] = None
    elif scan.session_dir:
        from app.services.celery_app import _read_scan_summary_files, _read_tool_runs

        metadata = dict(scan_data.get("scan_metadata") or {})
        metadata["tool_runs"] = _read_tool_runs(scan.session_dir, include_output=True)
        metadata.update(_read_scan_summary_files(scan.session_dir))
        scan_data["scan_metadata"] = metadata
    events = sorted(scan.events, key=lambda item: item.created_at)[-250:] if include_log else []
    tool_runs = sorted(scan.tool_runs, key=lambda item: item.created_at) if include_log else []
    artifacts = sorted(scan.artifacts, key=lambda item: item.path) if include_log else []
    return ScanExecutionResponse(
        **scan_data,
        assessment_name=assessment.name,
        target=assessment.target,
        target_type=assessment.target_type,
        scan_mode=assessment.scan_mode,
        events=events,
        tool_runs=tool_runs,
        artifacts=artifacts,
    )


async def _authorize_assessment_scan(
    assessment: Assessment,
    db: AsyncSession,
) -> AuthorizationCoverage:
    # Newly flushed assessments do not have a safely loaded relationship in an
    # async session. Query explicitly instead of triggering implicit lazy I/O.
    targets = list((await db.execute(
        select(Asset.value, Asset.asset_type).where(Asset.assessment_id == assessment.id)
    )).all())
    if not targets:
        targets = [(assessment.target, assessment.target_type)]
    flags = assessment.flags or {}
    phases = assessment.phases or {}
    passive_only = bool(flags.get("passive_only")) and not any(
        bool(phases.get(name)) for name in ("scan", "cloud", "exploit")
    )
    return await require_scan_authorization(
        db,
        org_id=assessment.org_id,
        targets=targets,
        passive_only=passive_only,
    )


@router.get("/scan-profiles", response_model=list[ScanProfileResponse])
async def list_scan_profiles(
    target_type: str = Query("domain"),
):
    """Return normalized platform scan profiles for UI and orchestration reuse."""
    return [
        ScanProfileResponse.model_validate({
            **profile,
            "tool_plan": build_tool_plan(
                target_type=target_type,
                scan_mode=mode,
                utilities=profile.get("utilities", []),
            ),
        })
        for mode in ("light", "medium", "aggressive")
        for profile in [get_scan_profile(mode, target_type)]
    ]


@router.post("/execution-preview", response_model=ExecutionPreviewResponse)
async def execution_preview(payload: AssessmentCreate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Resolve the exact safe execution plan without creating or dispatching work."""
    targets = payload.imported_targets or [{"target": payload.target, "target_type": payload.target_type}]
    normalized = [normalize_target(str(item.get("target") or ""), str(item.get("target_type") or payload.target_type)) for item in targets]
    plan = build_scan_plan(scan_mode=payload.scan_mode, target_type=payload.target_type, phases=payload.phases,
        flags=payload.flags, requested_scans=payload.requested_scans, requested_utilities=payload.requested_utilities,
        nuclei_tags=payload.nuclei_tags)
    preview_flags = {**plan["flags"], "_imported_targets": [{"target": item.normalized_value} for item in normalized],
        "_requested_scans": plan.get("requested_scans") or [], "_requested_utilities": plan.get("utilities") or [],
        "_nuclei_tags": plan.get("nuclei_tags") or []}
    metadata = build_scan_metadata(assessment_id="preview", scan_mode=payload.scan_mode, target_type=payload.target_type,
        phases=plan["phases"], flags=preview_flags)
    passive_only = bool(plan["flags"].get("passive_only")) and not any(plan["phases"].get(key) for key in ("scan", "cloud", "exploit"))
    authorization = await require_scan_authorization(db, org_id=current_user.org_id,
        targets=[(item.normalized_value, item.target_type) for item in normalized], passive_only=passive_only)
    policy = metadata.get("execution_policy") or {}
    estimated = min(int(policy.get("timeout_seconds") or 3600), max(60, len(normalized) * len(metadata.get("tool_plan") or []) * 45))
    warnings = [f"Optional tool {item['name']} is not required" for item in metadata.get("tool_plan", []) if not item.get("required")]
    adapters = [{"tool": item["name"], "requirements": item.get("prerequisites", []), "ready": item.get("bundled", False)}
        for item in metadata.get("tool_plan", []) if item.get("execution") == "adapter" or item.get("install_mode") == "external_adapter"]
    exclusions = [stage["label"] for stage in metadata.get("execution_manifest", []) if not stage.get("planned")]
    safety_controls = ["tenant scope authorization", "per-scan timeout and artifact quota", "secret-redacted command provenance", "cooperative cancellation"]
    if plan["flags"].get("passive_only"):
        safety_controls.append("passive-only network policy")
    return ExecutionPreviewResponse(target_type=payload.target_type, target_count=len(normalized), scan_mode=payload.scan_mode,
        phases=plan["phases"], flags=plan["flags"], tool_plan=metadata.get("tool_plan") or [],
        execution_manifest=metadata.get("execution_manifest") or [], execution_policy=policy,
        authorization=authorization.as_evidence(), estimated_seconds=estimated, warnings=warnings,
        template_plan={"engine": "nuclei", "tags": metadata.get("nuclei_tags") or [], "managed_updates": True,
            "excluded_tags": ["dos", "fuzz", "intrusive"]},
        wordlist_plan={"tier": payload.scan_mode, "content_discovery": bool(plan["flags"].get("crawl")),
            "custom_inputs": "recorded by SHA-256 when executed"},
        adapter_prerequisites=adapters, safety_controls=safety_controls, exclusions=exclusions,
        confidence="high" if not any(not item.get("ready") and item.get("requirements") for item in adapters) else "conditional")


@router.get("/saved-scan-profiles", response_model=list[SavedScanProfileResponse])
async def list_saved_scan_profiles(target_type: str | None = None, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    query = select(OrganizationScanProfile).where(OrganizationScanProfile.org_id == current_user.org_id, OrganizationScanProfile.is_active.is_(True))
    if target_type:
        query = query.where(OrganizationScanProfile.target_type == target_type)
    return (await db.execute(query.order_by(OrganizationScanProfile.name, OrganizationScanProfile.version.desc()))).scalars().all()


@router.post("/saved-scan-profiles", response_model=SavedScanProfileResponse, status_code=status.HTTP_201_CREATED)
async def save_scan_profile(payload: SavedScanProfileCreate, current_user: User = Depends(require_permission("assessments:run")), db: AsyncSession = Depends(get_db)):
    versions = (await db.execute(select(OrganizationScanProfile).where(
        OrganizationScanProfile.org_id == current_user.org_id, OrganizationScanProfile.name == payload.name,
    ).with_for_update())).scalars().all()
    version = max((item.version for item in versions), default=0) + 1
    for item in versions:
        if item.is_active:
            item.is_active = False
    profile = OrganizationScanProfile(org_id=current_user.org_id, created_by=current_user.id, version=version, **payload.model_dump())
    db.add(profile)
    await write_audit(db, event="scan_profile.version.create", user_id=str(current_user.id), org_id=str(current_user.org_id),
        resource_type="scan_profile", details={"name": payload.name, "version": version})
    await db.flush(); await db.refresh(profile)
    return profile


@router.delete("/saved-scan-profiles/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_scan_profile(profile_id: uuid.UUID, current_user: User = Depends(require_permission("assessments:run")), db: AsyncSession = Depends(get_db)):
    profile = await db.scalar(select(OrganizationScanProfile).where(OrganizationScanProfile.id == profile_id, OrganizationScanProfile.org_id == current_user.org_id))
    if not profile:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Saved profile not found")
    profile.is_active = False
    await write_audit(db, event="scan_profile.deactivate", user_id=str(current_user.id), org_id=str(current_user.org_id),
        resource_type="scan_profile", resource_id=str(profile.id), details={"name": profile.name, "version": profile.version})


@router.get("/schedules", response_model=list[ScanScheduleResponse])
async def list_scan_schedules(assessment_id: uuid.UUID | None = None, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    query = select(ScanSchedule).where(ScanSchedule.org_id == current_user.org_id)
    if assessment_id:
        query = query.where(ScanSchedule.assessment_id == assessment_id)
    return (await db.execute(query.order_by(ScanSchedule.next_run_at))).scalars().all()


@router.post("/schedules", response_model=ScanScheduleResponse, status_code=status.HTTP_201_CREATED)
async def create_scan_schedule(payload: ScanScheduleCreate, current_user: User = Depends(require_permission("assessments:run")), db: AsyncSession = Depends(get_db)):
    assessment = await db.scalar(select(Assessment).where(Assessment.id == payload.assessment_id, Assessment.org_id == current_user.org_id))
    if not assessment:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Assessment not found")
    _valid_timezone(payload.timezone)
    if bool(payload.window_start) != bool(payload.window_end):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Both maintenance-window times are required")
    schedule = ScanSchedule(
        org_id=current_user.org_id, created_by=current_user.id,
        next_run_at=datetime.now(timezone.utc) + timedelta(minutes=payload.interval_minutes), **payload.model_dump()
    )
    db.add(schedule); await db.flush(); await db.refresh(schedule)
    await write_audit(db, event="scan_schedule.create", user_id=str(current_user.id), org_id=str(current_user.org_id),
        resource_type="scan_schedule", resource_id=str(schedule.id), details={"assessment_id": str(assessment.id)})
    return schedule


@router.patch("/schedules/{schedule_id}", response_model=ScanScheduleResponse)
async def update_scan_schedule(schedule_id: uuid.UUID, payload: ScanScheduleUpdate, current_user: User = Depends(require_permission("assessments:run")), db: AsyncSession = Depends(get_db)):
    schedule = await db.scalar(select(ScanSchedule).where(ScanSchedule.id == schedule_id, ScanSchedule.org_id == current_user.org_id))
    if not schedule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    changes = payload.model_dump(exclude_unset=True)
    if changes.get("timezone"):
        _valid_timezone(changes["timezone"])
    candidate_start = changes.get("window_start", schedule.window_start)
    candidate_end = changes.get("window_end", schedule.window_end)
    if bool(candidate_start) != bool(candidate_end):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Both maintenance-window times are required")
    for key, value in changes.items():
        setattr(schedule, key, value)
    if "interval_minutes" in changes or changes.get("is_active") is True:
        schedule.next_run_at = datetime.now(timezone.utc) + timedelta(minutes=schedule.interval_minutes)
    await write_audit(db, event="scan_schedule.update", user_id=str(current_user.id), org_id=str(current_user.org_id),
        resource_type="scan_schedule", resource_id=str(schedule.id), details={"fields": sorted(changes)})
    await db.flush(); await db.refresh(schedule)
    return schedule


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan_schedule(schedule_id: uuid.UUID, current_user: User = Depends(require_permission("assessments:run")), db: AsyncSession = Depends(get_db)):
    schedule = await db.scalar(select(ScanSchedule).where(ScanSchedule.id == schedule_id, ScanSchedule.org_id == current_user.org_id))
    if not schedule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    await write_audit(db, event="scan_schedule.delete", user_id=str(current_user.id), org_id=str(current_user.org_id),
        resource_type="scan_schedule", resource_id=str(schedule.id), details={"assessment_id": str(schedule.assessment_id)})
    await db.delete(schedule)


@router.get("/schedules/{schedule_id}/history")
async def scan_schedule_history(schedule_id: uuid.UUID, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    schedule = await db.scalar(select(ScanSchedule).where(ScanSchedule.id == schedule_id, ScanSchedule.org_id == current_user.org_id))
    if not schedule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    rows = (await db.execute(select(ScanScheduleRun).where(ScanScheduleRun.schedule_id == schedule.id).order_by(ScanScheduleRun.created_at.desc()).limit(100))).scalars().all()
    return [{"id": str(row.id), "scan_id": str(row.scan_id) if row.scan_id else None, "planned_at": row.planned_at,
        "status": row.status, "message": row.message, "created_at": row.created_at} for row in rows]


@router.get("/capability-catalog")
async def capability_catalog():
    """Return blueprint coverage without claiming conditional work was executed."""
    return get_capability_catalog()


@router.post("/import", response_model=AssessmentImportResponse, status_code=status.HTTP_201_CREATED)
async def import_assessments(
    file: UploadFile = File(...),
    default_scan_mode: str = Form("medium"),
    default_auto_start: bool = Form(False),
    default_requested_scans: str = Form(""),
    default_requested_utilities: str = Form(""),
    default_nuclei_tags: str = Form(""),
    current_user: User = Depends(require_role("admin", "manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Import a flexible CSV and return a normalized batch draft for one assessment."""
    try:
        text = (await file.read()).decode("utf-8")
    except Exception:
        raise HTTPException(status_code=400, detail="File must be a UTF-8 encoded CSV")

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise HTTPException(status_code=400, detail="CSV is missing a header row")

    added = 0
    skipped = 0
    errors: list[str] = []
    seen_keys: set[str] = set()
    saw_row = False
    imported_targets: list[dict] = []

    default_scans = [item.strip() for item in default_requested_scans.replace(";", ",").split(",") if item.strip()]
    default_utilities = [item.strip() for item in default_requested_utilities.replace(";", ",").split(",") if item.strip()]
    default_tags = [item.strip() for item in default_nuclei_tags.replace(";", ",").split(",") if item.strip()]

    for i, row in enumerate(reader, start=2):
        saw_row = True
        try:
            parsed = parse_csv_row(row)
            normalized_target = normalize_target(parsed["target"], parsed["target_type"])
            if normalized_target.canonical_key in seen_keys:
                skipped += 1
                continue

            existing = (
                await db.execute(
                    select(Assessment.id)
                    .outerjoin(Asset, Asset.assessment_id == Assessment.id)
                    .where(
                        and_(
                            Assessment.org_id == current_user.org_id,
                            or_(
                                and_(
                                    Asset.asset_type == normalized_target.target_type,
                                    Asset.value == normalized_target.normalized_value,
                                ),
                                and_(
                                    Assessment.target_type == normalized_target.target_type,
                                    Assessment.target == normalized_target.normalized_value,
                                ),
                            ),
                        )
                    )
                    .limit(1)
                )
            ).scalar_one_or_none()
            if existing:
                skipped += 1
                seen_keys.add(normalized_target.canonical_key)
                continue

            imported_targets.append(
                {
                    "name": parsed["name"],
                    "target": normalized_target.normalized_value,
                    "target_type": normalized_target.target_type,
                    "description": parsed["description"],
                    "tags": parsed["tags"],
                    "raw": parsed["raw"],
                    "requested_scans": parsed["requested_scans"] or default_scans,
                    "requested_utilities": parsed["requested_utilities"] or default_utilities,
                    "nuclei_tags": parsed["nuclei_tags"] or default_tags,
                    "scan_mode": parsed["scan_mode"] if parsed["scan_mode"] in {"light", "medium", "aggressive"} else default_scan_mode,
                    "auto_start": parsed["auto_start"] if parsed["auto_start"] is not None else default_auto_start,
                    "canonical_key": normalized_target.canonical_key,
                    "root_domain": normalized_target.root_domain,
                    "parent_key": normalized_target.parent_key,
                }
            )
            added += 1
            seen_keys.add(normalized_target.canonical_key)
        except Exception as exc:
            errors.append(f"Row {i}: {exc}")

    if not saw_row:
        raise HTTPException(
            status_code=400,
            detail="CSV contains a header row but no data rows to import",
        )

    suggested_name, suggested_description = _summarize_import_name(file.filename, imported_targets)
    return AssessmentImportResponse(
        added=added,
        skipped=skipped,
        errors=errors,
        imported_targets=imported_targets,
        suggested_name=suggested_name,
        suggested_description=suggested_description,
    )


@router.get("", response_model=AssessmentList)
async def list_assessments(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    search: str | None = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List assessments for the current user's organization."""
    org_id = current_user.org_id
    base_query = select(Assessment).where(Assessment.org_id == org_id)

    if status_filter:
        base_query = base_query.where(Assessment.status == status_filter)
    if search:
        base_query = base_query.where(
            Assessment.name.ilike(f"%{search}%") | Assessment.target.ilike(f"%{search}%")
        )

    # Count
    count_q = select(func.count()).select_from(base_query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    # Paginate
    offset = (page - 1) * page_size
    result = await db.execute(
        base_query.order_by(Assessment.created_at.desc()).offset(offset).limit(page_size)
    )
    assessments = result.scalars().all()

    return AssessmentList(
        items=[AssessmentResponse.model_validate(a) for a in assessments],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/scan-executions", response_model=ScanExecutionList)
async def list_scan_executions(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    assessment_id: uuid.UUID | None = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List tenant-scoped scan executions with assessment context."""
    filters = [Assessment.org_id == current_user.org_id]
    if status_filter:
        filters.append(Scan.status == status_filter)
    if assessment_id:
        filters.append(Scan.assessment_id == assessment_id)

    base_query = select(Scan, Assessment).join(
        Assessment, Scan.assessment_id == Assessment.id
    ).where(and_(*filters))
    total = (
        await db.execute(
            select(func.count()).select_from(base_query.subquery())
        )
    ).scalar() or 0
    rows = (
        await db.execute(
            base_query
            .order_by(Scan.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()

    items = [
        _scan_execution_response(scan, assessment, include_log=False)
        for scan, assessment in rows
    ]
    return ScanExecutionList(items=items, total=total, page=page, page_size=page_size)


@router.get("/scan-executions/{scan_id}", response_model=ScanExecutionResponse)
async def get_scan_execution(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return one tenant-scoped execution including recent worker output."""
    row = (
        await db.execute(
            select(Scan, Assessment)
            .join(Assessment, Scan.assessment_id == Assessment.id)
            .where(
                and_(
                    Scan.id == scan_id,
                    Assessment.org_id == current_user.org_id,
                )
            )
        )
    ).one_or_none()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan execution not found")
    scan, assessment = row
    return _scan_execution_response(scan, assessment, include_log=True)


@router.post("/scan-executions/{scan_id}/retry", response_model=ScanExecutionResponse)
async def retry_scan_execution(
    scan_id: uuid.UUID,
    current_user: User = Depends(require_permission("assessments:run")),
    db: AsyncSession = Depends(get_db),
):
    """Create a clean execution attempt for a terminal scan."""
    row = (
        await db.execute(
            select(Scan, Assessment)
            .join(Assessment, Scan.assessment_id == Assessment.id)
            .where(and_(Scan.id == scan_id, Assessment.org_id == current_user.org_id))
        )
    ).one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan execution not found")
    previous, assessment = row
    if previous.status not in {"failed", "cancelled"}:
        raise HTTPException(status.HTTP_409_CONFLICT, "Only failed or cancelled scans can be retried")
    active = (
        await db.execute(
            select(Scan.id).where(
                Scan.assessment_id == assessment.id,
                Scan.status.in_(["queued", "running"]),
            ).limit(1)
        )
    ).scalar_one_or_none()
    if active:
        raise HTTPException(status.HTTP_409_CONFLICT, "This assessment already has an active scan")
    authorization = await _authorize_assessment_scan(assessment, db)
    scan = await _dispatch_assessment_scan(assessment, db, authorization)
    scan.attempt = previous.attempt + 1
    scan.max_attempts = max(previous.max_attempts, scan.attempt)
    scan.scan_metadata = {
        **(scan.scan_metadata or {}),
        "attempt": scan.attempt,
        "retry_of": str(previous.id),
    }
    await db.commit()
    await db.refresh(scan)
    return _scan_execution_response(scan, assessment, include_log=True)


@router.post("/scan-executions/{scan_id}/clone-draft", response_model=AssessmentResponse, status_code=status.HTTP_201_CREATED)
async def clone_scan_as_draft(scan_id: uuid.UUID, current_user: User = Depends(require_permission("assessments:run")), db: AsyncSession = Depends(get_db)):
    row = (await db.execute(select(Scan, Assessment).join(Assessment).where(
        Scan.id == scan_id, Assessment.org_id == current_user.org_id))).one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan execution not found")
    previous, source = row
    draft = Assessment(org_id=current_user.org_id, created_by=current_user.id, name=f"{source.name} recovery",
        description=f"Editable recovery draft cloned from scan {previous.id}", target=source.target,
        target_type=source.target_type, status="created", scan_mode=source.scan_mode,
        phases=dict(source.phases or {}), flags={**dict(source.flags or {}), "_recovery_of": str(previous.id)}, is_demo=False)
    db.add(draft)
    await db.flush()
    await _create_assessment_assets(db, draft, [{"target": asset.value, "target_type": asset.asset_type,
        "canonical_key": asset.canonical_key, "root_domain": asset.root_domain, "raw": {"owner": asset.owner}} for asset in source.assets])
    await write_audit(db, event="assessment.recovery.clone", user_id=str(current_user.id), org_id=str(current_user.org_id),
        resource_type="assessment", resource_id=str(draft.id), details={"scan_id": str(previous.id), "source_assessment_id": str(source.id)})
    await db.flush()
    await db.refresh(draft)
    return draft


@router.post("", response_model=AssessmentResponse, status_code=status.HTTP_201_CREATED)
async def create_assessment(
    payload: AssessmentCreate,
    current_user: User = Depends(require_role("admin", "manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new assessment."""
    imported_targets: list[dict] = []
    skipped_imports = 0
    if payload.imported_targets:
        try:
            imported_targets, skipped_imports = _dedupe_imported_targets(payload.imported_targets)
        except TargetValidationError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
        if not imported_targets:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Imported targets did not contain any valid rows",
            )

    try:
        normalized_target = normalize_target(payload.target, payload.target_type)
    except TargetValidationError as exc:
        if not imported_targets:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
        normalized_target = normalize_target(imported_targets[0]["target"], imported_targets[0]["target_type"])

    stored_target = normalized_target.normalized_value
    stored_target_type = normalized_target.target_type
    if len(imported_targets) > 1:
        stored_target = _build_batch_target_label(imported_targets)
        stored_target_type = "file"

    plan = build_scan_plan(
        scan_mode=payload.scan_mode,
        target_type=stored_target_type,
        phases=payload.phases,
        flags=payload.flags,
        requested_scans=payload.requested_scans,
        requested_utilities=payload.requested_utilities,
        nuclei_tags=payload.nuclei_tags,
    )
    assessment = Assessment(
        org_id=current_user.org_id,
        created_by=current_user.id,
        name=payload.name,
        description=payload.description,
        target=stored_target,
        target_type=stored_target_type,
        scan_mode=payload.scan_mode,
        phases=plan["phases"],
        flags={
            **plan["flags"],
            "_seed": build_seed_metadata(normalized_target.normalized_value, normalized_target.target_type, source="assessment", stage="seed"),
            "_requested_scans": plan["requested_scans"],
            "_requested_utilities": plan["utilities"],
            "_nuclei_tags": plan["nuclei_tags"],
            "_pipeline": plan.get("pipeline", []),
            "_scan_strategy": plan.get("scan_strategy"),
            "_normalized_key": normalized_target.canonical_key,
            "_parent_key": normalized_target.parent_key,
            "_root_domain": normalized_target.root_domain,
            "_batch_mode": len(imported_targets) > 1,
            "_imported_targets": imported_targets,
            "_imported_target_count": len(imported_targets),
            "_import_skipped_duplicates": skipped_imports,
        },
        status="created",
    )
    db.add(assessment)
    await db.flush()

    if imported_targets:
        await _create_assessment_assets(db, assessment, imported_targets)

    if payload.auto_start:
        authorization = await _authorize_assessment_scan(assessment, db)
        await _dispatch_assessment_scan(assessment, db, authorization)

    await db.refresh(assessment)
    return AssessmentResponse.model_validate(assessment)


@router.get("/{assessment_id}", response_model=AssessmentResponse)
async def get_assessment(
    assessment_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single assessment by ID."""
    result = await db.execute(
        select(Assessment).where(
            and_(Assessment.id == assessment_id, Assessment.org_id == current_user.org_id)
        )
    )
    assessment = result.scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")
    return AssessmentResponse.model_validate(assessment)


@router.get("/{assessment_id}/scans", response_model=list[AssessmentScanResponse])
async def list_assessment_scans(
    assessment_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List scan executions for a single assessment."""
    assessment = (
        await db.execute(
            select(Assessment).where(
                and_(Assessment.id == assessment_id, Assessment.org_id == current_user.org_id)
            )
        )
    ).scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    result = await db.execute(
        select(Scan)
        .where(Scan.assessment_id == assessment_id)
        .order_by(Scan.created_at.desc())
    )
    return [AssessmentScanResponse.model_validate(scan) for scan in result.scalars().all()]


@router.put("/{assessment_id}", response_model=AssessmentResponse)
async def update_assessment(
    assessment_id: uuid.UUID,
    payload: AssessmentCreate,
    current_user: User = Depends(require_role("admin", "manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Update an existing assessment."""
    result = await db.execute(
        select(Assessment).where(
            and_(Assessment.id == assessment_id, Assessment.org_id == current_user.org_id)
        )
    )
    assessment = result.scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    if assessment.status == "running":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot update a running assessment",
        )

    try:
        normalized_target = normalize_target(payload.target, payload.target_type)
    except TargetValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    plan = build_scan_plan(
        scan_mode=payload.scan_mode,
        target_type=normalized_target.target_type,
        phases=payload.phases,
        flags=payload.flags,
        requested_scans=payload.requested_scans,
        requested_utilities=payload.requested_utilities,
        nuclei_tags=payload.nuclei_tags,
    )

    assessment.name = payload.name
    assessment.description = payload.description
    assessment.target = normalized_target.normalized_value
    assessment.target_type = normalized_target.target_type
    assessment.scan_mode = payload.scan_mode
    assessment.phases = plan["phases"]
    assessment.flags = {
        **plan["flags"],
        "_seed": build_seed_metadata(normalized_target.normalized_value, normalized_target.target_type, source="assessment", stage="seed"),
        "_requested_scans": plan["requested_scans"],
        "_requested_utilities": plan["utilities"],
        "_nuclei_tags": plan["nuclei_tags"],
        "_pipeline": plan.get("pipeline", []),
        "_scan_strategy": plan.get("scan_strategy"),
        "_normalized_key": normalized_target.canonical_key,
        "_parent_key": normalized_target.parent_key,
        "_root_domain": normalized_target.root_domain,
    }

    await db.flush()
    await db.refresh(assessment)
    return AssessmentResponse.model_validate(assessment)


@router.delete("/{assessment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_assessment(
    assessment_id: uuid.UUID,
    current_user: User = Depends(require_role("admin", "manager")),
    db: AsyncSession = Depends(get_db),
):
    """Delete an assessment and all related data."""
    result = await db.execute(
        select(Assessment).where(
            and_(Assessment.id == assessment_id, Assessment.org_id == current_user.org_id)
        )
    )
    assessment = result.scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    if assessment.status == "running":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot delete a running assessment",
        )

    report_keys = (
        await db.execute(
            select(ReportArtifact.object_key).where(
                ReportArtifact.assessment_id == assessment.id,
                ReportArtifact.org_id == current_user.org_id,
                ReportArtifact.object_key.is_not(None),
            )
        )
    ).scalars().all()
    scan_metadata_rows = (
        await db.execute(select(Scan.scan_metadata).where(Scan.assessment_id == assessment.id))
    ).scalars().all()
    scan_keys = [
        key
        for metadata in scan_metadata_rows
        if (key := (metadata or {}).get("ingestion_result", {}).get("artifact_object_key"))
    ]
    object_keys = [*report_keys, *scan_keys]

    await db.delete(assessment)
    await db.commit()

    try:
        from app.services.celery_app import delete_assessment_artifacts

        delete_assessment_artifacts.apply_async(args=[str(assessment_id), object_keys], queue="default")
    except Exception as exc:
        logger.warning("Assessment %s deleted but artifact cleanup could not be queued: %s", assessment_id, exc)


@router.post("/{assessment_id}/cancel", response_model=AssessmentResponse)
async def cancel_assessment_scan(
    assessment_id: uuid.UUID,
    current_user: User = Depends(require_role("admin", "manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Cancel the latest queued or running scan for an assessment."""
    assessment = (
        await db.execute(
            select(Assessment).where(
                and_(Assessment.id == assessment_id, Assessment.org_id == current_user.org_id)
            )
        )
    ).scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    scan = (
        await db.execute(
            select(Scan)
            .where(
                and_(
                    Scan.assessment_id == assessment_id,
                    Scan.status.in_(["queued", "running"]),
                )
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No assessment scan is currently running",
        )

    scan.scan_metadata = _scan_cancel_metadata(scan)
    scan.cancel_requested_at = datetime.now(timezone.utc)
    if scan.status == "queued":
        scan.status = "cancelled"
        scan.current_phase = "cancelled"
        scan.progress = 0
        scan.completed_at = datetime.now(timezone.utc)
        assessment.status = "cancelled"
    else:
        # Let the worker stop its child process and persist the final log/state.
        scan.current_phase = "cancelling"

    task_id = scan.celery_task_id
    if task_id and not task_id.startswith("thread-"):
        try:
            from app.services.celery_app import celery_app

            celery_app.control.revoke(task_id, terminate=False)
        except Exception:
            pass

    await db.flush()
    await db.refresh(assessment)
    return AssessmentResponse.model_validate(assessment)


@router.post("/{assessment_id}/rescan", response_model=AssessmentResponse)
async def rescan_assessment(
    assessment_id: uuid.UUID,
    current_user: User = Depends(require_role("admin", "manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a rescan of an existing assessment (queues a new scan)."""
    result = await db.execute(
        select(Assessment).where(
            and_(Assessment.id == assessment_id, Assessment.org_id == current_user.org_id)
        )
    )
    assessment = result.scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    if assessment.status == "running":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Assessment is already running",
        )

    authorization = await _authorize_assessment_scan(assessment, db)
    await _dispatch_assessment_scan(assessment, db, authorization)

    return AssessmentResponse.model_validate(assessment)
