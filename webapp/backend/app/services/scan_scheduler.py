"""Database-backed recurring assessment scheduler."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import select

from app.database import async_session_factory
from app.models.assessment import Assessment
from app.models.scan import Scan
from app.models.scan_runtime import ScanSchedule, ScanScheduleRun


def _within_window(schedule: ScanSchedule, now: datetime) -> bool:
    if not schedule.window_start or not schedule.window_end:
        return True
    local_time = now.astimezone(ZoneInfo(schedule.timezone)).time()
    start = datetime.strptime(schedule.window_start, "%H:%M").time()
    end = datetime.strptime(schedule.window_end, "%H:%M").time()
    if start <= end:
        return start <= local_time <= end
    return local_time >= start or local_time <= end


async def dispatch_due_schedules(limit: int = 100) -> dict:
    now = datetime.now(timezone.utc)
    summary = {"due": 0, "started": 0, "skipped": 0, "blocked": 0}
    async with async_session_factory() as db:
        schedules = (await db.execute(
            select(ScanSchedule).where(ScanSchedule.is_active.is_(True), ScanSchedule.next_run_at <= now)
            .order_by(ScanSchedule.next_run_at).limit(limit).with_for_update(skip_locked=True)
        )).scalars().all()
        summary["due"] = len(schedules)
        for schedule in schedules:
            planned_at = schedule.next_run_at
            schedule.next_run_at = now + timedelta(minutes=schedule.interval_minutes)
            status = "skipped"
            message = None
            scan_id = None
            if schedule.missed_run_policy == "skip" and now - planned_at > timedelta(minutes=schedule.interval_minutes):
                message = "Missed run skipped by schedule policy"
            elif not _within_window(schedule, now):
                schedule.next_run_at = now + timedelta(minutes=min(schedule.interval_minutes, 60))
                message = "Outside the configured maintenance window"
            else:
                active = await db.scalar(select(Scan.id).where(
                    Scan.assessment_id == schedule.assessment_id, Scan.status.in_(["queued", "running"])
                ).limit(1))
                if active:
                    message = f"Overlap prevented; active scan {active} is still running"
                else:
                    assessment = await db.scalar(select(Assessment).where(
                        Assessment.id == schedule.assessment_id, Assessment.org_id == schedule.org_id
                    ))
                    if not assessment:
                        schedule.is_active = False
                        status = "blocked"
                        message = "Assessment no longer exists; schedule disabled"
                    else:
                        try:
                            from app.api.v1.assessments import _authorize_assessment_scan, _dispatch_assessment_scan

                            authorization = await _authorize_assessment_scan(assessment, db)
                            scan = await _dispatch_assessment_scan(assessment, db, authorization)
                            scan_id = scan.id
                            status = "started"
                            message = "Scheduled scan dispatched"
                        except Exception as exc:
                            status = "blocked"
                            message = str(getattr(exc, "detail", exc))[:1000]
            schedule.last_run_at = now
            schedule.last_status = status
            schedule.last_scan_id = scan_id
            db.add(ScanScheduleRun(
                schedule_id=schedule.id, scan_id=scan_id, planned_at=planned_at,
                status=status, message=message,
            ))
            summary[status if status in summary else "blocked"] += 1
            await db.commit()
        return summary
