"""Delivery of persisted exposure-change events to tenant integrations."""

import uuid

from sqlalchemy import select

from app.database import async_session_factory
from app.models.asset_graph import ExposureEvent
from app.services.integrations.dispatcher import dispatch_event


async def dispatch_scan_exposure_events(org_id: str, scan_id: str) -> int:
    async with async_session_factory() as session:
        events = (
            await session.execute(
                select(ExposureEvent)
                .where(
                    ExposureEvent.org_id == uuid.UUID(org_id),
                    ExposureEvent.scan_id == uuid.UUID(scan_id),
                )
                .order_by(ExposureEvent.observed_at)
            )
        ).scalars().all()
        for event in events:
            await dispatch_event(
                event=event.event_type,
                org_id=org_id,
                payload={
                    "event_id": str(event.id),
                    "assessment_id": str(event.assessment_id),
                    "scan_id": str(event.scan_id) if event.scan_id else None,
                    "asset_id": str(event.asset_id) if event.asset_id else None,
                    "severity": event.severity,
                    "observed_at": event.observed_at.isoformat(),
                    **(event.payload or {}),
                },
                db=session,
            )
        await session.commit()
        return len(events)
