"""Event dispatcher — fan-out an event to all active matching integrations.

Usage (from a background task or Celery worker)::

    from app.services.integrations.dispatcher import dispatch_event

    await dispatch_event(
        event="scan.completed",
        org_id="<uuid>",
        payload={"scan_id": "...", "findings": 42},
        db=db,
    )

The function is fire-and-forget: individual delivery failures are caught,
logged, and recorded on the ``OrgIntegration`` row but are never re-raised
to the caller.
"""

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.integration import OrgIntegration
from app.services.encryption import decrypt_dict
from app.services.integrations.base import get_service

logger = logging.getLogger("exposurescopex.integrations.dispatcher")


async def dispatch_event(
    event: str,
    org_id: str,
    payload: dict,
    db: AsyncSession,
) -> None:
    """Dispatch *event* to every active, subscribed integration for *org_id*.

    Steps:
    1. Query ``org_integrations`` for active rows that include *event*.
    2. Decrypt each row's ``config``.
    3. Instantiate the provider service from the registry.
    4. Call ``service.send()`` for all matching integrations concurrently
       (``asyncio.gather`` with ``return_exceptions=True``).
    5. Update ``last_used_at`` / ``last_status`` / ``last_error`` per result.

    Errors in individual deliveries are swallowed so one broken integration
    never blocks others.
    """
    try:
        result = await db.execute(
            select(OrgIntegration).where(
                and_(
                    OrgIntegration.org_id == org_id,
                    OrgIntegration.is_active.is_(True),
                )
            )
        )
        integrations: list[OrgIntegration] = [
            row for row in result.scalars().all()
            if event in (row.events or [])
        ]
    except Exception as exc:
        logger.error("dispatcher: DB query failed for event=%s org=%s: %s", event, org_id, exc)
        return

    if not integrations:
        return

    async def _deliver(integration: OrgIntegration) -> tuple[OrgIntegration, Exception | None]:
        try:
            raw_config = integration.config or {}
            if "_encrypted" in raw_config:
                config = decrypt_dict(raw_config["_encrypted"])
            else:
                config = raw_config

            service = get_service(integration.provider, config)
            await service.send(event, org_id, payload)
            return integration, None
        except Exception as exc:
            return integration, exc

    tasks = [_deliver(i) for i in integrations]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    now = datetime.now(timezone.utc)
    for outcome in results:
        # asyncio.gather with return_exceptions=True wraps non-exception
        # returns as-is; a raised exception inside _deliver won't happen
        # because _deliver catches internally — but guard anyway.
        if isinstance(outcome, BaseException):
            logger.error("dispatcher: unexpected gather exception: %s", outcome)
            continue

        integration, exc = outcome
        integration.last_used_at = now
        if exc is None:
            integration.last_status = "ok"
            integration.last_error = None
        else:
            integration.last_status = "error"
            integration.last_error = str(exc)[:500]
            logger.warning(
                "dispatcher: delivery failed provider=%s integration=%s event=%s: %s",
                integration.provider,
                integration.id,
                event,
                exc,
            )

    try:
        await db.flush()
    except Exception as exc:
        logger.warning("dispatcher: failed to flush status updates: %s", exc)
