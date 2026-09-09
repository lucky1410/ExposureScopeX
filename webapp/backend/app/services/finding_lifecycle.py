"""Finding disposition lifecycle and automatic suppression expiry."""

from datetime import datetime, timezone
import hashlib

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.database import async_session_factory
from app.models.assessment import Assessment
from app.models.finding import Finding, FindingIdentity, FindingObservation


SUPPRESSIVE_STATUSES = (
    "false_positive", "suppressed", "approved_exception", "accepted_risk",
    "compensating_control", "not_exploitable",
)


async def reopen_expired_suppressions() -> int:
    now = datetime.now(timezone.utc)
    async with async_session_factory() as session:
        result = await session.execute(
            update(Finding)
            .where(
                Finding.status.in_(SUPPRESSIVE_STATUSES),
                Finding.suppression_expires_at.is_not(None),
                Finding.suppression_expires_at <= now,
            )
            .values(
                status="new",
                status_scope=None,
                status_changed_by=None,
                status_changed_at=now,
            )
        )
        await session.commit()
        return int(result.rowcount or 0)


async def backfill_finding_observations(batch_size: int = 1000) -> int:
    """Attach legacy scan findings to stable identities without changing triage state."""
    now = datetime.now(timezone.utc)
    async with async_session_factory() as session:
        rows = (await session.execute(
            select(Finding, Assessment.org_id).join(Assessment, Assessment.id == Finding.assessment_id).where(
                Finding.identity_id.is_(None), Finding.scan_id.is_not(None)
            ).order_by(Finding.created_at).limit(batch_size)
        )).all()
        for finding, org_id in rows:
            fingerprint = hashlib.sha256(
                f"{finding.source or 'unknown'}|{finding.template_id or ''}|{(finding.url or '').lower()}|{finding.title.lower()}".encode()
            ).hexdigest()
            identity_id = (await session.execute(
                pg_insert(FindingIdentity).values(
                    org_id=org_id, fingerprint=fingerprint, source=finding.source or "unknown",
                    template_id=finding.template_id, title=finding.title, severity=finding.severity,
                    status="resolved" if finding.status in {"remediated", "resolved"} else "open",
                    first_seen=finding.first_seen or finding.created_at or now,
                    last_seen=finding.last_seen or finding.created_at or now,
                ).on_conflict_do_update(
                    constraint="uq_finding_identity_org_fingerprint",
                    set_={"last_seen": finding.last_seen or finding.created_at or now},
                ).returning(FindingIdentity.id)
            )).scalar_one()
            finding.identity_id = identity_id
            session.add(FindingObservation(
                identity_id=identity_id, finding_id=finding.id, scan_id=finding.scan_id,
                assessment_id=finding.assessment_id, observed_at=finding.first_seen or finding.created_at or now,
                evidence_sha256=hashlib.sha256((finding.evidence or "").encode()).hexdigest() if finding.evidence else None,
                payload={"backfilled": True, "severity": finding.severity, "source": finding.source},
            ))
        if rows:
            await session.commit()
        return len(rows)
