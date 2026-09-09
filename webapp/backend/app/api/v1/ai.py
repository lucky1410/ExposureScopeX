"""AI chat endpoint using Anthropic Claude."""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.dependencies import get_current_user, get_db
from app.models.asset import Asset
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.models.user import User

logger = logging.getLogger("exposurescopex.ai")

router = APIRouter(prefix="/ai", tags=["AI"])


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    response: str


@router.post("/chat", response_model=ChatResponse)
async def chat(
    payload: ChatRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Send a message to the AI security analyst."""
    if not settings.ANTHROPIC_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI analyst is not configured (ANTHROPIC_API_KEY missing)",
        )

    org_id = current_user.org_id

    # Gather context from DB
    total_assets = (
        await db.execute(
            select(func.count(Asset.id)).join(Assessment).where(Assessment.org_id == org_id)
        )
    ).scalar() or 0

    severity_counts: dict[str, int] = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        q = await db.execute(
            select(func.count(Finding.id))
            .join(Assessment)
            .where(and_(Assessment.org_id == org_id, Finding.severity == sev))
        )
        severity_counts[sev] = q.scalar() or 0

    recent_q = await db.execute(
        select(Finding)
        .join(Assessment)
        .where(and_(Assessment.org_id == org_id, Finding.severity.in_(["CRITICAL", "HIGH"])))
        .order_by(Finding.created_at.desc())
        .limit(10)
    )
    critical_findings = recent_q.scalars().all()

    finding_summary = "\n".join(
        f"- [{f.severity}] {f.title} (asset: {f.asset.value if f.asset else 'unknown'}, status: {f.status})"
        for f in critical_findings
    )

    system_prompt = f"""You are an AI Security Analyst for ExposureScopeX, an Attack Surface Management platform.

Current organization context:
- Total assets discovered: {total_assets}
- Findings by severity: CRITICAL={severity_counts.get('CRITICAL', 0)}, HIGH={severity_counts.get('HIGH', 0)}, MEDIUM={severity_counts.get('MEDIUM', 0)}, LOW={severity_counts.get('LOW', 0)}, INFO={severity_counts.get('INFO', 0)}

Top critical/high findings:
{finding_summary if finding_summary else '(none)'}

Provide concise, actionable security analysis. Focus on real risks and remediation steps.
Reference specific assets and findings from the context above when relevant."""

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        message = client.messages.create(
            model=settings.AGENT_MODEL or "claude-opus-4-6",
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": payload.message}],
        )
        return ChatResponse(response=message.content[0].text)
    except Exception as e:
        logger.error(f"AI chat error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI request failed: {str(e)}",
        )
