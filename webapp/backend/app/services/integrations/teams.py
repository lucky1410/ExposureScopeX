import httpx
from app.models.integration import EXPOSURE_EVENTS
from .base import IntegrationService, register

_THEME = {
    "finding.critical": "FF0000",
    "finding.high": "FF6600",
    "scan.completed": "00CC00",
    "assessment.completed": "00CC00",
}


@register
class TeamsIntegration(IntegrationService):
    PROVIDER = "teams"
    SUPPORTED_EVENTS = [
        "finding.critical", "finding.high", "finding.medium",
        "scan.completed", "scan.failed", "assessment.completed",
    ] + sorted(EXPOSURE_EVENTS)

    def _build_card(self, event: str, payload: dict) -> dict:
        color = _THEME.get(event, "0078D7")
        facts = [{"name": k, "value": str(v)} for k, v in payload.items()]
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": color,
            "summary": f"ExposureScopeX: {event}",
            "sections": [{
                "activityTitle": f"**[ExposureScopeX]** {event}",
                "facts": facts,
            }],
        }

    async def send(self, event: str, org_id: str, payload: dict) -> None:
        webhook_url = self.config["webhook_url"]
        card = self._build_card(event, payload)
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(webhook_url, json=card)
        if resp.status_code not in (200, 202):
            raise RuntimeError(f"Teams webhook failed: {resp.status_code} {resp.text}")

    async def test_connection(self) -> dict:
        webhook_url = self.config.get("webhook_url", "")
        if not webhook_url:
            return {"ok": False, "message": "webhook_url not configured"}
        try:
            card = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "themeColor": "0078D7",
                "summary": "ExposureScopeX test",
                "sections": [{"activityTitle": "**[ExposureScopeX]** connection verified ✓"}],
            }
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(webhook_url, json=card)
            if resp.status_code in (200, 202):
                return {"ok": True, "message": "Teams connection verified"}
            return {"ok": False, "message": f"Unexpected response: {resp.status_code} {resp.text}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
