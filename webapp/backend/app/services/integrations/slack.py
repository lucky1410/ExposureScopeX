import httpx
from app.models.integration import EXPOSURE_EVENTS
from .base import IntegrationService, register


@register
class SlackIntegration(IntegrationService):
    PROVIDER = "slack"
    SUPPORTED_EVENTS = [
        "finding.critical", "finding.high", "finding.medium",
        "scan.completed", "scan.failed", "assessment.completed",
    ] + sorted(EXPOSURE_EVENTS)

    def _build_payload(self, event: str, payload: dict) -> dict:
        if event == "finding.critical":
            severity = payload.get("severity", "CRITICAL")
            title = payload.get("title", "Finding")
            target = payload.get("target", "unknown")
            return {
                "text": f"*[ExposureScopeX]* {event}",
                "attachments": [{
                    "color": "#FF0000",
                    "fields": [
                        {"title": "Severity", "value": severity, "short": True},
                        {"title": "Title", "value": title, "short": True},
                        {"title": "Target", "value": target, "short": True},
                    ],
                }],
            }
        if event == "scan.completed":
            target = payload.get("target", "unknown")
            counts = payload.get("finding_counts", {})
            count_str = ", ".join(f"{k}: {v}" for k, v in counts.items()) if counts else "none"
            return {
                "text": f"*[ExposureScopeX]* {event}",
                "attachments": [{
                    "color": "#00CC00",
                    "fields": [
                        {"title": "Target", "value": target, "short": True},
                        {"title": "Findings", "value": count_str, "short": False},
                    ],
                }],
            }
        # generic
        details = "\n".join(f"{k}: {v}" for k, v in payload.items())
        return {"text": f"*[ExposureScopeX]* {event}\n{details}"}

    async def send(self, event: str, org_id: str, payload: dict) -> None:
        webhook_url = self.config["webhook_url"]
        body = self._build_payload(event, payload)
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(webhook_url, json=body)
        if resp.status_code != 200 or resp.text != "ok":
            raise RuntimeError(f"Slack webhook failed: {resp.status_code} {resp.text}")

    async def test_connection(self) -> dict:
        webhook_url = self.config.get("webhook_url", "")
        if not webhook_url:
            return {"ok": False, "message": "webhook_url not configured"}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    webhook_url,
                    json={"text": "ExposureScopeX test message — connection verified ✓"},
                )
            if resp.status_code == 200 and resp.text == "ok":
                return {"ok": True, "message": "Slack connection verified"}
            return {"ok": False, "message": f"Unexpected response: {resp.status_code} {resp.text}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
