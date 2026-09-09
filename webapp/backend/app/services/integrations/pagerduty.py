import httpx
from .base import IntegrationService, register

_PD_URL = "https://events.pagerduty.com/v2/enqueue"

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "info",
    "INFO": "info",
}


@register
class PagerDutyIntegration(IntegrationService):
    PROVIDER = "pagerduty"
    SUPPORTED_EVENTS = ["finding.critical", "finding.high", "scan.failed", "scan.completed"]

    async def _post(self, body: dict) -> dict:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(_PD_URL, json=body)
        if resp.status_code not in (200, 202):
            raise RuntimeError(f"PagerDuty API error: {resp.status_code} {resp.text}")
        return resp.json()

    async def send(self, event: str, org_id: str, payload: dict) -> None:
        routing_key = self.config["routing_key"]
        target = payload.get("target", "unknown")
        dedup_key = f"esxscope-{org_id}-{target}"

        if event == "scan.completed":
            body = {
                "routing_key": routing_key,
                "event_action": "resolve",
                "dedup_key": dedup_key,
            }
        else:
            raw_sev = str(payload.get("severity", "HIGH")).upper()
            pd_sev = _SEVERITY_MAP.get(raw_sev, "error")
            summary = payload.get("title", event)
            body = {
                "routing_key": routing_key,
                "event_action": "trigger",
                "dedup_key": dedup_key,
                "payload": {
                    "summary": f"[ExposureScopeX] {summary}",
                    "severity": pd_sev,
                    "source": "ExposureScopeX",
                    "custom_details": payload,
                },
            }
        await self._post(body)

    async def test_connection(self) -> dict:
        routing_key = self.config.get("routing_key", "")
        if not routing_key:
            return {"ok": False, "message": "routing_key not configured"}
        try:
            dedup_key = "esxscope-test-connection"
            trigger = {
                "routing_key": routing_key,
                "event_action": "trigger",
                "dedup_key": dedup_key,
                "payload": {
                    "summary": "[ExposureScopeX] test — connection verified",
                    "severity": "info",
                    "source": "ExposureScopeX",
                },
            }
            await self._post(trigger)
            resolve = {
                "routing_key": routing_key,
                "event_action": "resolve",
                "dedup_key": dedup_key,
            }
            await self._post(resolve)
            return {"ok": True, "message": "PagerDuty connection verified"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
