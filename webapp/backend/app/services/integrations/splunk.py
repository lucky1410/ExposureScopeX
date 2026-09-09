import httpx
from app.models.integration import EXPOSURE_EVENTS
from .base import IntegrationService, register


@register
class SplunkIntegration(IntegrationService):
    PROVIDER = "splunk"
    SUPPORTED_EVENTS = [
        "finding.critical", "finding.high", "finding.medium", "finding.low",
        "scan.completed", "scan.failed", "assessment.completed",
    ] + sorted(EXPOSURE_EVENTS)

    async def send(self, event: str, org_id: str, payload: dict) -> None:
        hec_url = self.config["hec_url"]
        token = self.config["hec_token"]
        index = self.config.get("index", "main")
        source = self.config.get("source", "exposurescopex")
        body = {
            "event": {**payload, "event_type": event, "org_id": org_id},
            "index": index,
            "source": source,
            "sourcetype": "json",
        }
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                hec_url,
                json=body,
                headers={"Authorization": f"Splunk {token}"},
            )
        if resp.status_code != 200:
            raise RuntimeError(f"Splunk HEC error: {resp.status_code} {resp.text}")
        data = resp.json()
        if data.get("code", -1) != 0:
            raise RuntimeError(f"Splunk HEC rejected event: {data}")

    async def test_connection(self) -> dict:
        hec_url = self.config.get("hec_url", "")
        token = self.config.get("hec_token", "")
        if not hec_url or not token:
            return {"ok": False, "message": "hec_url and hec_token are required"}
        try:
            body = {
                "event": {"message": "ExposureScopeX connection test"},
                "index": self.config.get("index", "main"),
                "source": self.config.get("source", "exposurescopex"),
                "sourcetype": "json",
            }
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    hec_url,
                    json=body,
                    headers={"Authorization": f"Splunk {token}"},
                )
            if resp.status_code != 200:
                return {"ok": False, "message": f"HTTP {resp.status_code}: {resp.text}"}
            data = resp.json()
            if data.get("code", -1) == 0:
                return {"ok": True, "message": "Splunk HEC connection verified"}
            return {"ok": False, "message": f"Splunk error: {data.get('text', data)}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
