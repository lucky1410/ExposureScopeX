import httpx
from datetime import datetime, timezone
from app.models.integration import EXPOSURE_EVENTS
from .base import IntegrationService, register


@register
class ElasticIntegration(IntegrationService):
    PROVIDER = "elastic"
    SUPPORTED_EVENTS = [
        "finding.critical", "finding.high", "finding.medium", "finding.low",
        "scan.completed", "scan.failed", "assessment.completed",
    ] + sorted(EXPOSURE_EVENTS)

    async def send(self, event: str, org_id: str, payload: dict) -> None:
        base_url = self.config["url"].rstrip("/")
        api_key = self.config["api_key"]
        index = self.config.get("index", "exposurescopex-findings")
        doc = {
            **payload,
            "event": event,
            "org_id": org_id,
            "@timestamp": datetime.now(timezone.utc).isoformat(),
        }
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{base_url}/{index}/_doc",
                json=doc,
                headers={"Authorization": f"ApiKey {api_key}"},
            )
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Elasticsearch indexing failed: {resp.status_code} {resp.text}")

    async def test_connection(self) -> dict:
        base_url = self.config.get("url", "").rstrip("/")
        api_key = self.config.get("api_key", "")
        if not base_url or not api_key:
            return {"ok": False, "message": "url and api_key are required"}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"{base_url}/_cluster/health",
                    headers={"Authorization": f"ApiKey {api_key}"},
                )
            if resp.status_code != 200:
                return {"ok": False, "message": f"HTTP {resp.status_code}: {resp.text}"}
            data = resp.json()
            status = data.get("status", "red")
            if status == "red":
                return {"ok": False, "message": f"Cluster status is red"}
            return {"ok": True, "message": f"Elasticsearch cluster status: {status}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
