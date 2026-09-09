import httpx
from .base import IntegrationService, register

_GN_URL = "https://api.greynoise.io/v3/community"


async def enrich_ip(ip: str, api_key: str) -> dict:
    """Standalone helper — call without an OrgIntegration instance."""
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(f"{_GN_URL}/{ip}", headers={"key": api_key})
    if resp.status_code == 404:
        return {"noise": False, "riot": False, "message": "Not seen by GreyNoise"}
    if resp.status_code == 429:
        return {"noise": False, "riot": False, "message": "Rate limited"}
    if resp.status_code != 200:
        return {"noise": False, "riot": False, "message": f"GreyNoise error: {resp.status_code}"}
    data = resp.json()
    return {
        "noise": data.get("noise", False),
        "riot": data.get("riot", False),
        "classification": data.get("classification"),
        "name": data.get("name"),
        "link": data.get("link"),
        "last_seen": data.get("last_seen"),
        "message": data.get("message", ""),
    }


@register
class GreyNoiseIntegration(IntegrationService):
    PROVIDER = "greynoise"
    SUPPORTED_EVENTS = []  # enrichment service, not event-driven

    async def enrich_ip(self, ip: str) -> dict:
        return await enrich_ip(ip, self.config["api_key"])

    async def send(self, event: str, org_id: str, payload: dict) -> None:
        pass  # not used

    async def test_connection(self) -> dict:
        api_key = self.config.get("api_key", "")
        if not api_key:
            return {"ok": False, "message": "api_key not configured"}
        try:
            result = await self.enrich_ip("8.8.8.8")
            if "error" in result.get("message", "").lower():
                return {"ok": False, "message": result["message"]}
            return {"ok": True, "message": f"GreyNoise connected — 8.8.8.8: {result.get('message', 'ok')}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
