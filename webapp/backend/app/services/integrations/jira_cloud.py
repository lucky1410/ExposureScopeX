import base64
import httpx
from .base import IntegrationService, register

_PRIORITY_MAP = {
    "CRITICAL": "Highest",
    "HIGH": "High",
}


def _basic_auth(email: str, token: str) -> str:
    return base64.b64encode(f"{email}:{token}".encode()).decode()


@register
class JiraCloudIntegration(IntegrationService):
    PROVIDER = "jira_cloud"
    SUPPORTED_EVENTS = ["finding.critical", "finding.high"]

    async def send(self, event: str, org_id: str, payload: dict) -> None:
        base_url = self.config["base_url"].rstrip("/")
        email = self.config["email"]
        api_token = self.config["api_token"]
        project_key = self.config["project_key"]
        issue_type = self.config.get("issue_type", "Bug")

        severity = payload.get("severity", "HIGH").upper()
        title = payload.get("title", event)
        target = payload.get("target", "unknown")
        priority = _PRIORITY_MAP.get(severity, "High")
        summary = f"[ExposureScopeX] {severity}: {title} on {target}"

        description_text = "\n".join(f"{k}: {v}" for k, v in payload.items())
        body = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{"type": "text", "text": description_text}],
                    }],
                },
                "issuetype": {"name": issue_type},
                "priority": {"name": priority},
            }
        }
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{base_url}/rest/api/3/issue",
                json=body,
                headers={
                    "Authorization": f"Basic {_basic_auth(email, api_token)}",
                    "Content-Type": "application/json",
                },
            )
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Jira issue creation failed: {resp.status_code} {resp.text}")

    async def test_connection(self) -> dict:
        base_url = self.config.get("base_url", "").rstrip("/")
        email = self.config.get("email", "")
        api_token = self.config.get("api_token", "")
        if not base_url or not email or not api_token:
            return {"ok": False, "message": "base_url, email, and api_token are required"}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"{base_url}/rest/api/3/myself",
                    headers={"Authorization": f"Basic {_basic_auth(email, api_token)}"},
                )
            if resp.status_code == 200:
                data = resp.json()
                return {"ok": True, "message": f"Jira connected as {data.get('displayName', email)}"}
            return {"ok": False, "message": f"HTTP {resp.status_code}: {resp.text}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
