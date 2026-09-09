import base64
import json
import httpx
from .base import IntegrationService, register

_SEV_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}

_GH_API = "https://api.github.com"


def _findings_to_sarif(findings: list, tool_name: str) -> dict:
    rules = []
    results = []
    seen_ids: set = set()
    for i, f in enumerate(findings):
        rule_id = f"ESX{i:04d}"
        sev = str(f.get("severity", "INFO")).upper()
        level = _SEV_MAP.get(sev, "none")
        title = f.get("title", f"Finding {i}")
        if rule_id not in seen_ids:
            seen_ids.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": title},
                "helpUri": f.get("url", ""),
                "properties": {"severity": sev},
            })
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f.get("description", title)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("source", f.get("target", "unknown"))},
                }
            }],
        })
    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": "2.2.0",
                    "informationUri": "https://github.com/secops24/ExposureScopeX",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }


@register
class GitHubSarifIntegration(IntegrationService):
    PROVIDER = "github_sarif"
    SUPPORTED_EVENTS = ["scan.completed", "assessment.completed"]

    async def send(self, event: str, org_id: str, payload: dict) -> None:
        token = self.config["token"]
        owner = self.config["owner"]
        repo = self.config["repo"]
        ref = self.config.get("ref", "refs/heads/main")
        tool_name = self.config.get("tool_name", "ExposureScopeX")

        findings = payload.get("findings", [])
        sarif = _findings_to_sarif(findings, tool_name)
        sarif_b64 = base64.b64encode(json.dumps(sarif).encode()).decode()

        body = {
            "commit_sha": payload.get("commit_sha", "HEAD"),
            "ref": ref,
            "sarif": sarif_b64,
            "tool_name": tool_name,
        }
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{_GH_API}/repos/{owner}/{repo}/code-scanning/sarifs",
                json=body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
            )
        if resp.status_code not in (200, 202):
            raise RuntimeError(f"GitHub SARIF upload failed: {resp.status_code} {resp.text}")

    async def test_connection(self) -> dict:
        token = self.config.get("token", "")
        owner = self.config.get("owner", "")
        repo = self.config.get("repo", "")
        if not token or not owner or not repo:
            return {"ok": False, "message": "token, owner, and repo are required"}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"{_GH_API}/repos/{owner}/{repo}",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json",
                    },
                )
            if resp.status_code == 200:
                data = resp.json()
                return {"ok": True, "message": f"GitHub repo accessible: {data.get('full_name', f'{owner}/{repo}')}"}
            return {"ok": False, "message": f"HTTP {resp.status_code}: {resp.text}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
