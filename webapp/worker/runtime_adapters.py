"""Authorized external runtime analyzers for mobile and Kubernetes targets."""

from __future__ import annotations

from pathlib import Path


class RuntimeAdapterError(RuntimeError):
    pass


def _normalized_findings(payload: dict, source: str, target: str) -> list[dict]:
    findings = payload.get("findings") or []
    if not isinstance(findings, list) or len(findings) > 10_000:
        raise RuntimeAdapterError("Runtime adapter returned an invalid finding collection")
    normalized = []
    allowed_severity = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity") or "INFO").upper()
        normalized.append({
            "severity": severity if severity in allowed_severity else "INFO",
            "title": str(item.get("title") or f"Runtime analyzer finding {index + 1}")[:500],
            "description": str(item.get("description") or "")[:8000],
            "url": str(item.get("url") or target)[:2000],
            "source": source,
            "template_id": str(item.get("id") or item.get("template_id") or f"runtime-{index + 1}")[:255],
            "evidence": str(item.get("evidence") or "")[:4000],
        })
    return normalized


def run_runtime_adapter(endpoint: str, api_key: str | None, artifact: Path, target_type: str, target: str) -> tuple[list[dict], dict]:
    import httpx

    if not endpoint.startswith(("https://", "http://")):
        raise RuntimeAdapterError("Runtime adapter URL must use HTTP or HTTPS")
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    with artifact.open("rb") as handle:
        response = httpx.post(
            endpoint.rstrip("/") + "/v1/scan",
            headers=headers,
            data={"target_type": target_type, "target": target},
            files={"artifact": (artifact.name, handle, "application/octet-stream")},
            timeout=3600,
            follow_redirects=False,
        )
    if len(response.content) > 10 * 1024 * 1024:
        raise RuntimeAdapterError("Runtime adapter response exceeded 10 MiB")
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeAdapterError("Runtime adapter response must be an object")
    source = "mobile-dynamic" if target_type in {"android", "ios"} else "kubernetes-runtime"
    summary = {
        "status": str(payload.get("status") or "completed"),
        "job_id": str(payload.get("job_id") or "")[:255] or None,
        "checks": int(payload.get("checks") or 0),
    }
    return _normalized_findings(payload, source, target), summary
