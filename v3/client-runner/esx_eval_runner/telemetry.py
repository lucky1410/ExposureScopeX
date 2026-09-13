"""Local redacting OpenTelemetry JSON collector for assurance evidence."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
from typing import Any


_SAFE_ATTRIBUTE_KEYS = {
    "service.name", "gen_ai.operation.name", "gen_ai.usage.input_tokens",
    "gen_ai.usage.output_tokens", "gen_ai.response.model", "gen_ai.tool.name",
    "gen_ai.request.model", "error.type", "http.response.status_code",
    "esx.case_id", "esx.agent_id", "esx.event_type", "esx.evidence_id",
}


def _attributes(items: object) -> dict[str, object]:
    result: dict[str, object] = {}
    if not isinstance(items, list):
        return result
    for item in items:
        if not isinstance(item, dict) or item.get("key") not in _SAFE_ATTRIBUTE_KEYS:
            continue
        value = item.get("value")
        if not isinstance(value, dict):
            continue
        scalar = next((candidate for candidate in value.values() if isinstance(candidate, (str, int, float, bool))), None)
        if scalar is not None:
            result[str(item["key"])] = scalar
    return result


def redact_otel_payload(payload: dict[str, Any]) -> list[dict[str, object]]:
    """Keep only allowlisted operational metadata, never prompts or outputs."""
    records: list[dict[str, object]] = []
    for resource_span in payload.get("resourceSpans", []):
        if not isinstance(resource_span, dict):
            continue
        resource = _attributes((resource_span.get("resource") or {}).get("attributes"))
        for scope_span in resource_span.get("scopeSpans", []):
            if not isinstance(scope_span, dict):
                continue
            for span in scope_span.get("spans", []):
                if not isinstance(span, dict):
                    continue
                record = {"name": str(span.get("name", "unnamed"))[:160], "attributes": {**resource, **_attributes(span.get("attributes"))}}
                records.append(record)
    return records


def telemetry_summary(path: str | Path) -> dict[str, object]:
    span_count = tool_calls = retrievals = 0
    services: set[str] = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        try:
            span = json.loads(line)
        except json.JSONDecodeError:
            continue
        attributes = span.get("attributes", {}) if isinstance(span, dict) else {}
        if not isinstance(attributes, dict):
            continue
        if isinstance(attributes.get("service.name"), str):
            services.add(attributes["service.name"])
        name = str(span.get("name", "")).lower()
        tool_calls += int("tool" in name or "gen_ai.tool.name" in attributes)
        retrievals += int("retriev" in name or "vector" in name)
        span_count += 1
    return {"schema_version": "esx-redacted-telemetry-summary-1.0", "span_count": span_count, "service_count": len(services), "tool_span_count": tool_calls, "retrieval_span_count": retrievals}


def serve_collector(output: str | Path) -> None:
    """Receive OTLP JSON on loopback and append redacted spans locally."""
    target = Path(output).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(24)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/v1/traces" or self.headers.get("X-ESX-Telemetry-Token") != token:
                self.send_error(403)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 1 <= length <= 1_048_576:
                    raise ValueError
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                records = redact_otel_payload(payload)
                with target.open("a", encoding="utf-8") as stream:
                    for record in records:
                        stream.write(json.dumps(record, separators=(",", ":")) + "\n")
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                self.send_error(400)
                return
            self.send_response(202)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    print(f"Local OTLP JSON collector: http://127.0.0.1:{server.server_port}/v1/traces")
    print(f"Set X-ESX-Telemetry-Token: {token}; redacted spans will be written to {target}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
