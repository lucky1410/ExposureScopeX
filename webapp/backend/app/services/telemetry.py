"""Small dependency-free Prometheus telemetry registry."""

from __future__ import annotations

import threading
from collections import Counter

_lock = threading.Lock()
_requests: Counter[tuple[str, str, int]] = Counter()
_request_seconds: Counter[tuple[str, str]] = Counter()


def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def observe_request(method: str, route: str, status_code: int, duration_seconds: float) -> None:
    route = route[:200]
    with _lock:
        _requests[(method, route, status_code)] += 1
        _request_seconds[(method, route)] += duration_seconds


def render_prometheus(extra: dict[str, float | int] | None = None) -> str:
    lines = [
        "# HELP exposurescopex_http_requests_total HTTP requests processed.",
        "# TYPE exposurescopex_http_requests_total counter",
    ]
    with _lock:
        for (method, route, status), value in sorted(_requests.items()):
            lines.append(
                f'exposurescopex_http_requests_total{{method="{_label(method)}",route="{_label(route)}",status="{status}"}} {value}'
            )
        lines.extend([
            "# HELP exposurescopex_http_request_duration_seconds_total Cumulative request time.",
            "# TYPE exposurescopex_http_request_duration_seconds_total counter",
        ])
        for (method, route), value in sorted(_request_seconds.items()):
            lines.append(
                f'exposurescopex_http_request_duration_seconds_total{{method="{_label(method)}",route="{_label(route)}"}} {value:.6f}'
            )
    for name, value in sorted((extra or {}).items()):
        safe_name = "".join(char if char.isalnum() or char == "_" else "_" for char in name)
        lines.append(f"exposurescopex_{safe_name} {value}")
    return "\n".join(lines) + "\n"
