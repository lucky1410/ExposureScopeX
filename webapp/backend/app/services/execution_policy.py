"""Central scan scheduling, isolation, and resource policy."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


QUEUE_BY_TARGET = {
    "repository": "scans-artifact",
    "image": "scans-artifact",
    "kubernetes": "scans-artifact",
    "android": "scans-mobile",
    "ios": "scans-mobile",
    "cloud_account": "scans-cloud",
    "mcp": "scans-api",
    "api": "scans-api",
}

BASE_POLICY: dict[str, Any] = {
    "queue": "scans-web",
    "timeout_seconds": 7200,
    "cpu_seconds": 7000,
    "memory_mb": 4096,
    "disk_mb": 4096,
    "max_processes": 512,
    "max_open_files": 4096,
    "max_targets": 1000,
    "log_bytes": 50_000,
    "artifact_retention_days": 30,
    "network_policy": "authorized-egress",
    "workspace_isolation": "per-scan-0700",
}

MODE_POLICY = {
    "light": {
        "timeout_seconds": 3600,
        "cpu_seconds": 3300,
        "memory_mb": 2048,
        "disk_mb": 2048,
        "max_targets": 250,
    },
    "medium": {},
    "aggressive": {
        "timeout_seconds": 14_400,
        "cpu_seconds": 14_000,
        "memory_mb": 6144,
        "disk_mb": 8192,
        "max_targets": 2500,
        "artifact_retention_days": 60,
    },
}

TARGET_POLICY = {
    "repository": {"timeout_seconds": 10_800, "disk_mb": 8192, "max_targets": 1},
    "image": {"timeout_seconds": 10_800, "disk_mb": 8192, "max_targets": 1},
    "kubernetes": {"timeout_seconds": 5400, "disk_mb": 4096, "max_targets": 1},
    "android": {"timeout_seconds": 7200, "disk_mb": 6144, "max_targets": 1},
    "ios": {"timeout_seconds": 7200, "disk_mb": 6144, "max_targets": 1},
    "cloud_account": {"timeout_seconds": 28_800, "disk_mb": 8192, "max_targets": 1},
    "mcp": {"timeout_seconds": 7200, "disk_mb": 2048, "max_targets": 1},
    "api": {"timeout_seconds": 7200, "disk_mb": 3072, "max_targets": 1},
}


def resolve_execution_policy(
    scan_mode: str,
    target_type: str,
    *,
    target_count: int = 1,
) -> dict[str, Any]:
    """Return bounded policy values suitable for persistence and enforcement."""
    policy = deepcopy(BASE_POLICY)
    policy.update(MODE_POLICY.get(scan_mode, MODE_POLICY["medium"]))
    policy.update(TARGET_POLICY.get(target_type, {}))
    policy["queue"] = QUEUE_BY_TARGET.get(target_type, "scans-web")
    count = max(1, int(target_count))
    if count > int(policy["max_targets"]):
        raise ValueError(
            f"Target count {count} exceeds the {scan_mode}/{target_type} policy limit "
            f"of {policy['max_targets']}"
        )
    per_target = {"light": 30, "medium": 60, "aggressive": 120}.get(scan_mode, 60)
    policy["timeout_seconds"] = min(
        86_400,
        max(int(policy["timeout_seconds"]), count * per_target),
    )
    policy["target_count"] = count
    return policy


def estimate_remaining_seconds(
    progress: int,
    elapsed_seconds: float,
    timeout_seconds: int,
) -> int | None:
    """Calculate a bounded ETA after enough work has completed to be useful."""
    if progress < 5 or elapsed_seconds < 10 or progress >= 100:
        return 0 if progress >= 100 else None
    projected_total = elapsed_seconds / (progress / 100)
    remaining = max(0, projected_total - elapsed_seconds)
    return int(min(remaining, max(0, timeout_seconds - elapsed_seconds)))
