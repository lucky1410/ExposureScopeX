"""Privacy-preserving, hash-chained local audit records."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from .runner import canonical_json, sha256


AUDIT_SCHEMA_VERSION = "esx-local-audit-1.0"


def append_audit_event(path: str | Path, event_type: str, details: dict[str, Any]) -> dict[str, Any]:
    """Append a hash-linked event containing only redacted identifiers and hashes."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    previous = _last_hash(target)
    entry = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "previous_sha256": previous,
        "details": details,
    }
    entry["entry_sha256"] = sha256(entry)
    with target.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
    try:
        target.chmod(0o600)
    except OSError:
        # Windows access is controlled through the invoking user's ACL.
        pass
    return entry


def verify_audit_log(path: str | Path) -> dict[str, Any]:
    """Verify ordering and hash links; an external signed anchor is still needed for immutability."""
    target = Path(path)
    try:
        lines = target.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"Cannot read audit log: {target}") from exc
    if not lines:
        raise ValueError("Audit log is empty")
    previous: str | None = None
    for number, line in enumerate(lines, start=1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Audit log line {number} is not valid JSON") from exc
        if not isinstance(entry, dict) or entry.get("schema_version") != AUDIT_SCHEMA_VERSION:
            raise ValueError(f"Audit log line {number} has an invalid schema")
        claimed = entry.pop("entry_sha256", None)
        if not isinstance(claimed, str) or claimed != sha256(entry):
            raise ValueError(f"Audit log line {number} has an invalid hash")
        if entry.get("previous_sha256") != previous:
            raise ValueError(f"Audit log line {number} breaks the hash chain")
        previous = claimed
    return {"status": "valid", "record_count": len(lines), "tail_sha256": previous}


def _last_hash(path: Path) -> str | None:
    if not path.exists() or path.stat().st_size == 0:
        return None
    try:
        last_line = path.read_text(encoding="utf-8").rstrip("\n").split("\n")[-1]
        entry = json.loads(last_line)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Cannot append to an invalid audit log") from exc
    claimed = entry.get("entry_sha256") if isinstance(entry, dict) else None
    if not isinstance(claimed, str):
        raise ValueError("Cannot append to an audit log without a valid previous hash")
    return claimed
