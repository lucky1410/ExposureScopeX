"""Strict read-only agent authoring handoff for system evaluation plans."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import os
import re
from typing import Any

from .release import GATE_FIELDS
from .runner import RunnerError, sha256
from .system_engine import plan_digest, validate_plan
from .system_inventory import LAYERS, document
from .system_readiness import coverage_readiness, draft_coverage_packs, evidence_gap_report
from .system_safety import guard_output, protected_roots


TASK_SCHEMA = "pre-d-agent-task-pack-1.0"
PACK_SCHEMA = "pre-d-agent-pack-1.0"
PROPOSAL_TYPES = {"scope_objective", "system_check", "evaluation_config"}
CHECK_TYPES = {"http", "load"}
SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,160}$")


def build_agent_task_pack(plan: dict, root: Path) -> dict:
    """Export source-linked authoring context without code contents or target calls."""
    validate_plan(plan, root)
    readiness = coverage_readiness(plan, root)
    drafts = draft_coverage_packs(plan, root)
    gaps = evidence_gap_report(plan, root)
    return {
        "schema_version": TASK_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "plan_sha256": plan_digest(plan),
        "target_calls_made": False,
        "application_code_modified": False,
        "project": {
            "project_id": plan["project_id"],
            "application_version": plan["application_version"],
            "environment": plan["environment"],
            "roles": plan.get("roles", []),
        },
        "non_invasive_contract": {
            "agent_role": "draft_author_only",
            "allowed": [
                "Inspect supplied metadata and source files read-only.",
                "Draft evaluation checks, behavior objectives, and evaluation config bindings.",
                "Explain evidence gaps using source anchors.",
            ],
            "forbidden": [
                "Do not modify application source code.",
                "Do not execute target application workflows or production writes.",
                "Do not approve, enable, or score checks.",
                "Do not make release decisions.",
                "Do not submit proposals without source/component/OpenAPI anchors.",
            ],
        },
        "inventory_summary": {
            "component_count": len(plan.get("components", [])),
            "check_count": len(plan.get("checks", [])),
            "inventory_confirmed": bool(plan.get("inventory_confirmed")),
            "discovery": plan.get("discovery", {}),
        },
        "components": [_component_view(component) for component in plan.get("components", [])],
        "existing_checks": [_check_view(check) for check in plan.get("checks", [])],
        "coverage_readiness": readiness,
        "evidence_gaps": gaps,
        "draft_templates": drafts,
        "expected_agent_output": {
            "schema_version": PACK_SCHEMA,
            "target_calls_made": False,
            "application_code_modified": False,
            "proposals": [
                {
                    "id": "draft-id",
                    "type": "scope_objective | system_check | evaluation_config",
                    "title": "Human-readable draft title",
                    "reason": "Why this draft is needed",
                    "anchors": [
                        {"kind": "component", "component_id": "existing-component-id"},
                        {"kind": "source_file", "path": "relative/source/path.py"},
                        {"kind": "openapi_path", "method": "GET", "path": "/route"},
                    ],
                }
            ],
        },
        "import_rules": [
            "PRE-D will reject stale packs, missing anchors, hallucinated components/routes/files, target calls, code-modification claims, enabled checks, and unsupported proposal types.",
            "Imported proposals become disabled, unreviewed drafts with agent provenance. A human must review and enable them separately.",
        ],
    }


def import_agent_pack(plan: dict, root: Path, pack: dict) -> dict:
    """Import agent proposals as disabled drafts only, after source-anchor validation."""
    validate_plan(plan, root)
    _validate_pack_header(plan, pack)
    updated = deepcopy(plan)
    imported: list[str] = []
    for proposal in pack["proposals"]:
        proposal_id = _safe_text(proposal.get("id"), "proposal id", max_length=160)
        if not SAFE_ID.fullmatch(proposal_id):
            raise RunnerError("Agent proposal IDs must be safe identifiers")
        proposal_type = proposal.get("type")
        if proposal_type not in PROPOSAL_TYPES:
            raise RunnerError("Unsupported agent proposal type")
        anchors = _validate_anchors(updated, root, proposal.get("anchors"))
        provenance = {
            "status": "agent_drafted",
            "proposal_id": proposal_id,
            "proposal_sha256": sha256(proposal),
            "pack_sha256": sha256(pack),
            "anchors": anchors,
            "target_calls_made": False,
            "application_code_modified": False,
            "review_required": True,
        }
        if proposal_type == "scope_objective":
            _import_scope_objective(updated, proposal, provenance)
        elif proposal_type == "system_check":
            _import_system_check(updated, proposal, provenance)
        else:
            _import_evaluation_config(updated, root, proposal, provenance)
        imported.append(proposal_id)
    updated.setdefault("agent_imports", []).append({
        "schema_version": "pre-d-agent-import-record-1.0",
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "pack_sha256": sha256(pack),
        "proposal_ids": imported,
        "status": "drafted_for_human_review",
    })
    updated["inventory_confirmed"] = False
    updated.pop("approval", None)
    validate_plan(updated, root)
    return updated


def _component_view(component: dict) -> dict:
    return {
        "id": component["id"],
        "name": component["name"],
        "module": component["module"],
        "kind": component["kind"],
        "path": component.get("path"),
        "method": component.get("method"),
        "required_layers": component.get("required_layers", []),
        "suggested_dimensions": component.get("suggested_dimensions", []),
        "enabled": component.get("enabled", "unknown"),
        "depends_on": component.get("depends_on", []),
        "evidence": [
            {"source": str(item.get("source", "")), "basis": str(item.get("basis", ""))}
            for item in component.get("evidence", [])[:20] if isinstance(item, dict)
        ],
    }


def _check_view(check: dict) -> dict:
    return {
        "id": check["id"],
        "type": check["type"],
        "layer": check["layer"],
        "component_ids": check.get("component_ids", []),
        "enabled": bool(check.get("enabled")),
        "reviewed": bool(check.get("reviewed")),
        "requested_dimensions": check.get("requested_dimensions", []),
        "config": check.get("config"),
        "path": check.get("path"),
        "method": check.get("method"),
    }


def _validate_pack_header(plan: dict, pack: dict) -> None:
    if not isinstance(pack, dict):
        raise RunnerError("Agent pack must be a JSON object")
    if pack.get("schema_version") != PACK_SCHEMA:
        raise RunnerError("Unsupported agent pack schema")
    if pack.get("plan_sha256") != plan_digest(plan):
        raise RunnerError("Agent pack is stale; regenerate it from the current plan")
    if pack.get("target_calls_made") is not False:
        raise RunnerError("Agent packs must declare target_calls_made=false")
    if pack.get("application_code_modified") is not False:
        raise RunnerError("Agent packs must declare application_code_modified=false")
    proposals = pack.get("proposals")
    if not isinstance(proposals, list) or not proposals or len(proposals) > 1000:
        raise RunnerError("Agent pack requires 1..1000 proposals")
    for proposal in proposals:
        if not isinstance(proposal, dict):
            raise RunnerError("Agent proposals must be objects")


def _validate_anchors(plan: dict, root: Path, anchors: object) -> list[dict]:
    if not isinstance(anchors, list) or not anchors or len(anchors) > 20:
        raise RunnerError("Every agent proposal requires 1..20 source anchors")
    normalized = []
    for anchor in anchors:
        if not isinstance(anchor, dict) or not isinstance(anchor.get("kind"), str):
            raise RunnerError("Agent anchors must be objects with kind")
        kind = anchor["kind"]
        if kind == "component":
            component_id = _safe_text(anchor.get("component_id"), "component anchor", max_length=500)
            _component(plan, component_id)
            normalized.append({"kind": "component", "component_id": component_id})
        elif kind == "source_file":
            path = _relative_path(anchor.get("path"))
            _verify_source_file_anchor(plan, root, path)
            row = {"kind": "source_file", "path": path}
            for key in ("line_start", "line_end"):
                if key in anchor:
                    if type(anchor[key]) is not int or anchor[key] < 1 or anchor[key] > 1_000_000:
                        raise RunnerError("Source anchor lines must be positive integers")
                    row[key] = anchor[key]
            if row.get("line_end", row.get("line_start", 1)) < row.get("line_start", 1):
                raise RunnerError("Source anchor line_end must be greater than or equal to line_start")
            normalized.append(row)
        elif kind == "openapi_path":
            method = _safe_text(anchor.get("method"), "OpenAPI method", max_length=16).upper()
            path = _safe_text(anchor.get("path"), "OpenAPI path", max_length=1000)
            if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} or not path.startswith("/"):
                raise RunnerError("OpenAPI anchors require a valid method and path")
            if not any(component.get("kind") == "api" and component.get("method") == method and component.get("path") == path for component in plan["components"]):
                raise RunnerError("Agent OpenAPI anchor does not match discovered API inventory")
            normalized.append({"kind": "openapi_path", "method": method, "path": path})
        else:
            raise RunnerError("Unsupported agent anchor kind")
    return normalized


def _import_scope_objective(plan: dict, proposal: dict, provenance: dict) -> None:
    _require_fields(proposal, {"component_id", "layer", "title", "expected_behavior"})
    _reject_fields(proposal, {"enabled", "reviewed", "check_id"})
    component_id = _safe_text(proposal["component_id"], "component_id", max_length=500)
    _component(plan, component_id)
    layer = _safe_text(proposal["layer"], "layer", max_length=64)
    if layer not in LAYERS:
        raise RunnerError("Agent objective layer is not supported")
    role = proposal.get("role")
    if role is not None and role not in plan.get("roles", []):
        raise RunnerError("Agent objective role must be declared in the plan")
    if layer == "authorization" and role is None:
        raise RunnerError("Authorization objectives need an explicit role")
    objective = {
        "id": _unique_scope_id(plan, "agent-" + _slug(proposal["id"])),
        "component_id": component_id,
        "title": _safe_text(proposal["title"], "objective title", max_length=500),
        "layer": layer,
        "role": role,
        "reviewed": False,
        "check_id": "",
        "case_ids": _string_list(proposal.get("case_ids", []), "case_ids", limit=1000),
        "assertion_paths": _string_list(proposal.get("assertion_paths", []), "assertion_paths", limit=1000),
        "expected_business_behavior": _safe_text(proposal["expected_behavior"], "expected_behavior", max_length=1000),
        "agent_provenance": provenance,
    }
    if proposal.get("business_rule_id"):
        objective["business_rule_id"] = _safe_text(proposal["business_rule_id"], "business_rule_id", max_length=1000)
    plan.setdefault("scope_contract", {
        "mode": "whole_system",
        "policy_reviewed": False,
        "inventory_totals_reviewed": False,
        "inventory_totals": {},
        "build": {},
        "objectives": [],
    })
    plan["scope_contract"].setdefault("objectives", []).append(objective)


def _import_system_check(plan: dict, proposal: dict, provenance: dict) -> None:
    _require_fields(proposal, {"check"})
    check = deepcopy(proposal["check"])
    if not isinstance(check, dict):
        raise RunnerError("Agent system_check proposal requires a check object")
    if check.get("type") not in CHECK_TYPES:
        raise RunnerError("Agent system checks can only draft built-in http or load checks")
    if any(field in check for field in {"command", "inject_command", "recover_command", "trusted_command_policy"}):
        raise RunnerError("Agent system checks cannot include command execution fields")
    if check.get("id") in {row["id"] for row in plan.get("checks", [])}:
        raise RunnerError("Agent check ID already exists")
    if not isinstance(check.get("component_ids"), list) or not check["component_ids"]:
        raise RunnerError("Agent checks must reference components")
    for component_id in check["component_ids"]:
        _component(plan, component_id)
    if check.get("layer") not in LAYERS:
        raise RunnerError("Agent check layer is not supported")
    if not SAFE_ID.fullmatch(str(check.get("id", ""))):
        raise RunnerError("Agent check ID must be a safe identifier")
    _validate_agent_http_check(plan, check)
    if "enabled" in check and check["enabled"] is not False:
        raise RunnerError("Agent checks must be imported disabled")
    if "reviewed" in check and check["reviewed"] is not False:
        raise RunnerError("Agent checks must be imported unreviewed")
    check["enabled"] = False
    check["reviewed"] = False
    check["agent_provenance"] = provenance
    check.setdefault("authoring_note", "Agent-authored draft. Human review must set expectations and enable it before execution.")
    plan["checks"].append(check)


def _import_evaluation_config(plan: dict, root: Path, proposal: dict, provenance: dict) -> None:
    _require_fields(proposal, {"check_id", "config", "component_ids", "layer"})
    check_id = _safe_text(proposal["check_id"], "check_id", max_length=160)
    if not SAFE_ID.fullmatch(check_id) or check_id in {row["id"] for row in plan.get("checks", [])}:
        raise RunnerError("Agent evaluation check ID must be unique and safe")
    components = _string_list(proposal["component_ids"], "component_ids", limit=1000)
    for component_id in components:
        _component(plan, component_id)
    layer = _safe_text(proposal["layer"], "layer", max_length=64)
    if layer not in LAYERS:
        raise RunnerError("Agent evaluation layer is not supported")
    config_path = (root / _relative_path(proposal["config"])).resolve()
    guard_output(plan, config_path)
    config = document(config_path)
    evaluation = config.get("evaluation", {})
    if evaluation.get("project_key") != plan["project_id"] or evaluation.get("subject_version") != plan["application_version"]:
        raise RunnerError("Agent evaluation config project/version must match the system plan")
    requested = evaluation.get("required_dimensions", [])
    if not isinstance(requested, list) or any(not isinstance(item, str) for item in requested):
        raise RunnerError("Agent evaluation config requires explicit metric dimensions")
    plan["checks"].append({
        "id": check_id,
        "type": "evaluation",
        "layer": layer,
        "component_ids": components,
        "enabled": False,
        "reviewed": False,
        "config": os.path.relpath(config_path, root),
        "config_sha256": sha256(config),
        "timeout_seconds": _bounded_int(proposal.get("timeout_seconds", 600), "timeout_seconds", 1, 600),
        "gates": _gate_list(proposal.get("gates", [])),
        "requested_dimensions": requested,
        "authoring_note": "Agent-authored evaluation binding. Review dataset, adapter, gates and evidence before enabling.",
        "agent_provenance": provenance,
    })


def _validate_agent_http_check(plan: dict, check: dict) -> None:
    method = _safe_text(check.get("method", "GET"), "check method", max_length=16).upper()
    if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
        raise RunnerError("Agent check method is not supported")
    path = _safe_text(check.get("path"), "check path", max_length=1000)
    if not path.startswith("/") or path.startswith("//") or "\\" in path or any(ord(ch) < 32 for ch in path) or "{" in path or "[" in path:
        raise RunnerError("Agent check paths must be resolved same-origin paths")
    statuses = check.get("expected_status", [])
    if not isinstance(statuses, list) or len(statuses) > 32 or any(type(status) is not int or status < 100 or status > 599 for status in statuses):
        raise RunnerError("Agent checks need bounded expected HTTP status values")
    role = check.get("role", "anonymous")
    if role not in plan.get("roles", []):
        raise RunnerError("Agent check role must be declared")
    assertions = check.get("json_assertions", [])
    if not isinstance(assertions, list) or len(assertions) > 100:
        raise RunnerError("Agent check json_assertions must be bounded")
    for assertion in assertions:
        if not isinstance(assertion, dict) or not isinstance(assertion.get("path"), str) or not assertion["path"]:
            raise RunnerError("Agent JSON assertions require a path")
        fields = set(assertion)
        if fields == {"path", "equals"}:
            continue
        if fields == {"path", "operator", "value"} and assertion["operator"] in {"gte", "lte", "gt", "lt"} and _number(assertion["value"]):
            continue
        raise RunnerError("Agent JSON assertions must use path/equals or numeric path/operator/value")
    if check.get("type") == "load":
        if method not in {"GET", "HEAD", "OPTIONS"}:
            raise RunnerError("Agent load checks must use read-only methods")
        _bounded_int(check.get("requests", 10), "requests", 1, 100)
        _bounded_int(check.get("concurrency", 2), "concurrency", 1, 8)
        if not _number(check.get("max_p95_ms")) or check["max_p95_ms"] <= 0:
            raise RunnerError("Agent load checks require max_p95_ms")


def _gate_list(value: object) -> list[dict]:
    if not isinstance(value, list) or len(value) > 100:
        raise RunnerError("Agent gates must be a bounded list")
    gates = []
    for gate in value:
        if not isinstance(gate, dict):
            raise RunnerError("Agent gates must be objects")
        dimension, _, field = str(gate.get("signal", "")).partition(".")
        if field not in GATE_FIELDS.get(dimension, {}) or gate.get("operator") not in {"gte", "lte"} or not _number(gate.get("threshold")):
            raise RunnerError("Agent gates must reference supported metric fields")
        threshold = gate["threshold"]
        unbounded = dimension == "cost_efficiency" and field != "timeout_rate"
        if threshold < 0 or (not unbounded and threshold > 1):
            raise RunnerError("Agent gate thresholds must be non-negative; rates must be 0..1")
        gates.append({"signal": gate["signal"], "operator": gate["operator"], "threshold": threshold})
    return gates


def _verify_source_file_anchor(plan: dict, root: Path, relative: str) -> None:
    evidence_sources = {
        str(item.get("source"))
        for component in plan.get("components", [])
        for item in component.get("evidence", [])
        if isinstance(item, dict) and item.get("source")
    }
    if relative in evidence_sources:
        return
    roots = protected_roots(plan)
    for source_root in roots:
        candidate = (source_root / relative).resolve()
        try:
            candidate.relative_to(source_root)
        except ValueError:
            continue
        if candidate.is_file():
            return
    if not roots and (root / relative).is_file():
        return
    raise RunnerError("Agent source_file anchor could not be verified against source inventory")


def _component(plan: dict, component_id: str) -> dict:
    for component in plan.get("components", []):
        if component.get("id") == component_id:
            return component
    raise RunnerError("Agent proposal references an unknown component")


def _relative_path(value: object) -> str:
    text = _safe_text(value, "relative path", max_length=1000)
    path = Path(text)
    if path.is_absolute() or any(part in {"..", ""} for part in path.parts) or "\\" in text:
        raise RunnerError("Agent paths must be relative POSIX-style paths inside reviewed workspaces")
    return text


def _safe_text(value: object, field: str, *, max_length: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length or any(ord(ch) < 32 for ch in value):
        raise RunnerError(f"Agent {field} must be bounded text")
    return value


def _string_list(value: object, field: str, *, limit: int) -> list[str]:
    if not isinstance(value, list) or len(value) > limit or any(not isinstance(item, str) or not item or len(item) > 1000 for item in value):
        raise RunnerError(f"Agent {field} must be a bounded string list")
    if len(value) != len(set(value)):
        raise RunnerError(f"Agent {field} must not contain duplicates")
    return list(value)


def _number(value: object) -> bool:
    return type(value) in (int, float) and value == value and value not in {float("inf"), float("-inf")}


def _bounded_int(value: object, field: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise RunnerError(f"Agent {field} must be an integer between {low} and {high}")
    return value


def _require_fields(value: dict, fields: set[str]) -> None:
    missing = sorted(field for field in fields if field not in value)
    if missing:
        raise RunnerError("Agent proposal is missing required fields: " + ", ".join(missing))


def _reject_fields(value: dict, fields: set[str]) -> None:
    present = sorted(field for field in fields if field in value)
    if present:
        raise RunnerError("Agent proposal may not set controlled fields: " + ", ".join(present))


def _unique_scope_id(plan: dict, base: str) -> str:
    existing = {row.get("id") for row in plan.get("scope_contract", {}).get("objectives", [])}
    candidate = base[:180] or "agent-objective"
    suffix = 2
    while candidate in existing:
        candidate = f"{base[:170]}-{suffix}"
        suffix += 1
    return candidate


def _slug(value: Any) -> str:
    slug = "-".join(re.findall(r"[a-z0-9]+", str(value).lower()))[:120]
    return slug or sha256(value)[:16]
