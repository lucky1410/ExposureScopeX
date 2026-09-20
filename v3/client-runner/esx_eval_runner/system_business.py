"""Reviewed business-rule inputs for non-invasive system planning."""

from __future__ import annotations

import re

from .runner import RunnerError, sha256
from .system_inventory import LAYERS


SCHEMA = "pre-d-business-context-1.0"


def _bounded_text(value: object, field: str, *, required: bool = True, limit: int = 1000) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str) or not value.strip() or len(value) > limit or any(ord(ch) < 32 and ch not in "\t" for ch in value):
        raise RunnerError(f"Business context {field} must be bounded text")
    return value.strip()


def _bounded_list(value: object, field: str, *, limit: int = 32, item_limit: int = 200,
                  required: bool = False) -> list[str]:
    if value is None:
        if required:
            raise RunnerError(f"Business context {field} is required")
        return []
    if not isinstance(value, list) or len(value) > limit:
        raise RunnerError(f"Business context {field} must be a bounded array")
    rows = [_bounded_text(item, field, limit=item_limit) for item in value]
    if len(rows) != len(set(rows)):
        raise RunnerError(f"Business context {field} must not contain duplicates")
    return rows


def normalize_business_context(plan: dict, value: dict | None) -> dict | None:
    """Validate and bound owner-supplied rules without treating them as approval."""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RunnerError("Business context must be a JSON object")
    if value.get("schema_version", SCHEMA) != SCHEMA:
        raise RunnerError("Unsupported business context schema version")
    rules = value.get("rules")
    if not isinstance(rules, list) or not 1 <= len(rules) <= 500:
        raise RunnerError("Business context needs 1..500 rules")
    component_ids = {component["id"] for component in plan["components"]}
    ids: set[str] = set()
    normalized = []
    for rule in rules:
        if not isinstance(rule, dict):
            raise RunnerError("Every business rule must be an object")
        allowed = {"id", "title", "expected_behavior", "component_ids", "layers", "actors", "entities",
                   "states", "permissions", "dependencies", "expected_outcomes", "negative_outcomes",
                   "source", "risk", "reviewed"}
        if set(rule) - allowed:
            raise RunnerError("Business rule contains unsupported fields")
        rule_id = _bounded_text(rule.get("id"), "rule.id", limit=120)
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", rule_id) or rule_id in ids:
            raise RunnerError("Business rule IDs must be distinct and stable")
        ids.add(rule_id)
        components = _bounded_list(rule.get("component_ids"), "rule.component_ids", required=True, limit=40)
        unknown = sorted(set(components) - component_ids)
        if unknown:
            raise RunnerError("Business rule references unknown components: " + ", ".join(unknown))
        layers = _bounded_list(rule.get("layers"), "rule.layers", required=True, limit=8)
        if any(layer not in LAYERS for layer in layers):
            raise RunnerError("Business rule layers must use PRE-D system layers")
        reviewed = rule.get("reviewed", False)
        if type(reviewed) is not bool:
            raise RunnerError("Business rule reviewed must be boolean")
        normalized.append({
            "id": rule_id,
            "title": _bounded_text(rule.get("title"), "rule.title", limit=240),
            "expected_behavior": _bounded_text(rule.get("expected_behavior"), "rule.expected_behavior", limit=1000),
            "component_ids": components,
            "layers": layers,
            "actors": _bounded_list(rule.get("actors"), "rule.actors"),
            "entities": _bounded_list(rule.get("entities"), "rule.entities"),
            "states": _bounded_list(rule.get("states"), "rule.states"),
            "permissions": _bounded_list(rule.get("permissions"), "rule.permissions"),
            "dependencies": _bounded_list(rule.get("dependencies"), "rule.dependencies"),
            "expected_outcomes": _bounded_list(rule.get("expected_outcomes"), "rule.expected_outcomes"),
            "negative_outcomes": _bounded_list(rule.get("negative_outcomes"), "rule.negative_outcomes"),
            "source": _bounded_text(rule.get("source"), "rule.source", required=False, limit=300),
            "risk": _bounded_text(rule.get("risk"), "rule.risk", required=False, limit=80),
            "reviewed": reviewed,
        })
    supplied_digest = value.get("source_sha256")
    source_digest = supplied_digest if isinstance(supplied_digest, str) and re.fullmatch(r"[0-9a-f]{64}", supplied_digest) else sha256(value)
    return {
        "schema_version": SCHEMA,
        "source_sha256": source_digest,
        "rules": normalized,
        "notice": "Business rules are owner-supplied planning inputs. They draft expectations; they do not approve execution or prove correctness.",
    }


def business_rule_summary(context: dict | None) -> dict:
    if not context:
        return {"schema_version": SCHEMA, "rule_count": 0, "rules": []}
    return {
        "schema_version": SCHEMA,
        "source_sha256": context["source_sha256"],
        "rule_count": len(context["rules"]),
        "rules": [
            {
                "id": rule["id"],
                "title": rule["title"],
                "expected_behavior": rule["expected_behavior"],
                "component_ids": rule["component_ids"],
                "layers": rule["layers"],
                "actors": rule["actors"],
                "entities": rule["entities"],
                "states": rule["states"],
                "permissions": rule["permissions"],
                "dependencies": rule["dependencies"],
                "expected_outcomes": rule["expected_outcomes"],
                "negative_outcomes": rule["negative_outcomes"],
                "source": rule["source"],
                "risk": rule["risk"],
                "reviewed": rule["reviewed"],
            }
            for rule in context["rules"]
        ],
    }


def deterministic_business_suggestions(plan: dict, context: dict) -> list[dict]:
    components = {component["id"]: component for component in plan["components"]}
    rows = []
    for rule in context["rules"]:
        for component_id in rule["component_ids"]:
            component = components[component_id]
            for layer in rule["layers"]:
                if len(rows) >= 100:
                    return rows
                rows.append({
                    "component_id": component_id,
                    "module": component["module"],
                    "layer": layer,
                    "title": rule["title"],
                    "reason": "Business rule " + rule["id"] + " needs executable evidence for " + layer + ".",
                    "business_rule_id": rule["id"],
                    "expectation": rule["expected_behavior"],
                    "evidence_needed": "Bind a reviewed check that proves expected outcomes and rejects negative outcomes: "
                    + "; ".join((rule["expected_outcomes"] + rule["negative_outcomes"])[:6] or [rule["expected_behavior"][:240]]),
                })
    return rows
