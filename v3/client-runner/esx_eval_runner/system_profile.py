"""Reusable local onboarding profiles; discovery updates never grant execution approval."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from .runner import RunnerError, sha256
from .system_inventory import discover_system, document, add_role_matrix
from .system_safety import POLICY, MAX_BYTES, MAX_FILES, EXCLUDED, EXCLUDED_EXTENSIONS, snapshot_sources, source_diff
from .system_scope import draft_scope


PROFILE = "pre-d-application-profile-1.0"


def bootstrap(*, project: str, version: str, repository: str | None = None,
              openapi: str | None = None, base_url: str = "", roles: list[str] | None = None,
              max_files: int = 2000) -> dict:
    inputs = {"repository": str(Path(repository).resolve()) if repository else None,
              "openapi": str(Path(openapi).resolve()) if openapi else None,
              "max_files": max_files}
    roots = [Path(inputs["repository"])] if repository else []
    before = snapshot_sources(roots)
    plan = discover_system(project_id=project, version=version, base_url=base_url, **inputs)
    after = snapshot_sources(roots)
    if source_diff(before, after)["status"] == "changed":
        raise RunnerError("Application source changed during discovery; retry against a stable checkout")
    for component in plan["components"]:
        component["discovered_sha256"] = sha256(component)
    if roles:
        add_role_matrix(plan, roles)
    plan["source_protection"] = {"schema_version": POLICY, "mode": "read_only",
                                 "roots": [str(p) for p in roots],
                                 "scan_limits": {
                                     "max_files": MAX_FILES,
                                     "max_bytes": MAX_BYTES,
                                     "excluded_directories": sorted(EXCLUDED),
                                     "excluded_extensions": sorted(EXCLUDED_EXTENSIONS),
                                 },
                                 "snapshot": after}
    plan["profile"] = {"schema_version": PROFILE, "revision": 1, "inputs": inputs,
                       "created_at": datetime.now(timezone.utc).isoformat(),
                       "openapi_sha256": sha256(document(openapi)) if openapi else None,
                       "notice": "Reusable local profile. Discovery and agent suggestions require owner review; credentials remain environment references."}
    plan["scope_contract"] = draft_scope(plan)
    plan["onboarding"] = onboarding_tasks(plan)
    return plan


def onboarding_tasks(plan: dict) -> list[dict]:
    """Expose the irreducible missing inputs with a concrete action per component."""
    tasks = []
    for component in plan["components"]:
        checks = [c for c in plan["checks"] if component["id"] in c["component_ids"]]
        if not any(c.get("enabled") and c.get("reviewed") for c in checks):
            tasks.append({"component_id": component["id"], "kind": "execution",
                          "action": "Review a check and its expected behavior, then enable it."})
        if component["kind"] == "page":
            tasks.append({"component_id": component["id"], "kind": "workflow",
                          "action": "Attach a recorded browser workflow with a visible content assertion and approved session."})
        if "ai" in component["required_layers"]:
            tasks.append({"component_id": component["id"], "kind": "evidence",
                          "action": "Bind a decision endpoint and independently labelled cases. Add response/source evidence for semantic metrics."})
        if "authorization" in component["required_layers"]:
            tasks.append({"component_id": component["id"], "kind": "policy",
                          "action": "Confirm expected allow/deny behavior and identity references for each role."})
    return tasks


def refresh_profile(plan: dict, *, version: str | None = None) -> dict:
    from .system_engine import plan_digest
    profile = plan.get("profile", {})
    if profile.get("schema_version") != PROFILE:
        raise RunnerError("Use system bootstrap to create a reusable application profile first")
    inputs = profile.get("inputs")
    if not isinstance(inputs, dict):
        raise RunnerError("Profile discovery inputs are missing")
    fresh = bootstrap(project=plan["project_id"], version=version or plan["application_version"],
                      base_url=plan.get("base_url", ""), roles=plan["roles"], **inputs)
    updated = deepcopy(plan)
    old = {c["id"]: c for c in plan["components"]}
    found = {c["id"]: c for c in fresh["components"]}
    changed, added, absent = [], [], []
    components = []
    for key, component in found.items():
        if key not in old:
            components.append(component)
            added.append(key)
            continue
        previous = old[key]
        merged = deepcopy(previous)
        merged["evidence"] = component["evidence"]
        merged["discovered_sha256"] = component["discovered_sha256"]
        merged.pop("not_rediscovered", None)
        if previous.get("discovered_sha256") != component["discovered_sha256"] or previous.get("not_rediscovered"):
            changed.append(key)
            merged["required_layers"] = sorted(set(previous["required_layers"] + component["required_layers"]))
        components.append(merged)
    for key, component in old.items():
        if key in found:
            continue
        retained = deepcopy(component)
        # Owner-declared components remain part of scope even when static discovery cannot see them.
        if "discovered_sha256" in component:
            retained["not_rediscovered"] = True
            absent.append(key)
        components.append(retained)
    affected = set(changed + absent)
    checks = deepcopy(plan["checks"])
    existing_ids = {c["id"] for c in checks}
    for check in fresh["checks"]:
        if check["id"] not in existing_ids and any(c in added for c in check["component_ids"]):
            checks.append(check)
    for check in checks:
        if affected.intersection(check["component_ids"]):
            check.update(enabled=False, reviewed=False)
    delta = source_diff(plan.get("source_protection", {}).get("snapshot", {}), fresh["source_protection"]["snapshot"])
    spec_changed = profile.get("openapi_sha256") != fresh["profile"]["openapi_sha256"]
    version_changed = fresh["application_version"] != plan["application_version"]
    if version_changed:
        for check in checks:
            if check["type"] == "evaluation":
                check.update(enabled=False, reviewed=False)
                check["authoring_note"] = "Candidate version changed. Rebind a matching evaluation configuration before enabling."
    meaningful = bool(added or changed or absent or spec_changed or version_changed or delta["status"] not in {"unchanged", "not_configured"})
    updated.update(components=components, checks=checks, discovery=fresh["discovery"],
                   source_protection=fresh["source_protection"], application_version=fresh["application_version"])
    if meaningful:
        updated.pop("approval", None)
        updated["inventory_confirmed"] = False
        if "scope_contract" in updated:
            updated["scope_contract"]["policy_reviewed"] = False
            updated["scope_contract"]["inventory_totals_reviewed"] = False
            scope = updated["scope_contract"]
            existing = {(o["component_id"], o["layer"], o.get("role")) for o in scope["objectives"]}
            for objective in scope["objectives"]:
                if objective["component_id"] in affected:
                    objective["reviewed"] = False
            for objective in draft_scope(updated)["objectives"]:
                key = (objective["component_id"], objective["layer"], objective.get("role"))
                if key not in existing:
                    objective["id"] = "refresh-objective-" + sha256(key)[:20]
                    scope["objectives"].append(objective)
                    existing.add(key)
    updated["profile"] = {**profile, "revision": profile["revision"] + 1,
                          "parent_plan_sha256": plan_digest(plan), "openapi_sha256": fresh["profile"]["openapi_sha256"],
                          "refreshed_at": datetime.now(timezone.utc).isoformat()}
    updated["profile_changes"] = {"added_components": added, "changed_components": changed,
                                  "not_rediscovered_components": absent, "source": delta,
                                  "openapi_changed": spec_changed, "version_changed": version_changed,
                                  "action": "Review changes, reconcile whole-system objectives and approve again. Existing checks and evidence bindings are retained."}
    # The profile revision is itself part of approval: every refresh must be reapproved.
    updated.pop("approval", None)
    updated.pop("assistant_proposal", None)
    updated["onboarding"] = onboarding_tasks(updated)
    return updated
