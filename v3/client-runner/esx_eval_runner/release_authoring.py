"""Offline authoring of application test objectives and reviewed case bindings."""

from __future__ import annotations

import json
from pathlib import Path

from .release import validate_manifest
from .release_coverage import draft_requirements, plan_requirement_issues
from .release_execution import load_plan
from .runner import RunnerError, read_json


def register_authoring_commands(actions) -> None:
    scope = actions.add_parser("scope", help="Draft generic module objectives without generating fake tests or calling the app")
    scope.add_argument("--manifest", required=True)
    scope.add_argument("--module", required=True)
    scope.add_argument("--profile", required=True, choices=("workflow", "decision", "mixed"))
    scope.add_argument("--persona", action="append", help="Existing browser persona ID; repeat for every role to cover")
    scope.add_argument("--depends-on", action="append", help="Module dependency to exercise in an integration objective")
    scope.add_argument("--replace", action="store_true", help="Explicitly replace this module's objectives and discard their old bindings")
    bind = actions.add_parser("bind", help="Map a reviewed objective to real case IDs and describe the assertion")
    bind.add_argument("--manifest", required=True)
    bind.add_argument("--module", required=True)
    bind.add_argument("--requirement", required=True)
    bind.add_argument("--suite-id", required=True)
    bind.add_argument("--case-id", action="append", required=True)
    bind.add_argument("--assertion", required=True, help="Explain the actual assertion in these cases; do not include credentials or customer data")
    bind.add_argument("--replace", action="store_true", help="Replace this requirement's binding for the selected suite only")


def authoring_command(args) -> int:
    from .release_cli import _write

    path = Path(args.manifest).resolve()
    manifest = validate_manifest(read_json(path))
    module = next((m for m in manifest["modules"] if m["id"] == args.module), None)
    if module is None or not module["required"]:
        raise RunnerError("Scope and bind require an existing required module")
    if args.release_action == "scope":
        if module.get("test_requirements") and not args.replace:
            raise RunnerError("Module objectives already exist; --replace explicitly discards their old bindings")
        kinds = ["workflow", "decision"] if args.profile == "mixed" else [args.profile]
        module["required_kinds"] = sorted(set(module.get("required_kinds", [])) | set(kinds))
        module["depends_on"] = sorted(set(module["depends_on"]) | set(args.depends_on or []))
        module["test_requirements"] = draft_requirements(module["required_kinds"], sorted(set(args.persona or [])), module["depends_on"])
        next_step = "Review the draft objectives. Attach real plans, then use release bind for each objective. Missing bindings will block an all-module run; no cases or expected outcomes were invented."
    else:
        requirement = next((r for r in module.get("test_requirements", []) if r["id"] == args.requirement), None)
        suite = next((s for s in module["suites"] if s["id"] == args.suite_id), None)
        if requirement is None or suite is None or "config" not in suite:
            raise RunnerError("Binding requires an existing objective and config-backed suite in this module")
        _, cases, _, _ = load_plan((path.parent / suite["config"]).resolve(), manifest["application"], suite)
        existing = next((b for b in requirement["bindings"] if b["suite_id"] == args.suite_id), None)
        if existing and not args.replace:
            raise RunnerError("Binding already exists; use --replace after reviewing the new case selection")
        binding = {"suite_id": args.suite_id, "case_ids": args.case_id, "assertion": args.assertion}
        if existing:
            requirement["bindings"][requirement["bindings"].index(existing)] = binding
        else:
            requirement["bindings"].append(binding)
        manifest = validate_manifest(manifest)
        checked = next(m for m in manifest["modules"] if m["id"] == args.module)
        issues = [i for i in plan_requirement_issues(checked, {args.suite_id: cases})
                  if i["requirement_id"] == args.requirement and i.get("suite_id") == args.suite_id]
        if issues:
            raise RunnerError(issues[0]["action"])
        next_step = "Run release preflight, then release run. The assertion mapping is your reviewed test contract, not independent proof of business completeness."
    manifest = validate_manifest(manifest)
    _write(path, manifest)
    print(json.dumps({"manifest": str(path), "module": args.module, "next_step": next_step, "target_calls_made": False}))
    return 0
