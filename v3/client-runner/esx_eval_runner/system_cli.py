"""Whole-system local discovery, review, execution and opt-in repeated checks."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from uuid import uuid4

from .runner import RunnerError, sha256
from .system_inventory import add_role_matrix, discover_system, document, sample_population
from .system_engine import approve_plan, execute_system, plan_digest, preflight, validate_plan
from .system_history import prune_history, record_run, trend, validate_rules


def write_json(path: Path, value: dict, *, replace: bool = False) -> None:
    from .system_safety import guard_output
    if "source_protection" in value:
        guard_output(value, path)
    if path.exists() and not replace:
        raise RunnerError("Output already exists; choose a new path")
    path.parent.mkdir(parents=True, exist_ok=True)
    # An exclusive temporary file plus atomic replacement avoids partial artifacts.
    temporary = path.with_name(path.name + "." + uuid4().hex + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, allow_nan=False)
            handle.write("\n")
        if not replace and path.exists():
            raise RunnerError("Output appeared during write; refusing to overwrite")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def bind_evaluation(plan: dict, root: Path, *, config_path: Path, components: list[str], check_id: str,
                    gates: list[dict] | None = None, layer: str | None = None) -> None:
    config_path = config_path.resolve()
    config = document(config_path)
    evaluation = config.get("evaluation", {})
    if evaluation.get("project_key") != plan["project_id"] or evaluation.get("subject_version") != plan["application_version"]:
        raise RunnerError("Evaluation project/version must match the system plan")
    browser = config.get("adapter", {}).get("type") == "browser_journey"
    required = ["workflow_coverage"] if browser else evaluation.get("required_dimensions", ["classification", "confidence"])
    defaults = {
        "classification": [("accuracy", "gte", .95), ("macro_f1", "gte", .9)],
        "confidence": [("expected_calibration_error", "lte", .15)],
        "workflow_coverage": [("workflow_execution_rate", "gte", 1), ("workflow_signal_match_rate", "gte", 1)],
    }
    suggested = [{"signal": dimension + "." + field, "operator": op, "threshold": value}
                 for dimension in (["workflow_coverage"] if browser else required)
                 for field, op, value in defaults.get(dimension, [])]
    import os
    try:
        reference = os.path.relpath(config_path, root)
    except ValueError:
        reference = str(config_path)
    plan["checks"].append({"id": check_id, "type": "evaluation", "layer": layer or ("workflow" if browser else "ai"),
                          "component_ids": components, "enabled": False, "reviewed": False,
                          "config": reference, "config_sha256": sha256(config), "timeout_seconds": 600,
                          "gates": gates if gates is not None else suggested,
                          "requested_dimensions": required,
                          "authoring_note": "Review thresholds and enable; every requested metric needs an applicable explicit gate. Suggested defaults are not universal safety standards."})
    plan.pop("approval", None)
    validate_plan(plan, root)


def register_system_commands(commands: argparse._SubParsersAction) -> None:
    parent = commands.add_parser("system", help="Discover, review and evaluate whole-system coverage locally")
    actions = parent.add_subparsers(dest="system_action", required=True)
    bootstrap = actions.add_parser("bootstrap", help="Discover once into a reusable protected profile outside the application repository")
    bootstrap.add_argument("--project", required=True)
    bootstrap.add_argument("--version", required=True)
    bootstrap.add_argument("--repo")
    bootstrap.add_argument("--openapi")
    bootstrap.add_argument("--base-url", default="")
    bootstrap.add_argument("--role", action="append", default=[])
    bootstrap.add_argument("--max-files", type=int, default=2000)
    bootstrap.add_argument("--source-max-files", type=int, help="Maximum regular source files to hash for source protection")
    bootstrap.add_argument("--source-max-bytes", type=int, help="Maximum source bytes to hash for source protection")
    bootstrap.add_argument("--source-exclude-dir", action="append", default=[], help="Additional generated/cache directory name to exclude from source protection")
    bootstrap.add_argument("--source-exclude-ext", action="append", default=[], help="Additional file extension to exclude from source protection, such as .bin")
    bootstrap.add_argument("--out", required=True)
    refresh = actions.add_parser("refresh", help="Rediscover a profile, preserve reviewed work, report changes and invalidate approval")
    refresh.add_argument("--plan", required=True)
    refresh.add_argument("--version")
    refresh.add_argument("--source-max-files", type=int, help="Override source-protection max_files while preserving other reviewed scan limits")
    refresh.add_argument("--source-max-bytes", type=int, help="Override source-protection max_bytes while preserving other reviewed scan limits")
    refresh.add_argument("--source-exclude-dir", action="append", default=[], help="Additional generated/cache directory name to exclude from source protection")
    refresh.add_argument("--source-exclude-ext", action="append", default=[], help="Additional file extension to exclude from source protection, such as .bin")
    assist = actions.add_parser("assist", help="Create a reviewable proposal using templates or an explicitly selected local model; no target calls")
    assist.add_argument("--plan", required=True)
    assist.add_argument("--model", help="Existing Ollama model name; no model is downloaded")
    assist.add_argument("--endpoint", default="http://127.0.0.1:11434")
    assist.add_argument("--max-turns", type=int, default=4)
    assist.add_argument("--business-context", help="Local JSON business-rule context; drafts expectations only, never approves checks")
    assist.add_argument("--out", required=True)
    accept = actions.add_parser("accept", help="Accept selected proposal IDs as unbound behavior objectives; never enables tests")
    accept.add_argument("--plan", required=True)
    accept.add_argument("--proposal", required=True)
    accept.add_argument("--suggestion", action="append", required=True)
    compare = actions.add_parser("compare", help="Compare two sealed reports with per-check evidence and protocol provenance")
    compare.add_argument("--before", required=True)
    compare.add_argument("--after", required=True)
    compare.add_argument("--out", required=True)
    discover = actions.add_parser("discover", help="Create source-linked inventory and unapproved check candidates; no target calls")
    discover.add_argument("--project", required=True)
    discover.add_argument("--version", required=True)
    discover.add_argument("--repo")
    discover.add_argument("--openapi", help="Local OpenAPI 3.x JSON; no remote references are fetched")
    discover.add_argument("--base-url", default="")
    discover.add_argument("--max-files", type=int, default=2000)
    discover.add_argument("--source-exclude-dir", action="append", default=[], help="Additional generated/cache directory name to exclude from discovery")
    discover.add_argument("--source-exclude-ext", action="append", default=[], help="Additional file extension to exclude from discovery, such as .bin")
    discover.add_argument("--out", required=True)
    sample = actions.add_parser("sample", help="Stratify supplied labelled cases reproducibly; never invent labels or execute targets")
    sample.add_argument("--dataset", required=True)
    sample.add_argument("--per-class", required=True, type=int)
    sample.add_argument("--seed", type=int, default=0)
    sample.add_argument("--out", required=True)
    setup = actions.add_parser("setup", help="Open local guided inventory/check review; never executes a target")
    setup.add_argument("--plan", required=True)
    bind = actions.add_parser("bind", help="Attach an existing AI/browser plan without replacing its metric engines")
    bind.add_argument("--plan", required=True)
    bind.add_argument("--config", required=True)
    bind.add_argument("--component", action="append", required=True)
    bind.add_argument("--id", required=True)
    bind.add_argument("--gates", help="JSON file containing a gates array")
    bind.add_argument("--layer", choices=["ai", "workflow", "security", "integration"])
    matrix = actions.add_parser("roles", help="Draft API x role checks with empty policy expectations for review")
    matrix.add_argument("--plan", required=True)
    matrix.add_argument("--role", action="append", required=True)
    approve = actions.add_parser("approve", help="Approve the exact reviewed plan; this does not sandbox side effects")
    approve.add_argument("--plan", required=True)
    approve.add_argument("--isolated-writes", action="store_true")
    approve.add_argument("--allow-disruption", action="store_true", help="Separate permission for configured failure-injection/recovery commands")
    check = actions.add_parser("preflight", help="Validate scope, approvals, identities and coverage without target calls")
    check.add_argument("--plan", required=True)
    check.add_argument("--require-whole-system", action="store_true", help="Exit nonzero unless every reviewed behavior is bound and candidate checks are configured")
    workflows = actions.add_parser("validate-workflows", help="Validate browser workflow packs, personas, sessions and assertions without target calls")
    workflows.add_argument("--plan", required=True)
    workflows.add_argument("--out", help="Optional JSON output path")
    workflows.add_argument("--include-disabled", action="store_true", help="Also inspect disabled browser plans as authoring drafts")
    drafts = actions.add_parser("draft-packs", help="Draft review-only workflow/API/AI coverage pack templates; never enables checks")
    drafts.add_argument("--plan", required=True)
    drafts.add_argument("--out", required=True)
    agent_tasks = actions.add_parser("agent-tasks", help="Export strict read-only tasks for Claude/Codex authoring; no target calls")
    agent_tasks.add_argument("--plan", required=True)
    agent_tasks.add_argument("--out", required=True)
    agent_import = actions.add_parser("import-agent-pack", help="Import source-anchored Claude/Codex drafts as disabled unreviewed checks/objectives")
    agent_import.add_argument("--plan", required=True)
    agent_import.add_argument("--pack", required=True)
    gaps = actions.add_parser("evidence-gaps", help="Write a standalone evidence-gap JSON and HTML report without target calls")
    gaps.add_argument("--plan", required=True)
    gaps.add_argument("--out", required=True, help="JSON output path; HTML is written beside it")
    scope = actions.add_parser("scope", help="Draft or inspect behavior-level coverage without target calls")
    scope.add_argument("--plan", required=True)
    scope.add_argument("--init", action="store_true", help="Add unreviewed obligations; never overwrite an existing scope contract")
    for name in ("run", "monitor"):
        sub = actions.add_parser(name, help="Execute approved checks and write evidence" if name == "run" else "Opt-in foreground scheduled runs with local alerts; stop with Ctrl+C")
        sub.add_argument("--plan", required=True)
        sub.add_argument("--out", required=True, help="New run directory, or monitor output root")
        sub.add_argument("--history", help="Local SQLite history file; no database service required")
        sub.add_argument("--rules", help="JSON trend rules; file alerts and exit status, no outbound notification")
        sub.add_argument("--baseline", help="Previously accepted system-report.json; comparison never silently changes this baseline")
        sub.add_argument("--require-whole-system", action="store_true", help="Do not dispatch if reviewed behavior bindings or scope prerequisites are incomplete")
        if name == "monitor":
            sub.add_argument("--cycles", required=True, type=int)
            sub.add_argument("--interval-seconds", type=int, default=3600)
    trends = actions.add_parser("trend", help="Review compatible rolling-baseline changes without executing targets")
    trends.add_argument("--history", required=True)
    trends.add_argument("--project", required=True)
    trends.add_argument("--rules", required=True)
    trends.add_argument("--window", type=int, default=10)
    trends.add_argument("--min-baseline", type=int, default=2)
    trends.add_argument("--out")
    prune = actions.add_parser("prune", help="Explicitly prune only local history rows; report files are retained")
    prune.add_argument("--history", required=True)
    prune.add_argument("--project", required=True)
    prune.add_argument("--keep", type=int, required=True)


def _rules(path: str) -> list[dict]:
    value = document(path).get("rules")
    validate_rules(value)
    return value


def system_command(args: argparse.Namespace) -> int:
    try:
        return _system_command(args)
    except KeyboardInterrupt:
        print("System evaluation stopped. Completed local run artifacts were retained.")
        return 130
    except OSError as exc:
        raise RunnerError(f"Local system file/process operation failed: {exc}") from exc


def _system_command(args: argparse.Namespace) -> int:
    from .system_ui import render_evidence_gap_report, render_report, serve_system_setup
    action = args.system_action
    from .audit import append_audit_event, verify_audit_log
    from .system_safety import guard_output
    if action == "bootstrap":
        from .system_profile import bootstrap
        plan = bootstrap(project=args.project, version=args.version, repository=args.repo, openapi=args.openapi,
                         base_url=args.base_url, roles=args.role, max_files=args.max_files,
                         source_max_files=args.source_max_files, source_max_bytes=args.source_max_bytes,
                         source_exclude_dirs=args.source_exclude_dir,
                         source_exclude_extensions=args.source_exclude_ext)
        path = Path(args.out).resolve()
        guard_output(plan, path.with_suffix(".audit.jsonl"))
        write_json(path, plan)
        append_audit_event(path.with_suffix(".audit.jsonl"), "profile_bootstrapped", {"plan_sha256": plan_digest(plan)})
        print(json.dumps({"plan": str(path), "components": len(plan["components"]), "target_calls_made": False,
                          "next_step": "Open system setup to review the profile; optional system assist drafts suggestions."}))
        return 0
    if action == "compare":
        from .system_changes import compare_reports
        result = compare_reports(document(args.before), document(args.after))
        write_json(Path(args.out), result)
        print(json.dumps(result["summary"]))
        return 2 if result["summary"]["regressions"] else 0
    if action == "sample":
        dataset = sample_population(document(args.dataset), args.per_class, args.seed)
        write_json(Path(args.out), dataset)
        print(json.dumps({"dataset": args.out, "selected_cases": len(dataset["cases"]), "population": dataset["population"], "target_calls_made": False}))
        return 0
    if action == "discover":
        plan = discover_system(project_id=args.project, version=args.version, repository=args.repo,
                               openapi=args.openapi, base_url=args.base_url, max_files=args.max_files,
                               exclude_dirs=args.source_exclude_dir,
                               exclude_extensions=args.source_exclude_ext)
        write_json(Path(args.out).resolve(), plan)
        print(json.dumps({"plan": str(Path(args.out).resolve()), "components": len(plan["components"]),
                          "next_step": "Run esx-eval system setup --plan <path>; review inventory and checks before approval."}))
        return 0
    if action == "prune":
        print(json.dumps({"removed_history_rows": prune_history(Path(args.history), args.project, args.keep)}))
        return 0
    if action == "trend":
        report = trend(Path(args.history), args.project, _rules(args.rules), window=args.window, min_baseline=args.min_baseline)
        if args.out:
            write_json(Path(args.out), report)
        print(json.dumps(report))
        return 2 if report["status"] != "stable" else 0
    path = Path(args.plan).resolve()
    plan = document(path)
    guard_output(plan, path)
    audit_path = path.with_suffix(".audit.jsonl")
    guard_output(plan, audit_path)
    if audit_path.exists():
        verify_audit_log(audit_path)
    previous_digest = plan_digest(plan)
    if action == "assist":
        from .system_assistant import propose
        guard_output(plan, Path(args.out))
        result = propose(plan, model=args.model, endpoint=args.endpoint, max_turns=args.max_turns,
                         business_context=document(args.business_context) if args.business_context else None)
        write_json(Path(args.out), result)
        append_audit_event(audit_path, "onboarding_proposal_created", {"plan_sha256": previous_digest, "proposal_sha256": result["proposal_sha256"], "producer": result["producer"]})
        print(json.dumps({"proposal": args.out, "suggestions": len(result["suggestions"]), "target_calls_made": False}))
        return 0
    if action == "scope":
        from .system_scope import assess_scope, draft_scope
        if args.init:
            if "scope_contract" in plan:
                raise RunnerError("Scope contract already exists; review it in setup instead of overwriting")
            plan["scope_contract"] = draft_scope(plan)
            plan.pop("approval", None)
            validate_plan(plan, path.parent)
            write_json(path, plan, replace=True)
            append_audit_event(audit_path, "system_scope_drafted", {"before_sha256": previous_digest, "after_sha256": plan_digest(plan)})
        validate_plan(plan, path.parent)
        print(json.dumps({"scope_contract": assess_scope(plan, root=path.parent), "target_calls_made": False}))
        return 0
    if action == "validate-workflows":
        from .system_readiness import validate_workflow_packs
        result = validate_workflow_packs(plan, path.parent, include_disabled=args.include_disabled)
        if args.out:
            guard_output(plan, Path(args.out))
            write_json(Path(args.out), result)
        print(json.dumps({"ready": result["ready"], "summary": result["summary"], "target_calls_made": False}))
        return 0 if result["ready"] else 2
    if action == "draft-packs":
        from .system_readiness import draft_coverage_packs
        guard_output(plan, Path(args.out))
        result = draft_coverage_packs(plan, path.parent)
        write_json(Path(args.out), result)
        print(json.dumps({"drafts": args.out, "summary": result["summary"], "target_calls_made": False}))
        return 0
    if action == "agent-tasks":
        from .system_agent_pack import build_agent_task_pack
        guard_output(plan, Path(args.out))
        result = build_agent_task_pack(plan, path.parent)
        write_json(Path(args.out), result)
        append_audit_event(audit_path, "agent_task_pack_created", {"plan_sha256": previous_digest, "task_pack_sha256": sha256(result)})
        print(json.dumps({"task_pack": args.out, "component_count": result["inventory_summary"]["component_count"],
                          "target_calls_made": False, "application_code_modified": False}))
        return 0
    if action == "import-agent-pack":
        from .system_agent_pack import import_agent_pack
        pack = document(args.pack)
        plan = import_agent_pack(plan, path.parent, pack)
        write_json(path, plan, replace=True)
        append_audit_event(audit_path, "agent_pack_imported", {"before_sha256": previous_digest, "after_sha256": plan_digest(plan),
                                                               "pack_sha256": sha256(pack)})
        print(json.dumps({"plan": str(path), "imported_proposals": len(pack.get("proposals", [])),
                          "approval_current": False, "target_calls_made": False, "application_code_modified": False}))
        return 0
    if action == "evidence-gaps":
        from .system_readiness import evidence_gap_report
        output = Path(args.out)
        guard_output(plan, output)
        result = evidence_gap_report(plan, path.parent)
        has_gaps = bool(result["summary"]["action_item_count"])
        status = "report_generated_with_actionable_gaps" if has_gaps else "report_generated_no_actionable_gaps"
        exit_reason = (
            "Report generated successfully; nonzero exit means actionable evidence gaps remain."
            if has_gaps else
            "Report generated successfully; no actionable evidence gaps were found."
        )
        result["command_status"] = {"status": status, "exit_code": 2 if has_gaps else 0, "exit_reason": exit_reason}
        write_json(output, result)
        html_path = output.with_suffix(".html")
        guard_output(plan, html_path)
        html_path.write_text(render_evidence_gap_report(result), encoding="utf-8")
        print(json.dumps({"status": status, "report": str(html_path), "json": str(output), "summary": result["summary"],
                          "exit_reason": exit_reason, "target_calls_made": False}))
        return 2 if has_gaps else 0
    if action == "setup":
        serve_system_setup(path)
        return 0
    if action == "refresh":
        from .system_profile import refresh_profile
        plan = refresh_profile(plan, version=args.version, source_max_files=args.source_max_files,
                               source_max_bytes=args.source_max_bytes,
                               source_exclude_dirs=args.source_exclude_dir,
                               source_exclude_extensions=args.source_exclude_ext)
    elif action == "accept":
        from .system_assistant import apply_suggestions
        plan = apply_suggestions(plan, document(args.proposal), args.suggestion)
        validate_plan(plan, path.parent)
    elif action == "bind":
        bind_evaluation(plan, path.parent, config_path=Path(args.config), components=args.component,
                        check_id=args.id, gates=document(args.gates).get("gates") if args.gates else None, layer=args.layer)
    elif action == "roles":
        add_role_matrix(plan, args.role)
        validate_plan(plan, path.parent)
    elif action == "approve":
        approve_plan(plan, path.parent, isolated=args.isolated_writes, allow_disruption=args.allow_disruption)
    elif action == "preflight":
        result = preflight(plan, path.parent)
        print(json.dumps(result))
        return 0 if result["ready"] and (not args.require_whole_system or result["whole_system_ready"]) else 2
    else:
        if args.rules and not args.history:
            raise RunnerError("Trend alerts require --history")
        rules = _rules(args.rules) if args.rules else None
        cycles = args.cycles if action == "monitor" else 1
        if type(cycles) is not int or not 1 <= cycles <= 100:
            raise RunnerError("Monitor cycles must be 1..100")
        if action == "monitor" and not 60 <= args.interval_seconds <= 86400:
            raise RunnerError("Monitor interval must be 60..86400 seconds")
        if action == "monitor" and not args.history:
            raise RunnerError("Monitor requires explicit local --history")
        original_digest = plan_digest(plan)
        baseline = document(args.baseline) if getattr(args, "baseline", None) else None
        if baseline:
            from .system_changes import verify_report
            verify_report(baseline)
            if baseline["project_id"] != plan["project_id"]:
                raise RunnerError("Baseline must belong to the profile project")
        exit_code = 0
        for index in range(cycles):
            current = document(path)
            if plan_digest(current) != original_digest:
                raise RunnerError("Plan changed during monitoring; review and restart explicitly")
            if args.require_whole_system and not preflight(current, path.parent)["whole_system_ready"]:
                raise RunnerError("Whole-system preflight is incomplete. Run system preflight and resolve scope_contract gaps before dispatch.")
            output = Path(args.out).resolve()
            guard_output(current, output)
            if args.history:
                guard_output(current, Path(args.history))
            if action == "monitor":
                output /= datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid4().hex[:8]
            report = execute_system(current, path.parent, output)
            if baseline:
                from .system_changes import attach_comparison
                comparison = attach_comparison(report, baseline)
                write_json(output / "changes.json", comparison)
                append_audit_event(output / "audit.jsonl", "baseline_compared", {
                    "baseline_run_id": baseline["run_id"], "changes_sha256": comparison["changes_sha256"],
                    "report_sha256": report["report_sha256"]})
            write_json(output / "system-report.json", report)
            (output / "system-report.html").write_text(render_report(report), encoding="utf-8")
            if args.history:
                record_run(Path(args.history).resolve(), report)
            alerts = trend(Path(args.history), current["project_id"], rules) if rules else None
            if alerts:
                write_json(output / "alerts.json", alerts)
            failed = report["verdict"] != "checks_passed_within_reviewed_scope" or alerts and alerts["status"] != "stable"
            exit_code = max(exit_code, 2 if failed else 0)
            print(json.dumps({"report": str(output / "system-report.html"), "verdict": report["verdict"],
                              "summary": report["summary"], "trend": alerts["status"] if alerts else "not_configured"}), flush=True)
            if any(r["reason"] == "failure_injection_or_cleanup_failed" for r in report["checks"]):
                break
            if index + 1 < cycles:
                time.sleep(args.interval_seconds)
        return exit_code
    write_json(path, plan, replace=True)
    append_audit_event(audit_path, "system_plan_" + action, {"before_sha256": previous_digest, "after_sha256": plan_digest(plan)})
    print(json.dumps({"plan": str(path), "approval_current": plan.get("approval", {}).get("plan_sha256") == plan_digest(plan), "target_calls_made": False}))
    return 0
