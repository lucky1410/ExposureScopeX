"""Local application-level composition of existing PRE-D evaluation plans."""

from __future__ import annotations

import argparse
from contextlib import chdir, redirect_stdout
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import sys
from typing import Any
from uuid import uuid4

from .audit import append_audit_event
from .release_authoring import authoring_command, register_authoring_commands
from .release import MANIFEST_SCHEMA, build_release_report, default_gates, validate_manifest
from .release_comparison import validate_baseline
from .release_execution import execution_summary, load_plan, plan_metadata, preflight_all_modules
from .release_html import render_release_report
from .runner import RunnerError, read_json, sha256


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def register_release_commands(commands: Any) -> None:
    release = commands.add_parser("release", help="Evaluate an application release using existing local PRE-D plans")
    actions = release.add_subparsers(dest="release_action", required=True)
    register_authoring_commands(actions)
    init = actions.add_parser("init", help="Create a module inventory for a local release review")
    init.add_argument("--application-id", required=True, help="Must match evaluation.project_key in the plans")
    init.add_argument("--subject-version", required=True)
    init.add_argument("--module", action="append", required=True, help="Module ID; repeat for each application module")
    init.add_argument("--inventory-complete", action="store_true", help="Explicitly confirm that all release-relevant modules have been listed")
    init.add_argument("--out", required=True)
    check = actions.add_parser("check", help="Assess local reports against the declared release policy")
    check.add_argument("--manifest", required=True)
    check.add_argument("--out", required=True, help="Local release JSON path; also writes an HTML report")
    check.add_argument("--run", action="store_true", help="Execute the config-backed plans sequentially before assessment")
    check.add_argument("--require-ship", action="store_true", help="Exit 2 unless the recommendation is Ship")
    check.add_argument("--baseline", help="Compare against a previous local release-review JSON; does not execute that release")
    check.add_argument("--history", action="append", default=[], help="Additional previous local release-review JSON reports for multi-run trend context; repeat as needed")
    attach = actions.add_parser("attach", help="Bind an approved existing plan to a module without editing the manifest by hand")
    attach.add_argument("--manifest", required=True)
    attach.add_argument("--module", required=True)
    attach.add_argument("--suite-id", required=True)
    attach.add_argument("--config", required=True)
    attach.add_argument("--require-kind", choices=("workflow", "decision"), action="append", help="Additional required test kind for this module; repeat for both")
    attach.add_argument("--minimum-cases", type=int)
    attach.add_argument("--replace", action="store_true", help="Explicitly replace and reapprove this existing suite, preserving its release gates")
    approval = attach.add_mutually_exclusive_group(required=True)
    approval.add_argument("--read-only", action="store_true", help="Declare that the reviewed test plans will not mutate application or external state")
    approval.add_argument("--isolated-writes", action="store_true", help="Approve writes only in a disposable test environment, with external production effects disabled")
    attach.add_argument("--isolation-note", help="Required for isolated writes; record the isolation controls, not secrets")
    preflight = actions.add_parser("preflight", help="Check every declared module's plans and approvals without calling the app")
    preflight.add_argument("--manifest", required=True)
    preflight.add_argument("--out", required=True)
    run = actions.add_parser("run", help="Execute all declared modules; reject exclusions, report reuse, and missing or unapproved plans before any target calls", description="Strict all-module execution: no exclusions, report reuse, missing plans, or unapproved execution. For explicitly partial scope use release check --run; excluded modules never count as evaluated.")
    run.add_argument("--manifest", required=True)
    run.add_argument("--out", required=True)
    run.add_argument("--baseline", help="Previous release-review JSON for an actual matched-pack comparison")
    run.add_argument("--history", action="append", default=[], help="Additional previous local release-review JSON reports for multi-run trend context; repeat as needed")
    run.add_argument("--require-ship", action="store_true", help="Also exit 2 when complete execution does not yield Ship")


def release_command(args: argparse.Namespace) -> int:
    try:
        return _release_command(args)
    except RunnerError:
        raise
    except (OSError, ValueError) as exc:
        raise RunnerError("The local release review could not read or write its artifacts. Check the paths and local audit log before retrying.") from exc


def _release_command(args: argparse.Namespace) -> int:
    if args.release_action in ("scope", "bind"):
        return authoring_command(args)
    if args.release_action == "init":
        target = Path(args.out).resolve()
        if target.exists():
            raise RunnerError(f"Refusing to overwrite existing release manifest: {target}")
        manifest = validate_manifest({
            "schema_version": MANIFEST_SCHEMA,
            "application": {"id": args.application_id, "version": args.subject_version, "inventory_complete": args.inventory_complete},
            "modules": [{"id": item, "required": True, "suites": []} for item in args.module],
        })
        _write(target, manifest)
        print(json.dumps({"manifest": str(target), "next_step": "Use release attach for each approved workflow/decision plan, then release preflight and release run."}))
        return 0

    if args.release_action == "attach":
        return _attach_plan(args)
    if args.release_action == "preflight":
        path = Path(args.manifest).resolve()
        manifest = validate_manifest(read_json(path))
        out = Path(args.out).resolve()
        if out.suffix.lower() != ".json" or out in _manifest_sources(manifest, path):
            raise RunnerError("Preflight --out must be a JSON path that does not overwrite the manifest or its input files")
        preflight, _, _ = preflight_all_modules(manifest, path)
        _write(out, preflight)
        print(json.dumps({"preflight": str(out), **preflight}))
        return 0 if preflight["status"] == "ready" else 2

    all_modules = args.release_action == "run"
    run_requested = all_modules or args.run
    manifest_path = Path(args.manifest).resolve()
    out = Path(args.out).resolve()
    if out.suffix.lower() != ".json":
        raise RunnerError("Release --out must end in .json")
    manifest = validate_manifest(read_json(manifest_path))
    html = out.with_suffix(".html")
    audit = out.with_suffix(".audit.jsonl")
    evidence: dict[str, dict[str, Any]] = {}
    prepared: dict[str, tuple[Path, str]] = {}
    sources: set[Path] = {manifest_path}
    baseline = None
    baseline_path = None
    history = []
    preflight = None
    attempted: list[str] = []
    reused: list[str] = []
    plan_metadata_by_suite: dict[str, dict[str, Any]] = {}
    if getattr(args, "baseline", None):
        baseline_path = Path(args.baseline).resolve()
        baseline = read_json(baseline_path)
        validate_baseline(baseline, manifest["application"]["id"], datetime.now(timezone.utc))
        sources.update({baseline_path, baseline_path.with_suffix(".html")})
    for item in getattr(args, "history", []) or []:
        path = Path(item).resolve()
        report = read_json(path)
        validate_baseline(report, manifest["application"]["id"], datetime.now(timezone.utc))
        history.append(report)
        sources.update({path, path.with_suffix(".html")})
    if all_modules:
        preflight, prepared, plan_metadata_by_suite = preflight_all_modules(manifest, manifest_path)
    # Resolve and validate every plan before running any target. Paths in a
    # plan keep their established meaning relative to that plan's directory.
    for module in manifest["modules"]:
        for suite in module["suites"]:
            key = "config" if "config" in suite else "report"
            path = (manifest_path.parent / suite[key]).resolve()
            sources.add(path)
            if all_modules:
                if key == "report":
                    sources.add(path.with_suffix(".html"))
                if preflight["status"] != "ready":
                    evidence[suite["id"]] = {"error_code": "all_module_preflight_blocked", "error": "No suite was run: the whole-inventory preflight has unresolved module, plan, or execution-approval gaps. Review execution_review.preflight.issues."}
                continue
            if key == "report":
                sources.add(path.with_suffix(".html"))
                evidence[suite["id"]] = _load_report(path, out.parent)
                if isinstance(evidence[suite["id"]].get("report"), dict):
                    reused.append(suite["id"])
                continue
            if not run_requested:
                evidence[suite["id"]] = {"error_code": "run_not_requested", "error": "This suite references a plan which has not been executed for this release review. Use --run or supply its completed report."}
                continue
            try:
                evaluation, cases, _, digest = load_plan(path, manifest["application"], suite)
                prepared[suite["id"]] = (path, digest)
                plan_metadata_by_suite[suite["id"]] = plan_metadata(evaluation, cases, kind=suite["kind"])
            except (RunnerError, OSError, ValueError):
                evidence[suite["id"]] = {"error_code": "invalid_plan", "error": "The evaluation plan is invalid or its project, subject, version, or type does not match this release suite. Review the plan with esx-eval evidence-check."}
    if {out, html, audit} & sources:
        raise RunnerError("Release output paths must not overwrite the manifest, an evaluation plan, or an input report")
    out.parent.mkdir(parents=True, exist_ok=True)
    if all_modules and preflight["status"] != "ready":
        prepared.clear()
    append_audit_event(audit, "release_review_started", {"manifest_sha256": sha256(manifest), "execute_plans": run_requested,
                                                       "execution_mode": "all_modules" if all_modules else "partial_or_report_review",
                                                       "preflight_status": preflight["status"] if preflight else None,
                                                       "baseline_sha256": sha256(baseline) if baseline is not None else None})
    run_dir = out.parent / (out.stem + ".runs") / uuid4().hex
    for suite_id, (path, digest) in prepared.items():
        print(f"PRE-D release: running {suite_id}", file=sys.stderr)
        package = run_dir / suite_id / "evaluation.json"
        try:
            if sha256(read_json(path)) != digest:
                raise RunnerError("Plan changed after validation")
            from .cli import run_command

            run_args = argparse.Namespace(
                config=str(path), out=str(package), github_oidc_token_file=None,
                sign=False, summary_only=True, output_format="json", discovery=None,
                scope=None, plan=None, telemetry=None, ground_truth=None, grounding_material=None,
            )
            with chdir(path.parent), redirect_stdout(io.StringIO()):
                append_audit_event(audit, "release_suite_started", {"suite_id": suite_id, "config_sha256": digest})
                attempted.append(suite_id)
                run_command(run_args)
            item = _load_report(package.with_name("evaluation.local-report.json"), out.parent)
            if not isinstance(item.get("report"), dict):
                raise RunnerError("Suite did not produce a completed local report")
            provenance = item["report"].get("run_provenance")
            if not isinstance(provenance, dict) or provenance.get("config_sha256") != digest:
                raise RunnerError("Run configuration differs from validated plan")
            evidence[suite_id] = item
            append_audit_event(audit, "release_suite_completed", {"suite_id": suite_id, "report_sha256": item.get("report_sha256")})
        except (RunnerError, OSError, ValueError):
            diagnostic_dir = Path(os.path.relpath(package.parent, out.parent)).as_posix()
            evidence[suite_id] = {"error_code": "suite_execution_failed", "error": f"The suite did not produce a usable completed report. Review its local evaluation audit/debug artifacts under {diagnostic_dir} and rerun the plan."}
            append_audit_event(audit, "release_suite_failed", {"suite_id": suite_id})
    report = build_release_report(
        manifest,
        evidence,
        baseline=baseline,
        history=history,
        plan_metadata=plan_metadata_by_suite,
    )
    report["execution_review"] = execution_summary(
        report, mode="all_modules" if all_modules else ("configured_suites" if run_requested else "report_review_only"),
        attempted=attempted, reused=reused, preflight=preflight,
    )
    if baseline_path and report["comparison"]:
        try:
            report["comparison"]["artifact"] = Path(os.path.relpath(baseline_path, out.parent)).as_posix()
        except ValueError:
            report["comparison"]["artifact"] = None
    _write(out, report)
    html.write_text(render_release_report(report), encoding="utf-8")
    append_audit_event(audit, "release_review_completed", {"manifest_sha256": report["manifest_sha256"], "report_sha256": sha256(report), "verdict": report["verdict"]})
    print(json.dumps({"report": str(out), "html_report": str(html), "audit_log": str(audit),
                      "verdict": report["verdict"], "summary": report["summary"],
                      "all_modules_executed": report["execution_review"]["all_modules_executed"], "uploaded": False}))
    if all_modules and (preflight["status"] != "ready" or not report["execution_review"]["all_modules_executed"]):
        return 2
    return 2 if args.require_ship and report["verdict"] != "ship" else 0


def _manifest_sources(manifest: dict, path: Path) -> set[Path]:
    sources = {path}
    for module in manifest["modules"]:
        for suite in module["suites"]:
            key = "config" if "config" in suite else "report"
            source = (path.parent / suite[key]).resolve()
            sources.add(source)
            if key == "report":
                sources.add(source.with_suffix(".html"))
    return sources


def _attach_plan(args: argparse.Namespace) -> int:
    path = Path(args.manifest).resolve()
    manifest = validate_manifest(read_json(path))
    module = next((m for m in manifest["modules"] if m["id"] == args.module), None)
    if module is None or not module["required"]:
        raise RunnerError("Attach requires an existing required module; review excluded scope explicitly before changing it")
    config_path = Path(args.config).resolve()
    evaluation, _, adapter, digest = load_plan(config_path, manifest["application"])
    kind = "workflow" if adapter["type"] == "browser_journey" else "decision"
    existing = next((s for s in module["suites"] if s["id"] == args.suite_id), None)
    if existing is not None and not args.replace:
        raise RunnerError("Suite already exists; use --replace only after reviewing the changed plan")
    if existing is not None and existing["kind"] != kind:
        raise RunnerError("Replacing a suite cannot change its evaluation kind; use a new suite ID and review coverage requirements")
    for other in manifest["modules"]:
        for suite in other["suites"]:
            if suite is not existing and "config" in suite and (path.parent / suite["config"]).resolve() == config_path:
                raise RunnerError("This plan is already attached; use a distinct plan for additional module coverage")
    try:
        config_reference = Path(os.path.relpath(config_path, path.parent)).as_posix()
    except ValueError:
        config_reference = config_path.as_posix()
    entry = {**(existing or {}), "id": args.suite_id, "kind": kind,
             "subject_id": evaluation["agent_id"], "config": config_reference,
             "execution_policy": {"mode": "isolated_write" if args.isolated_writes else "read_only", "config_sha256": digest}}
    entry.pop("report", None)
    if existing is None:
        entry["gates"] = default_gates(kind, evaluation.get("required_dimensions", ["classification", "confidence"]))
        if not entry["gates"]:
            raise RunnerError("This plan has no baseline classification/workflow gates. Add a suite with explicit reviewed gates for its requested dimensions to release.json; confidence is not required.")
    population = read_json(config_path).get("dataset", {}).get("population")
    if population is not None:
        if existing and existing.get("population") not in (None, population):
            raise RunnerError("Plan and manifest population differ; reconcile them explicitly before replacing this suite")
        entry["population"] = population
    if args.isolation_note is not None:
        entry["execution_policy"]["isolation_note"] = args.isolation_note
    if args.minimum_cases is not None:
        entry["minimum_cases"] = args.minimum_cases
    if existing is not None:
        module["suites"][module["suites"].index(existing)] = entry
    else:
        module["suites"].append(entry)
    module["required_kinds"] = sorted(set(module.get("required_kinds", [])) | {kind} | set(args.require_kind or []))
    manifest = validate_manifest(manifest)
    _write(path, manifest)
    print(json.dumps({"manifest": str(path), "module": args.module, "suite": args.suite_id, "kind": kind,
                      "next_step": "Run release preflight to check all modules. Approval records your reviewed execution scope; it does not sandbox external side effects."}))
    return 0


def _load_report(path: Path, output_dir: Path) -> dict[str, Any]:
    try:
        report = read_json(path)
        # Evidence is evaluated from this snapshot, not reread after a suite runs.
        try:
            artifact = Path(os.path.relpath(path, output_dir)).as_posix()
            html_path = path.with_suffix(".html")
            html_artifact = Path(os.path.relpath(html_path, output_dir)).as_posix() if html_path.is_file() else None
        except ValueError:
            artifact = None  # Windows paths on another drive have no relative URL.
            html_artifact = None
        return {"report": report, "report_sha256": sha256(report), "artifact": artifact, "html_artifact": html_artifact}
    except (RunnerError, OSError, ValueError):
        return {"error_code": "report_unavailable", "error": "The referenced local report is missing or is not a valid JSON report."}
