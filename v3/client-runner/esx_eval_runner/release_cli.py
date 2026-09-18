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
from .release import MANIFEST_SCHEMA, build_release_report, validate_manifest
from .release_comparison import validate_baseline
from .release_html import render_release_report
from .runner import RunnerError, _validate_config, read_json, sha256


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def register_release_commands(commands: Any) -> None:
    release = commands.add_parser("release", help="Evaluate an application release using existing local PRE-D plans")
    actions = release.add_subparsers(dest="release_action", required=True)
    init = actions.add_parser("init", help="Create a module inventory for a local release review")
    init.add_argument("--application-id", required=True, help="Must match evaluation.project_key in the plans")
    init.add_argument("--subject-version", required=True)
    init.add_argument("--module", action="append", required=True, help="Module ID; repeat for each application module")
    init.add_argument("--out", required=True)
    check = actions.add_parser("check", help="Assess local reports against the declared release policy")
    check.add_argument("--manifest", required=True)
    check.add_argument("--out", required=True, help="Local release JSON path; also writes an HTML report")
    check.add_argument("--run", action="store_true", help="Execute the config-backed plans sequentially before assessment")
    check.add_argument("--require-ship", action="store_true", help="Exit 2 unless the recommendation is Ship")
    check.add_argument("--baseline", help="Compare against a previous local release-review JSON; does not execute that release")


def release_command(args: argparse.Namespace) -> int:
    try:
        return _release_command(args)
    except RunnerError:
        raise
    except (OSError, ValueError) as exc:
        raise RunnerError("The local release review could not read or write its artifacts. Check the paths and local audit log before retrying.") from exc


def _release_command(args: argparse.Namespace) -> int:
    if args.release_action == "init":
        target = Path(args.out).resolve()
        if target.exists():
            raise RunnerError(f"Refusing to overwrite existing release manifest: {target}")
        manifest = validate_manifest({
            "schema_version": MANIFEST_SCHEMA,
            "application": {"id": args.application_id, "version": args.subject_version, "inventory_complete": False},
            "modules": [{"id": item, "required": True, "suites": []} for item in args.module],
        })
        _write(target, manifest)
        print(json.dumps({"manifest": str(target), "next_step": "Add existing evaluation plans to each module and review the release thresholds."}))
        return 0

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
    if getattr(args, "baseline", None):
        baseline_path = Path(args.baseline).resolve()
        baseline = read_json(baseline_path)
        validate_baseline(baseline, manifest["application"]["id"], datetime.now(timezone.utc))
        sources.update({baseline_path, baseline_path.with_suffix(".html")})
    # Resolve and validate every plan before running any target. Paths in a
    # plan keep their established meaning relative to that plan's directory.
    for module in manifest["modules"]:
        for suite in module["suites"]:
            key = "config" if "config" in suite else "report"
            path = (manifest_path.parent / suite[key]).resolve()
            sources.add(path)
            if key == "report":
                sources.add(path.with_suffix(".html"))
                evidence[suite["id"]] = _load_report(path, out.parent)
                continue
            if not args.run:
                evidence[suite["id"]] = {"error_code": "run_not_requested", "error": "This suite references a plan which has not been executed for this release review. Use --run or supply its completed report."}
                continue
            try:
                config = read_json(path)
                with chdir(path.parent):
                    evaluation, _, adapter = _validate_config(config)
                if (evaluation.get("project_key") != manifest["application"]["id"]
                        or evaluation.get("subject_version") != manifest["application"]["version"]
                        or evaluation.get("agent_id") != suite["subject_id"]
                        or (adapter["type"] == "browser_journey") != (suite["kind"] == "workflow")):
                    raise RunnerError("Plan identity does not match release scope")
                prepared[suite["id"]] = (path, sha256(config))
            except (RunnerError, OSError, ValueError):
                evidence[suite["id"]] = {"error_code": "invalid_plan", "error": "The evaluation plan is invalid or its project, subject, version, or type does not match this release suite. Review the plan with esx-eval evidence-check."}
    if {out, html, audit} & sources:
        raise RunnerError("Release output paths must not overwrite the manifest, an evaluation plan, or an input report")
    out.parent.mkdir(parents=True, exist_ok=True)
    append_audit_event(audit, "release_review_started", {"manifest_sha256": sha256(manifest), "execute_plans": args.run,
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
                run_command(run_args)
            item = _load_report(package.with_name("evaluation.local-report.json"), out.parent)
            if isinstance(item.get("report"), dict) and item["report"].get("run_provenance", {}).get("config_sha256") != digest:
                raise RunnerError("Run configuration differs from validated plan")
            evidence[suite_id] = item
            append_audit_event(audit, "release_suite_completed", {"suite_id": suite_id, "report_sha256": item.get("report_sha256")})
        except (RunnerError, OSError, ValueError):
            diagnostic_dir = Path(os.path.relpath(package.parent, out.parent)).as_posix()
            evidence[suite_id] = {"error_code": "suite_execution_failed", "error": f"The suite did not produce a usable completed report. Review its local evaluation audit/debug artifacts under {diagnostic_dir} and rerun the plan."}
            append_audit_event(audit, "release_suite_failed", {"suite_id": suite_id})
    report = build_release_report(manifest, evidence, baseline=baseline)
    if baseline_path and report["comparison"]:
        try:
            report["comparison"]["artifact"] = Path(os.path.relpath(baseline_path, out.parent)).as_posix()
        except ValueError:
            report["comparison"]["artifact"] = None
    _write(out, report)
    html.write_text(render_release_report(report), encoding="utf-8")
    append_audit_event(audit, "release_review_completed", {"manifest_sha256": report["manifest_sha256"], "report_sha256": sha256(report), "verdict": report["verdict"]})
    print(json.dumps({"report": str(out), "html_report": str(html), "audit_log": str(audit),
                      "verdict": report["verdict"], "summary": report["summary"], "uploaded": False}))
    return 2 if args.require_ship and report["verdict"] != "ship" else 0


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
