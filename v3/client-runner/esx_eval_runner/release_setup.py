"""Local application setup from existing plans; no adapters are executed.

The setup server owns routing and CSRF checks. Both JSON handlers raise
RunnerError for invalid requests; preview writes nothing, create writes only
release.json and setup-summary.json in a newly created directory.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import html
import json
import os
from pathlib import Path
import shlex
from threading import RLock

from .release import MANIFEST_SCHEMA, REVIEW_STATUSES, build_release_report, default_gates, validate_manifest
from .release_coverage import draft_requirements, plan_requirement_issues
from .release_execution import load_plan, plan_metadata, preflight_all_modules
from .runner import RunnerError, sha256


# load_plan temporarily changes cwd. Serialize requests from the threaded server.
_SETUP_LOCK = RLock()
_PROFILES = {"workflow": ["workflow"], "decision": ["decision"],
             "mixed": ["workflow", "decision"]}
_METRIC_PRESETS = [
    {"use_case": "UI workflow", "guidance": "Execution and visible assertion outcomes. Browser plans do not measure AI decision quality."},
    {"use_case": "Decision", "guidance": "Classification from labelled cases; confidence is optional and requires reviewed probability semantics for calibration gates."},
    {"use_case": "RAG / agent", "guidance": "Retrieval, grounding, tool use and trajectory need their configured evidence and evaluators. Judge-based metrics require a configured judge; if missing, review and configure one in the source plan. Setup adds no judge or metrics."},
]
_NOTICE = (
    "Setup reads existing local plans and creates no cases or expected labels. "
    "Draft objectives are not tests; review and bind actual cases and assertions. "
    "Browser workflows measure visible behavior, not AI decision quality. "
    "Manual review notes stay distinct from executable PRE-D evidence. "
    "Readiness does not establish complete business coverage or a passing release. "
    "Execution approval records your review; it does not sandbox external writes."
)


def _fields(value: object, allowed: set[str], label: str) -> dict:
    if not isinstance(value, dict) or any(key not in allowed for key in value):
        raise RunnerError(f"{label} must be an object with only supported fields")
    return value


def _text(value: object, label: str) -> str:
    if (not isinstance(value, str) or not value.strip() or len(value) > 500
            or any(ord(char) < 32 for char in value)):
        raise RunnerError(f"{label} must contain 1 to 500 characters without control characters")
    return value


def _local_path(value: object, label: str) -> Path:
    text = _text(value, label)
    if text.startswith(("\\\\", "//")) or "://" in text:
        raise RunnerError(f"{label} must be a local filesystem path, not a URL or network share")
    path = Path(text).expanduser()
    if path.is_symlink():
        raise RunnerError(f"{label} must not be a symbolic link")
    resolved = path.resolve()
    if str(resolved).startswith(("\\\\", "//")):
        raise RunnerError(f"{label} must resolve to a local filesystem path")
    return resolved


def _strings(value: object, label: str, limit: int = 100) -> list[str]:
    if (not isinstance(value, list) or len(value) > limit
            or any(not isinstance(item, str) for item in value)
            or len(set(value)) != len(value)):
        raise RunnerError(f"{label} must be a list of at most {limit} distinct strings")
    return list(value)


def _suite_id(module_id: str, kind: str, index: int) -> str:
    key = f"{module_id}-{kind}-{index}"
    if len(key) <= 80:
        return key
    suffix = f"-{sha256(module_id)[:12]}-{kind}-{index}"
    return module_id[:80 - len(suffix)] + suffix


def _review_method_id(module_id: str, index: int) -> str:
    key = f"{module_id}-review-{index}"
    if len(key) <= 80:
        return key
    suffix = f"-review-{index}"
    return module_id[:80 - len(suffix)] + suffix


def _review_methods(value: object, module_id: str) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 100:
        raise RunnerError("review_methods must be a list of at most 100 entries")
    methods = []
    for index, item in enumerate(value, 1):
        _fields(item, {"label", "status", "summary", "evidence_pointer"}, "Review method")
        label = item.get("label")
        status = item.get("status")
        summary = item.get("summary")
        pointer = item.get("evidence_pointer")
        if not any(isinstance(field, str) and field.strip() for field in (label, status, summary, pointer)):
            continue
        if status not in REVIEW_STATUSES:
            raise RunnerError("review_method.status must be evaluated, inspected, blocked, or untouched")
        method = {
            "id": _review_method_id(module_id, index),
            "label": _text(label, "review_method.label"),
            "status": status,
            "summary": _text(summary, "review_method.summary"),
        }
        if isinstance(pointer, str) and pointer.strip():
            method["evidence_pointer"] = _text(pointer, "review_method.evidence_pointer")
        methods.append(method)
    return methods


def _status_summary(status: str) -> str:
    return {
        "evaluated": "All declared executable suites completed with usable PRE-D evidence; check their quality verdict separately.",
        "inspected": "Only manual review activity is recorded for this module right now.",
        "blocked": "Executable PRE-D review is incomplete for this module right now.",
        "untouched": "No executable or manual review activity is recorded for this module yet.",
    }.get(status, "Review scope is not available.")


def _review_scope_preview(manifest: dict) -> dict:
    report = build_release_report(manifest, {}, now=datetime.now(timezone.utc))
    modules = []
    for module in report["modules"]:
        methods = module.get("review_methods", [])
        modules.append({
            "id": module["id"],
            "name": module["name"],
            "review_status": module["review_status"],
            "status_summary": _status_summary(module["review_status"]),
            "executable_methods": [
                {
                    "id": item["id"],
                    "label": item["label"],
                    "status": item["status"],
                    "summary": item["summary"],
                    "kind": item.get("kind"),
                    "suite_ids": item.get("suite_ids", []),
                }
                for item in methods if item.get("source") == "pre_d_executable_evidence"
            ],
            "manual_methods": [
                {
                    key: item[key]
                    for key in ("id", "label", "status", "summary", "evidence_pointer")
                    if key in item
                }
                for item in methods if item.get("source") == "reviewer_declared"
            ],
        })
    return {
        "summary": report["review_scope"],
        "modules": modules,
        "manifest_json": json.dumps(manifest, indent=2, allow_nan=False),
    }


def _plain_issue(issue: dict[str, object], scope: dict[str, dict[str, object]]) -> dict[str, object]:
    module_id = issue.get("module_id")
    module = scope.get(module_id) if isinstance(module_id, str) else None
    review_status = module.get("review_status") if isinstance(module, dict) else None
    code = issue.get("code")
    summary = str(issue.get("action", "Review this preflight gap."))
    if code == "inventory_unconfirmed":
        summary = "The full module inventory is not confirmed yet."
    elif code == "module_has_no_plans":
        summary = (
            "This module was inspected only; no executable PRE-D evidence is attached yet."
            if review_status == "inspected"
            else "No executable PRE-D plan is attached for this module yet."
        )
    elif code == "test_objectives_unconfirmed":
        summary = "This module has plans, but its reviewed objectives are not confirmed yet."
    elif code == "requirement_unbound":
        summary = "A reviewed objective still has no real case binding."
    elif code == "required_kind_missing":
        summary = "A required evaluation kind is still missing for this module."
    elif code == "required_kind_objective_missing":
        summary = "A required evaluation kind has no reviewed objective yet."
    elif code == "dependency_objective_missing":
        summary = "A declared dependency still lacks an executable integration objective."
    elif code == "report_reuse_not_execution":
        summary = "An existing report cannot stand in for fresh execution in an all-module run."
    elif code == "duplicate_plan":
        summary = "This plan is duplicated and cannot prove additional coverage."
    elif code == "execution_not_approved":
        summary = "This plan changed after review or has not been reapproved for execution."
    elif code == "invalid_plan":
        summary = "This attached plan cannot be validated for the declared release scope."
    elif code == "module_excluded":
        summary = "This module is excluded from all-module execution."
    elif code == "test_kinds_unconfirmed":
        summary = "The required PRE-D test kinds for this module are not confirmed yet."
    return {**issue, "summary": summary, "review_status": review_status,
            "module_name": module.get("name") if isinstance(module, dict) else None}


def _plain_advisory(advisory: dict[str, object], scope: dict[str, dict[str, object]]) -> dict[str, object]:
    module_id = advisory.get("module_id")
    module = scope.get(module_id) if isinstance(module_id, str) else None
    summary = str(advisory.get("summary", "Review this coverage advisory."))
    if advisory.get("code") == "baseline_dimension_unexercised":
        summary = "Baseline decision evidence is not requested by this plan yet."
    elif advisory.get("code") == "population_context_missing":
        summary = "This decision plan has no declared labelled-population context yet."
    elif advisory.get("code") == "workflow_route_only_signal":
        summary = "Some workflow cases rely only on route-level assertions."
    elif advisory.get("code") == "workflow_title_only_signal":
        summary = "Some workflow cases rely only on title-level assertions."
    elif advisory.get("code") == "workflow_element_state_signal":
        summary = "Some workflow cases check element state without requiring visible page content."
    elif advisory.get("code") == "workflow_final_signal_missing":
        summary = "Some workflow cases have no explicit check after the last navigation or interaction."
    return {
        **advisory,
        "summary": summary,
        "module_name": module.get("name") if isinstance(module, dict) else None,
    }


def _command(args: list[str], *, windows: bool) -> str:
    if windows:
        return "& " + " ".join("'" + arg.replace("'", "''") + "'" for arg in args)
    return shlex.join(args)


def _next_steps(directory: Path) -> list[dict]:
    manifest = str(directory / "release.json")
    report = directory / "release-review.json"
    steps = [
        ("Check local preflight; resolve every listed gap before running", False,
         ["release", "preflight", "--manifest", manifest, "--out", str(directory / "preflight.json")]),
        ("After preflight is ready, explicitly execute the approved plans", True,
         ["release", "run", "--manifest", manifest, "--out", str(report)]),
        ("After the run, open the local release report", False,
         ["view", "--report", str(report.with_suffix(".html"))]),
    ]
    return [{"description": description, "executes_plans": executes,
             "command": _command(["esx-eval", *args], windows=os.name == "nt")}
            for description, executes, args in steps]


def _prepare(values: dict) -> dict:
    _fields(values, {"application_id", "subject_version", "directory", "inventory_complete",
                     "modules", "confirm_plan", "host_os", "review_sha256"}, "Application setup")
    directory = _local_path(values.get("directory"), "directory")
    if directory.exists():
        raise RunnerError("Refusing an existing target folder or file; choose a new directory")
    raw_modules = values.get("modules")
    if not isinstance(raw_modules, list) or not 1 <= len(raw_modules) <= 1000:
        raise RunnerError("modules must contain 1 to 1000 modules")
    modules = []
    for raw in raw_modules:
        _fields(raw, {"id", "name", "owner", "profile", "personas", "depends_on", "plans",
                      "requirement_bindings", "review_methods"}, "Module")
        module_id = raw.get("id")
        if not isinstance(module_id, str):
            raise RunnerError("Module id must be a string")
        profile = raw.get("profile")
        if not isinstance(profile, str) or profile not in _PROFILES:
            raise RunnerError("Module profile must be workflow, decision, or mixed")
        personas = _strings(raw.get("personas", []), "personas")
        dependencies = _strings(raw.get("depends_on", []), "depends_on", 1000)
        modules.append({"id": module_id,
                        **{key: raw[key] for key in ("name", "owner") if key in raw},
                        "required": True, "required_kinds": _PROFILES[profile],
                        "depends_on": dependencies, "suites": [],
                        "test_requirements": draft_requirements(_PROFILES[profile], personas, dependencies),
                        **({"review_methods": _review_methods(raw.get("review_methods"), module_id)}
                           if raw.get("review_methods") is not None else {})})
    manifest = validate_manifest({
        "schema_version": MANIFEST_SCHEMA,
        "application": {"id": values.get("application_id"), "version": values.get("subject_version"),
                        "inventory_complete": values.get("inventory_complete", False)},
        "modules": modules,
    })
    plan_rows = {}
    plan_cases = {}
    for raw, module in zip(raw_modules, manifest["modules"]):
        plans = raw.get("plans", [])
        if not isinstance(plans, list) or len(plans) > 100:
            raise RunnerError("plans must be a list of at most 100 existing local plans")
        rows, cases_by_suite = [], {}
        plan_rows[module["id"]] = rows
        plan_cases[module["id"]] = cases_by_suite
        for index, plan in enumerate(plans, 1):
            _fields(plan, {"path", "mode", "isolation_note", "gates"}, "Plan")
            mode = plan.get("mode")
            if mode not in ("read_only", "isolated_write"):
                raise RunnerError("Review each plan and select read_only or isolated_write mode")
            policy = {"mode": mode}
            if mode == "isolated_write" or "isolation_note" in plan:
                policy["isolation_note"] = _text(plan.get("isolation_note"), "isolation_note")
            path = _local_path(plan.get("path"), "plan.path")
            try:
                evaluation, cases, adapter, digest = load_plan(path, manifest["application"])
            except (RunnerError, OSError, ValueError, TypeError, KeyError) as exc:
                # Validation errors can include config contents. Never echo them to the page.
                raise RunnerError(
                    f"Module {module['id']}, plan {index}: cannot validate this local plan. "
                    "Check the path, project_key, subject_version, adapter type and dataset. "
                    "Every workflow case needs an explicit success assertion; navigation alone is insufficient."
                ) from exc
            kind = "workflow" if adapter["type"] == "browser_journey" else "decision"
            metadata = plan_metadata(evaluation, cases, kind=kind)
            suite_id = _suite_id(module["id"], kind, index)
            policy["config_sha256"] = digest
            gates = plan.get("gates", default_gates(kind, metadata["required_dimensions"]))
            if not gates:
                raise RunnerError("Supply explicit reviewed gates for this plan's requested dimensions. Labels and confidence are not prerequisites for semantic-only evaluation.")
            module["suites"].append({"id": suite_id, "kind": kind, "config": str(path),
                                     "subject_id": evaluation["agent_id"], "execution_policy": policy, "gates": gates})
            cases_by_suite[suite_id] = cases
            rows.append({"suite_id": suite_id, "path": str(path), "kind": kind, "mode": mode,
                         "required_dimensions": deepcopy(metadata["required_dimensions"]),
                         **({"workflow_signal_strength": deepcopy(metadata["workflow_signal_strength"])}
                            if "workflow_signal_strength" in metadata else {}),
                         "cases": [{"case_id": case["case_id"],
                                    "persona": case.get("persona", "default" if kind == "workflow" else None),
                                    "expected_label": case.get("expected_label")} for case in cases]})
        bindings = raw.get("requirement_bindings", {})
        if not isinstance(bindings, dict):
            raise RunnerError("requirement_bindings must map objective IDs to reviewed bindings")
        objectives = {item["id"]: item for item in module["test_requirements"]}
        if any(key not in objectives for key in bindings):
            raise RunnerError("requirement_bindings contains an unknown objective ID")
        for key, reviewed in bindings.items():
            objectives[key]["bindings"] = deepcopy(reviewed)
    manifest = validate_manifest(manifest)
    for module in manifest["modules"]:
        invalid = [issue for issue in plan_requirement_issues(module, plan_cases[module["id"]])
                   if issue["code"] != "requirement_unbound"]
        if invalid:
            raise RunnerError(invalid[0]["code"] + ": " + invalid[0]["action"])
    preflight, _, _ = preflight_all_modules(manifest, directory / "release.json")
    if any(issue["code"] in ("invalid_plan", "execution_not_approved") for issue in preflight["issues"]):
        raise RunnerError("A plan changed during review or is no longer valid; preview the current plans again")
    review_scope = _review_scope_preview(manifest)
    scope_by_module = {item["id"]: item for item in review_scope["modules"]}
    preflight_display = {
        "status": preflight["status"],
        "notice": preflight["notice"],
        "issues": [_plain_issue(issue, scope_by_module) for issue in preflight["issues"]],
        "advisories": [_plain_advisory(item, scope_by_module) for item in preflight.get("advisories", [])],
    }
    return {
        "status": "preview", "directory": str(directory),
        "review_sha256": sha256({"directory": str(directory), "manifest": manifest,
                                  "cases": plan_cases}),
        "manifest_path": str(directory / "release.json"),
        "summary_path": str(directory / "setup-summary.json"), "manifest": manifest,
        "modules": [{"id": module["id"], "plans": plan_rows[module["id"]],
                     "objectives": module["test_requirements"]} for module in manifest["modules"]],
        "review_scope": review_scope,
        "preflight": preflight, "next_steps": _next_steps(directory),
        "preflight_display": preflight_display,
        "metric_presets": deepcopy(_METRIC_PRESETS),
        "shell": "PowerShell" if os.name == "nt" else "POSIX shell",
        "target_calls_made": False, "notice": _NOTICE,
    }


def preview_application(values: dict) -> dict:
    """Validate local inputs and return sanitized case choices and preflight gaps."""
    with _SETUP_LOCK:
        try:
            return _prepare(values)
        except (OSError, ValueError) as exc:
            raise RunnerError("Cannot read the local setup paths; check the directory and plan files") from exc


def create_application(values: dict) -> dict:
    """Revalidate explicit approval and bindings before exclusively creating files."""
    if not isinstance(values, dict) or values.get("confirm_plan") is not True:
        raise RunnerError("confirm_plan must be true after reviewing the plans and bindings")
    if values.get("inventory_complete") is not True:
        raise RunnerError("inventory_complete must be true before creating an application release")
    with _SETUP_LOCK:
        result = preview_application(values)
        if values.get("review_sha256") != result["review_sha256"]:
            raise RunnerError("Plans or reviewed bindings changed, or no preview was confirmed; preview and review them again before creating files")
        result["status"] = "created"
        artifacts = [(Path(result["manifest_path"]), result["manifest"]),
                     (Path(result["summary_path"]), result)]
        serialized = [(path, json.dumps(value, indent=2, allow_nan=False) + "\n")
                      for path, value in artifacts]
        try:
            Path(result["directory"]).mkdir(parents=True, exist_ok=False)
            for path, content in serialized:
                with path.open("x", encoding="utf-8") as stream:
                    stream.write(content)
        except OSError as exc:
            raise RunnerError(
                "Could not create the new release directory and both files. Nothing was overwritten "
                "or deleted; inspect any partial output and choose a new directory before retrying."
            ) from exc
        return result


def _script_json(value: str) -> str:
    return (json.dumps(value, ensure_ascii=True).replace("<", "\\u003c")
            .replace(">", "\\u003e").replace("&", "\\u0026"))


def application_setup_html(token: str, default_directory: str | None) -> str:
    """Three-step, dependency-free page for the existing CSRF-protected server."""
    directory = default_directory if default_directory is not None else str(Path.cwd() / "pred-application-release")
    # Split before substitution so user text resembling a template marker stays literal.
    parts = _PAGE.split("__SETUP_VALUE__")
    return parts[0] + html.escape(directory, quote=True) + parts[1] + _script_json(token) + parts[2]


_PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PRE-D Application Release Setup</title>
<style>
:root{color-scheme:light dark;--ink:#102c26;--paper:#f7f5ee;--field:#fffdf7;--muted:#52685e;--line:#a8bcb0;--coral:#ef7151;--forest:#216c4a;--tint:#e5eee5;--back:#f8f2e7}
*{box-sizing:border-box}body{margin:0;color:var(--ink);background:linear-gradient(125deg,var(--tint),var(--back));font:16px Georgia,serif;line-height:1.5}
main{max-width:1050px;margin:32px auto;padding:36px;background:var(--paper);border:1px solid var(--ink);box-shadow:8px 8px var(--forest)}
h1{font-size:48px;line-height:1;letter-spacing:-.045em;margin:12px 0}h1 em{color:var(--coral)}h2{font-size:26px;font-weight:400;margin:0 0 12px}h3{margin:0 0 10px}
.eyebrow,label,button{font-family:Consolas,monospace}.eyebrow{color:var(--forest);font-size:12px;letter-spacing:.12em}.lead{font-size:19px;color:var(--muted);max-width:760px}
section{border-top:1px solid var(--line);margin-top:28px;padding-top:24px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.module,.objective,details{border:1px solid var(--line);padding:18px;margin:18px 0;background:var(--field)}
label{display:block;font-size:12px;margin:12px 0 5px}input,select,textarea{display:block;width:100%;padding:10px;border:1px solid var(--line);background:var(--field);color:var(--ink);font:14px Consolas,monospace}textarea{min-height:80px;resize:vertical}
button{padding:10px 15px;margin:12px 8px 0 0;border:1px solid var(--ink);box-shadow:2px 2px var(--ink);background:var(--coral);color:#172c25;cursor:pointer;font-weight:bold}button.secondary{background:var(--tint);color:var(--ink)}button:disabled{opacity:.5;cursor:default}
a{color:var(--forest)}.note{border-left:4px solid var(--forest);padding:12px;background:var(--tint)}.small{font-size:14px;color:var(--muted)}.check{display:flex;gap:10px;align-items:start;font:16px Georgia,serif}.check input{width:auto;margin-top:5px}
.plan{border-top:1px dashed var(--line);margin-top:16px;padding-top:10px}.scope-grid,.issue-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.scope-card{border:1px solid var(--line);padding:12px;background:var(--tint)}.status-pill{display:inline-block;padding:2px 8px;border:1px solid var(--ink);font:12px Consolas,monospace;margin-bottom:10px}.status-pill.evaluated{border-color:var(--forest);color:var(--forest)}.status-pill.inspected{border-color:#8c6d1f;color:#8c6d1f}.status-pill.blocked{border-color:var(--coral);color:var(--coral)}.status-pill.untouched{border-color:var(--muted);color:var(--muted)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--tint);padding:16px;font:13px Consolas,monospace}summary{cursor:pointer}li{overflow-wrap:anywhere}input:focus-visible,select:focus-visible,textarea:focus-visible,button:focus-visible,a:focus-visible{outline:3px solid var(--coral);outline-offset:3px}
@media(prefers-color-scheme:dark){:root{--ink:#e6f0e9;--paper:#172a25;--field:#20362e;--muted:#b7c9bf;--line:#597669;--coral:#f3896c;--forest:#9accb0;--tint:#294437;--back:#0d1b17}}
@media(max-width:720px){main{margin:0;padding:22px;border:0;box-shadow:none}.grid{grid-template-columns:1fr}h1{font-size:38px}.module,.objective{padding:12px}}
</style></head><body><main>
<p class="eyebrow">PRE-D LOCAL / APPLICATION RELEASE / NO UPLOAD</p>
<h1>A release starts with<br><em>reviewed evidence.</em></h1>
<p class="lead">Bring existing PRE-D plans together, record manual review work, review module objectives, and connect them to actual cases. Setup only reads local files. It never calls your application.</p>
<p class="note">Need plans first? Use <a href="/">single-plan decision setup</a> or <a href="/browser">browser workflow setup</a>. Browser assertions measure visible behavior, not AI decision quality. Manual review notes stay visible, but never replace executable PRE-D evidence. No cases or expected labels are generated here.</p>
<section id="inventory"><h2>1. Application, modules &amp; existing plans</h2>
<div class="grid"><label>APPLICATION ID (plan project_key)<input id="application_id" maxlength="80" required></label>
<label>SUBJECT VERSION (exact plan version)<input id="subject_version" maxlength="500" required></label></div>
<label>NEW RELEASE DIRECTORY (must not exist)<input id="directory" value="__SETUP_VALUE__" maxlength="500" required></label>
<div id="modules"></div><button id="add_module" class="secondary" type="button">Add module</button>
<label class="check"><input id="inventory_complete" type="checkbox">I have listed all release-relevant modules and dependencies.</label>
<button id="preview" type="button">Preview objectives &amp; real cases</button></section>
<section><h2>2. Review scope, objectives &amp; bind cases</h2>
<p class="small">Draft objectives describe review work, not test coverage. Select existing cases and describe their actual assertion. A case may support multiple objectives only when you have reviewed that mapping. Manual review notes stay separate from executable PRE-D evidence.</p>
<details><summary>Metric presets: guidance for your use case</summary><p>Source plans retain their exact required_dimensions. Guidance below does not enable metrics or change plans.</p><div id="metric_presets"><p>Preview plans to see workflow, decision, and RAG / agent guidance.</p></div></details>
<div id="review_scope"><p>Preview the inventory to see the resulting review-scope matrix.</p></div>
<details><summary>Preview generated manifest JSON</summary><pre id="manifest_json">Preview the inventory to inspect the generated manifest.</pre></details>
<div id="objectives"><p>Preview the inventory to see available cases. No bindings are selected automatically.</p></div>
<button id="check_bindings" class="secondary" type="button" disabled>Check reviewed bindings</button>
<div id="preflight" role="status" aria-live="polite"></div></section>
<section><h2>3. Create the local release</h2>
<p>Writes release.json and setup-summary.json. Unbound objectives may be saved as drafts, but block execution. Review approval does not isolate external writes. Use only approved test environments.</p>
<label class="check"><input id="confirm_plan" type="checkbox">I reviewed these plans, their execution modes and isolation controls, and the selected cases and assertions.</label>
<button id="create" type="button" disabled>Create local release</button>
<p id="status" role="status" aria-live="polite">Preview first. No application code will be imported or executed by setup.</p>
<div id="result"></div></section></main>
<script>
'use strict';
const token=__SETUP_VALUE__;
const byId=id=>document.getElementById(id);
let preview=null,reviewSha=null,busy=false,created=false;
let moduleReaders=[],bindingReaders=[];
function node(tag,text,className){const item=document.createElement(tag);if(text!==undefined)item.textContent=text;if(className)item.className=className;return item;}
function field(parent,title,kind='input',choices=[]){const label=node('label',title),control=node(kind);if(kind==='select')choices.forEach(([value,text])=>{const option=node('option',text);option.value=value;control.append(option);});else control.maxLength=500;label.append(control);parent.append(label);return control;}
function button(parent,title,callback){const item=node('button',title,'secondary');item.type='button';item.addEventListener('click',callback);parent.append(item);return item;}
function split(value){return value.split(',').map(item=>item.trim()).filter(Boolean);}
function humanStatus(status){return status?status.replace(/_/g,' '):'unknown';}
function statusPill(status){const item=node('span',humanStatus(status),'status-pill '+status);return item;}
function invalidate(){preview=null;reviewSha=null;created=false;bindingReaders=[];byId('confirm_plan').checked=false;byId('objectives').replaceChildren(node('p','Inventory changed. Preview again to select cases.'));byId('review_scope').replaceChildren(node('p','Inventory changed. Preview again to inspect review scope.'));byId('manifest_json').textContent='Preview the inventory to inspect the generated manifest.';byId('preflight').replaceChildren();byId('result').replaceChildren();refresh();}
function refresh(){byId('create').disabled=busy||created||!preview||!reviewSha||!byId('confirm_plan').checked||!byId('inventory_complete').checked;byId('check_bindings').disabled=busy||created||!preview;byId('preview').disabled=busy||created;}
function addModule(){
  const card=node('div',undefined,'module'),grid=node('div',undefined,'grid');card.append(node('h3','Module'),grid);byId('modules').append(card);
  const id=field(grid,'MODULE ID'),name=field(grid,'NAME (optional)'),owner=field(grid,'OWNER (optional)');
  const profile=field(grid,'REQUIRED TEST TYPES','select',[['mixed','Workflow + decision'],['workflow','Workflow'],['decision','Decision']]);
  const personas=field(grid,'WORKFLOW PERSONA IDs (comma-separated)'),dependencies=field(grid,'DEPENDENCY MODULE IDs (comma-separated)');
  const plans=node('div');card.append(plans);let readers=[];
  function addPlan(){const row=node('div',undefined,'plan');plans.append(row);const path=field(row,'EXISTING LOCAL PLAN PATH');
    const mode=field(row,'REVIEWED EXECUTION MODE','select',[['','Select after review'],['read_only','Read only'],['isolated_write','Isolated writes']]);
    const note=field(row,'ISOLATION CONTROLS (required for writes; no secrets)');
    const read=()=>({path:path.value,mode:mode.value,...(note.value.trim()?{isolation_note:note.value}:{})});readers.push(read);
    button(row,'Remove plan',()=>{readers=readers.filter(item=>item!==read);row.remove();invalidate();});invalidate();}
  const reviewNotes=node('div');card.append(node('p','Manual review notes are optional. They stay visible in scope previews and reports, but never replace executable PRE-D evidence.','small'),reviewNotes);let reviewReaders=[];
  function addReview(saved){const row=node('div',undefined,'plan');reviewNotes.append(row);row.append(node('p','Manual review note','small'));
    const label=field(row,'REVIEW NOTE LABEL');
    const status=field(row,'REVIEW NOTE STATUS','select',[['','Select review state'],['evaluated','Evaluated'],['inspected','Inspected'],['blocked','Blocked'],['untouched','Untouched']]);
    const summary=field(row,'WHAT WAS REVIEWED','textarea');
    const pointer=field(row,'EVIDENCE POINTER (optional)');
    if(saved){label.value=saved.label||'';status.value=saved.status||'';summary.value=saved.summary||'';pointer.value=saved.evidence_pointer||'';}
    const read=()=>{const entry={label:label.value,status:status.value,summary:summary.value};const hasValue=[label.value,status.value,summary.value,pointer.value].some(value=>value.trim());if(!hasValue)return null;return pointer.value.trim()?{...entry,evidence_pointer:pointer.value}:entry;};reviewReaders.push(read);
    button(row,'Remove review note',()=>{reviewReaders=reviewReaders.filter(item=>item!==read);row.remove();invalidate();});}
  button(card,'Add existing plan',addPlan);
  button(card,'Add review note',()=>{addReview();invalidate();});
  const read=()=>({id:id.value,name:name.value||id.value,owner:owner.value||'Unassigned',profile:profile.value,personas:split(personas.value),depends_on:split(dependencies.value),plans:readers.map(item=>item()),review_methods:reviewReaders.map(item=>item()).filter(Boolean)});
  moduleReaders.push(read);button(card,'Remove module',()=>{moduleReaders=moduleReaders.filter(item=>item!==read);card.remove();invalidate();});invalidate();
}
function values(withBindings){const modules=moduleReaders.map(read=>read());if(withBindings)bindingReaders.forEach(read=>{const {moduleIndex,requirementId,bindings}=read();modules[moduleIndex].requirement_bindings??={};modules[moduleIndex].requirement_bindings[requirementId]=bindings;});return {application_id:byId('application_id').value,subject_version:byId('subject_version').value,directory:byId('directory').value,inventory_complete:byId('inventory_complete').checked,confirm_plan:byId('confirm_plan').checked,modules};}
function showScope(data){const holder=byId('review_scope');holder.replaceChildren();const scope=data.review_scope||{};const summary=scope.summary||{};const intro=node('div',undefined,'module');intro.append(node('h3','Resulting review scope'));intro.append(node('p',summary.notice||'Preview the review-scope outcomes before creating local files.'));const stats=node('div',undefined,'scope-grid');[['evaluated','Executed PRE-D evidence'],['inspected','Manual review only'],['blocked','Executable review incomplete'],['untouched','No review recorded']].forEach(([status,label])=>{const card=node('div',undefined,'scope-card');card.append(node('strong',String(summary[status]||0)));card.append(node('p',label));stats.append(card);});intro.append(stats);holder.append(intro);(scope.modules||[]).forEach(module=>{const card=node('div',undefined,'module');card.append(node('h3',module.name+' ('+module.id+')'));card.append(statusPill(module.review_status));card.append(node('p',module.status_summary));const exec=node('ul');(module.executable_methods||[]).forEach(method=>exec.append(node('li',method.label+': '+humanStatus(method.status)+'. '+method.summary)));card.append(node('p','Executable PRE-D methods','small'));card.append(exec.childNodes.length?exec:node('p','No executable PRE-D method is declared for this module.','small'));const manual=node('ul');(module.manual_methods||[]).forEach(method=>manual.append(node('li',method.label+': '+humanStatus(method.status)+'. '+method.summary+(method.evidence_pointer?' Evidence: '+method.evidence_pointer:''))));card.append(node('p','Manual review notes','small'));card.append(manual.childNodes.length?manual:node('p','No manual review notes recorded.','small'));holder.append(card);});}
function showManifest(data){byId('manifest_json').textContent=(data.review_scope&&data.review_scope.manifest_json)||'Preview the inventory to inspect the generated manifest.';}
function showObjectives(data){bindingReaders=[];const holder=byId('objectives');holder.replaceChildren();
  const guidance=byId('metric_presets');guidance.replaceChildren();data.metric_presets.forEach(preset=>guidance.append(node('p',preset.use_case+': '+preset.guidance)));
  data.modules.forEach((module,moduleIndex)=>{holder.append(node('h3',module.id));
    const details=node('details'),list=node('ul');details.append(node('summary','Available cases: ID / persona / expected label'),list);
    module.plans.forEach(plan=>{const notes=[];if(plan.kind==='decision'&&!(plan.required_dimensions||[]).includes('decision_evidence'))notes.push('baseline decision evidence not requested');if(plan.workflow_signal_strength){const strength=plan.workflow_signal_strength;notes.push('planned workflow checks: '+strength.content_signal_count+' content, '+strength.title_signal_only_count+' title-only, '+strength.route_signal_only_count+' route-only, '+(strength.element_state_only_count||0)+' element-state-only, '+(strength.no_explicit_signal_count||0)+' without a final assertion');}list.append(node('li',plan.suite_id+' ('+plan.kind+'); required_dimensions: '+(plan.required_dimensions?.join(', ')??'not declared; runner defaults apply')+(notes.length?'; '+notes.join(' | '):'')));plan.cases.forEach(item=>list.append(node('li',item.case_id+' / '+(item.persona??'not declared')+' / '+item.expected_label)));});holder.append(details);
    module.objectives.forEach(objective=>{const card=node('div',undefined,'objective');card.append(node('h3',objective.id),node('p',objective.description));
      if(objective.persona)card.append(node('p','Required persona: '+objective.persona,'small'));
      if(objective.dependency)card.append(node('p','Dependency: '+objective.dependency,'small'));
      let rows=[];
      function addBinding(saved){const row=node('div',undefined,'plan');card.append(row);const candidates=module.plans.filter(plan=>plan.kind===objective.kind);
        const suite=field(row,'SUITE','select',[['','Select a reviewed suite'],...candidates.map(plan=>[plan.suite_id,plan.suite_id])]);
        const cases=field(row,'CASE IDs (select one or more; Ctrl / Command for multiple)','select');cases.multiple=true;cases.size=5;
        const assertion=field(row,'DESCRIBE THE ACTUAL ASSERTION (no secrets)','textarea');
        function updateCases(){cases.replaceChildren();const plan=candidates.find(item=>item.suite_id===suite.value);(plan?.cases||[]).filter(item=>!objective.persona||item.persona===objective.persona).forEach(item=>{const option=node('option',item.case_id+' / '+(item.persona??'not declared')+' / '+item.expected_label);option.value=item.case_id;cases.append(option);});}
        suite.addEventListener('change',updateCases);
        if(saved){suite.value=saved.suite_id;updateCases();[...cases.options].forEach(option=>option.selected=saved.case_ids.includes(option.value));assertion.value=saved.assertion;}
        const read=()=>({suite_id:suite.value,case_ids:[...cases.selectedOptions].map(option=>option.value),assertion:assertion.value});rows.push(read);
        button(row,'Remove binding',()=>{rows=rows.filter(item=>item!==read);row.remove();bindingChanged();});}
      button(card,'Add reviewed case binding',()=>{addBinding();bindingChanged();});
      objective.bindings.forEach(addBinding);
      bindingReaders.push(()=>({moduleIndex,requirementId:objective.id,bindings:rows.map(read=>read())}));holder.append(card);
    });
  });
}
function showPreflight(data){const holder=byId('preflight');holder.replaceChildren();const display=data.preflight_display||{};holder.append(node('p','Preflight: '+(display.status||data.preflight.status)+'. No plans executed.','note'));if(display.notice)holder.append(node('p',display.notice,'small'));const issues=display.issues||[];const advisories=display.advisories||[];if(!issues.length)holder.append(node('p','All blocking setup checks are ready. The application still has not been called.'));issues.forEach(issue=>{const card=node('div',undefined,'objective');const title=[issue.module_name||issue.module_id||'Application inventory',issue.suite_id,issue.requirement_id].filter(Boolean).join(' / ');card.append(node('h3',title));if(issue.review_status)card.append(statusPill(issue.review_status));card.append(node('p',issue.summary||issue.action||'Review this preflight gap.'));card.append(node('p',issue.action||'','small'));card.append(node('p','Preflight code: '+issue.code,'small'));holder.append(card);});if(advisories.length){holder.append(node('p','Coverage advisories: these do not block execution, but they do explain where the current plan is weaker than the headline might suggest.','small'));advisories.forEach(issue=>{const card=node('div',undefined,'objective');const title=[issue.module_name||issue.module_id||'Application inventory',issue.suite_id].filter(Boolean).join(' / ');card.append(node('h3',title||'Coverage advisory'));card.append(node('p',issue.summary||issue.action||'Review this advisory.'));card.append(node('p',issue.action||'','small'));card.append(node('p','Advisory code: '+issue.code,'small'));holder.append(card);});}if(!issues.length&&!advisories.length)holder.append(node('p','No additional setup advisories were found.'));}
function bindingChanged(){reviewSha=null;byId('confirm_plan').checked=false;byId('preflight').replaceChildren(node('p','Bindings changed. Check reviewed bindings to refresh preflight.'));refresh();}
async function post(path,payload){const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-ESX-Setup-Token':token},body:JSON.stringify(payload)});const result=await response.json();if(!response.ok)throw Error(result.error||'Local setup request failed');return result;}
async function request(create,withBindings){
  if(busy)return;let payload;
  try{payload=values(withBindings);if(create)payload.review_sha256=reviewSha;}catch(error){byId('status').textContent=error.message;return;}
  busy=true;document.querySelectorAll('input,select,textarea,button').forEach(control=>control.disabled=true);byId('status').textContent=create?'Validating and creating local files...':'Reading local plans...';
  try{const data=await post(create?'/api/application/create':'/api/application/preview',payload);preview=data;reviewSha=data.review_sha256;showScope(data);showManifest(data);showPreflight(data);showObjectives(data);byId('confirm_plan').checked=false;
    if(create){created=true;byId('status').textContent='Local release created. No plans executed.';const result=byId('result');result.replaceChildren(node('p',data.manifest_path),node('p',data.summary_path),node('p',data.notice));result.append(node('p','Next steps ('+data.shell+'):'));data.next_steps.forEach(step=>result.append(node('p',step.description),node('pre',step.command)));}
    else{byId('result').replaceChildren();byId('status').textContent='Preview ready. Review the objectives, selected cases, and execution modes.';}
  }catch(error){preview=null;reviewSha=null;byId('confirm_plan').checked=false;byId('status').textContent=error.message;byId('review_scope').replaceChildren(node('p','Validation failed. Correct the request and preview again.'));byId('manifest_json').textContent='Preview the inventory to inspect the generated manifest.';byId('preflight').replaceChildren(node('p','Validation failed. Correct the request and preview again.'));}
  finally{busy=false;document.querySelectorAll('input,select,textarea,button').forEach(control=>control.disabled=created);refresh();}
}
byId('inventory').addEventListener('input',invalidate);byId('inventory').addEventListener('change',invalidate);
byId('objectives').addEventListener('input',bindingChanged);byId('objectives').addEventListener('change',bindingChanged);
byId('confirm_plan').addEventListener('change',refresh);byId('add_module').addEventListener('click',addModule);
byId('preview').addEventListener('click',()=>request(false,false));byId('check_bindings').addEventListener('click',()=>request(false,true));byId('create').addEventListener('click',()=>request(true,true));
addModule();
</script></body></html>'''
