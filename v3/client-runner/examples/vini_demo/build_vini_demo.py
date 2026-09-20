"""Build a reviewed PRE-D demo workspace for a local VINI evaluation.

This example keeps VINI-specific naming in the generated profile, not in PRE-D
core logic. It does not modify the target repository.
"""

from __future__ import annotations

import argparse
from collections import Counter
from html import escape
import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from esx_eval_runner.runner import RunnerError
from esx_eval_runner.system_cli import bind_evaluation, write_json
from esx_eval_runner.system_engine import validate_plan
from esx_eval_runner.system_profile import bootstrap
from esx_eval_runner.system_safety import command_sha256
from esx_eval_runner.system_scope import draft_scope
from esx_eval_runner.system_inventory import document


MODULES = [
    ("vini-backend-suite", "Backend pytest suite", "Quality foundation", "test_suite", ["code"]),
    ("vini-core-workflows", "Core browser workflows", "Core analyst workflow", "workflow", ["workflow"]),
    ("vini-investigation-disposition", "Investigation disposition", "AI decision quality", "ai_decision", ["ai"]),
    ("vini-dlp-decisions", "DLP decisions", "AI decision quality", "ai_decision", ["ai"]),
    ("vini-governance-decisions", "Governance decisions", "Governance", "ai_decision", ["ai", "authorization"]),
    ("vini-correlation-quality", "Correlation quality", "Correlation", "ai_decision", ["ai", "integration"]),
    ("vini-threat-hunt", "Threat hunt conclusions", "Threat operations", "ai_decision", ["ai", "workflow"]),
    ("vini-detection-engineering", "Detection engineering", "Threat operations", "ai_decision", ["ai", "integration"]),
    ("vini-knowledge-retrieval", "Knowledge retrieval", "Knowledge", "retrieval", ["ai", "integration"]),
    ("vini-response-planner", "Response planner", "Automation", "ai_decision", ["ai", "authorization"]),
    ("vini-slm-benchmark", "SLM benchmark", "Model governance", "ai_decision", ["ai"]),
]


def command_paths(value: object, prefix: str = "") -> list[tuple[str, list[str]]]:
    rows = []
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else key
            if key in {"command", "inject_command", "recover_command"} and isinstance(item, list):
                rows.append((path, item))
            else:
                rows.extend(command_paths(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            rows.extend(command_paths(item, f"{prefix}.{index}" if prefix else str(index)))
    return rows


def ensure_component(plan: dict, component_id: str, name: str, module: str, kind: str, layers: list[str]) -> None:
    if any(c["id"] == component_id for c in plan["components"]):
        return
    plan["components"].append({
        "id": component_id,
        "name": name,
        "module": module,
        "kind": kind,
        "path": "",
        "method": "",
        "state": "owner_declared",
        "enabled": "unknown",
        "required_layers": layers,
        "suggested_layers": layers,
        "depends_on": [],
        "evidence": [{"source": "vini-demo-intake", "basis": "owner_declared_module"}],
    })


def trust_command(plan: dict, check_id: str, field: str, argv: list[str], reason: str) -> None:
    policy = plan.setdefault("trusted_command_policy", {
        "schema_version": "pre-d-trusted-local-commands-1.0",
        "reviewed": True,
        "entries": [],
    })
    entry = {"check_id": check_id, "field": field, "argv_sha256": command_sha256(argv), "reason": reason}
    if entry not in policy["entries"]:
        policy["entries"].append(entry)


def gates_for(config: dict) -> list[dict]:
    if config.get("adapter", {}).get("type") == "browser_journey":
        return [
            {"signal": "workflow_coverage.workflow_execution_rate", "operator": "gte", "threshold": 1.0},
            {"signal": "workflow_coverage.workflow_signal_match_rate", "operator": "gte", "threshold": 1.0},
        ]
    gates = []
    for dimension in config.get("evaluation", {}).get("required_dimensions", []):
        if dimension == "classification":
            gates.extend([
                {"signal": "classification.accuracy", "operator": "gte", "threshold": 0.95},
                {"signal": "classification.macro_f1", "operator": "gte", "threshold": 0.90},
            ])
        elif dimension == "confidence":
            gates.append({"signal": "confidence.expected_calibration_error", "operator": "lte", "threshold": 0.15})
        elif dimension == "decision_evidence":
            gates.append({"signal": "decision_evidence.correct_abstention_rate", "operator": "gte", "threshold": 0.95})
        elif dimension == "groundedness":
            gates.extend([
                {"signal": "groundedness.grounded_claim_rate", "operator": "gte", "threshold": 0.95},
                {"signal": "groundedness.contradiction_rate", "operator": "lte", "threshold": 0.0},
            ])
        elif dimension == "hallucination":
            gates.extend([
                {"signal": "hallucination.hallucination_free_response_rate", "operator": "gte", "threshold": 0.95},
                {"signal": "hallucination.false_answer_rate", "operator": "lte", "threshold": 0.05},
            ])
    return gates


def attach_eval(plan: dict, root: Path, config: Path, component: str, check_id: str, *, enable: bool) -> None:
    before = len(plan["checks"])
    data = document(config)
    bind_evaluation(plan, root, config_path=config, components=[component], check_id=check_id, gates=gates_for(data))
    check = plan["checks"][before]
    if enable:
        check.update(enabled=True, reviewed=True)
    for field, argv in command_paths(data):
        trust_command(plan, check_id, field, argv, "Approved local adapter or judge command for the VINI demo workspace.")


def add_backend_check(plan: dict, spec: Path, *, enable: bool) -> None:
    data = document(spec)
    command = data.get("command")
    if not isinstance(command, list) or not command:
        raise RunnerError("Backend command spec needs a command argv array")
    check = {
        "id": data.get("id", "vini-backend-pytest"),
        "type": "command",
        "layer": "code",
        "component_ids": ["vini-backend-suite"],
        "enabled": enable,
        "reviewed": enable,
        "command": command,
        "cwd": data.get("cwd", "."),
        "result_file": data.get("result_file", "pred-backend-tests.xml"),
        "format": "junit",
        "timeout_seconds": data.get("timeout_seconds", 600),
        "authoring_note": "Application-provided backend suite command. Skipped tests remain blocked evidence.",
    }
    plan["checks"].append(check)
    trust_command(plan, check["id"], "command", command, "Approved backend test runner for the VINI demo workspace.")


def add_build_check(plan: dict, manifest_sha256: str) -> None:
    check = {
        "id": "vini-running-build-identity",
        "type": "http",
        "layer": "functional",
        "component_ids": ["vini-core-workflows"],
        "enabled": True,
        "reviewed": True,
        "method": "GET",
        "path": "/health",
        "role": "anonymous",
        "expected_status": [200],
        "headers_from_env": {},
        "json_assertions": [{"path": "manifest_sha256", "equals": manifest_sha256}],
        "timeout_seconds": 15,
        "authoring_note": "Bind the running service to the reviewed candidate manifest hash.",
    }
    plan["checks"].append(check)
    plan.setdefault("scope_contract", {})["build"] = {
        "check_id": check["id"],
        "assertion_path": "manifest_sha256",
        "expected_value": manifest_sha256,
    }


def write_runbook(out: Path, plan_name: str) -> None:
    (out / "RUNBOOK.md").write_text(f"""# VINI PRE-D Demo Runbook

This workspace is VINI-specific demo configuration generated outside the VINI
repository. PRE-D core remains application-neutral.

## Run

```text
esx-eval system preflight --plan ./{plan_name}
esx-eval system approve --plan ./{plan_name}
esx-eval system run --plan ./{plan_name} --out ./runs/candidate-001 --history ./pred-history.sqlite
```

Use `--require-whole-system` only after the remaining generated objectives are
reviewed and bound. Without that, the report should honestly show
`insufficient_evidence` for untouched modules.

## Demo Talking Points

- Discovery inventories the broad application surface without modifying source.
- Bound checks produce real evidence: backend tests, browser workflows, decision
  packs and running-build identity when supplied.
- Untouched modules remain visible gaps, not hidden passes.
- Protected source mode can now run exact reviewed local commands by argv hash.
- The report separates application failures from PRE-D gaps and adapter failures.
""", encoding="utf-8")


def _rows(items: list[tuple[str, int]]) -> str:
    if not items:
        return "<tr><td>None</td><td>0</td></tr>"
    return "\n".join(f"<tr><td>{escape(str(name))}</td><td>{count}</td></tr>" for name, count in items)


def _summarize_plan(plan: dict) -> dict:
    components = plan.get("components", [])
    checks = plan.get("checks", [])
    enabled = [check for check in checks if check.get("enabled") is True]
    return {
        "artifact": "pre-d-source-readiness-1.0",
        "project_id": plan.get("project_id"),
        "application_version": plan.get("application_version"),
        "target_calls_made": False,
        "source_modified": False,
        "status": "source_inventory_ready" if components else "source_inventory_missing",
        "execution_ready": bool(enabled),
        "message": (
            "PRE-D built a source-first whole-system plan. Live scoring still "
            "requires reviewed, enabled evidence checks."
        ),
        "counts": {
            "components": len(components),
            "drafted_checks": len(checks),
            "enabled_checks": len(enabled),
            "roles": len(plan.get("roles", [])),
        },
        "component_kinds": Counter(c.get("kind", "unknown") for c in components).most_common(),
        "modules": Counter(c.get("module", "unknown") for c in components).most_common(),
        "check_types": Counter(c.get("type", "unknown") for c in checks).most_common(),
        "check_layers": Counter(c.get("layer", "unknown") for c in checks).most_common(),
        "required_inputs_to_execute": [
            "Approve inventory and behavior expectations.",
            "Bind runtime identity/build check from /health manifest_sha256.",
            "Attach browser workflows with stable content assertions for critical pages.",
            "Attach decision-evaluation packs for AI decision modules.",
            "Attach backend/security suites through reviewed JUnit command checks.",
            "Provide role identity environment variables for admin, soc_lead, analyst, read_only and anonymous policy checks.",
        ],
        "limitations": [
            "This source-readiness artifact is not a live evaluation result.",
            "No application endpoint, database, browser flow or decision adapter was called.",
            "Drafted checks are not coverage until reviewed, enabled and executed.",
        ],
    }


def write_source_readiness(out: Path, plan: dict) -> None:
    summary = _summarize_plan(plan)
    (out / "source-readiness.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    counts = summary["counts"]
    html = f"""<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PRE-D Source Readiness</title>
<style>
body{{margin:0;background:#0d1414;color:#f3efe6;font:16px Georgia,serif}}
main{{max-width:1120px;margin:0 auto;padding:42px 24px 72px}}
.eyebrow{{font:700 12px ui-monospace,monospace;letter-spacing:.18em;color:#ff8061;text-transform:uppercase}}
h1{{font-size:56px;line-height:.95;margin:12px 0 18px;max-width:900px}}
h2{{font-size:28px;margin:0 0 12px}}
p{{color:#cfdbd7;line-height:1.55}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:28px 0}}
.card,section{{background:#142020;border:1px solid #344846;border-radius:16px;padding:22px}}
.card b{{display:block;font-size:34px;color:#c9f77b}}
.warn{{border-color:#ff8061;background:#221a17}}
table{{width:100%;border-collapse:collapse;margin-top:12px}}
td,th{{border-top:1px solid #344846;padding:10px;text-align:left}}
th{{color:#c9f77b;font:700 12px ui-monospace,monospace;letter-spacing:.12em;text-transform:uppercase}}
ul{{padding-left:20px;color:#cfdbd7}}
.split{{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:18px}}
@media(max-width:800px){{h1{{font-size:40px}}.grid,.split{{grid-template-columns:1fr}}}}
</style>
<main>
  <p class="eyebrow">PRE-D Source Readiness / no target calls</p>
  <h1>Whole-system inventory is drafted. Live evidence is still required.</h1>
  <p>{escape(summary["message"])}</p>
  <div class="grid">
    <div class="card"><span>Components</span><b>{counts["components"]}</b></div>
    <div class="card"><span>Drafted Checks</span><b>{counts["drafted_checks"]}</b></div>
    <div class="card warn"><span>Enabled Checks</span><b>{counts["enabled_checks"]}</b></div>
    <div class="card"><span>Roles</span><b>{counts["roles"]}</b></div>
  </div>
  <section class="warn">
    <h2>What this means</h2>
    <p>This artifact proves PRE-D can read the supplied source snapshot and draft a broad evaluation surface. It does not claim the application passed or failed, because no live checks were enabled from this zip alone.</p>
  </section>
  <div class="split">
    <section><h2>Component Kinds</h2><table><tr><th>Kind</th><th>Count</th></tr>{_rows(summary["component_kinds"])}</table></section>
    <section><h2>Check Layers</h2><table><tr><th>Layer</th><th>Count</th></tr>{_rows(summary["check_layers"])}</table></section>
  </div>
  <section><h2>Top Modules</h2><table><tr><th>Module</th><th>Components</th></tr>{_rows(summary["modules"][:30])}</table></section>
  <div class="split">
    <section><h2>To Execute Next</h2><ul>{"".join(f"<li>{escape(item)}</li>" for item in summary["required_inputs_to_execute"])}</ul></section>
    <section><h2>Limitations</h2><ul>{"".join(f"<li>{escape(item)}</li>" for item in summary["limitations"])}</ul></section>
  </div>
</main>
</html>
"""
    (out / "source-readiness.html").write_text(html, encoding="utf-8")


def build(args: argparse.Namespace) -> dict:
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    plan_path = out / "vini-system-plan.json"
    if plan_path.exists() and not args.replace:
        raise RunnerError("vini-system-plan.json already exists; use --replace or choose a new --out")
    plan = bootstrap(project=args.project, version=args.version, repository=args.repo, openapi=args.openapi,
                     base_url=args.base_url, roles=args.role, max_files=args.max_files)
    for row in MODULES:
        ensure_component(plan, *row)
    if args.confirm_inventory:
        plan["inventory_confirmed"] = True
    for spec in args.backend_command or []:
        add_backend_check(plan, Path(spec).resolve(), enable=not args.draft_only)
    for item in args.browser_config or []:
        attach_eval(plan, out, Path(item).resolve(), "vini-core-workflows", "vini-core-browser-workflows", enable=not args.draft_only)
    for item in args.disposition_config or []:
        attach_eval(plan, out, Path(item).resolve(), "vini-investigation-disposition", "vini-investigation-disposition", enable=not args.draft_only)
    for item in args.dlp_config or []:
        attach_eval(plan, out, Path(item).resolve(), "vini-dlp-decisions", "vini-dlp-decisions", enable=not args.draft_only)
    if args.manifest_sha256:
        add_build_check(plan, args.manifest_sha256)
    plan["scope_contract"] = draft_scope(plan)
    if args.manifest_sha256:
        plan["scope_contract"]["build"] = {
            "check_id": "vini-running-build-identity",
            "assertion_path": "manifest_sha256",
            "expected_value": args.manifest_sha256,
        }
    validate_plan(plan, out)
    write_json(plan_path, plan, replace=args.replace)
    write_runbook(out, plan_path.name)
    write_source_readiness(out, plan)
    return {"plan": str(plan_path), "components": len(plan["components"]), "checks": len(plan["checks"]),
            "enabled_checks": sum(c.get("enabled") is True for c in plan["checks"]),
            "trusted_command_entries": len(plan.get("trusted_command_policy", {}).get("entries", [])),
            "source_readiness": str(out / "source-readiness.html")}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="Local VINI repository path; never modified by this script")
    parser.add_argument(
        "--openapi",
        help=(
            "Optional local OpenAPI JSON export. Supply it when a running app can "
            "export /api/openapi.json; otherwise PRE-D still inventories the repo."
        ),
    )
    parser.add_argument("--base-url", required=True, help="Local/staging VINI origin, for example http://localhost")
    parser.add_argument("--version", required=True, help="Candidate version or manifest identity")
    parser.add_argument("--project", default="vini-demo")
    parser.add_argument("--role", action="append", default=["admin", "soc_lead", "analyst", "read_only"])
    parser.add_argument("--max-files", type=int, default=5000)
    parser.add_argument("--out", required=True)
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--confirm-inventory", action="store_true", help="Only use after the owner reviews discovered and declared modules")
    parser.add_argument("--draft-only", action="store_true", help="Attach configs as disabled drafts instead of enabling them")
    parser.add_argument("--backend-command", action="append", help="JSON file with command/cwd/result_file for backend JUnit ingestion")
    parser.add_argument("--browser-config", action="append", help="Existing PRE-D browser evaluation config")
    parser.add_argument("--disposition-config", action="append", help="Existing PRE-D disposition/decision config")
    parser.add_argument("--dlp-config", action="append", help="Existing PRE-D DLP decision config")
    parser.add_argument("--manifest-sha256", help="Expected GET /health manifest_sha256 value")
    print(json.dumps(build(parser.parse_args()), indent=2))


if __name__ == "__main__":
    main()
