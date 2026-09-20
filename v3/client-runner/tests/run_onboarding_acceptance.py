"""Retain real local execution artifacts for protected onboarding and comparisons."""

import argparse
from contextlib import redirect_stdout
from copy import deepcopy
import html
import io
import json
from pathlib import Path
from unittest.mock import patch

from esx_eval_runner.cli import main
from esx_eval_runner.audit import verify_audit_log
from esx_eval_runner.system_assistant import propose, apply_suggestions
from esx_eval_runner.system_changes import verify_report
from esx_eval_runner.system_cli import write_json
from esx_eval_runner.system_engine import approve_plan, execute_system, http_check, preflight, validate_plan
from esx_eval_runner.system_safety import snapshot_sources, source_diff
from esx_eval_runner.system_ui import render_report, STYLE
from test_system_onboarding import model_server
from test_system_evaluation import reference_app


def run(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=False)
    source, work = out / "reference-source", out / "profile"
    source.mkdir()
    work.mkdir()
    app = source / "app.py"
    app.write_text("@app.get('/ok')\ndef health(): return {'ready': True}\n", encoding="utf-8")
    before_source = snapshot_sources([source])
    assertions = []
    def expect(name, condition):
        assertions.append({"check": name, "passed": bool(condition)})

    with reference_app() as (url, state):
        path = work / "application-profile.json"
        with redirect_stdout(io.StringIO()):
            expect("CLI bootstraps a protected profile", main(["system", "bootstrap", "--project", "sample-app", "--version", "candidate-1", "--repo", str(source), "--base-url", url, "--out", str(path)]) == 0)
        plan = json.loads(path.read_text())
        component = plan["components"][0]["id"]
        with model_server([{"action": "inspect_components", "ids": [component]},
                           {"action": "propose", "suggestions": [{"component_id": component, "module": "health", "layer": "functional",
                                                                "title": "Health response contains ready=true", "reason": "Assert the response content, not only its HTTP status."}]}]) as (model_url, calls):
            proposal = propose(plan, model="scripted-acceptance-model", endpoint=model_url)
            expect("Bounded agent inspects then proposes", len(calls) == 2)
        write_json(out / "agent-proposal.json", proposal)
        accepted = apply_suggestions(plan, proposal, [proposal["suggestions"][0]["id"]])
        validate_plan(accepted, work)
        expect("Accepted suggestions do not enable tests", all(not c["enabled"] for c in accepted["checks"]))
        write_json(out / "review-draft.json", accepted)
        expect("Setup preserves reference source", source_diff(before_source, snapshot_sources([source]))["status"] == "unchanged")
        expect("Planning makes no application calls", state["calls"] == [])

        # This fixture tests selected checks, not a whole-system coverage claim.
        plan.pop("scope_contract")
        plan["inventory_confirmed"] = True
        plan["checks"][0].update(enabled=True, reviewed=True, expected_status=[200], json_assertions=[{"path": "ready", "equals": True}])
        write_json(path, plan, replace=True)
        with redirect_stdout(io.StringIO()):
            expect("Reviewed profile approved", main(["system", "approve", "--plan", str(path)]) == 0)
            expect("Healthy local execution succeeds", main(["system", "run", "--plan", str(path), "--out", str(out / "healthy")]) == 0)
        baseline = out / "healthy" / "system-report.json"
        state["ready"] = False
        with redirect_stdout(io.StringIO()):
            expect("Seeded regression makes CLI fail", main(["system", "run", "--plan", str(path), "--out", str(out / "regression"), "--baseline", str(baseline)]) == 2)
        regression = json.loads((out / "regression" / "system-report.json").read_text())
        verify_report(regression)
        expect("Comparison names one compatible regression", regression["changes"]["summary"]["regressions"] == 1)
        expect("Comparison has baseline evidence hash", regression["changes"]["baseline_report_sha256"] == json.loads(baseline.read_text())["report_sha256"])
        expect("Run source remained unchanged", regression["source_integrity"]["status"] == "unchanged")
        state["ready"] = True
        plan = json.loads(path.read_text())
        plan["checks"].append({**deepcopy(plan["checks"][0]), "id": "second-check"})
        approve_plan(plan, work)
        def mutate(*args):
            result = http_check(*args)
            app.write_text("# simulated concurrent editor change\n", encoding="utf-8")
            return result
        with patch("esx_eval_runner.system_engine.http_check", side_effect=mutate):
            changed = execute_system(plan, work, out / "source-change")
        write_json(out / "source-change" / "system-report.json", changed)
        (out / "source-change" / "system-report.html").write_text(render_report(changed), encoding="utf-8")
        expect("Source mutation stops remaining checks", changed["summary"]["checks_executed"] == 1)
        expect("Source mutation prevents release readiness", changed["verdict"] == "insufficient_evidence")
        expect("Source mutation retains changed file evidence", changed["source_integrity"]["files"][0]["path"] == "0/app.py")
        expect("Stale profile cannot dispatch", not preflight(plan, work)["ready"])
        expect("Profile audit chain verifies", verify_audit_log(path.with_suffix(".audit.jsonl"))["status"] == "valid")
        expect("Execution audit chain verifies", verify_audit_log(out / "source-change" / "audit.jsonl")["status"] == "valid")
    result = {"schema_version": "pre-d-onboarding-acceptance-1.0", "passed": all(a["passed"] for a in assertions),
              "assertions": assertions, "test_boundary": "Real local HTTP checks and scripted local planning transport; no customer app or real semantic model evaluated."}
    write_json(out / "acceptance.json", result)
    rows = "".join(f'<tr><td>{html.escape(a["check"])}</td><td>{"Passed" if a["passed"] else "Failed"}</td></tr>' for a in assertions)
    (out / "testing-readiness.html").write_text(
        f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PRE-D protected onboarding acceptance</title><style>{STYLE}</style><main><p class="eyebrow">PRE-D / LOCAL ACCEPTANCE</p><h1>Reusable setup.<br>Traceable changes.</h1><p>{sum(a["passed"] for a in assertions)} / {len(assertions)} acceptance checks passed.</p><p>{html.escape(result["test_boundary"])}</p><div class="grid"><a class="card" href="healthy/system-report.html"><h2>Healthy control</h2><p>Content assertion passes; source unchanged.</p></a><a class="card" href="regression/system-report.html"><h2>Seeded regression</h2><p>Same test detects a failing readiness signal.</p></a><a class="card" href="source-change/system-report.html"><h2>Source change</h2><p>Execution stops and records changed paths.</p></a></div><section><h2>Evidence retained</h2><p><a href="agent-proposal.json">Agent proposal</a> | <a href="review-draft.json">Reviewable profile</a> | <a href="acceptance.json">Acceptance assertions</a></p><div class="scroll"><table><tr><th>Requirement</th><th>Result</th></tr>{rows}</table></div></section><p>Controlled testing is ready. A production application still needs its approved scope, expected behaviors, identities and evidence. External commands remain blocked by protected profiles until separately isolated.</p></main></html>',
        encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.out.resolve())
    print(json.dumps({"passed": result["passed"], "assertions": len(result["assertions"]), "report": str(args.out / "testing-readiness.html")}))
    raise SystemExit(0 if result["passed"] else 1)
