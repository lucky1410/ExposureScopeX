"""Behavior-level whole-system acceptance on an isolated ten-module application."""

from collections import Counter
from copy import deepcopy
from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from esx_eval_runner.cli import main
from esx_eval_runner.runner import RunnerError, sha256
from esx_eval_runner.system_cli import bind_evaluation, write_json
from esx_eval_runner.system_engine import approve_plan, command_check, execute_system, preflight, validate_plan
from esx_eval_runner.system_scope import assess_scope, draft_scope
from esx_eval_runner.system_history import record_run, trend
from esx_eval_runner.system_ui import render_report, SETUP_SCRIPT
from test_system_acceptance import fixture, FIXTURE
from test_system_evaluation import basic_plan, decision_config


ROLES = ["read_only", "analyst", "soc_lead", "admin"]
IDENTITIES = {"PRED_REF_" + role.upper(): role for role in ROLES}
IDENTITIES.update(PRED_REF_TENANT_A="a", PRED_REF_TENANT_B="b")


def whole_plan(root, app):
    plan = basic_plan(app.url)
    plan.update(roles=ROLES, isolation_note="Disposable loopback reference app; synthetic SQLite data and no external integrations.")
    plan["components"] = [
        {"id": name, "name": name.title(), "module": name, "kind": kind, "enabled": True,
         "required_layers": layers, "depends_on": [], "evidence": []}
        for name, kind, layers in [
            ("runtime", "api", ["functional"]), ("triage", "ai_candidate", ["ai"]),
            ("ledger", "service", ["code", "integration"]), ("records", "api", ["authorization"]),
            ("admin", "api", ["authorization"]), ("tenants", "api", ["security"]),
            ("agent", "service", ["security"]), ("queue", "service", ["reliability"]),
            ("worker", "worker", ["reliability"]), ("throughput", "service", ["reliability"]),
        ]]
    plan["checks"] = []
    objectives = []

    def add(check, title, *, case_ids=None):
        check.update(enabled=True, reviewed=True)
        if check["type"] in {"http", "load", "recovery"}:
            check.setdefault("role", "admin")
            check.setdefault("method", "GET")
            check.setdefault("expected_status", [200])
            check.setdefault("headers_from_env", {"Authorization": "PRED_REF_" + check["role"].upper()})
        plan["checks"].append(check)
        objectives.append({"id": "objective-" + check["id"], "title": title,
                           "component_id": check["component_ids"][0], "layer": check["layer"],
                           "role": check.get("role") if check["layer"] == "authorization" else None,
                           "reviewed": True, "check_id": check["id"], "case_ids": case_ids or [],
                           "assertion_paths": [a["path"] for a in check.get("json_assertions", [])]})

    add({"id": "candidate", "type": "http", "layer": "functional", "component_ids": ["runtime"],
         "path": "/build", "json_assertions": [{"path": "build_id", "equals": app.build_id}]},
        "Running candidate matches the reviewed reference source digest")
    config = decision_config(["classification", "confidence", "decision_evidence"], confidence=True)
    config["dataset"]["cases"] = [{"case_id": f"risk-{i}", "input": {"risk": bool(i % 2)},
                                    "expected_label": "escalate" if i % 2 else "hold", "must_abstain": False,
                                    "expected_evidence_ids": ["risk-evidence"] if i % 2 else []} for i in range(6)]
    config["adapter"]["command"] = [sys.executable, str(FIXTURE), "adapter", app.url]
    write_json(root / "decisions.json", config)
    bind_evaluation(plan, root, config_path=root / "decisions.json", components=["triage"], check_id="triage")
    check = plan["checks"].pop()
    check["gates"].append({"signal": "decision_evidence.correct_abstention_rate", "operator": "gte", "threshold": 1})
    add(check, "Risk decisions match independent labels and do not abstain on sufficient evidence",
        case_ids=[c["case_id"] for c in config["dataset"]["cases"]])
    for name, module, layer, cases in [
        ("contract", "ledger", "code", ["Contract.test_content_not_status_only", "Contract.test_dependency_contract"]),
        ("security", "agent", "security", ["AgentBoundary.test_attack_blocks_private_tool", "AgentBoundary.test_benign_tool_still_executes"]),
    ]:
        add({"id": name, "type": "command", "layer": layer, "component_ids": [module],
             "command": [sys.executable, str(FIXTURE), name, app.url, str(root / (name + ".xml"))],
             "result_file": name + ".xml", "format": "junit"},
            "Contract content and dependency consistency" if name == "contract" else "Adversarial tool request denied while benign lookup works",
            case_ids=["__main__.contract_suite.<locals>." + c for c in cases])
    add({"id": "ledger-integration", "type": "http", "layer": "integration", "component_ids": ["ledger"],
         "path": "/contract", "json_assertions": [{"path": "amount", "equals": 10}, {"path": "dependency", "equals": "ledger"}]},
        "Ledger contract returns the expected amount from its dependency")
    for module in ("records", "admin"):
        for role in ROLES:
            allowed = module == "records" or role == "admin"
            add({"id": module + "-" + role, "type": "http", "layer": "authorization", "role": role,
                 "component_ids": [module], "path": "/" + module, "expected_status": [200 if allowed else 403],
                 "json_assertions": [{"path": "allowed", "equals": allowed}, {"path": "role", "equals": role}]},
                f"{role} {'can' if allowed else 'cannot'} access {module}")
    for owner in ("a", "b"):
        for caller in ("a", "b"):
            allowed = owner == caller
            add({"id": f"tenant-{owner}-as-{caller}", "type": "http", "layer": "security", "component_ids": ["tenants"],
                 "path": "/tenants/" + owner, "expected_status": [200 if allowed else 403],
                 "headers_from_env": {"Authorization": "PRED_REF_ANALYST", "X-Tenant": "PRED_REF_TENANT_" + caller.upper()},
                 "role": "analyst", "json_assertions": [{"path": "tenant", "equals": owner}] if allowed else [{"path": "denied", "equals": True}]},
                f"Tenant {caller} {'can' if allowed else 'cannot'} read tenant {owner}'s fixture")
    add({"id": "queue", "type": "http", "layer": "reliability", "component_ids": ["queue"], "path": "/health",
         "json_assertions": [{"path": "ready", "equals": True}, {"path": "dead_letters", "equals": 0}]},
        "Queue is healthy with no dead letters")
    add({"id": "worker-recovery", "type": "recovery", "layer": "reliability", "component_ids": ["worker"],
         "path": "/recovery", "json_assertions": [{"path": "restored", "equals": True}],
         "disruption_expected_status": [503], "inject_command": app.control_command("kill"),
         "recover_command": app.control_command("restart"), "recovery_timeout_seconds": 3},
        "Worker recovers interrupted jobs with exactly one recorded effect")
    add({"id": "throughput", "type": "load", "layer": "reliability", "component_ids": ["throughput"],
         "path": "/load", "json_assertions": [{"path": "ready", "equals": True}],
         "requests": 12, "concurrency": 4, "max_p95_ms": 1500},
        "Read-only requests complete under the reviewed bounded workload")
    plan["scope_contract"] = {"mode": "whole_system", "policy_reviewed": True, "inventory_totals_reviewed": True,
        "inventory_totals": dict(Counter(c["kind"] for c in plan["components"])), "objectives": objectives,
        "build": {"check_id": "candidate", "assertion_path": "build_id", "expected_value": app.build_id}}
    return plan


class WholeSystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, IDENTITIES)
        self.env.start()
        self.addCleanup(self.env.stop)

    def run_plan(self, plan, name):
        approve_plan(plan, self.root, isolated=True, allow_disruption=True)
        report = execute_system(plan, self.root, self.root / name)
        self.assertEqual(report["report_sha256"], sha256({k: v for k, v in report.items() if k != "report_sha256"}))
        return report

    def test_ten_modules_four_roles_seeded_faults_and_repaired_rerun(self):
        with fixture.application(self.root) as app:
            plan = whole_plan(self.root, app)
            approve_plan(plan, self.root, isolated=True, allow_disruption=True)
            self.assertTrue(preflight(plan, self.root)["whole_system_ready"])
            reports = []
            for name in ("healthy", "faults", "repaired"):
                app.faults = {"abstention", "contract", "rbac", "tenant_leak", "injection", "dead_letters", "stuck_job", "capacity"} if name == "faults" else set()
                if name == "repaired":
                    app.stop_worker()
                    app.start_worker()
                    app.wait(lambda: all(j["state"] == "done" for j in app.jobs()))
                report = self.run_plan(plan, name)
                reports.append(report)
                self.assertTrue(report["scope_contract"]["complete"], report["scope_contract"])
                self.assertEqual(report["summary"]["components"], 10)
                self.assertEqual(report["summary"]["complete_components"], 10)
                matrix = report["module_evaluation_summary"]
                self.assertEqual(matrix["summary"]["area_count"], 8)
                self.assertGreaterEqual(matrix["summary"]["areas_with_executed_evidence"], 6)
                ai_area = next(area for area in matrix["areas"] if area["id"] == "ai_decision")
                self.assertIn("classification", ai_area["verified_metrics"])
                self.assertEqual(ai_area["evidence_strength"], "verified")
                rag_area = next(area for area in matrix["areas"] if area["id"] == "rag_knowledge")
                self.assertEqual(rag_area["executed_check_count"], 0)
                self.assertNotIn("classification", rag_area["verified_metrics"])
                self.assertEqual(report["verdict"], "do_not_ship" if name == "faults" else "checks_passed_within_reviewed_scope")
                if name == "faults":
                    failed = {c["id"] for c in report["checks"] if c["status"] == "failed"}
                    self.assertTrue({"triage", "contract", "admin-read_only", "tenant-a-as-b", "security", "queue", "worker-recovery", "throughput"} <= failed, failed)
                rendered = render_report(report)
                self.assertIn("behavior objectives evaluated", rendered)
                self.assertIn("Module evaluation map", rendered)
                self.assertIn("AI decision modules", rendered)
                self.assertIn("Security modules", rendered)

    def test_missing_objective_and_role_cannot_hide_behind_check_attachment(self):
        with fixture.application(self.root) as app:
            plan = whole_plan(self.root, app)
            plan["scope_contract"]["objectives"] = [o for o in plan["scope_contract"]["objectives"] if o["check_id"] != "admin-read_only"]
            report = self.run_plan(plan, "missing-role")
            self.assertEqual(report["verdict"], "insufficient_evidence")
            self.assertFalse(report["scope_contract"]["complete"])
            self.assertEqual(report["summary"]["complete_components"], 9)
            self.assertEqual(report["scope_contract"]["summary"]["total"], 20)
            self.assertEqual(report["scope_contract"]["summary"]["complete"], 19)

    def test_unknown_inventory_and_exclusion_are_gaps_not_success(self):
        plan = basic_plan()
        plan["scope_contract"] = draft_scope(plan)
        plan["scope_contract"]["objectives"][0]["exclude_reason"] = "No isolated environment yet"
        plan["scope_contract"]["inventory_totals"]["api"] = 33
        result = assess_scope(plan, [], root=self.root)
        self.assertFalse(result["complete"])
        self.assertEqual(result["objectives"][0]["status"], "excluded")
        self.assertTrue(any("33 declared" in gap for gap in result["gaps"]))

    def test_wrong_candidate_stops_before_decisions_and_mutation(self):
        with fixture.application(self.root) as app:
            plan = whole_plan(self.root, app)
            app.faults.add("wrong_build")
            report = self.run_plan(plan, "wrong-build")
            self.assertEqual(report["verdict"], "insufficient_evidence")
            self.assertEqual(app.calls, ["/build"])
            self.assertEqual(report["summary"]["checks_executed"], 1)

    def test_candidate_changes_during_run_invalidate_readiness_and_history(self):
        with fixture.application(self.root) as app:
            plan = whole_plan(self.root, app)
            app.faults.add("build_changed")
            report = self.run_plan(plan, "changed-build")
            self.assertEqual(report["verdict"], "insufficient_evidence")
            self.assertEqual(report["build_verification"]["status"], "candidate_changed_or_unreachable")
            record_run(self.root / "history.sqlite", report)
            result = trend(self.root / "history.sqlite", plan["project_id"], [{"check_id": "triage", "signal": "classification.accuracy", "direction": "decrease", "delta": .1}])
            self.assertIsNone(result["rules"][0]["current"])

    def test_case_binding_requires_actual_case_not_suite_aggregate(self):
        with fixture.application(self.root) as app:
            plan = whole_plan(self.root, app)
            objective = next(o for o in plan["scope_contract"]["objectives"] if o["check_id"] == "security")
            objective["case_ids"] = ["not-a-real-test"]
            report = self.run_plan(plan, "missing-case")
            row = next(o for o in report["scope_contract"]["objectives"] if o["id"] == objective["id"])
            self.assertFalse(row["complete"])
            self.assertEqual(report["verdict"], "insufficient_evidence")

    def test_weak_http_assertions_and_missing_eval_case_block_preflight_scope(self):
        with fixture.application(self.root) as app:
            plan = whole_plan(self.root, app)
            for objective in plan["scope_contract"]["objectives"]:
                if objective["check_id"] == "queue":
                    objective["assertion_paths"] = []
                if objective["check_id"] == "triage":
                    objective["case_ids"] = ["not-in-dataset"]
            approve_plan(plan, self.root, isolated=True, allow_disruption=True)
            result = preflight(plan, self.root)
            self.assertTrue(result["ready"])
            self.assertFalse(result["whole_system_ready"])
            self.assertEqual(app.calls, [])

    def test_schema_rejects_cross_module_binding_and_fake_build_probe(self):
        with fixture.application(self.root) as app:
            plan = whole_plan(self.root, app)
            for mutator in (
                lambda p: p["scope_contract"]["objectives"][0].update(component_id="queue"),
                lambda p: p["scope_contract"]["build"].update(expected_value="unbound-value"),
                lambda p: p["scope_contract"].update(policy_reviewed="true"),
                lambda p: p["scope_contract"]["inventory_totals"].update(api=True),
            ):
                changed = deepcopy(plan)
                mutator(changed)
                with self.assertRaises(RunnerError):
                    validate_plan(changed, self.root)

    def test_cli_scope_drafts_do_not_claim_coverage_or_call_target(self):
        plan = basic_plan()
        path = self.root / "plan.json"
        write_json(path, plan)
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["system", "scope", "--plan", str(path), "--init"]), 0)
        self.assertFalse(json.loads(output.getvalue())["scope_contract"]["complete"])
        drafted = json.loads(path.read_text())
        self.assertFalse(drafted["scope_contract"]["policy_reviewed"])
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["system", "preflight", "--plan", str(path), "--require-whole-system"]), 2)

    def test_duplicate_junit_cases_do_not_establish_objective_coverage(self):
        check = {"command": [sys.executable, "-c", "from pathlib import Path; Path('duplicate.xml').write_text('<testsuite><testcase name=\"same\"/><testcase name=\"same\"/></testsuite>')"],
                 "result_file": "duplicate.xml", "format": "junit"}
        result = command_check(check, self.root)
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(result["ambiguous_case_ids"])
        self.assertEqual(result["case_results"], [])

    def test_strict_run_rejects_selected_check_plan_without_target_calls(self):
        with fixture.application(self.root) as app:
            plan = basic_plan(app.url)
            approve_plan(plan, self.root)
            path = self.root / "selected.json"
            write_json(path, plan)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = main(["system", "run", "--plan", str(path), "--require-whole-system", "--out", str(self.root / "not-run")])
            self.assertNotEqual(code, 0)
            self.assertEqual(app.calls, [])
            self.assertFalse((self.root / "not-run").exists())

    def test_route_only_browser_binding_is_not_visible_behavior_coverage(self):
        plan = basic_plan()
        plan["components"][0]["required_layers"] = ["workflow"]
        plan["checks"] = [{"id": "browser", "type": "evaluation", "layer": "workflow", "component_ids": ["api-health"],
                           "enabled": True, "reviewed": True, "config": "browser.json"}]
        plan["scope_contract"] = draft_scope(plan)
        objective = plan["scope_contract"]["objectives"][0]
        objective.update(reviewed=True, check_id="browser", case_ids=["page"])
        config = {"adapter": {"type": "browser_journey"}, "dataset": {"cases": [{"case_id": "page", "input": {"journey": [
            {"type": "goto", "path": "/"}, {"type": "assert_path", "value": "/"}]}}]}}
        write_json(self.root / "browser.json", config)
        result = assess_scope(plan, root=self.root)
        self.assertFalse(result["objectives"][0]["complete"])
        self.assertIn("Visible outcome", result["objectives"][0]["gaps"][0])
        config["dataset"]["cases"][0]["input"]["journey"].append({"type": "expect_text", "value": "Ready"})
        write_json(self.root / "browser.json", config, replace=True)
        self.assertTrue(assess_scope(plan, root=self.root)["objectives"][0]["complete"])

    def test_passing_junit_case_not_blamed_for_unrelated_suite_failure(self):
        plan = basic_plan()
        plan["components"][0]["required_layers"] = ["code"]
        plan["checks"] = [{"id": "tests", "type": "command", "layer": "code", "enabled": True, "component_ids": ["api-health"]}]
        plan["scope_contract"] = draft_scope(plan)
        plan["scope_contract"]["objectives"][0].update(reviewed=True, check_id="tests", case_ids=["independent-pass"])
        result = assess_scope(plan, [{"id": "tests", "status": "failed", "case_results": [
            {"id": "independent-pass", "status": "passed"}, {"id": "other", "status": "failed"}]}])
        self.assertEqual(result["objectives"][0]["status"], "passed")
        self.assertTrue(result["objectives"][0]["complete"])

    @unittest.skipUnless(shutil.which("node"), "Node is only needed to exercise setup JavaScript handlers")
    def test_setup_input_handlers_commit_edits_before_blur_and_validate_json(self):
        helpers = "function field" + SETUP_SCRIPT.split("function field", 1)[1].split("function render", 1)[0]
        script = """
const assert=require('node:assert/strict');
const el=()=>({children:[],append(...items){this.children.push(...items)},setCustomValidity(value){this.error=value}});
const status={textContent:''};const byId=()=>status;
""" + helpers + """
const parent=el();let observed=null;
const input=field(parent,'Behavior','old',value=>observed=value);
input.value='edited without blur';input.oninput();assert.equal(observed,'edited without blur');
jsonField(parent,'Assertions',[],value=>observed=value);
const json=parent.children[1].children[0];
json.value='{broken';json.oninput();assert.equal(json.error,'Invalid JSON');
json.value='[{"path":"ready","equals":true}]';json.oninput();
assert.equal(json.error,'');assert.deepEqual(observed,[{path:'ready',equals:true}]);
"""
        result = subprocess.run([shutil.which("node"), "-e", script], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
