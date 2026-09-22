"""System contracts tested against a live, deliberately fallible loopback app."""

from contextlib import contextmanager, redirect_stdout, redirect_stderr
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import HTTPConnection
import io
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from unittest.mock import patch

from esx_eval_runner.cli import main
from esx_eval_runner.local_metrics import calculate_local_metrics
from esx_eval_runner.runner import RunnerError, build_package, sha256
from esx_eval_runner.system_cli import bind_evaluation, write_json
from esx_eval_runner.system_engine import (
    approve_plan, command_check, execute_system, http_check, plan_digest,
    preflight, validate_plan, population_coverage, evaluation_check,
)
from esx_eval_runner.system_history import history_runs, prune_history, record_run, signals, trend
from esx_eval_runner.system_inventory import SCHEMA, add_role_matrix, discover_system, document, sample_population
from esx_eval_runner.system_readiness import (
    coverage_readiness, draft_coverage_packs, evidence_gap_report, full_platform_setup_plan,
    validate_workflow_packs,
)
from esx_eval_runner.system_ui import render_evidence_gap_report, render_report, setup_handler, setup_html


@contextmanager
def reference_app():
    state = {"calls": [], "ready": True}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            state["calls"].append(self.path)
            code = 200
            if state.get("marker") and Path(state["marker"]).exists():
                code = 503
            if self.path == "/admin" and self.headers.get("Authorization") != "admin-test":
                code = 403
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/ok")
                self.end_headers()
                return
            payload = json.dumps({"ready": state["ready"] and self.path != "/broken", "tenant": "tenant-a"}).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def basic_plan(base="http://127.0.0.1:9876"):
    return {
        "schema_version": SCHEMA, "project_id": "sample-app", "application_version": "candidate",
        "inventory_confirmed": True, "environment": "local", "roles": ["anonymous"], "base_url": base,
        "components": [{"id": "api-health", "name": "Health", "module": "core", "kind": "api",
                        "path": "/ok", "method": "GET", "required_layers": ["functional"],
                        "depends_on": [], "evidence": [], "enabled": "unknown"}],
        "checks": [{"id": "health", "type": "http", "layer": "functional", "component_ids": ["api-health"],
                    "enabled": True, "reviewed": True, "path": "/ok", "method": "GET", "role": "anonymous",
                    "expected_status": [200], "json_assertions": [{"path": "ready", "equals": True}]}],
        "discovery": {"truncated": False},
    }


def decision_config(dimensions=None, *, labels=True, confidence=False, version=2):
    cases = [
        {"case_id": "case-a", "input": {"signal": "risk"}, "expected_evidence_ids": ["ev-a"], "must_abstain": False},
        {"case_id": "case-b", "input": {"signal": "clear"}, "expected_evidence_ids": [], "must_abstain": True},
    ]
    if labels:
        for case, label in zip(cases, ("escalate", "hold")):
            case["expected_label"] = label
    script = (
        "import json,sys; request=json.load(sys.stdin); "
        "rows=[{'case_id':c['case_id'],'predicted_label':'escalate' if c['input']['signal']=='risk' else 'hold',"
        "'evidence_ids':['ev-a'] if c['input']['signal']=='risk' else [],'abstained':c['input']['signal']=='clear'} for c in request['cases']]; "
        + ("[r.update(confidence=0.9) for r in rows]; " if confidence else "")
        + f"json.dump({{'schema_version':'esx-client-adapter-response-{version}.0','results':rows"
        + (",'measurements':{}" if version == 2 else "") + "},sys.stdout)"
    )
    return {"schema_version": "esx-client-runner-config-1.0",
            "evaluation": {"name": "Local decisions", "agent_id": "sample-engine", "project_key": "sample-app",
                           "subject_version": "candidate", "dataset_version": "gold-v1",
                           "confidence_provenance": {"kind": "native_probability", "meaning": "predicted_label_correctness"},
                           "required_dimensions": dimensions or ["classification", "decision_evidence"]},
            "dataset": {"version": "gold-v1", "cases": cases}, "adapter": {"type": f"command_json_v{version}", "command": [sys.executable, "-c", script]}}


class BaselineInputTests(unittest.TestCase):
    def test_guided_plan_omits_unavailable_confidence(self):
        from esx_eval_runner.setup import create_http_plan
        with TemporaryDirectory() as directory:
            _, config = create_http_plan({"directory": str(Path(directory) / "plan"), "agent_id": "sample-app",
                "subject_version": "candidate", "project_key": "sample-app", "profile": "smoke",
                "url": "http://127.0.0.1:9900/eval", "response_label_path": "label", "response_confidence_path": ""})
            self.assertNotIn("confidence", config["evaluation"]["required_dimensions"])
            self.assertNotIn("response_confidence_path", config["adapter"])

    def test_release_attach_keeps_population_metadata(self):
        from test_release_execution import initialize, call
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = initialize(root, version="candidate")
            config = decision_config(["classification", "confidence"], confidence=True)
            config["dataset"]["population"] = {"available_case_count": 100, "class_counts": {"escalate": 50, "hold": 50}}
            write_json(root / "config.json", config)
            self.assertEqual(call("release", "attach", "--manifest", str(manifest), "--module", "decisions", "--suite-id", "pack", "--config", str(root / "config.json"), "--read-only"), 0)
            self.assertEqual(document(manifest)["modules"][0]["suites"][0]["population"]["available_case_count"], 100)

    def test_semantic_only_full_cli_without_classification_or_confidence(self):
        fixtures = Path(__file__).parent / "fixtures" / "local-metrics"
        material = document(fixtures / "semantic-grounding-mixed.json")
        config = decision_config(["groundedness", "hallucination"], labels=False)
        config["dataset"]["cases"] = [{"case_id": "case-1", "input": {}}]
        script = ("import json,sys; r=json.load(sys.stdin); "
                  f"m={material!r}; "
                  "json.dump({'schema_version':'esx-client-adapter-response-2.0','results':[{'case_id':'case-1'}], 'measurements':{},'grounding_material':m},sys.stdout)")
        config["adapter"]["command"] = [sys.executable, "-c", script]
        config["assurance"] = {"grounding_judge": {"type": "command_json_v1",
            "command": [sys.executable, str((fixtures / "semantic-grounding-judge.py").resolve())],
            "identity": "fixture-semantic-judge", "version": "1", "independent_from_target": True}}
        with TemporaryDirectory() as directory:
            root = Path(directory)
            write_json(root / "config.json", config)
            with redirect_stdout(io.StringIO()):
                status = main(["run", "--config", str(root / "config.json"), "--out", str(root / "run.json"), "--summary-only"])
            self.assertEqual(status, 0)
            report = document(root / "run.local-report.json")
            self.assertAlmostEqual(report["metrics"]["groundedness"]["grounded_claim_rate"], 1 / 3, places=6)
            self.assertAlmostEqual(report["metrics"]["hallucination"]["unsupported_claim_rate"], 2 / 3, places=6)
            self.assertEqual(report["metrics"]["classification"]["measurement_status"], "not_measurable")

    def test_v2_decision_evidence_without_confidence_runs_real_adapter(self):
        package = build_package(decision_config())
        metrics = calculate_local_metrics(package)
        self.assertEqual(metrics["classification"]["accuracy"], 1.0)
        self.assertEqual(metrics["decision_evidence"]["correct_abstention_rate"], 1.0)
        self.assertEqual(metrics["confidence"]["measurement_status"], "not_measurable")

    def test_decision_evidence_does_not_require_labels(self):
        config = decision_config(["decision_evidence"], labels=False)
        package = build_package(config)
        self.assertEqual(package["evaluation"]["expected_labels"], [])
        self.assertEqual(calculate_local_metrics(package)["decision_evidence"]["evidence_reference_precision"], 1.0)

    def test_requested_confidence_still_requires_real_confidence(self):
        with self.assertRaises(RunnerError):
            build_package(decision_config(["classification", "confidence"]))

    def test_v1_labels_only_full_cli_report(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            write_json(root / "config.json", decision_config(["classification"], version=1))
            with redirect_stdout(io.StringIO()):
                status = main(["run", "--config", str(root / "config.json"), "--out", str(root / "result.json"), "--summary-only"])
            self.assertEqual(status, 0)
            report = document(root / "result.local-report.json")
            self.assertEqual(report["metrics"]["classification"]["accuracy"], 1.0)
            self.assertTrue((root / "result.local-report.html").is_file())


class SystemEvaluationTests(unittest.TestCase):
    def test_sampling_is_reproducible_and_preserves_population(self):
        source = {"version": "gold", "cases": [{"case_id": str(i), "input": {"value": i}, "expected_label": "a" if i < 90 else "b"} for i in range(100)]}
        a = sample_population(source, 4, 42)
        b = sample_population({**source, "cases": list(reversed(source["cases"]))}, 4, 42)
        self.assertEqual(a["cases"], b["cases"])
        self.assertEqual(len(a["cases"]), 8)
        self.assertEqual(a["population"]["class_counts"], {"a": 90, "b": 10})
        source["cases"].append(source["cases"][0])
        with self.assertRaises(RunnerError):
            sample_population(source, 4, 42)

    def test_numeric_budgets_and_boolean_equality_remain_distinct(self):
        from esx_eval_runner.system_engine import _matches
        self.assertFalse(_matches(True, {"equals": 1}))
        self.assertTrue(_matches(1.0, {"equals": 1}))
        self.assertFalse(_matches(4, {"operator": "lte", "value": 0}))
        self.assertFalse(_matches(float("nan"), {"operator": "lte", "value": 1}))

    def test_preflight_cannot_be_ready_with_no_enabled_checks(self):
        plan = basic_plan()
        plan["checks"][0]["enabled"] = False
        approve_plan(plan, Path.cwd())
        self.assertFalse(preflight(plan, Path.cwd())["ready"])

    def test_incomplete_evaluation_metrics_do_not_feed_drift(self):
        row = {"status": "failed", "evidence_complete": False, "observed_abstention_rate": .99,
               "metrics": {"classification": {"trust_status": "verified", "measurement_status": "measured", "accuracy": 1.0}}}
        self.assertEqual(signals(row), {"check_success": 0.0})

    def test_monitor_runs_explicit_cycles_without_installing_a_scheduler(self):
        with TemporaryDirectory() as directory, reference_app() as (url, state):
            root = Path(directory)
            plan = basic_plan(url)
            approve_plan(plan, root)
            write_json(root / "plan.json", plan)
            with patch("esx_eval_runner.system_cli.time.sleep") as sleep, redirect_stdout(io.StringIO()):
                status = main(["system", "monitor", "--plan", str(root / "plan.json"), "--out", str(root / "runs"),
                               "--history", str(root / "history.sqlite"), "--cycles", "3", "--interval-seconds", "60"])
            self.assertEqual(status, 0)
            self.assertEqual(sleep.call_count, 2)
            self.assertEqual(len(state["calls"]), 3)
            self.assertEqual(len(history_runs(root / "history.sqlite", "sample-app")), 3)

    def test_invalid_trend_rules_fail_before_target_calls(self):
        with TemporaryDirectory() as directory, reference_app() as (url, state):
            root = Path(directory)
            plan = basic_plan(url)
            approve_plan(plan, root)
            write_json(root / "plan.json", plan)
            write_json(root / "rules.json", {"rules": [{"signal": "bad"}]})
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                status = main(["system", "run", "--plan", str(root / "plan.json"), "--out", str(root / "run"),
                               "--history", str(root / "history.sqlite"), "--rules", str(root / "rules.json")])
            self.assertEqual(status, 1)
            self.assertEqual(state["calls"], [])

    def test_discovery_never_executes_source_or_target(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "api.py").write_text("raise RuntimeError('never import')\nrouter=APIRouter(prefix='/api')\n@router.get('/items')\ndef items(): pass\n# @router.get('/fake')\n", encoding="utf-8")
            spec = {"openapi": "3.1.0", "paths": {"/api/items": {"get": {"responses": {"200": {}}}}}}
            write_json(root / "openapi.json", spec)
            plan = discover_system(project_id="sample-app", version="candidate", repository=str(root), openapi=str(root / "openapi.json"))
            self.assertEqual(len(plan["components"]), 1)
            self.assertEqual(len(plan["components"][0]["evidence"]), 2)
            self.assertFalse(plan["checks"][0]["enabled"])
            self.assertFalse(plan["inventory_confirmed"])

    def test_plan_edits_invalidate_approval(self):
        plan = basic_plan()
        approve_plan(plan, Path.cwd())
        self.assertTrue(preflight(plan, Path.cwd())["ready"])
        plan["checks"][0]["expected_status"] = [201]
        self.assertFalse(preflight(plan, Path.cwd())["ready"])

    def test_enabled_unreviewed_checks_rejected(self):
        plan = basic_plan()
        plan["checks"][0]["reviewed"] = False
        with self.assertRaisesRegex(RunnerError, "Review"):
            approve_plan(plan, Path.cwd())

    def test_content_failure_is_detected_even_with_200(self):
        with TemporaryDirectory() as directory, reference_app() as (url, state):
            plan = basic_plan(url)
            plan["checks"][0]["path"] = "/broken"
            approve_plan(plan, Path(directory))
            report = execute_system(plan, Path(directory), Path(directory) / "run")
            self.assertEqual(report["verdict"], "do_not_ship")
            self.assertEqual(report["summary"]["complete_components"], 1)
            self.assertEqual(report["checks"][0]["assertions"][0]["matched"], False)
            self.assertEqual(state["calls"], ["/broken"])

    def test_missing_components_and_roles_remain_visible(self):
        with TemporaryDirectory() as directory, reference_app() as (url, _):
            plan = basic_plan(url)
            add_role_matrix(plan, ["admin", "read_only"])
            approve_plan(plan, Path(directory))
            report = execute_system(plan, Path(directory), Path(directory) / "run")
            self.assertEqual(report["verdict"], "insufficient_evidence")
            self.assertIn("read_only", str(report["coverage"][0]["gaps"]))

    def test_identity_missing_blocks_before_any_network_call(self):
        with reference_app() as (url, state):
            plan = basic_plan(url)
            plan["roles"].append("admin")
            plan["checks"][0].update(role="admin", headers_from_env={"Authorization": "PRED_TEST_MISSING_SECRET"})
            approve_plan(plan, Path.cwd())
            with patch.dict(os.environ, {}, clear=True):
                self.assertFalse(preflight(plan, Path.cwd())["ready"])
            self.assertEqual(state["calls"], [])

    def test_role_deny_and_tenant_mismatch_are_real_assertions(self):
        with reference_app() as (url, _):
            plan = basic_plan(url)
            check = plan["checks"][0]
            check.update(path="/admin", expected_status=[403], json_assertions=[])
            self.assertEqual(http_check(plan, check)["status"], "passed")
            check.update(path="/tenant", expected_status=[200], json_assertions=[{"path": "tenant", "equals": "tenant-b"}])
            self.assertEqual(http_check(plan, check)["status"], "failed")

    def test_redirects_not_followed(self):
        with reference_app() as (url, state):
            plan = basic_plan(url)
            plan["checks"][0]["path"] = "/redirect"
            self.assertEqual(http_check(plan, plan["checks"][0])["status"], "failed")
            self.assertEqual(state["calls"], ["/redirect"])

    def test_staging_and_writes_are_explicit(self):
        plan = basic_plan("http://production.example")
        with self.assertRaisesRegex(RunnerError, "loopback"):
            approve_plan(plan, Path.cwd())
        plan = basic_plan()
        plan["checks"][0]["method"] = "POST"
        approve_plan(plan, Path.cwd())
        self.assertFalse(preflight(plan, Path.cwd())["ready"])
        plan["isolation_note"] = "Disposable test tenant, no live integration credentials"
        approve_plan(plan, Path.cwd(), isolated=True)
        self.assertTrue(preflight(plan, Path.cwd())["ready"])

    def test_code_suite_reads_fresh_junit_not_exit_code_alone(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            check = {"command": [sys.executable, "-c", "from pathlib import Path; Path('tests.xml').write_text('<testsuite><testcase name=\"broken\"><failure/></testcase></testsuite>')"], "result_file": "tests.xml"}
            result = command_check(check, root)
            self.assertEqual(result["status"], "failed")
            check["command"] = [sys.executable, "-c", "pass"]
            self.assertEqual(command_check(check, root)["reason"], "fresh_junit_required")

    def test_real_ai_subprocess_preserves_metrics_and_missing_gates(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = decision_config(["classification"])
            write_json(root / "config.json", config)
            plan = basic_plan()
            plan["components"][0]["required_layers"] = ["ai"]
            plan["checks"] = []
            bind_evaluation(plan, root, config_path=root / "config.json", components=["api-health"], check_id="decisions")
            plan["checks"][0].update(enabled=True, reviewed=True)
            approve_plan(plan, root)
            report = execute_system(plan, root, root / "run")
            self.assertEqual(report["checks"][0]["status"], "passed", report)
            self.assertEqual(report["checks"][0]["metrics"]["classification"]["accuracy"], 1.0)
            self.assertTrue((root / "run" / "decisions.local-report.html").exists())

    def test_workflow_suite_incomplete_lists_blocked_and_not_run_cases(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "run"
            out.mkdir()
            config = {
                "schema_version": "esx-client-runner-config-1.0",
                "evaluation": {"project_key": "sample-app", "subject_version": "candidate", "required_dimensions": ["workflow_coverage"]},
                "adapter": {"type": "browser_journey", "base_url": "http://127.0.0.1"},
                "dataset": {"cases": [
                    {"case_id": "dashboard", "input": {"journey": [{"type": "goto", "path": "/"}, {"type": "wait_for_text", "value": "Dashboard"}]}},
                    {"case_id": "settings", "input": {"journey": [{"type": "goto", "path": "/settings"}, {"type": "wait_for_text", "value": "Settings"}]}},
                    {"case_id": "audit", "input": {"journey": [{"type": "goto", "path": "/audit"}, {"type": "wait_for_text", "value": "Audit"}]}},
                ]},
            }
            write_json(root / "workflow.json", config)
            execution = {
                "adapter_type": "browser_journey",
                "case_count": 3,
                "scored_case_count": 1,
                "blocked_case_count": 1,
                "browser_case_diagnostics": [
                    {"case_id": "dashboard", "outcome": "passed"},
                    {"case_id": "settings", "outcome": "blocked", "failure_stage": "session_setup", "failure_kind": "session_bootstrap_required"},
                ],
            }
            write_json(out / "workflow.json", {"evaluation": {"case_ids": ["dashboard"], "predicted_labels": [], "expected_labels": []}, "execution": execution})
            write_json(out / "workflow.local-report.json", {
                "evaluation": {"required_dimensions": ["workflow_coverage"]},
                "execution": execution,
                "metrics": {"workflow_coverage": {"measurement_status": "measured", "trust_status": "verified", "workflow_execution_rate": 0.333333, "workflow_signal_match_rate": 1.0}},
            })
            check = {"id": "workflow", "config": "workflow.json", "timeout_seconds": 30,
                     "gates": [{"signal": "workflow_coverage.workflow_execution_rate", "operator": "gte", "threshold": 1.0}]}
            with patch("esx_eval_runner.system_engine._process", return_value=0):
                result = evaluation_check(check, root, out)
            self.assertEqual(result["reason"], "workflow_suite_incomplete")
            self.assertEqual(result["planned_case_count"], 3)
            self.assertEqual(result["case_count"], 1)
            self.assertEqual(result["blocked_case_count"], 1)
            self.assertEqual(result["not_run_case_count"], 1)
            self.assertEqual([row["status"] for row in result["case_results"]], ["passed", "blocked", "not_run"])
            self.assertEqual(result["case_results"][1]["failure_kind"], "session_bootstrap_required")

    def test_workflow_readiness_blocks_missing_session_and_names_weak_cases(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = {
                "schema_version": "esx-client-runner-config-1.0",
                "evaluation": {"name": "Browser", "agent_id": "browser", "project_key": "sample-app",
                               "subject_version": "candidate", "dataset_version": "ui-v1",
                               "required_dimensions": ["workflow_coverage"]},
                "adapter": {"type": "browser_journey", "base_url": "http://127.0.0.1:3000",
                            "session_state_path": ".esx/session.json",
                            "session_bootstrap": {"login_path": "/login", "success": {"type": "wait_for_text", "value": "Dashboard"}}},
                "dataset": {"version": "ui-v1", "cases": [
                    {"case_id": "dashboard", "input": {"journey": [{"type": "goto", "path": "/"}, {"type": "wait_for_text", "value": "Dashboard"}]},
                     "expected_label": "pass", "requires_auth": True},
                    {"case_id": "audit", "input": {"journey": [{"type": "goto", "path": "/audit"}, {"type": "assert_path", "path": "/audit"}]},
                     "expected_label": "pass", "requires_auth": False},
                ]},
            }
            write_json(root / "workflow.json", config)
            plan = basic_plan("http://127.0.0.1:3000")
            plan["components"][0].update(kind="page", required_layers=["workflow"], path="/")
            plan["checks"] = [{"id": "core-workflows", "type": "evaluation", "layer": "workflow",
                               "component_ids": ["api-health"], "enabled": True, "reviewed": True,
                               "config": "workflow.json", "config_sha256": sha256(config), "timeout_seconds": 30,
                               "requested_dimensions": ["workflow_coverage"],
                               "gates": [{"signal": "workflow_coverage.workflow_execution_rate", "operator": "gte", "threshold": 1.0}]}]
            plan["scope_contract"] = {"mode": "whole_system", "policy_reviewed": True, "inventory_totals_reviewed": True,
                                      "inventory_totals": {"page": 1}, "build": {}, "objectives": [
                {"id": "obj-ui", "component_id": "api-health", "title": "Dashboard renders",
                 "layer": "workflow", "role": None, "reviewed": True, "check_id": "core-workflows",
                 "case_ids": ["dashboard"], "assertion_paths": []}
            ]}
            approve_plan(plan, root)
            workflows = validate_workflow_packs(plan, root)
            self.assertFalse(workflows["ready"])
            self.assertEqual(workflows["summary"]["planned_case_count"], 2)
            self.assertEqual(workflows["summary"]["missing_session_case_count"], 1)
            self.assertEqual(workflows["summary"]["weak_signal_case_count"], 1)
            self.assertIn("dashboard", str(workflows["checks"][0]["issues"]))
            self.assertIn("audit", str(workflows["checks"][0]["issues"]))
            result = preflight(plan, root)
            self.assertFalse(result["ready"])
            self.assertIn("coverage_readiness", result)

    def test_coverage_pack_drafts_and_evidence_gaps_are_review_only(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            plan = basic_plan("http://127.0.0.1:3000")
            plan["roles"].append("analyst")
            plan["components"].extend([
                {"id": "page-dashboard", "name": "Dashboard", "module": "workspace", "kind": "page",
                 "path": "/", "required_layers": ["workflow"], "depends_on": [], "evidence": [], "enabled": "unknown"},
                {"id": "ai-triage", "name": "Triage model", "module": "decisions", "kind": "ai_candidate",
                 "path": "services/triage.py", "required_layers": ["ai"], "depends_on": [], "evidence": [],
                 "enabled": "unknown", "suggested_dimensions": ["classification", "decision_evidence", "groundedness", "hallucination"]},
            ])
            drafts = draft_coverage_packs(plan, root)
            self.assertFalse(drafts["target_calls_made"])
            self.assertGreaterEqual(drafts["summary"]["workflow_case_templates"], 1)
            self.assertGreaterEqual(drafts["summary"]["decision_pack_templates"], 1)
            self.assertIn("REVIEW_VISIBLE_TEXT", json.dumps(drafts))
            readiness = coverage_readiness(plan, root)
            self.assertGreater(readiness["summary"]["metric_gap_count"], 0)
            gaps = evidence_gap_report(plan, root)
            self.assertFalse(gaps["target_calls_made"])
            self.assertGreater(gaps["summary"]["component_gap_count"], 0)
            self.assertIn("finding_register", gaps)
            self.assertGreater(gaps["finding_register"]["summary"]["finding_count"], 0)
            self.assertGreater(gaps["finding_register"]["summary"]["coverage_gap_count"], 0)
            self.assertIn("by_finding_class", gaps["finding_register"]["summary"])
            finding = gaps["finding_register"]["findings"][0]
            self.assertTrue(finding["finding_id"].startswith("finding-"))
            self.assertIn(finding["finding_class"], {"coverage_gap", "setup_gap"})
            self.assertEqual(finding["confidence"], "verified")
            self.assertIn("proof", finding)
            self.assertIn("audit_hash", finding)
            self.assertEqual(finding["non_invasive_status"], "pre_d_read_only_no_application_code_write")
            self.assertIn("harness_recommendations", gaps)
            self.assertGreater(gaps["harness_recommendations"]["summary"]["recommendation_count"], 0)
            self.assertGreater(gaps["harness_recommendations"]["summary"]["linked_coverage_gap_count"], 0)
            self.assertIn("decisions", json.dumps(gaps["module_gaps"]))
            self.assertIn("setup_plan", gaps)
            setup = full_platform_setup_plan(plan, root)
            self.assertGreater(setup["summary"]["component_action_count"], 0)
            self.assertIn("agent-tasks", json.dumps(setup))
            self.assertIn("FULL-PLATFORM SETUP", setup_html(plan, "token", root / "system-plan.json"))
            rendered = render_evidence_gap_report(gaps)
            self.assertIn("Evidence gap repair plan", rendered)
            self.assertIn("EVIDENCE-GAP TRACEABILITY", rendered)
            self.assertIn("HARNESS ENGINEERING RECOMMENDATIONS", rendered)
            self.assertIn("Coverage gaps prove missing evidence, not product defects", rendered)

    def test_load_is_bounded_and_observed(self):
        with TemporaryDirectory() as directory, reference_app() as (url, state):
            plan = basic_plan(url)
            plan["components"][0]["required_layers"] = ["reliability"]
            plan["checks"][0].update(type="load", layer="reliability", requests=6, concurrency=2, max_p95_ms=5000)
            approve_plan(plan, Path(directory))
            report = execute_system(plan, Path(directory), Path(directory) / "run")
            self.assertEqual(report["checks"][0]["status"], "passed")
            self.assertEqual(len(state["calls"]), 6)
            plan["checks"][0]["requests"] = 101
            with self.assertRaises(RunnerError):
                approve_plan(plan, Path(directory))

    def test_failed_cleanup_stops_later_checks(self):
        with TemporaryDirectory() as directory, reference_app() as (url, state):
            plan = basic_plan(url)
            recovery = deepcopy(plan["checks"][0])
            recovery.update(id="recover", type="recovery", disruption_expected_status=[503], inject_command=[sys.executable, "-c", "pass"], recover_command=[sys.executable, "-c", "raise SystemExit(1)"])
            plan["checks"].insert(0, recovery)
            plan["isolation_note"] = "Disposable reference app"
            approve_plan(plan, Path(directory), isolated=True, allow_disruption=True)
            report = execute_system(plan, Path(directory), Path(directory) / "run")
            self.assertEqual(len(report["checks"]), 1)
            self.assertEqual(report["checks"][0]["reason"], "failure_injection_or_cleanup_failed")
            self.assertEqual(report["verdict"], "insufficient_evidence")
            self.assertIn("finding_register", report)
            self.assertGreater(report["finding_register"]["summary"]["finding_count"], 0)
            self.assertGreater(report["finding_register"]["summary"]["blocked_evidence_count"], 0)
            self.assertIn("by_finding_class", report["finding_register"]["summary"])
            self.assertIn("harness_recommendations", report)
            self.assertGreater(report["harness_recommendations"]["summary"]["recommendation_count"], 0)
            rendered = render_report(report)
            self.assertIn("EXECUTIVE SUMMARY", rendered)
            self.assertIn("Release evidence review", rendered)
            self.assertIn("Verdict: Insufficient evidence", rendered)
            self.assertNotIn("<h1>Insufficient evidence</h1>", rendered)
            self.assertIn("HARNESS ENGINEERING RECOMMENDATIONS", rendered)
            self.assertIn("TRACEABLE FINDINGS", rendered)
            self.assertIn("Observed defects", rendered)
            self.assertIn("Blocked evidence", rendered)
            self.assertIn("Coverage gaps", rendered)

    def test_recovery_requires_observed_disruption_and_restoration(self):
        with TemporaryDirectory() as directory, reference_app() as (url, state):
            root = Path(directory)
            state["marker"] = str(root / "fault")
            plan = basic_plan(url)
            plan["isolation_note"] = "Disposable reference app"
            check = plan["checks"][0]
            check.update(type="recovery", disruption_expected_status=[503],
                         inject_command=[sys.executable, "-c", "from pathlib import Path; Path('fault').touch()"],
                         recover_command=[sys.executable, "-c", "from pathlib import Path; Path('fault').unlink(missing_ok=True)"])
            approve_plan(plan, root, isolated=True, allow_disruption=True)
            report = execute_system(plan, root, root / "real")
            self.assertEqual(report["checks"][0]["status"], "passed")
            self.assertEqual(report["checks"][0]["disruption_evidence"]["http_status"], 503)
            check["inject_command"] = [sys.executable, "-c", "pass"]
            approve_plan(plan, root, isolated=True, allow_disruption=True)
            report = execute_system(plan, root, root / "noop")
            self.assertEqual(report["checks"][0]["reason"], "disruption_not_observed")

    def test_population_exposes_class_sampling_and_unknowns(self):
        config = decision_config()
        self.assertEqual(population_coverage(config, 2)["status"], "unknown")
        config["dataset"]["population"] = {"available_case_count": 10000, "class_counts": {"escalate": 100, "hold": 9900}}
        coverage = population_coverage(config, 2)
        self.assertEqual(coverage["planned_fraction"], .0002)
        self.assertEqual(coverage["class_sampling"][0]["fraction"], .01)

    def test_feature_flags_and_dependencies_do_not_disappear(self):
        with TemporaryDirectory() as directory, reference_app() as (url, _):
            plan = basic_plan(url)
            c = deepcopy(plan["components"][0])
            c.update(id="retrieval", name="Retrieval", enabled=False, feature_flag="RETRIEVAL_ENABLED")
            plan["components"].append(c)
            plan["components"][0]["depends_on"] = ["retrieval"]
            approve_plan(plan, Path(directory))
            report = execute_system(plan, Path(directory), Path(directory) / "run")
            self.assertEqual(report["verdict"], "insufficient_evidence")
            self.assertIn("disabled", str(report["coverage"][1]["gaps"]))
            self.assertIn("dependency", str(report["coverage"][0]["gaps"]))

    def test_disabled_drafts_still_have_safe_schema(self):
        plan = basic_plan()
        plan["inventory_confirmed"] = "yes"
        with self.assertRaises(RunnerError):
            validate_plan(plan, Path.cwd())
        with TemporaryDirectory() as directory:
            path = Path(directory) / "nan.json"
            path.write_text('{"value": NaN}', encoding="utf-8")
            with self.assertRaises(RunnerError):
                document(path)

    def test_setup_requires_token_origin_and_current_digest(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "system.json"
            plan = basic_plan()
            approve_plan(plan, path.parent)
            write_json(path, plan)
            server = ThreadingHTTPServer(("127.0.0.1", 0), setup_handler(path, "review-token"))
            worker = Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                def post(token="review-token", digest=None, origin=None):
                    conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                    body = json.dumps({"token": token, "digest": digest or plan_digest(plan), "plan": plan})
                    headers = {"Content-Type": "application/json"}
                    if origin:
                        headers["Origin"] = origin
                    conn.request("POST", "/save", body, headers)
                    response = conn.getresponse()
                    status = response.status
                    response.read()
                    conn.close()
                    return status
                self.assertEqual(post(token="wrong"), 400)
                self.assertEqual(post(origin="https://untrusted.example"), 400)
                self.assertEqual(post(digest="stale"), 400)
                self.assertEqual(post(), 200)
                self.assertNotIn("approval", document(path))
            finally:
                server.shutdown()
                server.server_close()
                worker.join(5)

    def test_trend_detects_seeded_regression_and_excludes_protocol_change(self):
        with TemporaryDirectory() as directory, reference_app() as (url, state):
            root = Path(directory)
            plan = basic_plan(url)
            approve_plan(plan, root)
            db = root / "history.sqlite"
            reports = []
            for i in range(3):
                state["ready"] = i < 2
                report = execute_system(plan, root, root / str(i))
                report["created_at"] = (datetime.now(timezone.utc) + timedelta(seconds=i)).isoformat()
                report["report_sha256"] = sha256({k: v for k, v in report.items() if k != "report_sha256"})
                record_run(db, report)
                reports.append(report)
            rule = {"check_id": "health", "signal": "check_success", "direction": "decrease", "delta": .5}
            result = trend(db, "sample-app", [rule])
            self.assertEqual(result["status"], "alert")
            self.assertEqual(result["rules"][0]["baseline_count"], 2)
            record_run(db, reports[-1])
            self.assertEqual(len(history_runs(db, "sample-app")), 3)
            self.assertEqual(prune_history(db, "sample-app", 2), 1)
            self.assertEqual(trend(db, "sample-app", [rule])["status"], "insufficient_history")

    def test_report_escapes_content_and_warns_about_weak_checks(self):
        with TemporaryDirectory() as directory, reference_app() as (url, _):
            plan = basic_plan(url)
            plan["components"][0]["name"] = "<script>alert(1)</script>"
            plan["checks"][0]["json_assertions"] = []
            approve_plan(plan, Path(directory))
            rendered = render_report(execute_system(plan, Path(directory), Path(directory) / "run"))
            self.assertIn("Status-only checks", rendered)
            self.assertNotIn("<script>alert(1)</script>", rendered)
            self.assertIn("&lt;script&gt;", rendered)


if __name__ == "__main__":
    unittest.main()
