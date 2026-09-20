"""Six-stage acceptance: healthy control -> seeded fault -> repaired rerun.

Set PRED_ACCEPTANCE_OUT to retain actual system reports for each experiment.
These prove harness behavior on a disposable reference app, not customer coverage.
"""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, redirect_stdout, redirect_stderr
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from esx_eval_runner.cli import main
from esx_eval_runner.runner import RunnerError, sha256
from esx_eval_runner.system_cli import bind_evaluation, write_json
from esx_eval_runner.system_engine import (
    approve_plan, command_check, execute_system, load_check, preflight, validate_plan,
)
from esx_eval_runner.system_history import history_runs, record_run, trend
from esx_eval_runner.system_inventory import discover_system, document, sample_population
from esx_eval_runner.system_ui import render_report
from test_system_evaluation import basic_plan, decision_config

FIXTURE = Path(__file__).parent / "fixtures" / "system_app.py"
spec = importlib.util.spec_from_file_location("acceptance_app", FIXTURE)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class SystemAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        evidence = os.environ.get("PRED_ACCEPTANCE_OUT")
        self.evidence = (Path(evidence) / self._testMethodName) if evidence else self.root / "evidence"
        self.evidence.mkdir(parents=True, exist_ok=False)

    def run_plan(self, plan, name, *, disruptive=False):
        approve_plan(plan, self.root, isolated=disruptive, allow_disruption=disruptive)
        report = execute_system(plan, self.root, self.evidence / name)
        write_json(self.evidence / name / "system-report.json", report)
        (self.evidence / name / "system-report.html").write_text(render_report(report), encoding="utf-8")
        self.assertEqual(report["report_sha256"], sha256({k: v for k, v in report.items() if k != "report_sha256"}))
        return report

    def eval_plan(self, app):
        config = decision_config(["classification", "confidence", "decision_evidence"], confidence=True)
        config["dataset"]["cases"] = [
            {"case_id": str(i), "input": {"risk": bool(i % 2)},
             "expected_label": "escalate" if i % 2 else "hold", "must_abstain": False,
             "expected_evidence_ids": ["risk-evidence"] if i % 2 else []} for i in range(6)]
        config["dataset"]["population"] = {"available_case_count": 100, "class_counts": {"escalate": 20, "hold": 80}}
        config["adapter"]["command"] = [sys.executable, str(FIXTURE), "adapter", app.url]
        write_json(self.root / "decisions.json", config)
        plan = basic_plan(app.url)
        plan["components"][0]["required_layers"] = ["ai"]
        plan["checks"] = []
        bind_evaluation(plan, self.root, config_path=self.root / "decisions.json", components=["api-health"], check_id="decisions")
        plan["checks"][0].update(enabled=True, reviewed=True, gates=[
            {"signal": "classification.accuracy", "operator": "gte", "threshold": .95},
            {"signal": "confidence.expected_calibration_error", "operator": "lte", "threshold": .15},
            {"signal": "decision_evidence.correct_abstention_rate", "operator": "gte", "threshold": .95}])
        return plan

    def test_stage0_mixed_inventory_no_execution_and_limits(self):
        source = self.root / "source"
        source.mkdir()
        (source / "api.py").write_text("raise RuntimeError('must not import')\nr=APIRouter(prefix='/api')\n@r.get('/records')\ndef records(): pass\n", encoding="utf-8")
        (source / "routes.js").write_text("app.get('/settings', handler);", encoding="utf-8")
        (source / "test_contract.py").write_text("def test_contract(): pass", encoding="utf-8")
        write_json(self.root / "openapi.json", {"openapi": "3.1.0", "paths": {
            "/api/records": {"get": {"security": [{"bearer": []}], "responses": {"200": {}}}},
            "/only-in-spec": {"get": {"responses": {"200": {}}}}}})
        plan = discover_system(project_id="sample-app", version="candidate", repository=str(source), openapi=str(self.root / "openapi.json"))
        paths = {c.get("path") for c in plan["components"]}
        self.assertTrue({"/api/records", "/settings", "/only-in-spec"} <= paths, paths)
        self.assertTrue(any(c["kind"] == "test_suite" for c in plan["components"]))
        self.assertFalse(plan["inventory_confirmed"])
        self.assertTrue(all(not c["enabled"] for c in plan["checks"]))
        limited = discover_system(project_id="sample-app", version="candidate", repository=str(source), max_files=1)
        self.assertTrue(limited["discovery"]["truncated"])
        write_json(self.evidence / "inventory.json", plan)
        write_json(self.evidence / "limited-inventory.json", limited)

    def test_stage0_all_components_and_dimensions_accounted_for(self):
        with fixture.application(self.root) as app:
            plan = basic_plan(app.url)
            plan["checks"][0]["path"] = "/health"
            for i in range(9):
                component = deepcopy(plan["components"][0])
                component.update(id=f"uncovered-{i}", name=f"Uncovered {i}", required_layers=["ai"])
                plan["components"].append(component)
            report = self.run_plan(plan, "incomplete")
            self.assertEqual(report["summary"]["components"], 10)
            self.assertEqual(report["summary"]["complete_components"], 1)
            self.assertEqual(report["verdict"], "insufficient_evidence")
            self.assertEqual(len(report["coverage"][1]["dimension_inventory"]), 14)
            self.assertTrue(all(d["status"] == "not_requested" for d in report["coverage"][1]["dimension_inventory"]))

    def test_stage0_integrity_mutations_block_before_dispatch(self):
        with fixture.application(self.root) as app:
            plan = self.eval_plan(app)
            approve_plan(plan, self.root)
            config = document(self.root / "decisions.json")
            config["dataset"]["cases"][0]["expected_label"] = "modified"
            write_json(self.root / "decisions.json", config, replace=True)
            with self.assertRaisesRegex(RunnerError, "changed"):
                execute_system(plan, self.root, self.evidence / "must-not-run")
            self.assertEqual(app.calls, [])

    def test_stage0_boolean_and_metric_gate_schema_fail_closed(self):
        plan = basic_plan()
        plan["components"][0]["enabled"] = 1
        with self.assertRaises(RunnerError):
            validate_plan(plan, self.root)
        with fixture.application(self.root) as app:
            plan = self.eval_plan(app)
            for value in (-.1, 1.1, float("nan"), True):
                with self.subTest(threshold=value):
                    plan["checks"][0]["gates"][0]["threshold"] = value
                    with self.assertRaises(RunnerError):
                        validate_plan(plan, self.root)

    def test_stage1_real_decisions_abstention_calibration_drift_and_repair(self):
        with fixture.application(self.root) as app:
            plan = self.eval_plan(app)
            db = self.evidence / "history.sqlite"
            rule = {"check_id": "decisions", "signal": "observed_abstention_rate", "direction": "increase", "delta": .2}
            for name in ("baseline-a", "baseline-b", "regressed", "repaired"):
                app.faults = {"abstention"} if name == "regressed" else set()
                report = self.run_plan(plan, name)
                row = report["checks"][0]
                self.assertEqual(row["status"], "failed" if app.faults else "passed", row)
                self.assertEqual(row["metrics"]["classification"]["accuracy"], 0.0 if app.faults else 1.0)
                self.assertEqual(row["metrics"]["decision_evidence"]["correct_abstention_rate"], 0.0 if app.faults else 1.0)
                self.assertAlmostEqual(row["metrics"]["confidence"]["expected_calibration_error"], .4 if app.faults else .01)
                self.assertEqual(row["observed_abstention_rate"], float(bool(app.faults)))
                self.assertEqual(row["population"]["planned_fraction"], .06)
                record_run(db, report)
                if name in {"regressed", "repaired"}:
                    result = trend(db, "sample-app", [rule])
                    write_json(self.evidence / (name + "-trend.json"), result)
                    self.assertEqual(result["status"], "alert" if app.faults else "stable", result)

    def test_stage1_protocol_changes_and_corrupt_history_not_compared(self):
        with fixture.application(self.root) as app:
            plan = self.eval_plan(app)
            db = self.evidence / "history.sqlite"
            for name in ("a", "b", "changed"):
                if name == "changed":
                    config = document(self.root / "decisions.json")
                    config["dataset"]["cases"][0]["input"]["additional_context"] = "new-protocol"
                    write_json(self.root / "decisions.json", config, replace=True)
                    plan["checks"][0]["config_sha256"] = sha256(config)
                record_run(db, self.run_plan(plan, name))
            rule = {"check_id": "decisions", "signal": "classification.accuracy", "direction": "decrease", "delta": .1}
            result = trend(db, "sample-app", [rule])
            self.assertEqual(result["status"], "insufficient_history")
            self.assertEqual(result["rules"][0]["excluded_count"], 2)
            write_json(self.evidence / "comparison.json", result)
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute("UPDATE runs SET digest='tampered'")
            with self.assertRaisesRegex(RunnerError, "integrity"):
                history_runs(db, "sample-app")

    def test_stage1_application_version_change_remains_comparable(self):
        with fixture.application(self.root) as app:
            plan = self.eval_plan(app)
            db = self.evidence / "history.sqlite"
            for index in range(3):
                if index == 2:
                    plan["application_version"] = "next-candidate"
                    config = document(self.root / "decisions.json")
                    config["evaluation"]["subject_version"] = "next-candidate"
                    write_json(self.root / "decisions.json", config, replace=True)
                    plan["checks"][0]["config_sha256"] = sha256(config)
                    app.faults.add("abstention")
                record_run(db, self.run_plan(plan, str(index)))
            result = trend(db, "sample-app", [{"check_id": "decisions", "signal": "classification.accuracy", "direction": "decrease", "delta": .1}])
            write_json(self.evidence / "cross-version.json", result)
            self.assertEqual(result["status"], "alert", result)
            self.assertEqual(result["rules"][0]["baseline_count"], 2)

    def test_stage1_stratified_population_and_no_invented_confidence(self):
        source = {"version": "gold", "cases": [{"case_id": str(i), "input": {"risk": i < 10}, "expected_label": "escalate" if i < 10 else "hold"} for i in range(100)]}
        sampled = sample_population(source, 4, 7)
        self.assertEqual(len(sampled["cases"]), 8)
        self.assertEqual(len({c["case_id"] for c in sampled["cases"]}), 8)
        self.assertEqual(sampled["population"]["class_counts"], {"escalate": 10, "hold": 90})
        self.assertEqual(sampled["cases"], sample_population(source, 4, 7)["cases"])
        write_json(self.evidence / "sample.json", sampled)
        config = decision_config(["classification"])
        write_json(self.root / "labels.json", config)
        with redirect_stdout(io.StringIO()):
            code = main(["run", "--config", str(self.root / "labels.json"), "--out", str(self.evidence / "labels.json"), "--summary-only"])
        self.assertEqual(code, 0)
        metrics = document(self.evidence / "labels.local-report.json")["metrics"]
        self.assertEqual(metrics["classification"]["accuracy"], 1.0)
        self.assertEqual(metrics["confidence"]["measurement_status"], "not_measurable")

    def external_check(self, app, mode="contract"):
        plan = basic_plan(app.url)
        layer = "security" if mode == "security" else "code"
        plan["components"][0]["required_layers"] = [layer]
        plan["checks"] = [{"id": mode, "type": "command", "layer": layer, "component_ids": ["api-health"],
                           "enabled": True, "reviewed": True, "command": [sys.executable, str(FIXTURE), mode, app.url, str(self.root / "junit.xml")],
                           "result_file": "junit.xml", "format": "junit"}]
        return plan

    def test_stage2_real_test_runner_detects_bug_and_repaired_rerun(self):
        with fixture.application(self.root) as app:
            plan = self.external_check(app)
            for name in ("healthy", "bug", "repaired"):
                app.faults = {"contract"} if name == "bug" else set()
                row = self.run_plan(plan, name)["checks"][0]
                self.assertEqual(row["status"], "failed" if app.faults else "passed")
                self.assertEqual(row["case_count"], 2)
                self.assertEqual(row["failed_count"], int(bool(app.faults)))

    def test_stage2_dependency_content_required_not_only_200(self):
        with fixture.application(self.root) as app:
            plan = basic_plan(app.url)
            other = deepcopy(plan["components"][0])
            other.update(id="ledger", name="Ledger", required_layers=["integration"])
            plan["components"].append(other)
            plan["components"][0].update(depends_on=["ledger"], required_layers=["integration"])
            plan["checks"][0].update(layer="integration", component_ids=["api-health", "ledger"], path="/contract", json_assertions=[])
            weak = self.run_plan(plan, "weak")
            self.assertEqual(weak["verdict"], "insufficient_evidence")
            plan["checks"][0]["json_assertions"] = [{"path": "amount", "equals": 10}]
            app.faults.add("contract")
            self.assertEqual(self.run_plan(plan, "broken")["verdict"], "do_not_ship")
            app.faults.clear()
            self.assertEqual(self.run_plan(plan, "repaired")["verdict"], "checks_passed_within_reviewed_scope")

    def test_stage2_empty_skipped_malformed_and_encoded_junit_rejected(self):
        examples = [("<testsuite/>", "blocked"),
                    ("<testsuite><testcase><skipped/></testcase></testsuite>", "blocked"),
                    ("<broken", "error"),
                    ('<!DOCTYPE testsuite [<!ENTITY injected "fake">]><testsuite><testcase name="&injected;"/></testsuite>', "error")]
        for index, (xml, expected) in enumerate(examples):
            for encoding in ("utf-8", "utf-16", "utf-32"):
                with self.subTest(example=index, encoding=encoding):
                    output = self.root / f"results-{index}-{encoding}.xml"
                    script = f"from pathlib import Path; Path({str(output)!r}).write_bytes({xml!r}.encode({encoding!r}))"
                    check = {"command": [sys.executable, "-c", script], "result_file": str(output)}
                    if expected == "error" or encoding == "utf-32":
                        with self.assertRaises(RunnerError):
                            command_check(check, self.root)
                    else:
                        self.assertEqual(command_check(check, self.root)["status"], expected)

    def test_stage2_runner_timeout_is_blocked_not_product_failure(self):
        check = {"command": [sys.executable, "-c", "import time; time.sleep(30)"], "result_file": "never.xml", "timeout_seconds": 1}
        result = command_check(check, self.root)
        write_json(self.evidence / "timeout.json", result)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reason"], "test_runner_timeout")

    def test_stage2_timeout_terminates_owned_child_process(self):
        marker = self.root / "orphan.txt"
        child = f"import time; from pathlib import Path; time.sleep(3); Path({str(marker)!r}).touch()"
        parent = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{child!r}]); time.sleep(30)"
        result = command_check({"command": [sys.executable, "-c", parent], "result_file": "never.xml", "timeout_seconds": 1}, self.root)
        time.sleep(3)
        self.assertEqual(result["reason"], "test_runner_timeout")
        self.assertFalse(marker.exists(), "Owned child survived timeout")
        write_json(self.evidence / "process-cleanup.json", {"timeout": True, "child_marker_absent_after_deadline": True})

    def test_stage3_complete_four_role_allow_deny_matrix_and_leak(self):
        with fixture.application(self.root) as app:
            plan = basic_plan(app.url)
            plan["roles"] = ["admin", "soc_lead", "analyst", "read_only"]
            plan["components"][0]["required_layers"] = ["authorization"]
            plan["checks"] = []
            identities = {}
            for path in ("/records", "/admin"):
                for role in plan["roles"]:
                    variable = "PRED_FIXTURE_" + role.upper()
                    identities[variable] = role
                    allowed = path == "/records" or role == "admin"
                    plan["checks"].append({"id": path[1:] + "_" + role, "type": "http", "layer": "authorization", "component_ids": ["api-health"],
                        "enabled": True, "reviewed": True, "role": role, "headers_from_env": {"Authorization": variable}, "path": path,
                        "expected_status": [200 if allowed else 403], "json_assertions": [{"path": "allowed", "equals": allowed}, {"path": "role", "equals": role}]})
            with patch.dict(os.environ, identities):
                self.assertEqual(self.run_plan(plan, "healthy")["summary"]["checks_executed"], 8)
                app.faults.add("rbac")
                self.assertEqual(self.run_plan(plan, "broken")["summary"]["failed"], 3)
                app.faults.clear()
                self.assertEqual(self.run_plan(plan, "repaired")["verdict"], "checks_passed_within_reviewed_scope")

    def test_stage3_tenant_positive_and_negative_controls(self):
        with fixture.application(self.root) as app:
            plan = basic_plan(app.url)
            plan["roles"] = ["tenant_a", "tenant_b"]
            plan["components"][0]["required_layers"] = ["authorization"]
            plan["checks"] = []
            for tenant in ("a", "b"):
                for owner in ("a", "b"):
                    allowed = tenant == owner
                    plan["checks"].append({"id": tenant + "_reads_" + owner, "type": "http", "layer": "authorization", "component_ids": ["api-health"],
                        "enabled": True, "reviewed": True, "role": "tenant_" + tenant, "headers_from_env": {"X-Tenant": "PRED_TENANT_" + tenant.upper()},
                        "path": "/tenants/" + owner, "expected_status": [200 if allowed else 403],
                        "json_assertions": [{"path": "tenant", "equals": owner}] if allowed else [{"path": "denied", "equals": True}]})
            with patch.dict(os.environ, {"PRED_TENANT_A": "a", "PRED_TENANT_B": "b"}):
                self.assertEqual(self.run_plan(plan, "healthy")["verdict"], "checks_passed_within_reviewed_scope")
                app.faults.add("tenant_leak")
                self.assertEqual(self.run_plan(plan, "broken")["summary"]["failed"], 2)
                app.faults.clear()
                self.assertEqual(self.run_plan(plan, "repaired")["summary"]["failed"], 0)

    def test_stage3_agent_policy_harness_checks_real_tool_events(self):
        with fixture.application(self.root) as app:
            plan = self.external_check(app, "security")
            for name in ("healthy", "injected", "repaired"):
                app.faults = {"injection"} if name == "injected" else set()
                report = self.run_plan(plan, name)
                self.assertEqual(report["checks"][0]["case_count"], 2)
                self.assertEqual(report["checks"][0]["failed_count"], int(bool(app.faults)))

    def test_stage4a_bounded_load_latency_capacity_and_repair(self):
        with fixture.application(self.root) as app:
            plan = basic_plan(app.url)
            plan["components"][0]["required_layers"] = ["reliability"]
            plan["checks"][0].update(type="load", layer="reliability", path="/load", requests=12, concurrency=4, max_p95_ms=5000)
            healthy = self.run_plan(plan, "healthy")["checks"][0]
            self.assertEqual(healthy["status"], "passed")
            self.assertEqual(len(healthy["observations"]), 12)
            self.assertGreater(app.peak, 1)
            self.assertLessEqual(app.peak, 4)
            app.faults.add("capacity")
            overloaded = self.run_plan(plan, "capacity")["checks"][0]
            self.assertEqual(overloaded["status"], "failed")
            self.assertGreater(overloaded["failure_count"], 0)
            self.assertTrue(any(r.get("http_status") == 503 for r in overloaded["observations"]))
            app.faults = {"latency"}
            plan["checks"][0]["max_p95_ms"] = 100
            self.assertEqual(self.run_plan(plan, "latency")["checks"][0]["status"], "failed")
            app.faults.clear()
            plan["checks"][0]["max_p95_ms"] = 5000
            self.assertEqual(self.run_plan(plan, "repaired")["checks"][0]["status"], "passed")

    def test_stage4a_transport_failure_remains_unattributed(self):
        # A closed owned listener provides a genuine refusal, not a fabricated response.
        import socket
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        plan = basic_plan(f"http://127.0.0.1:{port}")
        plan["checks"][0].update(type="load", requests=2, concurrency=1, max_p95_ms=5000, timeout_seconds=1)
        result = load_check(plan, plan["checks"][0])
        write_json(self.evidence / "transport.json", result)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["blocked_count"], 2)
        self.assertFalse(result["evidence_complete"])

    def test_stage4a_dead_letter_health_budget_is_not_adapter_error(self):
        with fixture.application(self.root) as app:
            plan = basic_plan(app.url)
            plan["checks"][0].update(path="/health", json_assertions=[{"path": "dead_letters", "operator": "lte", "value": 0}])
            app.faults.add("dead_letters")
            result = self.run_plan(plan, "bad-health")["checks"][0]
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["assertions"][0]["observed"], 5)
            app.faults.clear()
            self.assertEqual(self.run_plan(plan, "repaired")["checks"][0]["status"], "passed")

    def recovery_plan(self, app):
        plan = basic_plan(app.url)
        plan["isolation_note"] = "Temporary SQLite jobs and an owned local worker; no external integrations"
        plan["components"][0]["required_layers"] = ["reliability"]
        plan["checks"][0].update(type="recovery", layer="reliability", path="/recovery", json_assertions=[{"path": "restored", "equals": True}],
            disruption_expected_status=[503], inject_command=app.control_command("kill"), recover_command=app.control_command("restart"), recovery_timeout_seconds=5)
        return plan

    def test_stage4b_actual_worker_crash_recovery_and_idempotency(self):
        with fixture.application(self.root) as app:
            plan = self.recovery_plan(app)
            old_pid = app.process.pid
            report = self.run_plan(plan, "recovery", disruptive=True)
            self.assertEqual(report["checks"][0]["status"], "passed", report)
            self.assertEqual(report["checks"][0]["disruption_evidence"]["http_status"], 503)
            self.assertNotEqual(old_pid, app.process.pid)
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(lambda _: app.request("/jobs", {"id": "crash-case-1"}), range(12)))
            self.assertEqual(app.jobs(), [{"id": "crash-case-1", "state": "done", "effects": 1}])
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(lambda _: app.request("/jobs", {"id": "concurrent-new-case"}), range(12)))
            app.wait(lambda: all(j["state"] == "done" for j in app.jobs()))
            self.assertEqual(len(app.jobs()), 2)
            self.assertTrue(all(j["effects"] == 1 for j in app.jobs()))
            write_json(self.evidence / "job-observations.json", {"jobs": app.jobs(), "post_completion_retries": 12, "concurrent_new_submissions": 12})

    def test_stage4b_stuck_lease_fails_despite_healthy_worker(self):
        with fixture.application(self.root) as app:
            app.faults.add("stuck_job")
            plan = self.recovery_plan(app)
            plan["checks"][0]["recovery_timeout_seconds"] = 2
            report = self.run_plan(plan, "stuck", disruptive=True)
            self.assertEqual(report["checks"][0]["status"], "failed")
            self.assertEqual(report["checks"][0]["reason"], "recovery_deadline_exceeded")
            self.assertIsNone(app.process.poll())
            self.assertEqual(app.jobs()[0]["state"], "running")
            app.stop_worker()
            app.faults.clear()
            app.start_worker()
            app.wait(lambda: app.jobs()[0]["state"] == "done")
            self.assertEqual(self.run_plan(plan, "repaired", disruptive=True)["checks"][0]["status"], "passed")
            self.assertTrue(all(j["effects"] == 1 and j["state"] == "done" for j in app.jobs()))

    def test_stage4b_no_disruption_without_approval(self):
        with fixture.application(self.root) as app:
            plan = self.recovery_plan(app)
            approve_plan(plan, self.root)
            self.assertFalse(preflight(plan, self.root)["ready"])
            with self.assertRaises(RunnerError):
                execute_system(plan, self.root, self.evidence / "unapproved")
            self.assertEqual(app.calls, [])
            self.assertIsNone(app.process.poll())

    def test_stage4b_cleanup_failure_stops_monitor_and_later_checks(self):
        with fixture.application(self.root) as app:
            plan = self.recovery_plan(app)
            plan["checks"][0].update(inject_command=[sys.executable, "-c", "pass"], recover_command=[sys.executable, "-c", "raise SystemExit(1)"])
            plan["checks"].append({**basic_plan(app.url)["checks"][0], "id": "must-not-run", "path": "/health"})
            approve_plan(plan, self.root, isolated=True, allow_disruption=True)
            write_json(self.root / "plan.json", plan)
            monitor_sleeps = []

            def record_monitor_sleep(seconds):
                if seconds == 60:
                    monitor_sleeps.append(seconds)

            with patch("esx_eval_runner.system_cli.time.sleep", side_effect=record_monitor_sleep), redirect_stdout(io.StringIO()):
                status = main(["system", "monitor", "--plan", str(self.root / "plan.json"), "--out", str(self.evidence / "cycles"),
                    "--history", str(self.evidence / "history.sqlite"), "--cycles", "3", "--interval-seconds", "60"])
            self.assertEqual(status, 2)
            self.assertEqual(monitor_sleeps, [])
            self.assertNotIn("/health", app.calls)
            self.assertEqual(len(history_runs(self.evidence / "history.sqlite", "sample-app")), 1)

    def test_stage0_setup_roundtrip_drafts_and_invalid_requests(self):
        from http.client import HTTPConnection
        from http.server import ThreadingHTTPServer
        from threading import Thread
        from esx_eval_runner.system_engine import plan_digest
        from esx_eval_runner.system_ui import setup_handler
        plan = basic_plan()
        path = self.root / "plan.json"
        approve_plan(plan, self.root)
        write_json(path, plan)
        server = ThreadingHTTPServer(("127.0.0.1", 0), setup_handler(path, "fixture-token"))
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            def post(route, body):
                conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                conn.request("POST", route, json.dumps(body), {"Content-Type": "application/json"})
                response = conn.getresponse()
                data = json.load(response)
                conn.close()
                return response.status, data
            for body in ([], {"token": "fixture-token", "digest": plan_digest(plan), "plan": []}):
                self.assertEqual(post("/save", body)[0], 400)
            for route, extra in (("/component", {"name": "Worker", "module": "Operations"}),
                                 ("/roles", {"roles": ["admin", "read_only"]}),
                                 ("/add", {"kind": "load", "component": "api-health", "id": "draft-load"})):
                current = document(path)
                status, data = post(route, {"token": "fixture-token", "digest": plan_digest(current), "plan": current, **extra})
                self.assertEqual(status, 200, data)
            saved = document(path)
            self.assertNotIn("approval", saved)
            self.assertFalse(saved["inventory_confirmed"])
            self.assertTrue(all(not c["enabled"] for c in saved["checks"] if c["id"] != "health"))
            write_json(self.evidence / "reviewed-drafts.json", saved)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)

    def test_stage0_cli_exit_codes_and_report_contract(self):
        with fixture.application(self.root) as app:
            plan = basic_plan(app.url)
            plan["checks"][0].update(path="/contract", json_assertions=[{"path": "amount", "equals": 10}])
            for name, expected in (("healthy", 0), ("broken", 2), ("repaired", 0)):
                app.faults = {"contract"} if name == "broken" else set()
                approve_plan(plan, self.root)
                write_json(self.root / "plan.json", plan, replace=True)
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    code = main(["system", "run", "--plan", str(self.root / "plan.json"), "--out", str(self.evidence / name)])
                self.assertEqual(code, expected)
                report = document(self.evidence / name / "system-report.json")
                html = (self.evidence / name / "system-report.html").read_text(encoding="utf-8")
                self.assertIn("Health", html)
                self.assertIn("contract_or_content_mismatch" if name == "broken" else "assertions_matched", html)
                self.assertEqual(report["summary"]["checks_executed"], 1)
                self.assertTrue((self.evidence / name / "audit.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
