"""Protected onboarding, untrusted planner output, and real local run comparisons."""

from contextlib import contextmanager, redirect_stdout
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import HTTPConnection
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from unittest.mock import patch

from esx_eval_runner.audit import verify_audit_log
from esx_eval_runner.cli import main
from esx_eval_runner.runner import RunnerError, sha256
from esx_eval_runner.system_assistant import propose, apply_suggestions
from esx_eval_runner.system_changes import compare_reports, attach_comparison, verify_report
from esx_eval_runner.system_cli import write_json
from esx_eval_runner.system_engine import approve_plan, execute_system, preflight, validate_plan, plan_digest, http_check
from esx_eval_runner.system_history import record_run, history_runs, candidate_matches
from esx_eval_runner.system_profile import bootstrap, refresh_profile
from esx_eval_runner.system_safety import guard_output, snapshot_sources, source_diff, protection_blockers
from esx_eval_runner.system_ui import render_report, setup_handler
from test_system_evaluation import reference_app, basic_plan, decision_config


@contextmanager
def model_server(actions):
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            calls.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            action = actions[min(len(calls)-1, len(actions)-1)]
            body = json.dumps({"done": True, "message": {"content": json.dumps(action)}}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


class OnboardingTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "customer"
        self.repo.mkdir()
        self.work = self.root / "pred"
        self.work.mkdir()
        self.source = self.repo / "app.py"
        self.source.write_text("@app.get('/ok')\ndef health(): return {'ready': True}\n", encoding="utf-8")
        self.plan = bootstrap(project="sample-app", version="candidate", repository=str(self.repo))

    def tearDown(self):
        self.temp.cleanup()

    def runnable(self, url):
        plan = deepcopy(self.plan)
        plan.pop("scope_contract")
        plan["inventory_confirmed"] = True
        plan["base_url"] = url
        check = plan["checks"][0]
        check.update(enabled=True, reviewed=True, expected_status=[200], json_assertions=[{"path": "ready", "equals": True}])
        approve_plan(plan, self.work)
        return plan

    def test_bootstrap_reads_source_without_executing_or_writing(self):
        self.source.write_text("raise RuntimeError('never import me')\n@app.get('/ok')\ndef route(): pass\n")
        before = snapshot_sources([self.repo])
        plan = bootstrap(project="sample-app", version="candidate", repository=str(self.repo), roles=["admin", "reader"])
        self.assertEqual(source_diff(before, snapshot_sources([self.repo]))["status"], "unchanged")
        self.assertFalse(plan["inventory_confirmed"])
        self.assertTrue(all(not c["enabled"] for c in plan["checks"]))
        self.assertEqual(plan["roles"], ["admin", "anonymous", "reader"])
        validate_plan(plan, self.work)

    def test_rejects_outputs_inside_application(self):
        with self.assertRaisesRegex(RunnerError, "outside"):
            write_json(self.repo / "plan.json", self.plan)
        self.assertFalse((self.repo / "plan.json").exists())
        with self.assertRaisesRegex(RunnerError, "outside"):
            validate_plan(self.plan, self.repo)
        with self.assertRaisesRegex(RunnerError, "outside"):
            execute_system(self.plan, self.work, self.repo / "out")

    def test_resolved_output_alias_cannot_enter_repository(self):
        alias = self.work / "alias"
        try:
            alias.symlink_to(self.repo, target_is_directory=True)
        except OSError:
            self.skipTest("OS does not allow test symlinks")
        with self.assertRaisesRegex(RunnerError, "outside"):
            guard_output(self.plan, alias / "output.json")

    def test_source_mutation_invalidates_approval_before_dispatch(self):
        with reference_app() as (url, state):
            plan = self.runnable(url)
            self.source.write_text(self.source.read_text() + "# changed\n")
            self.assertFalse(preflight(plan, self.work)["ready"])
            with self.assertRaises(RunnerError):
                execute_system(plan, self.work, self.work / "blocked")
            self.assertEqual(state["calls"], [])

    def test_detected_mutation_stops_later_checks_and_retains_proof(self):
        with reference_app() as (url, state):
            plan = self.runnable(url)
            plan["checks"].append({**deepcopy(plan["checks"][0]), "id": "later"})
            approve_plan(plan, self.work)
            def mutate(*args):
                result = http_check(*args)
                self.source.write_text("# concurrent edit\n")
                return result
            with patch("esx_eval_runner.system_engine.http_check", side_effect=mutate):
                report = execute_system(plan, self.work, self.work / "mutation")
            self.assertEqual(len(state["calls"]), 1)
            self.assertEqual(report["verdict"], "insufficient_evidence")
            self.assertEqual(report["source_integrity"]["status"], "changed")
            self.assertEqual(report["source_integrity"]["files"][0]["path"], "0/app.py")
            self.assertFalse(candidate_matches(report))
            self.assertIn("Source changed", render_report(report))
            verify_report(report)

    def test_incomplete_fingerprint_is_not_a_clean_preflight(self):
        with patch("esx_eval_runner.system_safety.MAX_FILES", 0):
            plan = bootstrap(project="sample-app", version="candidate", repository=str(self.repo))
            self.assertEqual(plan["source_protection"]["snapshot"]["status"], "incomplete")
            self.assertTrue(protection_blockers(plan, self.work))

    def test_custom_commands_are_blocked_under_code_protection(self):
        plan = deepcopy(self.plan)
        plan["checks"] = [{"id": "custom", "type": "command", "layer": "code", "component_ids": [plan["components"][0]["id"]],
                           "enabled": True, "reviewed": True, "command": ["do-not-run"], "result_file": "out.xml"}]
        with self.assertRaisesRegex(RunnerError, "unrestricted"):
            approve_plan(plan, self.work)

    def test_nested_judge_commands_do_not_bypass_protection(self):
        plan = deepcopy(self.plan)
        config = decision_config()
        config["adapter"] = {"type": "http_json_target"}
        config["assurance"] = {"grounding_judge": {"command": ["not-executed"]}}
        write_json(self.work / "eval.json", config)
        plan["checks"] = [{"id": "ai", "type": "evaluation", "enabled": True, "config": "eval.json"}]
        self.assertTrue(any("judges" in s for s in protection_blockers(plan, self.work)))

    def test_refresh_preserves_custom_assertions_and_removed_components_as_gaps(self):
        plan = deepcopy(self.plan)
        plan["checks"][0].update(enabled=True, reviewed=True, expected_status=[200], json_assertions=[{"path": "ready", "equals": True}])
        plan["components"][0]["module"] = "my-owner-group"
        original_id = plan["components"][0]["id"]
        self.source.write_text("@app.get('/new')\ndef route(): pass\n")
        refreshed = refresh_profile(plan)
        previous = next(c for c in refreshed["components"] if c["id"] == original_id)
        self.assertTrue(previous["not_rediscovered"])
        self.assertEqual(previous["module"], "my-owner-group")
        self.assertEqual(refreshed["checks"][0]["json_assertions"], plan["checks"][0]["json_assertions"])
        self.assertFalse(refreshed["checks"][0]["enabled"])
        self.assertEqual(len(refreshed["profile_changes"]["added_components"]), 1)
        self.assertNotIn("approval", refreshed)
        validate_plan(refreshed, self.work)

    def test_changed_openapi_expectations_disable_affected_check(self):
        spec = self.work / "openapi.json"
        contract = {"openapi": "3.0.0", "paths": {"/ok": {"get": {"responses": {"200": {"description": "ready"}}}}}}
        write_json(spec, contract)
        plan = bootstrap(project="sample-app", version="candidate", openapi=str(spec))
        plan["checks"][0].update(enabled=True, reviewed=True)
        contract["paths"]["/ok"]["get"]["responses"] = {"204": {"description": "empty"}}
        write_json(spec, contract, replace=True)
        refreshed = refresh_profile(plan)
        self.assertTrue(refreshed["profile_changes"]["changed_components"])
        self.assertFalse(refreshed["checks"][0]["enabled"])
        self.assertEqual(refreshed["checks"][0]["expected_status"], [200])
        self.assertFalse(refreshed["scope_contract"]["policy_reviewed"])

    def test_agent_cannot_use_application_as_model_endpoint(self):
        self.plan["base_url"] = "http://127.0.0.1:12345"
        with self.assertRaisesRegex(RunnerError, "separate"):
            propose(self.plan, model="fixture", endpoint=self.plan["base_url"])

    def test_model_inspection_loop_is_metadata_only_and_proposal_requires_review(self):
        key = self.plan["components"][0]["id"]
        suggestion = {"component_id": key, "module": "health", "layer": "functional", "title": "Health reports ready", "reason": "Check returned readiness content"}
        with model_server([{"action": "inspect_components", "ids": [key]}, {"action": "propose", "suggestions": [suggestion]}]) as (url, calls):
            proposal = propose(self.plan, model="fixture-model", endpoint=url)
        self.assertEqual(len(calls), 2)
        self.assertNotIn(str(self.repo), json.dumps(calls))
        self.assertNotIn("def health", json.dumps(calls))
        self.assertEqual(proposal["producer"], "local_model")
        updated = apply_suggestions(self.plan, proposal, [proposal["suggestions"][0]["id"]])
        self.assertTrue(all(not c["enabled"] for c in updated["checks"]))
        self.assertTrue(all(not o["reviewed"] for o in updated["scope_contract"]["objectives"]))
        validate_plan(updated, self.work)

    def test_business_context_drafts_reviewable_rule_objectives(self):
        key = self.plan["components"][0]["id"]
        context = {"rules": [{
            "id": "BR-queue-approval",
            "title": "Queue approvals require reviewed state",
            "expected_behavior": "A queue item can move to approved only after the reviewed flag is true.",
            "component_ids": [key],
            "layers": ["functional", "authorization"],
            "actors": ["analyst"],
            "entities": ["queue_item"],
            "states": ["pending", "reviewed", "approved"],
            "permissions": ["approve_queue_item"],
            "expected_outcomes": ["approved item has reviewed=true"],
            "negative_outcomes": ["unreviewed item cannot be approved"],
            "source": "sanitized-product-policy",
            "risk": "high",
            "reviewed": True,
        }]}
        proposal = propose(self.plan, business_context=context)
        self.assertEqual(proposal["business_logic_model"]["rule_count"], 1)
        self.assertEqual(proposal["unaddressed_business_rule_ids"], [])
        self.assertTrue(all(row["business_rule_id"] == "BR-queue-approval" for row in proposal["suggestions"]))
        updated = apply_suggestions(self.plan, proposal, [row["id"] for row in proposal["suggestions"]])
        drafted = [row for row in updated["scope_contract"]["objectives"] if row.get("business_rule_id") == "BR-queue-approval"]
        self.assertEqual(len(drafted), 2)
        self.assertTrue(all(not row["reviewed"] and not row["check_id"] for row in drafted))
        self.assertTrue(all("reviewed flag" in row["expected_business_behavior"] for row in drafted))
        self.assertEqual(updated["business_logic"]["accepted_rule_ids"], ["BR-queue-approval"])
        self.assertEqual(updated["business_logic"]["source_sha256"], proposal["business_logic_model"]["source_sha256"])
        validate_plan(updated, self.work)

    def test_business_context_rejects_unknown_component_and_fields(self):
        with self.assertRaisesRegex(RunnerError, "unknown components"):
            propose(self.plan, business_context={"rules": [{
                "id": "BR-bad", "title": "Bad", "expected_behavior": "Bad rule",
                "component_ids": ["missing"], "layers": ["functional"],
            }]})
        key = self.plan["components"][0]["id"]
        with self.assertRaisesRegex(RunnerError, "unsupported fields"):
            propose(self.plan, business_context={"rules": [{
                "id": "BR-extra", "title": "Extra", "expected_behavior": "Bad rule",
                "component_ids": [key], "layers": ["functional"], "auto_approve": True,
            }]})

    def test_model_cannot_invent_business_rule_metadata_without_context(self):
        key = self.plan["components"][0]["id"]
        suggestion = {"component_id": key, "module": "health", "layer": "functional",
                      "title": "Health reports ready", "reason": "Check returned readiness content",
                      "business_rule_id": "invented"}
        with model_server([{"action": "propose", "suggestions": [suggestion]}]) as (url, _):
            with self.assertRaisesRegex(RunnerError, "without approved business context"):
                propose(self.plan, model="fixture-model", endpoint=url)

    def test_prompt_injection_cannot_grant_agent_commands(self):
        with model_server([{"action": "execute", "command": ["touch", "app.py"]}]) as (url, calls):
            with self.assertRaisesRegex(RunnerError, "forbidden"):
                propose(self.plan, model="fixture-model", endpoint=url)
        self.assertEqual(len(calls), 1)
        self.assertIn("def health", self.source.read_text())

    def test_model_turn_budget_is_enforced(self):
        key = self.plan["components"][0]["id"]
        with model_server([{"action": "inspect_components", "ids": [key]}]) as (url, calls):
            with self.assertRaisesRegex(RunnerError, "turn limit"):
                propose(self.plan, model="fixture-model", endpoint=url, max_turns=2)
            self.assertEqual(len(calls), 2)

    def test_remote_planning_endpoint_rejected(self):
        with self.assertRaisesRegex(RunnerError, "loopback"):
            propose(self.plan, model="fixture", endpoint="https://remote.example")

    def test_stale_and_tampered_proposals_are_rejected(self):
        proposal = propose(self.plan)
        selected = [proposal["suggestions"][0]["id"]]
        changed = deepcopy(self.plan)
        changed["application_version"] = "changed"
        with self.assertRaisesRegex(RunnerError, "Plan changed"):
            apply_suggestions(changed, proposal, selected)
        proposal["suggestions"][0]["title"] = "tampered"
        with self.assertRaisesRegex(RunnerError, "integrity"):
            apply_suggestions(self.plan, proposal, selected)

    def test_proposal_limit_discloses_unaddressed_inventory(self):
        plan = deepcopy(self.plan)
        plan["components"] = [{**deepcopy(plan["components"][0]), "id": "c-" + str(i)} for i in range(105)]
        proposal = propose(plan)
        self.assertEqual(len(proposal["suggestions"]), 100)
        self.assertEqual(proposal["suggested_component_count"], 100)
        self.assertEqual(len(proposal["unaddressed_component_ids"]), 5)

    def test_model_cannot_add_unknown_fields_or_components(self):
        suggestion = {"component_id": "fabricated", "module": "x", "layer": "functional", "title": "x", "reason": "x"}
        with model_server([{"action": "propose", "suggestions": [suggestion]}]) as (url, _):
            with self.assertRaisesRegex(RunnerError, "unknown"):
                propose(self.plan, model="fixture-model", endpoint=url)
        suggestion["component_id"] = self.plan["components"][0]["id"]
        suggestion["enabled"] = True
        with model_server([{"action": "propose", "suggestions": [suggestion]}]) as (url, _):
            with self.assertRaisesRegex(RunnerError, "unsupported"):
                propose(self.plan, model="fixture-model", endpoint=url)

    def test_real_run_baseline_regression_and_history(self):
        with reference_app() as (url, state):
            plan = self.runnable(url)
            before = execute_system(plan, self.work, self.work / "before")
            state["ready"] = False
            after = execute_system(plan, self.work, self.work / "after")
        comparison = attach_comparison(after, before)
        self.assertEqual(comparison["summary"]["regressions"], 1)
        self.assertEqual(after["source_integrity"]["status"], "unchanged")
        self.assertIn("1 regressions", render_report(after))
        verify_report(after)
        record_run(self.work / "history.sqlite", before)
        record_run(self.work / "history.sqlite", after)
        self.assertEqual(len(history_runs(self.work / "history.sqlite", "sample-app")), 2)

    def test_changed_protocol_and_declared_metrics_do_not_become_regressions(self):
        with reference_app() as (url, _):
            plan = self.runnable(url)
            before = execute_system(plan, self.work, self.work / "before")
            after = execute_system(plan, self.work, self.work / "after")
        before["checks"][0]["metrics"] = {"groundedness": {"measurement_status": "measured", "trust_status": "declared", "score": 1}}
        after["checks"][0]["metrics"] = {"groundedness": {"measurement_status": "measured", "trust_status": "declared", "score": 0}}
        for report in (before, after):
            report["report_sha256"] = sha256({k: v for k, v in report.items() if k != "report_sha256"})
        self.assertFalse(compare_reports(before, after)["checks"][0]["metric_deltas"])
        after["checks"][0].update(comparison_sha256="changed-protocol", status="failed")
        after["report_sha256"] = sha256({k: v for k, v in after.items() if k != "report_sha256"})
        compared = compare_reports(before, after)
        self.assertEqual(compared["summary"]["regressions"], 0)
        self.assertEqual(compared["summary"]["incomparable_checks"], 1)

    def test_cli_bootstrap_assist_accept_refresh_audit(self):
        path, proposal_path = self.work / "plan.json", self.work / "proposal.json"
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["system", "bootstrap", "--project", "sample-app", "--version", "candidate", "--repo", str(self.repo), "--out", str(path)]), 0)
            self.assertEqual(main(["system", "assist", "--plan", str(path), "--out", str(proposal_path)]), 0)
            proposal = json.loads(proposal_path.read_text())
            self.assertEqual(main(["system", "accept", "--plan", str(path), "--proposal", str(proposal_path), "--suggestion", proposal["suggestions"][0]["id"]]), 0)
            self.assertEqual(main(["system", "refresh", "--plan", str(path)]), 0)
        self.assertEqual(verify_audit_log(path.with_suffix(".audit.jsonl"))["record_count"], 4)

    def test_cli_assist_accepts_business_context_file(self):
        path, proposal_path, context_path = self.work / "plan.json", self.work / "proposal.json", self.work / "business.json"
        write_json(path, self.plan)
        write_json(context_path, {"rules": [{
            "id": "BR-health-ready",
            "title": "Health endpoint reports readiness",
            "expected_behavior": "The health endpoint reports ready only when dependencies are usable.",
            "component_ids": [self.plan["components"][0]["id"]],
            "layers": ["functional"],
            "expected_outcomes": ["ready is true"],
        }]})
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["system", "assist", "--plan", str(path), "--business-context", str(context_path), "--out", str(proposal_path)]), 0)
        proposal = json.loads(proposal_path.read_text())
        self.assertEqual(proposal["business_logic_model"]["rule_count"], 1)
        self.assertEqual(proposal["suggestions"][0]["business_rule_id"], "BR-health-ready")

    def test_setup_refuses_policy_removal_and_accepts_template_review(self):
        path = self.work / "plan.json"
        write_json(path, self.plan)
        server = ThreadingHTTPServer(("127.0.0.1", 0), setup_handler(path, "token"))
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            def post(action, submitted, **extra):
                conn = HTTPConnection("127.0.0.1", server.server_port)
                body = {"token": "token", "digest": plan_digest(json.loads(path.read_text())), "plan": submitted, **extra}
                conn.request("POST", "/" + action, json.dumps(body), {"Content-Type": "application/json"})
                response = conn.getresponse()
                result = json.loads(response.read())
                conn.close()
                return response.status, result
            tampered = deepcopy(self.plan)
            tampered.pop("source_protection")
            self.assertEqual(post("save", tampered)[0], 400)
            status, result = post("assist", self.plan)
            self.assertEqual(status, 200)
            status, saved = post("accept", result["plan"], proposal=result["proposal"], selected=[result["proposal"]["suggestions"][0]["id"]])
            self.assertEqual(status, 200)
            self.assertTrue(saved["plan"]["assistant_review"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)


if __name__ == "__main__":
    unittest.main()
