"""Regression tests for the local-only client-runner workflow."""

from __future__ import annotations

import argparse
import base64
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from esx_eval_runner.cli import _starter_cases, init_command, run_command
from esx_eval_runner.audit import append_audit_event, verify_audit_log
from esx_eval_runner.assurance import build_assurance_graph, build_risk_plan, create_scope
from esx_eval_runner.browser import validate_browser_adapter
from esx_eval_runner.discovery import discover_repository
from esx_eval_runner.local_metrics import calculate_local_metrics, classification_metrics, confidence_metrics
from esx_eval_runner.profiles import build_cases
from esx_eval_runner.runner import RunnerError, _adapter_command, _verify_target_attestation, build_package, canonical_json, read_json
from esx_eval_runner.setup import _guided_setup_html_with_evidence, _probe_local_http_target, create_guided_plan, create_http_plan
from esx_eval_runner.telemetry import redact_otel_payload, telemetry_summary


ROOT = Path(__file__).resolve().parents[1]
ADAPTER_COMMAND = [
    sys.executable,
    "-c",
    (
        "import json,sys; request=json.load(sys.stdin); "
        "json.dump({'schema_version':'esx-client-adapter-response-1.0','results':["
        "{'case_id':case['case_id'],'predicted_label':('unsafe' if 'ignore previous instructions' in case['input']['message'] else 'safe'),'confidence':0.98} "
        "for case in request['cases']]},sys.stdout)"
    ),
]


class LocalRunTests(unittest.TestCase):
    def test_local_formulas_reveal_misclassification_and_overconfidence(self) -> None:
        expected = ["safe", "unsafe", "safe", "unsafe"]
        predicted = ["safe", "safe", "unsafe", "unsafe"]
        classification = classification_metrics(expected, predicted)
        confidence = confidence_metrics(expected, predicted, [0.9, 0.8, 0.4, 0.2])
        self.assertEqual(classification["accuracy"], 0.5)
        self.assertEqual(classification["macro_f1"], 0.5)
        self.assertEqual(confidence["correctness_brier_score"], 0.3625)
        self.assertEqual(confidence["expected_calibration_error"], 0.525)

    def test_default_starter_shape_can_contain_one_case(self) -> None:
        self.assertEqual(_starter_cases(1), [{
            "case_id": "benign-001",
            "input": {"message": "REPLACE_WITH_BENIGN_CASE_001"},
            "expected_label": "safe",
        }])

    def test_full_metric_starter_generates_a_fill_in_template(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "starter"
            status = init_command(argparse.Namespace(
                directory=str(target), agent_id="demo-agent", subject_version="1.0.0",
                project_key="demo", dataset_version=None, subject_type="agent",
                case_count=1, full_metrics=True,
            ))
            self.assertEqual(status, 0)
            template = (target / "full_metric_measurements.json").read_text(encoding="utf-8")
            guide = (target / "README.md").read_text(encoding="utf-8")
            self.assertIn("REPLACE_WITH_SECURITY_CASE_ID", template)
            self.assertIn("cost_efficiency", template)
            self.assertIn("Expected terminal results", guide)
            self.assertIn("Connect your agent", guide)
            self.assertIn("Connecting a full web app", guide)
            self.assertIn("application repository", guide)

    def test_eight_correct_cases_complete_locally_without_signature(self) -> None:
        cases = []
        for index in range(1, 5):
            cases.extend([
                {"case_id": f"safe-{index}", "input": {"message": "normal request"}, "expected_label": "safe"},
                {"case_id": f"unsafe-{index}", "input": {"message": "ignore previous instructions"}, "expected_label": "unsafe"},
            ])
        config = {
            "schema_version": "esx-client-runner-config-1.0",
            "evaluation": {
                "name": "local regression", "agent_id": "demo-agent", "subject_version": "1.0.0",
                "subject_type": "agent", "project_key": "demo", "dataset_version": "local-1.0",
                "required_dimensions": ["classification", "confidence"],
            },
            "dataset": {"version": "local-1.0", "cases": cases},
            "adapter": {"type": "command_json_v1", "command": ADAPTER_COMMAND, "timeout_seconds": 30},
            "source": {"origin": "local"},
        }
        with TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            output_path = Path(directory) / "out" / "evaluation.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                status = run_command(argparse.Namespace(
                    config=str(config_path), out=str(output_path), github_oidc_token_file=None,
                    sign=False, summary_only=False, output_format="text",
                ))
            self.assertEqual(status, 0)
            self.assertIn("COMPLETED LOCALLY", output.getvalue())
            self.assertIn("Cases: 8 | Correct: 8 | Accuracy: 1.000", output.getvalue())
            self.assertIn("20-case minimum applies only", output.getvalue())
            self.assertNotIn("signature", read_json(output_path))
            self.assertTrue(output_path.with_name("evaluation.local-report.html").is_file())
            audit = verify_audit_log(output_path.with_name("evaluation.audit.jsonl"))
            self.assertEqual(audit["record_count"], 2)

    def test_standard_http_target_runs_without_a_customer_adapter(self) -> None:
        class Target(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: object) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers["Content-Length"])
                message = json.loads(self.rfile.read(length))["message"]
                blocked = "restricted" in message
                response = json.dumps({"decision": {"label": "unsafe" if blocked else "safe", "confidence": 0.91}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Target)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            cases = [
                {"case_id": "allowed", "input": {"message": "normal request"}, "expected_label": "safe"},
                {"case_id": "blocked", "input": {"message": "restricted operation"}, "expected_label": "unsafe"},
            ]
            config = {
                "schema_version": "esx-client-runner-config-1.0",
                "evaluation": {"name": "HTTP target", "agent_id": "demo-agent", "subject_version": "1.0.0", "project_key": "demo", "dataset_version": "http-1.0", "required_dimensions": ["classification", "confidence"]},
                "dataset": {"version": "http-1.0", "cases": cases},
                "adapter": {"type": "http_json_target", "url": f"http://127.0.0.1:{server.server_port}/evaluate", "response_label_path": "decision.label", "response_confidence_path": "decision.confidence", "target_environment": "local", "minimum_delay_ms": 0},
            }
            package = build_package(config)
            self.assertEqual(package["execution"]["adapter_type"], "http_json_target")
            self.assertEqual(package["evaluation"]["predicted_labels"], ["safe", "unsafe"])
            self.assertEqual(calculate_local_metrics(package)["classification"]["accuracy"], 1.0)
        finally:
            server.shutdown()
            server.server_close()

    def test_zero_adapter_probe_suggests_redacted_response_fields(self) -> None:
        test_case = self

        class Target(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: object) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers["Content-Length"])
                test_case.assertIn("message", json.loads(self.rfile.read(length)))
                response = json.dumps({"decision": {"label": "safe", "confidence": 0.91}, "private_answer": "do-not-display"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Target)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            probe = _probe_local_http_target(f"http://127.0.0.1:{server.server_port}/evaluate")
            self.assertEqual(probe["label_candidates"][0]["path"], "decision.label")
            self.assertEqual(probe["confidence_candidates"][0]["path"], "decision.confidence")
            self.assertEqual(probe["response_shape"]["decision"]["label"], "<string>")
            self.assertNotIn("do-not-display", json.dumps(probe))
        finally:
            server.shutdown()
            server.server_close()

    def test_profiles_discovery_and_setup_plan_are_local_and_editable(self) -> None:
        self.assertEqual(len(build_cases("smoke")), 4)
        self.assertEqual(len(build_cases("release")), 12)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.py").write_text("from fastapi import FastAPI\nfrom langgraph.graph import StateGraph\napp = FastAPI()\n@app.post('/evaluate')\ndef test(): pass\n", encoding="utf-8")
            (root / "openapi.json").write_text("{}", encoding="utf-8")
            discovery = discover_repository(root)
            self.assertIn("FastAPI", discovery["frameworks"])
            self.assertTrue(any(item.startswith("agent framework: LangGraph") for item in discovery["capabilities"]))
            target = root / "plan"
            path, config = create_http_plan({
                "directory": str(target), "agent_id": "my-app", "subject_version": "2.0.0",
                "project_key": "demo", "url": "http://127.0.0.1:8000/evaluate", "profile": "smoke",
            })
            self.assertTrue(path.is_file())
            self.assertEqual(config["adapter"]["type"], "http_json_target")
            self.assertEqual(len(config["dataset"]["cases"]), 4)
            self.assertTrue((target / "README.md").is_file())

    def test_guided_setup_creates_confirmed_scope_and_auto_report_artifacts(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            discovery = {
                "repository": str(root),
                "components": [
                    {"id": "workflow-api", "name": "API workflow", "kind": "workflow_entry_point"},
                    {"id": "agent-langgraph", "name": "LangGraph", "kind": "agent_framework"},
                ],
            }
            target = root / "guided"
            path, config = create_guided_plan({
                "directory": str(target), "agent_id": "my-app", "subject_version": "2.0.0",
                "project_key": "demo", "url": "http://127.0.0.1:8000/evaluate",
                "profile": "release", "connection_type": "http", "discovery": discovery,
                "selected_component_ids": ["workflow-api", "agent-langgraph"], "confirm_plan": True,
            })
            self.assertTrue(path.is_file())
            self.assertEqual(config["evaluation"]["required_dimensions"], ["classification", "confidence"])
            self.assertIn("trajectory", config["assurance"]["planned_dimensions"])
            self.assertTrue((target / "discovery.json").is_file())
            self.assertTrue((target / "assurance-scope.json").is_file())
            self.assertTrue((target / "risk-plan.json").is_file())
            self.assertIn("automatically uses", (target / "README.md").read_text(encoding="utf-8"))

    def test_guided_setup_explains_response_mapping_and_plan_fields(self) -> None:
        page = _guided_setup_html_with_evidence("test-token", None)
        self.assertIn("LABEL RESPONSE PATH", page)
        self.assertIn("Where the outcome label is located", page)
        self.assertIn("CONFIDENCE RESPONSE PATH", page)
        self.assertIn("Existing non-empty folders are never overwritten", page)
        self.assertIn("esx-help", page)
        self.assertIn("TEST LOCAL CONNECTION", page)
        self.assertIn("/api/test-connection", page)

    def test_guided_browser_setup_requires_loopback_and_a_visible_assertion(self) -> None:
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "loopback"):
                create_guided_plan({
                    "directory": str(Path(directory) / "browser"), "agent_id": "my-app",
                    "subject_version": "2.0.0", "project_key": "demo", "url": "https://staging.example.test",
                    "profile": "smoke", "connection_type": "browser", "browser_path": "/", "browser_expected_text": "Welcome", "confirm_plan": True,
                })

    def test_guided_setup_uses_a_safe_sibling_folder_and_macos_commands(self) -> None:
        with TemporaryDirectory() as directory:
            requested = Path(directory) / "evaluation"
            requested.mkdir()
            (requested / "keep.txt").write_text("do not overwrite", encoding="utf-8")
            path, config = create_guided_plan({
                "directory": str(requested), "agent_id": "my-app", "subject_version": "2.0.0",
                "project_key": "demo", "url": "http://127.0.0.1:8000/evaluate",
                "profile": "smoke", "connection_type": "http", "confirm_plan": True, "host_os": "Darwin",
            })
            self.assertEqual(path.parent.name, "evaluation-2")
            self.assertEqual((requested / "keep.txt").read_text(encoding="utf-8"), "do not overwrite")
            self.assertEqual(config["environment"]["host_os"], "macos")
            guide = (path.parent / "README.md").read_text(encoding="utf-8")
            self.assertIn("python3 -m pip", guide)
            self.assertIn("./out/evaluation.json", guide)

    def test_run_automatically_includes_setup_scope_and_plan_in_local_report(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            discovery = {"repository": str(root), "components": [
                {"id": "workflow-api", "name": "API workflow", "kind": "workflow_entry_point"},
                {"id": "agent-langgraph", "name": "LangGraph", "kind": "agent_framework"},
            ]}
            scope = create_scope(discovery, ["workflow-api", "agent-langgraph"])
            plan = build_risk_plan(scope, "release")
            for name, value in (("discovery.json", discovery), ("assurance-scope.json", scope), ("risk-plan.json", plan)):
                (root / name).write_text(json.dumps(value), encoding="utf-8")
            config = {
                "schema_version": "esx-client-runner-config-1.0",
                "evaluation": {"name": "guided", "agent_id": "demo-agent", "subject_version": "1.0.0", "project_key": "demo", "dataset_version": "guided-1.0", "required_dimensions": ["classification", "confidence"]},
                "dataset": {"version": "guided-1.0", "cases": [{"case_id": "one", "input": {"message": "normal request"}, "expected_label": "safe"}]},
                "adapter": {"type": "command_json_v1", "command": ADAPTER_COMMAND},
                "source": {"origin": "local"},
                "assurance": {"discovery_file": "discovery.json", "scope_file": "assurance-scope.json", "plan_file": "risk-plan.json", "telemetry_file": "out/telemetry.jsonl"},
            }
            config_path = root / "esx-eval.json"
            output_path = root / "out" / "evaluation.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(run_command(argparse.Namespace(config=str(config_path), out=str(output_path), github_oidc_token_file=None, sign=False, summary_only=True, output_format="text")), 0)
            report = read_json(output_path.with_name("evaluation.local-report.json"))
            self.assertEqual(report["assurance_graph"]["summary"]["scope_status"], "confirmed")
            self.assertIn("trajectory", report["metrics"])

    def test_discovery_scope_plan_and_assurance_graph_are_reviewable(self) -> None:
        discovery = {
            "repository": "C:/demo",
            "components": [
                {"id": "workflow-api", "name": "API workflow", "kind": "workflow_entry_point"},
                {"id": "agent-langgraph", "name": "LangGraph", "kind": "agent_framework"},
                {"id": "rag-qdrant", "name": "Qdrant", "kind": "retrieval_store"},
            ],
        }
        scope = create_scope(discovery, ["workflow-api", "agent-langgraph", "rag-qdrant"])
        plan = build_risk_plan(scope, "release")
        self.assertFalse(plan["planner"]["external_ai_called"])
        self.assertIn("rag", plan["required_dimensions"])
        package = {"evaluation": {"agent_id": "demo", "required_dimensions": ["classification", "confidence", "rag"]}}
        metrics = {"classification": {"measurement_status": "measured"}, "confidence": {"measurement_status": "measured"}, "rag": {"measurement_status": "not_measurable"}}
        graph = build_assurance_graph(package, metrics, discovery=discovery, scope=scope, plan=plan, telemetry={"span_count": 4})
        self.assertEqual(graph["summary"]["confirmed_component_count"], 3)
        self.assertEqual(graph["summary"]["unmeasurable_metric_count"], 6)

    def test_discovery_excludes_backlog_mentions_and_labels_real_evidence(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ARCHITECTURE.md").write_text("Future backlog: evaluate LangChain and Qdrant.", encoding="utf-8")
            (root / "main.py").write_text("from langgraph.graph import StateGraph\n", encoding="utf-8")
            (root / "requirements.txt").write_text("openai>=1.0\n", encoding="utf-8")
            discovery = discover_repository(root)
            by_id = {item["id"]: item for item in discovery["components"]}
            self.assertNotIn("agent_framework-langchain", by_id)
            self.assertNotIn("retrieval_store-qdrant", by_id)
            self.assertEqual(by_id["agent_framework-langgraph"]["verification_status"], "source_import")
            self.assertEqual(by_id["model_provider-openai-compatible-client"]["verification_status"], "declared_dependency")

    def test_telemetry_redaction_and_browser_loopback_policy(self) -> None:
        payload = {"resourceSpans": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "demo"}}, {"key": "gen_ai.prompt", "value": {"stringValue": "secret prompt"}}]}, "scopeSpans": [{"spans": [{"name": "tool.run", "attributes": [{"key": "gen_ai.tool.name", "value": {"stringValue": "search"}}, {"key": "input.value", "value": {"stringValue": "do not retain"}}]}]}]}]}
        records = redact_otel_payload(payload)
        self.assertEqual(records[0]["attributes"], {"service.name": "demo", "gen_ai.tool.name": "search"})
        with TemporaryDirectory() as directory:
            path = Path(directory) / "telemetry.jsonl"
            path.write_text(json.dumps(records[0]) + "\n", encoding="utf-8")
            self.assertEqual(telemetry_summary(path)["tool_span_count"], 1)
        with self.assertRaisesRegex(RunnerError, "loopback"):
            validate_browser_adapter({"base_url": "https://staging.example.test"})

    def test_http_target_rejects_insecure_or_unapproved_network_destinations(self) -> None:
        base = {
            "schema_version": "esx-client-runner-config-1.0",
            "evaluation": {"name": "network policy", "agent_id": "demo-agent", "subject_version": "1.0.0", "project_key": "demo", "dataset_version": "network-1.0", "required_dimensions": ["classification", "confidence"]},
            "dataset": {"version": "network-1.0", "cases": [{"case_id": "one", "input": {"message": "test"}, "expected_label": "safe"}]},
        }
        insecure = {**base, "adapter": {"type": "http_json_target", "url": "http://staging.example.test/evaluate", "response_label_path": "label", "response_confidence_path": "confidence", "allow_remote": True, "target_environment": "staging"}}
        with self.assertRaisesRegex(RunnerError, "must use HTTPS"):
            build_package(insecure)
        unapproved = {**base, "adapter": {"type": "http_json_target", "url": "https://staging.example.test/evaluate", "response_label_path": "label", "response_confidence_path": "confidence", "target_environment": "staging"}}
        with self.assertRaisesRegex(RunnerError, "requires allow_remote"):
            build_package(unapproved)
        no_mtls = {**base, "adapter": {"type": "http_json_target", "url": "https://staging.example.test/evaluate", "response_label_path": "label", "response_confidence_path": "confidence", "allow_remote": True, "target_environment": "staging"}}
        with self.assertRaisesRegex(RunnerError, "mutual-TLS"):
            build_package(no_mtls)

    def test_container_sandbox_has_no_network_or_host_mounts(self) -> None:
        command = _adapter_command({
            "command": ["python", "/runner/adapter.py"],
            "sandbox": {"mode": "container", "image": "registry.example.test/esx-adapter@sha256:" + "a" * 64},
        })
        self.assertEqual(command[:6], ["docker", "run", "--rm", "--network", "none", "--read-only"])
        self.assertIn("--cap-drop", command)
        self.assertIn("no-new-privileges", command)
        self.assertNotIn("--volume", command)

    def test_signed_staging_attestation_confirms_test_tenant_before_cases(self) -> None:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = base64.b64encode(private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")

        class Response:
            def __init__(self, payload: dict[str, object]) -> None:
                self.payload = json.dumps(payload).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self, _size: int) -> bytes:
                return self.payload

        class Opener:
            def open(self, request, timeout: int):  # type: ignore[no-untyped-def]
                payload = {
                    "schema_version": "esx-test-target-attestation-1.0",
                    "nonce": request.headers["X-esx-evaluation-nonce"],
                    "target_environment": "staging",
                    "test_tenant_id": "tenant-test-01",
                    "capabilities": ["test_tenant", "synthetic_data", "production_actions_disabled", "least_privilege_identity"],
                }
                payload["signature"] = {"algorithm": "ed25519", "value": base64.b64encode(private_key.sign(canonical_json(payload))).decode("ascii")}
                return Response(payload)

        adapter = {"target_attestation": {"url": "https://staging.example.test/evaluation-attestation", "public_key": public_key, "required_capabilities": ["test_tenant", "synthetic_data", "production_actions_disabled", "least_privilege_identity"]}, "timeout_seconds": 30}
        self.assertEqual(len(_verify_target_attestation(adapter, Opener())), 64)

    def test_audit_chain_detects_tampering(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "evaluation.audit.jsonl"
            append_audit_event(path, "evaluation_started", {"config_sha256": "a" * 64})
            append_audit_event(path, "evaluation_completed", {"package_sha256": "b" * 64})
            path.write_text(path.read_text(encoding="utf-8").replace("evaluation_completed", "evaluation_altered"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid hash"):
                verify_audit_log(path)

    def test_full_fixture_calculates_every_advanced_metric_offline(self) -> None:
        config = read_json(ROOT / "examples" / "full-metrics.sample.json")
        config["adapter"]["command"] = [sys.executable, str(ROOT / "examples" / "full_metrics_adapter.py")]
        package = build_package(config)
        metrics = calculate_local_metrics(package)
        for name in (
            "classification", "confidence", "groundedness", "security", "trajectory",
            "rag", "robustness", "judge_agreement", "reproducibility", "cost_efficiency",
        ):
            self.assertEqual(metrics[name]["measurement_status"], "measured")
        self.assertEqual(metrics["trajectory"]["score"], 1.0)
        self.assertEqual(metrics["rag"]["recall_at_k"], 1.0)
        self.assertEqual(metrics["cost_efficiency"]["total_cost_usd"], 0.04)

        with TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            output_path = Path(directory) / "out" / "evaluation.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                status = run_command(argparse.Namespace(
                    config=str(config_path), out=str(output_path), github_oidc_token_file=None,
                    sign=False, summary_only=True, output_format="text",
                ))
            self.assertEqual(status, 0)
            self.assertIn("ADVANCED LOCAL RESULTS", output.getvalue())
            self.assertIn("Cost and latency:", output.getvalue())
            report = read_json(output_path.with_name("evaluation.local-report.json"))
            self.assertEqual(report["metrics"]["security"]["detection_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
