"""Generate actual system reports from a disposable, deliberately failing fixture.

This is synthetic reference data, not an evaluation of a customer's application.
Run: python examples/system_reference_demo.py --out <new-directory>
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from threading import Thread

from esx_eval_runner.system_cli import bind_evaluation, write_json
from esx_eval_runner.system_engine import approve_plan, execute_system
from esx_eval_runner.system_history import record_run, trend
from esx_eval_runner.system_inventory import discover_system
from esx_eval_runner.system_ui import render_report


def generate(output: Path) -> None:
    if output.exists():
        raise ValueError("Choose a new directory; evidence is never overwritten")
    output.mkdir(parents=True)
    state = {"healthy": True}

    class ReferenceApp(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, payload):
            raw = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            self.reply({"ready": state["healthy"], "retrieval_enabled": False})

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            # Deliberate fixture defect: every input is allowed with high confidence.
            self.reply({"label": "allow", "confidence": .95, "abstained": False})

    server = ThreadingHTTPServer(("127.0.0.1", 0), ReferenceApp)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        spec = {"openapi": "3.1.0", "paths": {p: {"get": {"responses": {"200": {}}}} for p in ("/health", "/capabilities")}}
        write_json(output / "openapi.json", spec)
        plan = discover_system(project_id="reference-fixture", version="synthetic-candidate",
                               openapi=str(output / "openapi.json"), base_url=url)
        plan["inventory_confirmed"] = True
        for check in plan["checks"]:
            check.update(enabled=True, reviewed=True, json_assertions=[{"path": "ready" if check["path"] == "/health" else "retrieval_enabled", "equals": True}])
        plan["components"].append({"id": "decisions", "name": "Synthetic policy decisions", "module": "Decision quality",
                                  "kind": "ai", "required_layers": ["ai"], "evidence": [], "depends_on": []})
        config = {"schema_version": "esx-client-runner-config-1.0",
                  "evaluation": {"name": "Synthetic decisions", "agent_id": "reference-engine", "project_key": "reference-fixture",
                                 "subject_version": "synthetic-candidate", "dataset_version": "fixture-v1", "required_dimensions": ["classification", "confidence"]},
                  "dataset": {"version": "fixture-v1", "population": {"available_case_count": 100, "class_counts": {"allow": 50, "deny": 50}},
                              "cases": [{"case_id": f"case-{i}", "input": {"fixture": i}, "expected_label": "allow" if i % 2 else "deny"} for i in range(4)]},
                  "adapter": {"type": "http_json_target", "url": url + "/decision", "target_environment": "local", "request_mode": "decision",
                              "response_label_path": "label", "response_confidence_path": "confidence", "response_abstained_path": "abstained"}}
        write_json(output / "decisions.json", config)
        bind_evaluation(plan, output, config_path=output / "decisions.json", components=["decisions"], check_id="decisions")
        plan["checks"][-1].update(enabled=True, reviewed=True)
        approve_plan(plan, output)
        write_json(output / "system-plan.json", plan)
        health_id = next(c["id"] for c in plan["checks"] if c.get("path") == "/health")
        rules = [{"check_id": health_id, "signal": "check_success", "direction": "decrease", "delta": .5}]
        write_json(output / "rules.json", {"rules": rules})
        for index in range(3):
            state["healthy"] = index < 2
            run_dir = output / f"run-{index + 1}"
            report = execute_system(plan, output, run_dir)
            write_json(run_dir / "system-report.json", report)
            (run_dir / "system-report.html").write_text(render_report(report), encoding="utf-8")
            record_run(output / "history.sqlite", report)
        write_json(output / "alerts.json", trend(output / "history.sqlite", plan["project_id"], rules))
        print(json.dumps({"report": str(run_dir / "system-report.html"), "alerts": str(output / "alerts.json"),
                          "notice": "Synthetic fixture. Three real local executions; deliberately wrong decisions, disabled retrieval and a seeded health regression."}))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    generate(parser.parse_args().out.resolve())
