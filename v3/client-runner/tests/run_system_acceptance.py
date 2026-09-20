"""Run all six local acceptance stages and retain a machine-readable evidence index.

python tests/run_system_acceptance.py --out ./acceptance --real-schedule
The real schedule option adds two actual 60-second intervals; no service is installed.
"""

import argparse
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
from html import escape
import io
import json
import os
from pathlib import Path
import platform
import sys
from tempfile import TemporaryDirectory
import time
import unittest

import esx_eval_runner
from esx_eval_runner.cli import main
from esx_eval_runner.system_cli import write_json
from esx_eval_runner.system_engine import approve_plan
from esx_eval_runner.system_history import history_runs, trend
from test_system_acceptance import SystemAcceptanceTests, fixture
from test_system_evaluation import BaselineInputTests, SystemEvaluationTests, basic_plan


NAMES = {"0": "Inventory and integrity", "1": "Decision regression", "2": "Code and integration",
         "3": "Adversarial and authorization", "4a": "Operational behavior", "4b": "Recovery"}


def stage(test_id):
    if "real_schedule" in test_id or "BaselineInputTests" in test_id:
        return "1"
    for key in NAMES:
        if "test_stage" + key + "_" in test_id:
            return key
    method = test_id.rsplit(".", 1)[-1]
    if any(word in method for word in ("sampling", "evaluation_metrics", "monitor_runs", "trend", "population", "real_ai")):
        return "1"
    if "code_suite" in method:
        return "2"
    if "role_deny" in method or "identity_missing" in method:
        return "3"
    if "load_is" in method or "numeric_budgets" in method:
        return "4a"
    if "cleanup" in method or "recovery" in method:
        return "4b"
    return "0"


class EvidenceResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []
        self.problems = set()

    def startTest(self, test):
        self.started = time.monotonic()
        super().startTest(test)

    def addSubTest(self, test, subtest, error):
        if error is not None:
            self.problems.add(test.id())
        super().addSubTest(test, subtest, error)

    def addFailure(self, test, error):
        self.problems.add(test.id())
        super().addFailure(test, error)

    def addError(self, test, error):
        self.problems.add(test.id())
        super().addError(test, error)

    def stopTest(self, test):
        skipped = any(t.id() == test.id() for t, _ in self.skipped)
        self.records.append({"test": test.id(), "stage": stage(test.id()),
                             "status": "failed" if test.id() in self.problems else "skipped" if skipped else "passed",
                             "seconds": round(time.monotonic() - self.started, 3)})
        super().stopTest(test)


def real_schedule(out):
    evidence = out / "real-schedule"
    evidence.mkdir()
    with TemporaryDirectory() as directory, fixture.application(directory) as app:
        app.faults.add("health_after_two")
        plan = basic_plan(app.url)
        plan["checks"][0].update(path="/health", json_assertions=[{"path": "dead_letters", "operator": "lte", "value": 0}])
        root = Path(directory)
        approve_plan(plan, root)
        write_json(root / "plan.json", plan)
        rules = [{"check_id": "health", "signal": "check_success", "direction": "decrease", "delta": .5}]
        write_json(root / "rules.json", {"rules": rules})
        db = evidence / "history.sqlite"
        started = time.monotonic()
        with redirect_stdout(io.StringIO()):
            code = main(["system", "monitor", "--plan", str(root / "plan.json"), "--out", str(evidence / "runs"),
                         "--history", str(db), "--rules", str(root / "rules.json"), "--cycles", "3", "--interval-seconds", "60"])
        runs = history_runs(db, "sample-app")
        result = trend(db, "sample-app", rules)
        elapsed = time.monotonic() - started
        intervals = [(datetime.fromisoformat(b["created_at"]) - datetime.fromisoformat(a["created_at"])).total_seconds()
                     for a, b in zip(runs, runs[1:])]
        write_json(evidence / "schedule-observations.json", {"elapsed_seconds": elapsed, "intervals_seconds": intervals,
                   "exit_code": code, "cycles": len(runs), "alert": result})
        case = unittest.TestCase()
        case.assertEqual(code, 2)
        case.assertEqual(len(runs), 3)
        case.assertEqual(app.calls.count("/health"), 3)
        case.assertTrue(all(gap >= 59.5 for gap in intervals), intervals)
        case.assertEqual(result["status"], "alert")
        case.assertEqual(result["rules"][0]["baseline_count"], 2)


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--real-schedule", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    os.environ["PRED_ACCEPTANCE_OUT"] = str(out)
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls)
                               for cls in (SystemAcceptanceTests, BaselineInputTests, SystemEvaluationTests))
    if args.real_schedule:
        def test_real_schedule():
            real_schedule(out)
        suite.addTest(unittest.FunctionTestCase(test_real_schedule))
    started = datetime.now(timezone.utc).isoformat()
    result = unittest.TextTestRunner(verbosity=2, resultclass=EvidenceResult).run(suite)
    stages = []
    for key, title in NAMES.items():
        records = [r for r in result.records if r["stage"] == key]
        complete = bool(records) and all(r["status"] == "passed" for r in records)
        if key == "1" and not args.real_schedule:
            complete = False
        stages.append({"stage": key, "name": title, "checks": len(records), "status": "passed" if complete else "incomplete"})
    artifacts = [{"path": p.relative_to(out).as_posix(), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                 for p in sorted(out.rglob("*")) if p.is_file()]
    boundaries = [
        "This is acceptance of PRE-D against synthetic local reference behavior, not certification of a customer's application.",
        "Agent security uses a deterministic policy simulator with observed tool events, not a real LLM red-team benchmark.",
        "Semantic judge fixtures test contracts and arithmetic, not real-model semantic accuracy.",
        "Roles and tenants use fixture identities; real JWT/SSO and customer authorization matrices still require integration testing.",
        "Load is bounded and recovery targets an owned worker; distributed infrastructure and production-scale capacity are not established.",
        "HTML content, links and escaping are tested. Visual report acceptance is not established by these tests."]
    summary = {"scope": "local_reference_acceptance", "started_at": started, "completed_at": datetime.now(timezone.utc).isoformat(),
               "status": "passed" if result.wasSuccessful() and not result.skipped and args.real_schedule else "incomplete", "test_count": result.testsRun,
               "real_schedule_executed": args.real_schedule, "runtime": {"python": sys.version, "platform": platform.platform(),
               "package_path": str(Path(esx_eval_runner.__file__).resolve())}, "stages": stages, "tests": result.records,
               "boundaries": boundaries, "artifacts": artifacts}
    write_json(out / "acceptance-results.json", summary)
    rows = "".join(f"<tr><td>{r['stage']}</td><td>{escape(r['name'])}</td><td>{r['checks']}</td><td>{r['status']}</td></tr>" for r in stages)
    links = "".join(f'<li><a href="{escape(a["path"], quote=True)}">{escape(a["path"])}</a></li>' for a in artifacts if a["path"].endswith("system-report.html"))
    html = ("<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
            "<title>PRE-D local acceptance evidence</title><style>body{max-width:1050px;margin:3rem auto;padding:0 1.5rem;font:17px Georgia;background:#f4f1e9;color:#142c30}"
            "table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.7rem;border-bottom:1px solid #98a8a5}a{color:#03565d}li{margin:.7rem 0}</style>"
            f"<h1>PRE-D: six-stage local acceptance</h1><p>{result.testsRun} tests. Status: <strong>{summary['status']}</strong>.</p>"
            f"<p>Real timed monitor: {'executed' if args.real_schedule else 'not executed'}.</p>"
            "<table><tr><th>Stage</th><th>Area</th><th>Tests</th><th>Result</th></tr>" + rows + "</table>"
            "<h2>What this does not prove</h2><ul>" + "".join("<li>" + escape(b) + "</li>" for b in boundaries) + "</ul>"
            "<h2>Evidence</h2><p><a href='acceptance-results.json'>Full test results and SHA-256 artifact index</a></p><ul>" + links + "</ul></html>")
    (out / "acceptance-review.html").write_text(html, encoding="utf-8")
    print(json.dumps({"acceptance": str(out / "acceptance-results.json"), "status": summary["status"], "tests": result.testsRun}))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(run())
