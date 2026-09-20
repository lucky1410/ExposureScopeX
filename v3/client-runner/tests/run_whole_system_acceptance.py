"""Produce a retained, self-checking whole-system reference report, not app certification."""

import argparse
from copy import deepcopy
import hashlib
import html
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

from esx_eval_runner.system_cli import write_json
from esx_eval_runner.system_engine import approve_plan, execute_system, preflight
from esx_eval_runner.system_ui import STYLE, render_report
from test_whole_system import IDENTITIES, whole_plan, fixture


def run(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=False)
    root = out / "reference-app"
    root.mkdir()
    observations = []
    checks = []

    def expect(name, condition):
        checks.append({"check": name, "passed": bool(condition)})

    with patch.dict(os.environ, IDENTITIES), fixture.application(root) as app:
        base = whole_plan(root, app)
        approve_plan(base, root, isolated=True, allow_disruption=True)
        write_json(out / "preflight.json", preflight(base, root))
        expect("Complete reference plan is ready before dispatch", preflight(base, root)["whole_system_ready"])
        scenarios = [
            ("healthy", "Healthy control", set(), "checks_passed_within_reviewed_scope"),
            ("seeded-faults", "Eight seeded fault classes", {"abstention", "contract", "rbac", "tenant_leak", "injection", "dead_letters", "stuck_job", "capacity"}, "do_not_ship"),
            ("repaired", "Same checks after repair", set(), "checks_passed_within_reviewed_scope"),
            ("missing-behavior", "Missing non-admin behavior", set(), "insufficient_evidence"),
            ("wrong-build", "Wrong running candidate", {"wrong_build"}, "insufficient_evidence"),
            ("changing-build", "Candidate changes during testing", {"build_changed"}, "insufficient_evidence"),
        ]
        for slug, title, faults, expected in scenarios:
            app.faults = faults
            if slug == "repaired":
                app.stop_worker()
                app.start_worker()
                app.wait(lambda: all(j["state"] == "done" for j in app.jobs()))
            app.calls.clear()
            plan = deepcopy(base)
            if slug == "missing-behavior":
                plan["scope_contract"]["objectives"] = [o for o in plan["scope_contract"]["objectives"] if o["check_id"] != "admin-read_only"]
            approve_plan(plan, root, isolated=True, allow_disruption=True)
            report = execute_system(plan, root, out / slug)
            write_json(out / slug / "system-report.json", report)
            (out / slug / "system-report.html").write_text(render_report(report), encoding="utf-8")
            write_json(out / slug / "observed-reference-requests.json", {"requests": list(app.calls)})
            expect(title + ": expected verdict", report["verdict"] == expected)
            if slug in {"healthy", "seeded-faults", "repaired"}:
                expect(title + ": all ten modules have behavior evidence", report["summary"]["complete_components"] == 10 and report["scope_contract"]["complete"])
            if slug == "seeded-faults":
                failed = {c["id"] for c in report["checks"] if c["status"] == "failed"}
                for name in ("triage", "contract", "admin-read_only", "tenant-a-as-b", "security", "queue", "worker-recovery", "throughput"):
                    expect("Seeded defect detected: " + name, name in failed)
                metric = next(c["metrics"] for c in report["checks"] if c["id"] == "triage")
                expect("Incorrect decisions scored as zero accuracy", metric["classification"]["accuracy"] == 0)
                expect("Inappropriate abstention scored as zero correctness", metric["decision_evidence"]["correct_abstention_rate"] == 0)
            if slug == "wrong-build":
                expect("Wrong candidate prevents adapter/load/recovery dispatch", app.calls == ["/build"])
            if slug == "changing-build":
                expect("Candidate changed after dispatch is explicitly reported", report["build_verification"]["status"] == "candidate_changed_or_unreachable")
            observations.append({"id": slug, "title": title, "expected_verdict": expected,
                                 "observed_verdict": report["verdict"], "modules_evaluated": report["summary"]["complete_components"],
                                 "objectives": report["scope_contract"]["summary"], "failed_checks": report["summary"]["failed"],
                                 "checks_executed": report["summary"]["checks_executed"],
                                 "report": slug + "/system-report.html"})
    result = {"schema_version": "pre-d-whole-system-acceptance-1.0", "status": "passed" if all(c["passed"] for c in checks) else "failed",
              "checks_passed": sum(c["passed"] for c in checks), "checks_total": len(checks),
              "reference_modules": 10, "reference_roles": 4, "scenarios": observations, "checks": checks,
              "boundary": "Synthetic reference application only. Real HTTP, adapters, test subprocesses and worker termination/recovery execute locally. Decision probabilities are simulated. No customer application, real browser journeys, production model judge, production integrations or production-scale workload was evaluated here."}
    write_json(out / "acceptance-results.json", result)
    cards = ''.join(f'<article class="card"><p class="eyebrow">{html.escape(s["title"])}</p><h2>{html.escape(s["observed_verdict"].replace("_", " "))}</h2><p>{s["modules_evaluated"]}/10 modules with required behavior evidence. {s["failed_checks"]} failed checks.</p><a href="{s["report"]}">Inspect this run</a></article>' for s in observations)
    failures = ''.join(f'<li>{html.escape(c["check"])}</li>' for c in checks if not c["passed"])
    heading = "Ready for controlled application testing." if result["status"] == "passed" else "Acceptance failed. Not testing ready."
    document = f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PRE-D testing readiness</title><style>{STYLE}</style><main><p class="eyebrow">PRE-D / EXECUTABLE ACCEPTANCE</p><h1>{heading}</h1><p>Evidence from a disposable reference application, not a customer release approval.</p><div class="grid"><div class="card"><small>Acceptance checks</small><div class="number">{result["checks_passed"]}/{len(checks)}</div></div><div class="card"><small>Application modules</small><div class="number">10</div></div><div class="card"><small>Roles exercised</small><div class="number">4</div></div><div class="card"><small>Run scenarios</small><div class="number">6</div></div></div><section><h2>What this proves</h2><p>The same reviewed plan evaluates the healthy app, finds deliberately injected failures, and clears those failures after repair. Missing role behavior and wrong or changing candidates cannot receive a clean whole-system result.</p><p>{html.escape(result["boundary"])}</p>{"<ul>" + failures + "</ul>" if failures else ""}</section><div class="grid">{cards}</div><section><h2>Next: your application</h2><p>Use the whole-system setup contract to bind every critical behavior, role and integration to concrete evidence. Confirm the actual running build, expectations and isolated test environment. Run preflight with <code>--require-whole-system</code>; unresolved prerequisites are displayed before dispatch.</p><p>Inventory and behavioral expectations still need owner review. This acceptance does not establish autonomous discovery of every business behavior, universal defect detection or production judge accuracy.</p><a href="acceptance-results.json">Machine-readable results</a> / <a href="artifact-manifest.json">Evidence integrity manifest</a></section></main></html>'
    (out / "testing-readiness.html").write_text(document, encoding="utf-8")
    manifest = [{"path": p.relative_to(out).as_posix(), "sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "bytes": p.stat().st_size}
                for p in sorted(out.rglob("*")) if p.is_file()]
    write_json(out / "artifact-manifest.json", {"artifacts": manifest, "notice": "Hashes detect changes; they do not establish authenticity against a malicious editor."})
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.out.resolve())
    print(json.dumps({"status": result["status"], "passed": result["checks_passed"], "total": result["checks_total"],
                      "report": str(args.out.resolve() / "testing-readiness.html")}))
    raise SystemExit(0 if result["status"] == "passed" else 1)
