"""Approved, bounded system checks with coverage separate from test outcomes."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import uuid4
import xml.etree.ElementTree as ET

from .audit import append_audit_event
from .local_metrics import METRIC_CALCULATION_VERSION
from .release import BASELINE_TIER_DIMENSIONS, GATE_FIELDS, RECOMMENDATIONS, _population
from .runner import RunnerError, sha256, _validate_config
from .system_inventory import LAYERS, SCHEMA, document
from .workflow_signals import workflow_signal_strength, workflow_signal_advisories


TYPES = {"http", "evaluation", "command", "load", "recovery"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def plan_digest(plan: dict) -> str:
    return sha256({k: v for k, v in plan.items() if k != "approval"})


def _number(value: object) -> bool:
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def _bound(value: object, low: int, high: int, field: str) -> None:
    if type(value) is not int or not low <= value <= high:
        raise RunnerError(f"{field} must be an integer between {low} and {high}")


def _url(plan: dict, path: str) -> str:
    base = urlsplit(plan.get("base_url", ""))
    if base.scheme not in {"http", "https"} or not base.hostname or base.username or base.password or base.query or base.fragment:
        raise RunnerError("Use an explicit HTTP(S) origin without credentials, query or fragment")
    host = base.hostname.lower()
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if not loopback and not (plan.get("environment") == "staging" and base.scheme == "https"):
        raise RunnerError("Targets must be loopback or explicitly approved HTTPS staging; production is not supported")
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or "\\" in path or any(ord(c) < 32 for c in path):
        raise RunnerError("Check path must be same-origin and start with one slash")
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.fragment or "{" in path or "[" in path:
        raise RunnerError("Resolve route placeholders and use a same-origin path without fragments")
    return plan["base_url"].rstrip("/") + path


def _argv(value: object) -> None:
    if not isinstance(value, list) or not value or len(value) > 128 or any(not isinstance(v, str) or not v or "\x00" in v for v in value):
        raise RunnerError("Commands must be nonempty argv arrays; shell command strings are not accepted")


def validate_plan(plan: dict, root: Path) -> dict:
    if not isinstance(plan, dict):
        raise RunnerError("System plan must be an object")
    if plan.get("schema_version") != SCHEMA:
        raise RunnerError("Unsupported system plan schema")
    from .system_safety import guard_output
    guard_output(plan, root)
    if not isinstance(plan.get("project_id"), str) or not re.fullmatch(r"[a-z][a-z0-9-]{1,62}", plan["project_id"]):
        raise RunnerError("Invalid system project ID")
    if not isinstance(plan.get("application_version"), str) or not plan["application_version"]:
        raise RunnerError("application_version is required")
    if plan.get("environment") not in {"local", "staging"}:
        raise RunnerError("Use local or staging, never production")
    if type(plan.get("inventory_confirmed")) is not bool or not isinstance(plan.get("discovery", {}), dict):
        raise RunnerError("inventory_confirmed must be boolean and discovery must be an object")
    components, checks = plan.get("components"), plan.get("checks")
    if not isinstance(components, list) or not 1 <= len(components) <= 10000 or not isinstance(checks, list) or len(checks) > 10000:
        raise RunnerError("System plan requires 1..10000 components and at most 10000 checks")
    roles = plan.get("roles", [])
    if not isinstance(roles, list) or not roles or len(roles) > 32 or any(not isinstance(r, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", r) for r in roles) or len(set(roles)) != len(roles):
        raise RunnerError("Declare distinct role IDs, including anonymous when needed")
    ids = set()
    for c in components:
        if not isinstance(c, dict) or not isinstance(c.get("id"), str) or not c["id"] or c["id"] in ids:
            raise RunnerError("Components require unique IDs")
        ids.add(c["id"])
        for key in ("name", "module", "kind"):
            if not isinstance(c.get(key), str) or not c[key].strip():
                raise RunnerError("Components require name, module and kind")
        enabled = c.get("enabled", "unknown")
        if type(enabled) is not bool and enabled != "unknown":
            raise RunnerError("Component enabled must be true, false or unknown")
        layers = c.get("required_layers")
        if not isinstance(layers, list) or not layers or any(x not in LAYERS for x in layers) or len(layers) != len(set(layers)):
            raise RunnerError("Every component needs reviewed required_layers")
        if not isinstance(c.get("depends_on", []), list) or any(not isinstance(d, str) for d in c.get("depends_on", [])):
            raise RunnerError("depends_on must be a component-ID list")
    for c in components:
        if any(x not in ids or x == c["id"] for x in c.get("depends_on", [])):
            raise RunnerError("Dependencies must reference another component")
    seen = set()
    for c in checks:
        if not isinstance(c, dict) or not isinstance(c.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", c["id"]) or c["id"] in seen:
            raise RunnerError("Checks require unique safe IDs")
        seen.add(c["id"])
        if c.get("type") not in TYPES or c.get("layer") not in LAYERS:
            raise RunnerError("Unknown check type or layer")
        if not isinstance(c.get("component_ids"), list) or not c["component_ids"] or any(not isinstance(x, str) or x not in ids for x in c["component_ids"]):
            raise RunnerError("Checks must map to discovered or declared components")
        if type(c.get("enabled")) is not bool or type(c.get("reviewed")) is not bool:
            raise RunnerError("Check enabled/reviewed values must be booleans")
        if not c["enabled"]:
            continue
        if not c["reviewed"]:
            raise RunnerError(f"Review enabled check {c['id']} before execution")
        _bound(c.get("timeout_seconds", 30), 1, 600, "timeout_seconds")
        if c["type"] in {"http", "load", "recovery"}:
            _url(plan, c.get("path"))
            if c.get("method", "GET") not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
                raise RunnerError("Invalid HTTP method")
            statuses = c.get("expected_status")
            if not isinstance(statuses, list) or not statuses or any(type(s) is not int or s < 100 or s > 599 for s in statuses):
                raise RunnerError("Enabled HTTP checks require independently reviewed expected_status values")
            if c.get("role", "anonymous") not in roles:
                raise RunnerError("Check role is not declared in the inventory")
            headers = c.get("headers_from_env", {})
            if not isinstance(headers, dict) or any(not re.fullmatch(r"[A-Za-z0-9-]+", k) or not isinstance(v, str) or not re.fullmatch(r"[A-Z_][A-Z0-9_]*", v) for k, v in headers.items()):
                raise RunnerError("Headers must reference environment variable names, not secret values")
            if any(k.lower() in {"host", "content-length", "transfer-encoding"} for k in headers):
                raise RunnerError("Host and framing headers cannot be overridden")
            if c.get("role", "anonymous") != "anonymous" and not headers:
                raise RunnerError("Named-role tests require explicit identity headers_from_env")
            assertions = c.get("json_assertions", [])
            if not isinstance(assertions, list) or len(assertions) > 100:
                raise RunnerError("json_assertions must be a bounded list")
            for a in assertions:
                if not isinstance(a, dict) or not isinstance(a.get("path"), str) or not a["path"]:
                    raise RunnerError("Each JSON assertion requires a nonempty dotted path")
                if set(a) != {"path", "equals"} and not (set(a) == {"path", "operator", "value"} and a["operator"] in {"gte", "lte", "gt", "lt"} and _number(a["value"])):
                    raise RunnerError("Use path/equals, or path/operator/value for a finite numeric budget")
        if c["type"] == "load":
            if c.get("method", "GET") not in SAFE_METHODS:
                raise RunnerError("Built-in load tests permit read-only HTTP methods only")
            _bound(c.get("requests", 10), 1, 100, "requests")
            _bound(c.get("concurrency", 2), 1, 8, "concurrency")
            if not _number(c.get("max_p95_ms")) or c["max_p95_ms"] <= 0:
                raise RunnerError("Load checks require a reviewed max_p95_ms budget")
        if c["type"] == "recovery":
            if c.get("method", "GET") not in SAFE_METHODS:
                raise RunnerError("Recovery probes must be read-only")
            _argv(c.get("inject_command"))
            _argv(c.get("recover_command"))
            _bound(c.get("recovery_timeout_seconds", 30), 1, 120, "recovery_timeout_seconds")
            disrupted = c.get("disruption_expected_status")
            if not isinstance(disrupted, list) or not disrupted or any(type(s) is not int or not 100 <= s <= 599 or s in c["expected_status"] for s in disrupted):
                raise RunnerError("Recovery requires distinct disruption_expected_status values to prove the injection took effect")
        if c["type"] == "command":
            _argv(c.get("command"))
            if c.get("format", "junit") != "junit" or not isinstance(c.get("result_file"), str):
                raise RunnerError("External code/security suites must produce a fresh JUnit XML result_file")
        if c["type"] == "evaluation":
            path = (root / c.get("config", "")).resolve()
            config = document(path)
            if c.get("config_sha256") != sha256(config):
                raise RunnerError("Evaluation plan changed; rebind and reapprove before executing")
            # Existing validation may resolve dataset/session paths against its own directory.
            from contextlib import chdir
            with chdir(path.parent):
                evaluation, _, _ = _validate_config(config)
            population_coverage(config, 0)
            if evaluation["project_key"] != plan["project_id"] or evaluation["subject_version"] != plan["application_version"]:
                raise RunnerError("Bound evaluation project/version must match the system plan")
            gates = c.get("gates", [])
            if not isinstance(gates, list):
                raise RunnerError("Metric gates must be a list")
            for gate in gates:
                if not isinstance(gate, dict):
                    raise RunnerError("Each metric gate must be an object")
                dimension, _, field = str(gate.get("signal", "")).partition(".")
                if field not in GATE_FIELDS.get(dimension, {}) or gate.get("operator") not in {"gte", "lte"} or not _number(gate.get("threshold")):
                    raise RunnerError("Invalid explicit metric gate")
                unbounded = dimension == "cost_efficiency" and field != "timeout_rate"
                if gate["threshold"] < 0 or (not unbounded and gate["threshold"] > 1):
                    raise RunnerError("Metric gates require non-negative thresholds; rates must be between 0 and 1")
    from .system_scope import validate_scope
    validate_scope(plan)
    return plan


def approve_plan(plan: dict, root: Path, *, isolated: bool = False, allow_disruption: bool = False) -> dict:
    validate_plan(plan, root)
    from .system_safety import protection_blockers
    blockers = protection_blockers(plan, root)
    if blockers:
        raise RunnerError("Source protection blocked approval: " + "; ".join(blockers))
    if isolated and not str(plan.get("isolation_note", "")).strip():
        raise RunnerError("Isolated-write approval requires an isolation_note")
    if allow_disruption and not isolated:
        raise RunnerError("Failure injection needs isolated-write approval")
    plan["approval"] = {"plan_sha256": plan_digest(plan), "isolated_writes": isolated,
                        "allow_disruption": allow_disruption, "approved_at": datetime.now(timezone.utc).isoformat()}
    return plan


def preflight(plan: dict, root: Path) -> dict:
    validate_plan(plan, root)
    approval = plan.get("approval", {})
    from .system_safety import protection_blockers
    blockers = protection_blockers(plan, root)
    if approval.get("plan_sha256") != plan_digest(plan):
        blockers.append("Plan is not approved or changed after approval")
    if not any(check["enabled"] for check in plan["checks"]):
        blockers.append("No reviewed checks are enabled")
    for check in plan["checks"]:
        if not check["enabled"]:
            continue
        if check["type"] in {"http", "load", "recovery"}:
            if any(not os.environ.get(v) for v in check.get("headers_from_env", {}).values()):
                blockers.append(check["id"] + ": identity environment values are missing")
            if check.get("method", "GET") not in SAFE_METHODS and not approval.get("isolated_writes"):
                blockers.append(check["id"] + ": write methods require isolated-write approval")
        if check["type"] == "recovery" and not approval.get("allow_disruption"):
            blockers.append(check["id"] + ": failure injection requires separate disruption approval")
    coverage = coverage_rows(plan, [])
    planned = coverage_rows(plan, [{"id": c["id"], "status": "passed", "strength": "content_assertions" if c.get("json_assertions") else "status_only" if c["type"] == "http" else "planned"} for c in plan["checks"] if c["enabled"]])
    from .system_scope import assess_scope
    scope = assess_scope(plan, root=root)
    scope_ready = bool(plan["inventory_confirmed"]) and all(c["complete"] for c in planned) and not plan.get("discovery", {}).get("truncated", False)
    if scope["mode"] == "whole_system":
        scope_ready = scope_ready and scope["complete"]
    return {"ready": not blockers, "scope_ready": scope_ready, "whole_system_ready": scope["mode"] == "whole_system" and scope_ready and not blockers,
            "scope_contract": scope,
            "blockers": blockers, "coverage": coverage,
            "enabled_checks": sum(c["enabled"] for c in plan["checks"]), "target_calls_made": False}


def coverage_rows(plan: dict, results: list[dict]) -> list[dict]:
    by_id = {r["id"]: r for r in results}
    rows = []
    for component in plan["components"]:
        checks = [c for c in plan["checks"] if component["id"] in c["component_ids"] and c["enabled"]]
        gaps = []
        if component.get("enabled") is False:
            gaps.append("Capability is declared disabled; its runtime behavior was not validated")
        if component.get("feature_flag") and component.get("enabled", "unknown") == "unknown":
            gaps.append("Feature flag state is unknown; provide an observed capability/flag assertion")
        layer_rows = []
        for layer in component["required_layers"]:
            relevant = [c for c in checks if c["layer"] == layer]
            expected_roles = plan["roles"] if layer == "authorization" else []
            missing_roles = [role for role in expected_roles if not any(c.get("role", "anonymous") == role for c in relevant)]
            executed = [by_id[c["id"]] for c in relevant if c["id"] in by_id]
            complete = bool(relevant) and not missing_roles and len(executed) == len(relevant) and all(r["status"] in {"passed", "failed"} for r in executed)
            if not complete:
                gaps.append(layer + (": missing roles " + ", ".join(missing_roles) if missing_roles else ": missing, unexecuted, or blocked checks"))
            layer_rows.append({"layer": layer, "planned": len(relevant), "executed": len(executed), "complete": complete, "missing_roles": missing_roles})
        for dep in component.get("depends_on", []):
            if not any(c["layer"] == "integration" and dep in c["component_ids"] and by_id.get(c["id"], {}).get("status") in {"passed", "failed"} and by_id.get(c["id"], {}).get("strength") != "status_only" for c in checks):
                gaps.append("integration: dependency " + dep + " has no executed cross-component assertion")
        rows.append({"component_id": component["id"], "name": component["name"], "module": component["module"],
                     "layers": layer_rows, "complete": not gaps, "gaps": gaps,
                     "evidence": component.get("evidence", []), "enabled": component.get("enabled", "unknown"),
                     "dimension_inventory": dimension_inventory(checks, by_id, "ai" in component["required_layers"])})
    return rows


def dimension_inventory(checks: list[dict], results: dict, ai_expected: bool = False) -> list[dict]:
    evaluations = [c for c in checks if c["type"] == "evaluation"]
    if not evaluations and not ai_expected:
        return []
    requested = {d for c in evaluations for d in c.get("requested_dimensions", [])}
    return [{"dimension": d, "tier": "baseline" if d in BASELINE_TIER_DIMENSIONS else "advanced",
             "status": "verified" if any(results.get(c["id"], {}).get("metrics", {}).get(d, {}).get("trust_status") == "verified" and results.get(c["id"], {}).get("metrics", {}).get(d, {}).get("measurement_status") == "measured" for c in evaluations)
             else "declared" if any(results.get(c["id"], {}).get("metrics", {}).get(d, {}).get("trust_status") == "declared" for c in evaluations)
             else "requested_not_measured" if d in requested else "not_requested",
             "action": RECOMMENDATIONS[d][1]} for d in GATE_FIELDS]


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _path_value(value: object, path: str) -> object:
    for key in path.split("."):
        if isinstance(value, list) and key.isdigit():
            value = value[int(key)]
        elif isinstance(value, dict):
            value = value[key]
        else:
            raise KeyError(path)
    return value


def _matches(observed: object, assertion: dict) -> bool:
    if "equals" in assertion:
        # JSON booleans must not match numeric 0/1 as Python equality would allow.
        def equivalent(a, b):
            if _number(a) and _number(b):
                return a == b
            if type(a) is not type(b):
                return False
            if isinstance(a, dict):
                return a.keys() == b.keys() and all(equivalent(a[k], b[k]) for k in a)
            if isinstance(a, list):
                return len(a) == len(b) and all(equivalent(x, y) for x, y in zip(a, b))
            return a == b
        return equivalent(observed, assertion["equals"])
    if not _number(observed):
        return False
    expected = assertion["value"]
    return {"gte": observed >= expected, "lte": observed <= expected, "gt": observed > expected, "lt": observed < expected}[assertion["operator"]]


def http_check(plan: dict, check: dict) -> dict:
    headers = {k: os.environ[v] for k, v in check.get("headers_from_env", {}).items()}
    body = json.dumps(check["json_body"]).encode() if "json_body" in check else None
    if body is not None:
        if len(body) > 1_048_576:
            raise RunnerError("HTTP request exceeds 1 MB")
        headers["Content-Type"] = "application/json"
    started = time.monotonic()
    try:
        req = Request(_url(plan, check["path"]), data=body, headers=headers, method=check.get("method", "GET"))
        try:
            response = build_opener(ProxyHandler({}), NoRedirect()).open(req, timeout=check.get("timeout_seconds", 30))
        except HTTPError as exc:
            response = exc
        with response:
            status = response.code
            raw = response.read(1_048_577)
    except (TimeoutError, URLError, OSError):
        return {"status": "blocked", "reason": "target_transport_or_timeout", "latency_ms": round((time.monotonic() - started) * 1000),
                "action": "Inspect target, dependency and transport health; a timeout alone does not establish a capacity defect."}
    assertions = []
    for assertion in check.get("json_assertions", []):
        observed = None
        try:
            observed = _path_value(json.loads(raw), assertion["path"]) if len(raw) <= 1_048_576 else None
            matches = len(raw) <= 1_048_576 and _matches(observed, assertion)
        except (ValueError, KeyError, IndexError, TypeError):
            matches = False
        expected = assertion.get("equals", assertion.get("value"))
        assertions.append({"path": assertion["path"], "matched": matches, "operator": assertion.get("operator", "equals"),
                           "observed": observed if _number(observed) or type(observed) is bool else "value omitted",
                           "expected": expected if _number(expected) or type(expected) is bool else "value omitted",
                           "expectation_sha256": sha256(assertion)})
    passed = status in check["expected_status"] and all(a["matched"] for a in assertions) and len(raw) <= 1_048_576
    return {"status": "passed" if passed else "failed", "reason": "assertions_matched" if passed else "contract_or_content_mismatch",
            "http_status": status, "expected_status": check["expected_status"], "latency_ms": round((time.monotonic() - started) * 1000),
            "response_sha256": hashlib.sha256(raw).hexdigest(), "response_truncated": len(raw) > 1_048_576,
            "assertions": assertions, "strength": "content_assertions" if assertions else "status_only",
            "action": "Review the expected status/content and the application handler; rerun the same check after correction."}


def _process(command: list[str], cwd: Path, timeout: int, *, env: dict | None = None) -> int | None:
    """No shell, no retained stdout/stderr; terminate only the spawned process tree."""
    if os.name == "nt":
        from .process_job import run_windows_job
        return run_windows_job(command, cwd, timeout, env)
    process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        return process.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        finally:
            process.kill()
            process.wait(timeout=10)
        if isinstance(exc, KeyboardInterrupt):
            raise
        return None


def command_check(check: dict, root: Path) -> dict:
    output = (root / check["result_file"]).resolve()
    previous = output.stat().st_mtime_ns if output.exists() else None
    code = _process(check["command"], (root / check.get("cwd", ".")).resolve(), check.get("timeout_seconds", 30))
    if code is None:
        return {"status": "blocked", "reason": "test_runner_timeout", "action": "Inspect the runner and subject before attributing the timeout."}
    if not output.is_file() or output.stat().st_mtime_ns == previous or output.stat().st_size > 4_194_304:
        return {"status": "blocked", "reason": "fresh_junit_required", "exit_code": code, "action": "Configure the command to produce a fresh bounded JUnit XML file for this execution."}
    raw = output.read_bytes()
    # XML may be UTF-16/32; ASCII-only scanning of the raw bytes misses declarations.
    markup = raw.replace(b"\x00", b"").upper()
    if b"<!DOCTYPE" in markup or b"<!ENTITY" in markup:
        raise RunnerError("JUnit entity declarations are not accepted")
    try:
        tree = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise RunnerError("Invalid JUnit XML") from exc
    cases = list(tree.iter("testcase"))
    if len(cases) > 10000:
        raise RunnerError("JUnit results exceed 10000 cases")
    case_results = [{"id": (c.get("classname", "") + "::" if c.get("classname") else "") + c.get("name", ""),
                     "status": "failed" if c.find("failure") is not None or c.find("error") is not None
                     else "blocked" if c.find("skipped") is not None else "passed"} for c in cases]
    ambiguous = any(not c["id"] or len(c["id"]) > 1000 for c in case_results) or len({c["id"] for c in case_results}) != len(case_results)
    failed = sum(c.find("failure") is not None or c.find("error") is not None for c in cases)
    skipped = sum(c.find("skipped") is not None for c in cases)
    status = "blocked" if ambiguous else "failed" if failed or code else "blocked" if not cases or skipped else "passed"
    return {"status": status, "reason": "external_test_results", "exit_code": code, "case_count": len(cases),
            "case_results": [] if ambiguous else case_results, "ambiguous_case_ids": ambiguous,
            "failed_count": failed, "skipped_count": skipped, "result_sha256": hashlib.sha256(raw).hexdigest(),
            "trust": "observed_test_runner_results", "action": "Inspect the mapped code/security test failures; skipped tests do not establish coverage."}


def evaluation_check(check: dict, root: Path, out: Path) -> dict:
    config = (root / check["config"]).resolve()
    package = out / (check["id"] + ".json")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    code = _process([sys.executable, "-m", "esx_eval_runner.cli", "run", "--config", str(config), "--out", str(package), "--summary-only"], config.parent, check.get("timeout_seconds", 600), env=env)
    report = package.with_name(package.stem + ".local-report.json")
    if code != 0 or not report.exists():
        return {"status": "blocked", "reason": "evaluation_failure_unattributed", "exit_code": code,
                "action": "Inspect the local evaluation audit/debug artifacts; distinguish setup, adapter, judge and target failures before assigning cause."}
    result = document(report)
    config_data = document(config)
    package_data = document(package)
    observations = package_data.get("evaluation", {}).get("decision_observations", [])
    count = package_data.get("execution", {}).get("scored_case_count", 0)
    abstention_rate = sum(o["abstained"] for o in observations) / count if count and len(observations) == count and all(type(o.get("abstained")) is bool for o in observations) else None
    outcomes = []
    for gate in check.get("gates", []):
        dimension, field = gate["signal"].split(".")
        metric = result.get("metrics", {}).get(dimension, {})
        value = metric.get(field)
        usable = metric.get("measurement_status") == "measured" and metric.get("trust_status") == "verified" and _number(value)
        if dimension == "confidence":
            from .confidence import calibration_eligible
            usable = usable and calibration_eligible(metric)
        matched = (value >= gate["threshold"] if gate["operator"] == "gte" else value <= gate["threshold"]) if usable else None
        outcomes.append({**gate, "observed": value if _number(value) else None, "status": "passed" if matched else "failed" if usable else "blocked",
                         "trust": metric.get("trust_status", "missing"), "action": RECOMMENDATIONS[dimension][1]})
    required = result.get("evaluation", {}).get("required_dimensions", config_data["evaluation"].get("required_dimensions", []))
    ungated = sorted(set(required) - {g["signal"].split(".")[0] for g in outcomes})
    incomplete = result.get("execution", {}).get("blocked_case_count", 0) != 0 or count != len(config_data["dataset"]["cases"])
    status = "failed" if any(g["status"] == "failed" for g in outcomes) else "blocked" if not outcomes or ungated or incomplete or any(g["status"] == "blocked" for g in outcomes) else "passed"
    evaluated = package_data.get("evaluation", {})
    label_matches = {key: predicted == expected for key, predicted, expected in zip(
        evaluated.get("case_ids", []), evaluated.get("predicted_labels", []), evaluated.get("expected_labels", []))}
    strengths = {r["case_id"]: r["signal_strength"] for r in workflow_signal_strength(config_data["dataset"]["cases"])["cases"]}
    browser = config_data["adapter"]["type"] == "browser_journey"
    case_results = [{"id": key, "status": "passed" if label_matches.get(key) is True else "failed" if label_matches.get(key) is False else "executed",
                     **({"signal_strength": strengths.get(key, "no_explicit_signal")} if browser else {})}
                    for key in package_data.get("evaluation", {}).get("case_ids", [])]
    return {"status": status, "reason": "metric_gates", "gates": outcomes, "ungated_dimensions": ungated,
            "case_results": case_results,
            "metrics": result.get("metrics", {}), "case_count": count, "evidence_complete": not incomplete,
            "comparison_basis": result.get("evaluation", {}).get("comparison_basis"),
            "scored_case_ids_sha256": sha256(package_data.get("evaluation", {}).get("case_ids", [])),
            "workflow_advisories": workflow_signal_advisories(workflow_signal_strength(config_data["dataset"]["cases"])) if config_data["adapter"]["type"] == "browser_journey" else [],
            "observed_abstention_rate": abstention_rate,
            "population": population_coverage(config_data, count),
            "artifact": report.name, "artifact_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
            "action": "Review per-case evaluation evidence and configure explicit gates for all requested dimensions; declared evidence cannot pass a verified gate."}


def population_coverage(config: dict, executed: int) -> dict:
    population = _population(config.get("dataset", {}).get("population"), "system", "decision")
    if not population:
        return {"status": "unknown", "executed_cases": executed, "notice": "No available-population counts supplied; representativeness is unknown."}
    cases = config["dataset"]["cases"]
    sampled = {}
    for c in cases:
        if c.get("expected_label"):
            sampled[c["expected_label"]] = sampled.get(c["expected_label"], 0) + 1
    available = population["available_case_count"]
    inconsistent = len(cases) > available or any(n > population.get("class_counts", {}).get(label, available) for label, n in sampled.items())
    return {"status": "inconsistent" if inconsistent else "declared_population", "available_cases": available,
            "planned_cases": len(cases), "executed_cases": executed, "planned_fraction": None if inconsistent else len(cases) / available,
            "class_sampling": [{"label": label, "available": n, "planned": sampled.get(label, 0),
                                "fraction": sampled.get(label, 0) / n if n and not inconsistent else None} for label, n in population.get("class_counts", {}).items()],
            "notice": "Population counts are user-declared; sample fraction does not establish representativeness or statistical confidence."}


def load_check(plan: dict, check: dict) -> dict:
    with ThreadPoolExecutor(max_workers=check.get("concurrency", 2)) as pool:
        observations = list(pool.map(lambda _: http_check(plan, check), range(check.get("requests", 10))))
    latencies = sorted(r["latency_ms"] for r in observations)
    p95 = latencies[max(0, math.ceil(len(latencies) * .95) - 1)]
    failed = sum(r["status"] == "failed" for r in observations)
    blocked = sum(r["status"] == "blocked" for r in observations)
    # Missing transport evidence must not become a capacity finding or a passing run.
    status = "failed" if failed or (not blocked and p95 > check["max_p95_ms"]) else "blocked" if blocked else "passed"
    return {"status": status, "reason": "bounded_load_observation" if not blocked else "load_transport_incomplete",
            "requests": len(observations), "concurrency": check.get("concurrency", 2), "p95_latency_ms": p95,
            "failure_count": failed, "blocked_count": blocked, "evidence_complete": not blocked,
            "unsuccessful_count": failed + blocked, "failure_rate": (failed + blocked) / len(observations),
            "observations": observations,
            "action": "Inspect latency and failures at this tested load; this bounded experiment does not establish maximum production capacity."}


def recovery_check(plan: dict, check: dict, root: Path) -> dict:
    if http_check(plan, check)["status"] != "passed":
        return {"status": "blocked", "reason": "unhealthy_before_injection", "action": "Restore baseline health before testing recovery."}
    injected = recovered = None
    disruption = None
    start = time.monotonic()
    try:
        injected = _process(check["inject_command"], root, check.get("timeout_seconds", 30))
        disruption = http_check(plan, {**check, "expected_status": check["disruption_expected_status"], "json_assertions": []})
    except (OSError, subprocess.SubprocessError):
        injected = None
    finally:
        try:
            recovered = _process(check["recover_command"], root, check.get("timeout_seconds", 30))
        except (OSError, subprocess.SubprocessError):
            recovered = None
    if injected != 0 or recovered != 0:
        return {"status": "blocked", "reason": "failure_injection_or_cleanup_failed", "action": "Inspect the isolated environment and restore it manually before any further run."}
    if not disruption or disruption["status"] != "passed":
        return {"status": "blocked", "reason": "disruption_not_observed", "action": "Cleanup ran, but no expected disruption was observed; this is not proof of recovery."}
    deadline = start + check.get("recovery_timeout_seconds", 30)
    restored = {}
    while time.monotonic() < deadline:
        probe = dict(check, timeout_seconds=max(1, min(2, math.ceil(deadline - time.monotonic()))))
        restored = http_check(plan, probe)
        if restored["status"] == "passed":
            return {"status": "passed", "reason": "recovery_observed", "disruption_evidence": disruption,
                    "restoration_evidence": restored,
                    "recovery_ms": round((time.monotonic() - start) * 1000), "action": "Recovery was observed for this reviewed probe and disruption, not every failure mode."}
        time.sleep(.25)
    return {"status": "failed", "reason": "recovery_deadline_exceeded", "disruption_evidence": disruption,
            "restoration_evidence": restored,
            "recovery_timeout_seconds": check.get("recovery_timeout_seconds", 30),
            "action": "Inspect restart recovery, lease expiry and idempotency; preserve the failing test and rerun after correction."}


def execute_system(plan: dict, root: Path, out: Path) -> dict:
    from .system_safety import guard_output, protected_roots, snapshot_sources, source_diff, source_limits
    guard_output(plan, out)
    ready = preflight(plan, root)
    if not ready["ready"]:
        raise RunnerError("System preflight blocked: " + "; ".join(ready["blockers"]))
    if out.exists():
        raise RunnerError("Use a new output directory; prior evidence is never overwritten")
    roots = protected_roots(plan)
    max_files, max_bytes, excluded_dirs, excluded_exts = source_limits(plan)
    source_before = snapshot_sources(roots, max_files=max_files, max_bytes=max_bytes,
                                     excluded_directories=excluded_dirs, excluded_extensions=excluded_exts)
    if roots and source_diff(plan["source_protection"]["snapshot"], source_before)["status"] != "unchanged":
        raise RunnerError("Source changed after preflight; refresh and review")
    source_after = source_before
    integrity = source_diff(source_before, source_after)
    out.mkdir(parents=True)
    audit = out / "audit.jsonl"
    run_id = str(uuid4())
    append_audit_event(audit, "system_started", {"run_id": run_id, "plan_sha256": plan_digest(plan)})
    results = []
    build_binding = plan.get("scope_contract", {}).get("build", {})
    build_id = build_binding.get("check_id")
    ordered = sorted(plan["checks"], key=lambda c: c["id"] != build_id)
    build_evidence = {"status": "not_configured"}
    for check in ordered:
        if not check["enabled"]:
            continue
        start = time.monotonic()
        try:
            if check["type"] == "http":
                result = http_check(plan, check)
            elif check["type"] == "load":
                result = load_check(plan, check)
            elif check["type"] == "recovery":
                result = recovery_check(plan, check, root)
            elif check["type"] == "command":
                result = command_check(check, root)
            else:
                result = evaluation_check(check, root, out)
        except (RunnerError, OSError, ValueError, KeyError) as exc:
            result = {"status": "blocked", "reason": "check_execution_error", "error_type": type(exc).__name__,
                      "action": "Review the approved check configuration and local target state; no root cause is established."}
        basis = dict(check)
        basis.pop("config_sha256", None)
        if check["type"] == "evaluation":
            config = document((root / check["config"]).resolve())
            config["evaluation"].pop("subject_version", None)
            config["evaluation"].pop("name", None)
            basis["evaluation_protocol"] = config
            basis["observed_comparison_basis"] = result.get("comparison_basis")
            basis["scored_case_ids_sha256"] = result.get("scored_case_ids_sha256")
        basis["scope_objectives"] = [o for o in plan.get("scope_contract", {}).get("objectives", []) if o.get("check_id") == check["id"]]
        row = {"id": check["id"], "type": check["type"], "layer": check["layer"], "role": check.get("role"),
               "comparison_sha256": sha256({"check": basis, "metric_version": METRIC_CALCULATION_VERSION, "environment": plan["environment"], "base_url": plan.get("base_url"), "roles": plan["roles"]}),
               "component_ids": check["component_ids"], "duration_ms": round((time.monotonic() - start) * 1000), **result}
        if check["id"] == build_id:
            build_evidence = {"status": "matched_before" if row["status"] == "passed" else "candidate_mismatch_or_unreachable",
                              "expected_value": build_binding["expected_value"], "before": dict(row)}
            if row["status"] != "passed":
                row.update(status="blocked", reason="candidate_identity_not_established",
                           action="Match the running build to the reviewed candidate before executing application tests.")
        results.append(row)
        append_audit_event(audit, "system_check_completed", {"run_id": run_id, "check_id": check["id"], "status": row["status"], "result_sha256": sha256(row)})
        if roots:
            source_after = snapshot_sources(roots, max_files=max_files, max_bytes=max_bytes,
                                            excluded_directories=excluded_dirs, excluded_extensions=excluded_exts)
            integrity = source_diff(source_before, source_after)
            if integrity["status"] != "unchanged":
                integrity["after_check_id"] = check["id"]
                append_audit_event(audit, "application_source_changed_or_unreadable", {"run_id": run_id, "check_id": check["id"], "change_sha256": sha256(integrity)})
                break
        if row["reason"] in {"failure_injection_or_cleanup_failed", "candidate_identity_not_established"}:
            break
    if build_evidence["status"] == "matched_before" and integrity["status"] in {"unchanged", "not_configured"}:
        check = next(c for c in plan["checks"] if c["id"] == build_id)
        after = http_check(plan, check)
        build_evidence.update(after=after, status="matched_before_and_after" if after["status"] == "passed" else "candidate_changed_or_unreachable")
        append_audit_event(audit, "system_candidate_rechecked", {"run_id": run_id, "result_sha256": sha256(build_evidence)})
    if roots:
        source_after = snapshot_sources(roots, max_files=max_files, max_bytes=max_bytes,
                                        excluded_directories=excluded_dirs, excluded_extensions=excluded_exts)
        final_integrity = source_diff(source_before, source_after)
        if integrity["status"] not in {"unchanged", "not_configured"}:
            integrity["final_observation"] = final_integrity
        else:
            integrity = final_integrity
    from .system_scope import assess_scope
    scope = assess_scope(plan, results, root=root, build_status=build_evidence["status"])
    coverage = coverage_rows(plan, results)
    if scope["mode"] == "whole_system":
        for row in coverage:
            component_scope = next(m for m in scope["modules"] if m["component_id"] == row["component_id"])
            row["gaps"].extend(component_scope["gaps"])
            missing = [o["title"] for o in scope["objectives"] if o["component_id"] == row["component_id"] and not o["complete"]]
            if missing:
                row["gaps"].append("Behavior evidence incomplete: " + "; ".join(missing))
            row["complete"] = row["complete"] and component_scope["complete"]
    gaps = sum(not c["complete"] for c in coverage)
    failed = sum(r["status"] == "failed" for r in results)
    blocked = sum(r["status"] == "blocked" for r in results)
    review = not plan.get("inventory_confirmed") or plan.get("discovery", {}).get("truncated", False)
    verdict = "do_not_ship" if failed else "insufficient_evidence" if gaps or blocked or review else "checks_passed_within_reviewed_scope"
    if scope["mode"] == "whole_system":
        if build_evidence["status"] != "matched_before_and_after":
            verdict = "insufficient_evidence"
        elif verdict == "checks_passed_within_reviewed_scope" and not scope["complete"]:
            verdict = "insufficient_evidence"
    if roots and integrity["status"] != "unchanged":
        verdict = "insufficient_evidence"
    report = {"schema_version": "pre-d-system-report-1.0", "project_id": plan["project_id"],
              "application_version": plan["application_version"], "run_id": run_id,
              "created_at": datetime.now(timezone.utc).isoformat(), "plan_sha256": plan_digest(plan),
              "protocol_version": "pre-d-system-1.0/" + METRIC_CALCULATION_VERSION,
              "verdict": verdict, "inventory_confirmed": bool(plan.get("inventory_confirmed")),
              "summary": {"components": len(coverage), "complete_components": len(coverage) - gaps,
                          "checks_executed": len(results), "failed": failed, "blocked": blocked},
              "coverage": coverage, "checks": results, "discovery": plan.get("discovery", {}),
              "scope_contract": scope, "build_verification": build_evidence,
              "source_integrity": {**integrity, "before": source_before, "after": source_after,
                                   "notice": "Fingerprints cover readable regular files outside listed cache/build directories. Changes stop further checks; attribution is unknown. This is change detection, not an OS sandbox or proof of remote filesystem integrity."},
              "review_context": {"roles": plan["roles"], "environment": plan["environment"],
                                 "base_url": plan.get("base_url"), "profile_revision": plan.get("profile", {}).get("revision"),
                                 "assistant_review": plan.get("assistant_review")},
              "profile_changes": plan.get("profile_changes"),
              "notice": "Results cover reviewed checks only. Discovered, disabled and untested components are not validated. Suggested causes are not established root causes. Hashes detect changes, not independent authenticity."}
    report["report_sha256"] = sha256(report)
    append_audit_event(audit, "system_completed", {"run_id": run_id, "report_sha256": report["report_sha256"], "verdict": verdict})
    return report
