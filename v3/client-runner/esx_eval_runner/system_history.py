"""Local bounded history and explicit matched-protocol rolling change alerts."""

from __future__ import annotations

from contextlib import closing
from datetime import datetime
import json
from pathlib import Path
import sqlite3
from statistics import median

from .runner import RunnerError, sha256
from .system_engine import _number


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=10)
    db.execute("PRAGMA busy_timeout=10000")
    db.execute("CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, project TEXT NOT NULL, created TEXT NOT NULL, digest TEXT NOT NULL, report TEXT NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS by_project_time ON runs(project,created)")
    return db


def record_run(path: Path, report: dict) -> None:
    digest = sha256({k: v for k, v in report.items() if k != "report_sha256"})
    if report.get("schema_version") != "pre-d-system-report-1.0" or report.get("report_sha256") != digest:
        raise RunnerError("System report is invalid or changed after creation")
    created = datetime.fromisoformat(report["created_at"])
    if created.tzinfo is None:
        raise RunnerError("History timestamps must include a timezone")
    raw = json.dumps(report, separators=(",", ":"), allow_nan=False)
    if len(raw.encode()) > 8_000_000:
        raise RunnerError("Report exceeds history's 8 MB record limit")
    with closing(_connect(path)) as db, db:
        prior = db.execute("SELECT digest FROM runs WHERE run_id=?", (report["run_id"],)).fetchone()
        if prior and prior[0] != digest:
            raise RunnerError("An existing run ID cannot be replaced with different evidence")
        db.execute("INSERT OR IGNORE INTO runs VALUES(?,?,?,?,?)", (report["run_id"], report["project_id"], report["created_at"], digest, raw))


def history_runs(path: Path, project: str, limit: int = 30) -> list[dict]:
    if type(limit) is not int or not 2 <= limit <= 1000:
        raise RunnerError("History window must be 2..1000 runs")
    if not path.exists():
        return []
    with closing(_connect(path)) as db:
        rows = db.execute("SELECT report,digest FROM runs WHERE project=? ORDER BY julianday(created) DESC LIMIT ?", (project, limit)).fetchall()
    reports = []
    for raw, digest in rows:
        report = json.loads(raw)
        if report.get("report_sha256") != digest or sha256({k: v for k, v in report.items() if k != "report_sha256"}) != digest:
            raise RunnerError("History integrity check failed")
        reports.append(report)
    return list(reversed(reports))


def signals(check: dict) -> dict:
    result = {}
    if check.get("status") in {"passed", "failed"}:
        result["check_success"] = float(check["status"] == "passed")
    if check.get("evidence_complete") is False:
        return result
    for key in ("p95_latency_ms", "failure_rate", "recovery_ms", "observed_abstention_rate"):
        if _number(check.get(key)):
            result[key] = check[key]
    for dimension, metric in check.get("metrics", {}).items():
        if dimension == "confidence":
            from .confidence import calibration_eligible
            if not calibration_eligible(metric):
                continue
        if metric.get("measurement_status") == "measured" and metric.get("trust_status") == "verified":
            for field, value in metric.items():
                if _number(value):
                    result[dimension + "." + field] = value
    return result


def validate_rules(rules: list[dict]) -> None:
    if not isinstance(rules, list) or not 1 <= len(rules) <= 1000:
        raise RunnerError("Provide 1..1000 explicit trend rules")
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("signal"), str) or not isinstance(rule.get("check_id"), str) or rule.get("direction") not in {"increase", "decrease", "either"} or not _number(rule.get("delta")) or rule["delta"] <= 0:
            raise RunnerError("Trend rules require check_id, signal, direction and a positive absolute delta")


def candidate_matches(report: dict) -> bool:
    if report.get("source_integrity", {}).get("status") in {"changed", "incomplete"}:
        return False
    return report.get("scope_contract", {}).get("mode") != "whole_system" or report.get("build_verification", {}).get("status") == "matched_before_and_after"


def trend(path: Path, project: str, rules: list[dict], *, window: int = 10, min_baseline: int = 2) -> dict:
    if type(min_baseline) is not int or min_baseline < 1 or min_baseline >= window:
        raise RunnerError("min_baseline must be positive and smaller than window")
    validate_rules(rules)
    reports = history_runs(path, project, window)
    rows = []
    if not reports:
        return {"status": "insufficient_history", "rules": [], "alert_count": 0}
    current = reports[-1]
    for rule in rules:
        check = next((c for c in current["checks"] if c["id"] == rule["check_id"]), None)
        value = signals(check).get(rule["signal"]) if check and candidate_matches(current) else None
        baseline = []
        excluded = 0
        for report in reports[:-1]:
            prior = next((c for c in report["checks"] if c["id"] == rule["check_id"]), None)
            before = signals(prior).get(rule["signal"]) if prior and candidate_matches(report) else None
            if check and prior and value is not None and before is not None and check.get("comparison_sha256") and check["comparison_sha256"] == prior.get("comparison_sha256") and current["protocol_version"] == report["protocol_version"]:
                baseline.append(before)
            else:
                excluded += 1
        row = {**rule, "current": value, "baseline_count": len(baseline), "excluded_count": excluded, "status": "insufficient_comparable_history"}
        if value is not None and len(baseline) >= min_baseline:
            reference = median(baseline)
            delta = value - reference
            shifted = (delta >= rule["delta"] if rule["direction"] == "increase" else -delta >= rule["delta"] if rule["direction"] == "decrease" else abs(delta) >= rule["delta"])
            row.update(baseline_median=reference, observed_delta=delta, status="alert" if shifted else "stable")
        rows.append(row)
    alerts = sum(r["status"] == "alert" for r in rows)
    return {"schema_version": "pre-d-system-trend-1.0", "project_id": project, "run_id": current["run_id"],
            "status": "alert" if alerts else "insufficient_history" if not rows or any(r["status"].startswith("insufficient") for r in rows) else "stable",
            "rules": rows, "alert_count": alerts,
            "notice": "Absolute change against the median of compatible prior runs, not a statistical significance test or proof of cause. Dataset/protocol changes are excluded, not treated as improvements."}


def prune_history(path: Path, project: str, keep: int) -> int:
    if type(keep) is not int or not 2 <= keep <= 1000:
        raise RunnerError("Retain 2..1000 runs; pruning is explicit and does not delete report files")
    with closing(_connect(path)) as db, db:
        cursor = db.execute("DELETE FROM runs WHERE project=? AND run_id NOT IN (SELECT run_id FROM runs WHERE project=? ORDER BY julianday(created) DESC LIMIT ?)", (project, project, keep))
        return cursor.rowcount
