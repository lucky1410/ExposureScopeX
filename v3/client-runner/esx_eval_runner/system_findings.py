"""Traceable, proof-backed findings for PRE-D system reports."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .runner import sha256


SCHEMA = "pre-d-finding-register-1.0"
HARNESS_SCHEMA = "pre-d-harness-recommendations-1.0"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
FINDING_CLASS_ORDER = {"observed_defect": 0, "blocked_evidence": 1, "setup_gap": 2, "coverage_gap": 3, "informational": 4}


def _component_index(plan: dict) -> dict[str, dict]:
    return {component["id"]: component for component in plan.get("components", []) if isinstance(component, dict)}


def _finding(
    *,
    category: str,
    title: str,
    severity: str,
    source: str,
    evidence_type: str,
    confidence: str,
    proof: dict,
    owner_action: str,
    repro_steps: list[str] | None = None,
    finding_class: str | None = None,
    coverage_priority: str | None = None,
    status: str = "open",
    non_invasive_status: str = "pre_d_read_only_no_application_code_write",
) -> dict:
    classification = finding_class or _default_finding_class(category, evidence_type)
    row = {
        "category": category,
        "title": title,
        "severity": severity,
        "finding_class": classification,
        "source": source,
        "evidence_type": evidence_type,
        "confidence": confidence,
        "status": status,
        "proof": proof,
        "repro_steps": repro_steps or [],
        "owner_action": owner_action,
        "non_invasive_status": non_invasive_status,
    }
    if coverage_priority:
        row["coverage_priority"] = coverage_priority
    row["finding_id"] = "finding-" + sha256(row)[:20]
    row["audit_hash"] = sha256(row)
    return row


def _default_finding_class(category: str, evidence_type: str) -> str:
    if category in {"coverage_gap", "workflow_assertion_gap"} or evidence_type in {"missing_evidence", "static_workflow_review"}:
        return "coverage_gap"
    if category in {"blocked_execution", "source_integrity"}:
        return "blocked_evidence"
    if category == "not_executed":
        return "setup_gap"
    if category == "executed_check_result":
        return "observed_defect"
    return "informational"


def finding_register(findings: list[dict], *, context: dict | None = None, notice: str | None = None) -> dict:
    """Create a deterministic register with summary counts and stable hashes."""
    ordered = sorted(
        findings,
        key=lambda row: (
            FINDING_CLASS_ORDER.get(row.get("finding_class", "informational"), 9),
            SEVERITY_ORDER.get(row.get("severity", "info"), 9),
            row.get("category", ""),
            row.get("finding_id", ""),
        ),
    )
    confidence = Counter(row.get("confidence", "unknown") for row in ordered)
    evidence = Counter(row.get("evidence_type", "unknown") for row in ordered)
    severity = Counter(row.get("severity", "info") for row in ordered)
    finding_class = Counter(row.get("finding_class", "informational") for row in ordered)
    coverage_priority = Counter(row.get("coverage_priority", "none") for row in ordered)
    result = {
        "schema_version": SCHEMA,
        "summary": {
            "finding_count": len(ordered),
            "by_severity": dict(sorted(severity.items())),
            "by_finding_class": dict(sorted(finding_class.items())),
            "by_coverage_priority": dict(sorted(coverage_priority.items())),
            "by_confidence": dict(sorted(confidence.items())),
            "by_evidence_type": dict(sorted(evidence.items())),
            "observed_defect_count": finding_class.get("observed_defect", 0),
            "blocked_evidence_count": finding_class.get("blocked_evidence", 0),
            "setup_gap_count": finding_class.get("setup_gap", 0),
            "coverage_gap_count": finding_class.get("coverage_gap", 0),
            "execution_finding_count": finding_class.get("observed_defect", 0) + finding_class.get("blocked_evidence", 0),
            "read_only_finding_count": sum(row.get("non_invasive_status") == "pre_d_read_only_no_application_code_write" for row in ordered),
        },
        "context": context or {},
        "findings": ordered,
        "notice": notice or (
            "Every finding is a local PRE-D audit artifact. Findings are not release truth unless their proof, "
            "ground truth source and non-invasive status match the reviewed evaluation objective."
        ),
    }
    result["register_sha256"] = sha256(result)
    return result


def harness_recommendations(register: dict) -> dict:
    """Group proof-backed findings into concise harness engineering workstreams."""
    findings = register.get("findings", []) if isinstance(register, dict) else []
    groups: dict[str, list[dict]] = {}
    for finding in findings:
        for key in _recommendation_keys(finding):
            groups.setdefault(key, []).append(finding)
    recommendations = []
    for key, rows in groups.items():
        spec = _HARNESS_RECOMMENDATION_SPECS[key]
        related = sorted({row["finding_id"] for row in rows})
        classes = Counter(row.get("finding_class", "informational") for row in rows)
        row = {
            "recommendation_id": "harness-" + sha256({"key": key, "findings": related})[:16],
            "type": key,
            "priority": spec["priority"],
            "title": spec["title"],
            "why": spec["why"],
            "implementation": spec["implementation"],
            "acceptance_criteria": spec["acceptance_criteria"],
            "owner_input_needed": spec["owner_input_needed"],
            "based_on_finding_ids": related,
            "finding_count": len(related),
            "finding_classes": dict(sorted(classes.items())),
            "observed_defect_count": classes.get("observed_defect", 0),
            "blocked_evidence_count": classes.get("blocked_evidence", 0),
            "setup_gap_count": classes.get("setup_gap", 0),
            "coverage_gap_count": classes.get("coverage_gap", 0),
            "evidence_basis": sorted({row.get("evidence_type", "unknown") for row in rows}),
        }
        row["recommendation_hash"] = sha256(row)
        recommendations.append(row)
    recommendations.sort(key=lambda row: (SEVERITY_ORDER.get(row["priority"], 9), row["title"]))
    result = {
        "schema_version": HARNESS_SCHEMA,
        "summary": {
            "recommendation_count": len(recommendations),
            "high_priority_count": sum(row["priority"] in {"critical", "high"} for row in recommendations),
            "linked_finding_count": len({fid for row in recommendations for fid in row["based_on_finding_ids"]}),
            "linked_observed_defect_count": len({
                row["finding_id"] for rows in groups.values() for row in rows if row.get("finding_class") == "observed_defect"
            }),
            "linked_blocked_evidence_count": len({
                row["finding_id"] for rows in groups.values() for row in rows if row.get("finding_class") == "blocked_evidence"
            }),
            "linked_coverage_gap_count": len({
                row["finding_id"] for rows in groups.values() for row in rows if row.get("finding_class") == "coverage_gap"
            }),
        },
        "recommendations": recommendations,
        "notice": (
            "Harness recommendations are engineering workstreams derived from proof-backed findings. "
            "They are not additional product defects; they describe the harness needed to turn gaps into verified evidence."
        ),
    }
    result["recommendations_sha256"] = sha256(result)
    return result


def _recommendation_keys(finding: dict) -> set[str]:
    category = finding.get("category")
    proof = finding.get("proof", {}) if isinstance(finding.get("proof"), dict) else {}
    missing_layers = set(proof.get("missing_layers", []) or [])
    missing_metrics = set(proof.get("missing_metric_dimensions", []) or [])
    keys = set()
    if category == "workflow_assertion_gap" or "workflow" in missing_layers:
        keys.add("browser_workflow_hardening")
    if "functional" in missing_layers or "integration" in missing_layers:
        keys.add("api_contract_harness")
    if "ai" in missing_layers or missing_metrics & {"classification", "confidence", "decision_evidence"}:
        keys.add("decision_quality_harness")
    if missing_metrics & {"groundedness", "hallucination", "rag"}:
        keys.add("semantic_evidence_harness")
    if "authorization" in missing_layers or "security" in missing_layers or missing_metrics & {"security", "tool_use"}:
        keys.add("security_authorization_harness")
    if "reliability" in missing_layers or missing_metrics & {"robustness", "reproducibility", "cost_efficiency", "judge_agreement"}:
        keys.add("reliability_cost_regression_harness")
    if category == "blocked_execution":
        keys.add("blocked_adapter_repair")
    if category == "not_executed":
        keys.add("dispatch_readiness_harness")
    if category == "source_integrity":
        keys.add("source_integrity_harness")
    if not keys:
        keys.add("coverage_authoring_harness")
    return keys


_HARNESS_RECOMMENDATION_SPECS = {
    "browser_workflow_hardening": {
        "priority": "high",
        "title": "Harden browser workflow coverage",
        "why": "Workflow checks need stable visible signals, approved personas and session handling before UI coverage can be trusted.",
        "implementation": "Record or author workflow packs with login/session setup, content assertions, console/pageerror/requestfailed capture and per-persona cases.",
        "acceptance_criteria": ["No path-only browser passes", "Every workflow case has a stable content signal", "Required personas have explicit session profiles"],
        "owner_input_needed": ["safe test personas", "stable page text/selectors", "approved login/session method"],
    },
    "api_contract_harness": {
        "priority": "high",
        "title": "Bind API and integration contract checks",
        "why": "Discovered APIs are not evaluated until approved inputs, expected statuses and business assertions are attached.",
        "implementation": "Create reviewed HTTP checks from OpenAPI/source routes with fixture inputs, schema/content assertions and safe read-only or sandboxed write boundaries.",
        "acceptance_criteria": ["Critical endpoints have reviewed request fixtures", "Responses validate schema and business fields", "Write paths are sandboxed or explicitly excluded"],
        "owner_input_needed": ["approved fixtures", "expected business outputs", "safe side-effect policy"],
    },
    "decision_quality_harness": {
        "priority": "high",
        "title": "Add labelled decision-quality packs",
        "why": "Accuracy, precision/recall/F1, confidence and abstention require labelled cases and structured local adapter outputs.",
        "implementation": "Bind local decision endpoints/adapters to stratified labelled datasets with expected labels, confidence provenance, evidence IDs and abstention expectations.",
        "acceptance_criteria": ["At least two classes are represented", "Predicted label/confidence/evidence IDs are returned per case", "Abstention is scored explicitly"],
        "owner_input_needed": ["labelled cases", "positive class definition", "confidence provenance or mapping"],
    },
    "semantic_evidence_harness": {
        "priority": "high",
        "title": "Add groundedness, hallucination and retrieval evidence",
        "why": "Semantic quality cannot be verified from labels alone; it needs response text, source chunks and independent claim verdicts.",
        "implementation": "Provide response text, retrieved/source chunks, expected abstention/facts and a local judge or reviewed claim verdict file for each case.",
        "acceptance_criteria": ["Claims are extracted or supplied", "Every claim has supported/contradicted/insufficient verdicts", "Hallucination and abstention are reported separately"],
        "owner_input_needed": ["response text", "source chunks", "local judge config or reviewed claim verdicts"],
    },
    "security_authorization_harness": {
        "priority": "high",
        "title": "Add role, tenant and unsafe-action security checks",
        "why": "Security claims need explicit role/tenant matrices, prompt-injection cases and unsafe-action blocking tests.",
        "implementation": "Create role x endpoint allow/deny checks, tenant isolation probes, prompt-injection datasets and tool/action authorization assertions.",
        "acceptance_criteria": ["All critical roles have allow/deny expectations", "Tenant-isolation negative controls exist", "Unsafe action attempts are blocked and evidenced"],
        "owner_input_needed": ["role policy", "tenant fixtures", "prompt-injection/adversarial cases"],
    },
    "reliability_cost_regression_harness": {
        "priority": "medium",
        "title": "Add reliability, cost and regression tracking",
        "why": "Point-in-time checks do not catch drift, stuck states, timeout behavior, throughput ceilings or cost regressions.",
        "implementation": "Enable bounded load/recovery checks, local history, rolling drift rules, retry/dead-letter assertions and token/latency/cost telemetry.",
        "acceptance_criteria": ["Runs are recorded to local history", "Drift rules alert on meaningful changes", "Timeout/recovery/dead-letter paths are tested"],
        "owner_input_needed": ["history location", "drift thresholds", "runtime cost/latency telemetry"],
    },
    "blocked_adapter_repair": {
        "priority": "high",
        "title": "Repair blocked adapters or target readiness",
        "why": "A blocked check is neither pass nor fail; it prevents PRE-D from collecting the intended evidence.",
        "implementation": "Fix adapter configuration, endpoint readiness, credentials, timeouts or protected-profile trusted command policy, then rerun.",
        "acceptance_criteria": ["Previously blocked checks reach pass/fail terminal status", "Blocked reason disappears from the report"],
        "owner_input_needed": ["target availability", "adapter command/URL", "credentials via environment references"],
    },
    "dispatch_readiness_harness": {
        "priority": "high",
        "title": "Repair execution dispatch readiness",
        "why": "Enabled checks that do not execute leave reviewed scope unmeasured.",
        "implementation": "Inspect preflight blockers, stop conditions, check ordering and output directory state before rerunning.",
        "acceptance_criteria": ["Every enabled reviewed check has an executed result", "No not-executed findings remain"],
        "owner_input_needed": ["reviewed plan", "fresh output directory", "resolved preflight blockers"],
    },
    "source_integrity_harness": {
        "priority": "high",
        "title": "Stabilize source-integrity protection",
        "why": "Changed or unreadable source invalidates the candidate being evaluated.",
        "implementation": "Run against a stable checkout, tune generated/cache exclusions, refresh the profile and preserve source fingerprint evidence.",
        "acceptance_criteria": ["Preflight source status is unchanged", "Run source status remains unchanged", "Generated artifacts are excluded by policy"],
        "owner_input_needed": ["stable checkout", "artifact exclusion policy", "approved refresh"],
    },
    "coverage_authoring_harness": {
        "priority": "medium",
        "title": "Complete coverage authoring",
        "why": "A discovered component needs reviewed evidence before PRE-D can make a coverage claim.",
        "implementation": "Use setup, draft-packs or agent-tasks to author disabled drafts, then review, bind and enable only approved checks.",
        "acceptance_criteria": ["Missing evidence has an approved check or explicit exclusion", "No unreviewed draft is counted as coverage"],
        "owner_input_needed": ["module priority", "business behavior expectations", "safe execution boundaries"],
    },
}


def evidence_gap_findings(plan: dict, gaps: dict) -> dict:
    """Convert gap rows into traceable findings without calling the target."""
    plan_hash = gaps.get("plan_sha256") or sha256(plan)
    components = _component_index(plan)
    findings: list[dict] = []
    for row in gaps.get("module_gaps", []):
        component = components.get(row.get("component_id"), {})
        missing_layers = row.get("missing_layers", [])
        missing_metrics = row.get("missing_metric_dimensions", [])
        findings.append(_finding(
            category="coverage_gap",
            title=f'{row.get("module", "unknown")}: missing reviewed evidence for {row.get("component", "component")}',
            severity="info",
            finding_class="coverage_gap",
            coverage_priority="high" if missing_layers else "medium",
            source="pre_d_coverage_readiness",
            evidence_type="missing_evidence",
            confidence="verified",
            proof={
                "plan_sha256": plan_hash,
                "component_id": row.get("component_id"),
                "component_kind": component.get("kind"),
                "module": row.get("module"),
                "component": row.get("component"),
                "source_evidence": component.get("evidence", []),
                "missing_layers": missing_layers,
                "missing_metric_dimensions": missing_metrics,
            },
            repro_steps=['esx-eval system evidence-gaps --plan "<system-plan.json>" --out "./evidence-gaps.json"'],
            owner_action=row.get("action", "Bind reviewed evidence for this component."),
        ))
    for row in gaps.get("weak_workflows", []):
        findings.append(_finding(
            category="workflow_assertion_gap",
            title=f'{row.get("check_id", "workflow")}: weak or unbound browser workflow evidence',
            severity="info",
            finding_class="coverage_gap",
            coverage_priority="medium",
            source="pre_d_workflow_static_review",
            evidence_type="static_workflow_review",
            confidence="verified",
            proof={
                "plan_sha256": plan_hash,
                "check_id": row.get("check_id"),
                "case_ids": row.get("case_ids", []),
                "message": row.get("message"),
            },
            repro_steps=['esx-eval system validate-workflows --plan "<system-plan.json>" --include-disabled'],
            owner_action=row.get("action", "Add stable content assertions and bind reviewed cases."),
        ))
    for row in gaps.get("blocked_checks", []):
        findings.append(_finding(
            category="blocked_execution",
            title=f'{row.get("check_id", "check")}: execution blocked',
            severity="high",
            finding_class="blocked_evidence",
            source="pre_d_system_runner",
            evidence_type="observed_trace",
            confidence="verified",
            proof={"plan_sha256": plan_hash, "check_id": row.get("check_id"), "reason": row.get("reason")},
            repro_steps=['esx-eval system run --plan "<system-plan.json>" --out "./system-run"'],
            owner_action=row.get("action", "Inspect blocked evidence and repair the approved check configuration."),
        ))
    for row in gaps.get("not_executed_checks", []):
        findings.append(_finding(
            category="not_executed",
            title=f'{row.get("check_id", "check")}: enabled check did not execute',
            severity="medium",
            finding_class="setup_gap",
            source="pre_d_system_runner",
            evidence_type="configured_not_executed",
            confidence="verified",
            proof={"plan_sha256": plan_hash, "check_id": row.get("check_id"), "component_ids": row.get("component_ids", [])},
            repro_steps=['esx-eval system run --plan "<system-plan.json>" --out "./system-run"'],
            owner_action="Check dispatch ordering, preflight blockers and runtime stop conditions.",
        ))
    return finding_register(
        findings,
        context={"plan_sha256": plan_hash, "target_calls_made": False, "application_code_modified": False},
        notice="Evidence-gap findings are proof-backed repair items. They prove missing or weak evidence, not application defects.",
    )


def system_report_findings(report: dict) -> dict:
    """Create the system-run finding register from executed checks and embedded gaps."""
    findings = []
    plan_hash = report.get("plan_sha256")
    run_id = report.get("run_id")
    for check in report.get("checks", []):
        if check.get("status") == "passed":
            continue
        severity = "high" if check.get("status") in {"failed", "blocked"} else "medium"
        finding_class = "observed_defect" if check.get("status") == "failed" else "blocked_evidence" if check.get("status") == "blocked" else "setup_gap"
        findings.append(_finding(
            category="executed_check_result",
            title=f'{check.get("id", "check")}: {check.get("status", "unknown")}',
            severity=severity,
            finding_class=finding_class,
            source="pre_d_system_runner",
            evidence_type="observed_trace",
            confidence="verified",
            proof={
                "run_id": run_id,
                "plan_sha256": plan_hash,
                "check_id": check.get("id"),
                "status": check.get("status"),
                "reason": check.get("reason"),
                "component_ids": check.get("component_ids", []),
                "comparison_sha256": check.get("comparison_sha256"),
                "artifact": check.get("artifact"),
            },
            repro_steps=[f'esx-eval system run --plan "<system-plan.json>" --out "./{run_id or "system-run"}"'],
            owner_action=check.get("action", "Review detailed evidence and rerun after repair."),
        ))
    integrity = report.get("source_integrity", {})
    if integrity.get("status") not in {None, "unchanged", "not_configured"}:
        findings.append(_finding(
            category="source_integrity",
            title="Application source changed or became unreadable during evaluation",
            severity="high",
            finding_class="blocked_evidence",
            source="pre_d_source_protection",
            evidence_type="observed_trace",
            confidence="verified",
            proof={
                "run_id": run_id,
                "plan_sha256": plan_hash,
                "source_integrity_status": integrity.get("status"),
                "changed_file_count": integrity.get("changed_file_count"),
                "after_check_id": integrity.get("after_check_id"),
                "change_sha256": sha256({k: v for k, v in integrity.items() if k not in {"before", "after"}}),
            },
            repro_steps=['esx-eval system preflight --plan "<system-plan.json>"', 'esx-eval system run --plan "<system-plan.json>" --out "./system-run"'],
            owner_action="Refresh the profile against a stable checkout and rerun. PRE-D does not attribute who changed the source.",
            non_invasive_status="source_change_detected_unattributed",
        ))
    gap_register = report.get("evidence_gap_report", {}).get("finding_register", {})
    for finding in gap_register.get("findings", []):
        derived = {key: value for key, value in finding.items() if key != "audit_hash"}
        derived["derived_from"] = "evidence_gap_report"
        derived["audit_hash"] = sha256(derived)
        findings.append(derived)
    return finding_register(
        findings,
        context={
            "run_id": run_id,
            "plan_sha256": plan_hash,
            "report_verdict": report.get("verdict"),
            "target_calls_made": bool(report.get("summary", {}).get("checks_executed", 0)),
            "application_code_modified": False,
        },
        notice=(
            "System findings combine executed-check failures, source-integrity observations and evidence gaps. "
            "Agent-drafted or missing-evidence findings are not product defects until backed by reviewed ground truth or observed execution."
        ),
    )
