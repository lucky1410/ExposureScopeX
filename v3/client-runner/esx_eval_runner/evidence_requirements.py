"""Structured, local-only evidence requirements for PRE-D scorecards."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .ground_truth import read_ground_truth, validate_ground_truth_case_ids
from .metric_registry import ADVANCED_DIMENSIONS as _ADVANCED_DIMENSIONS, METRIC_ORDER, metric_title
from .runner import RunnerError


# These are evidence contracts, not claims that a metric can be inferred from a
# browser result, a framework name, or raw telemetry volume.
METRIC_REQUIREMENTS: dict[str, dict[str, str]] = {
    "workflow_coverage": {
        "title": "Browser workflow evidence",
        "user_supplies": "A reviewed browser journey and one stable, non-sensitive visible signal for each workflow.",
        "application_emits": "Nothing extra. PRE-D records local browser step diagnostics.",
        "minimum": "At least one approved journey; add one case for every workflow that should count as covered.",
        "source": "Local Playwright browser execution only.",
    },
    "classification": {
        "title": "Classification quality",
        "user_supplies": "Labelled local cases with the expected outcome for every case.",
        "application_emits": "One observed decision label for every case.",
        "minimum": "At least two expected classes. PRE-D can calculate a small local set, but use 20 or more representative labelled cases before treating the aggregate as release-quality evidence.",
        "source": "Labelled local dataset plus a decision endpoint or adapter result.",
    },
    "confidence": {
        "title": "Confidence calibration",
        "user_supplies": "The same labelled cases used for classification.",
        "application_emits": "A genuine numeric confidence from 0 to 1 for every decision, not a browser pass/fail value.",
        "minimum": "At least two expected classes. PRE-D can calculate a small local set, but use 20 or more cases and varied confidence values before interpreting calibration as release-quality evidence.",
        "source": "Local decision endpoint or adapter response metadata.",
    },
    "decision_evidence": {
        "title": "Decision evidence alignment and abstention",
        "user_supplies": "Expected allowed evidence IDs and/or whether the correct outcome must abstain for each relevant case.",
        "application_emits": "Opaque evidence IDs and/or an abstained true/false value for the same case.",
        "minimum": "At least one case with an explicit evidence or abstention expectation. This measures reference alignment and abstention, not groundedness.",
        "source": "Local decision API or local adapter response metadata.",
    },
    "groundedness": {
        "title": "Groundedness",
        "user_supplies": "An approved independent local semantic judge. Expected facts remain optional regression controls.",
        "application_emits": "The generated response and retrieved source chunks for every evaluated case, through adapter v2, mapped HTTP response fields, or a local grounding-material file.",
        "minimum": "Response and source list for every case, a separate model review of extraction, and one supported/contradicted/insufficient verdict per extracted claim. Empty source lists record absent retrieval. Model review is not proof of exhaustive extraction.",
        "source": "Raw semantic material is processed locally; the report retains only hashes, verdicts, confidence, evidence IDs, and judge provenance.",
    },
    "hallucination": {
        "title": "Hallucination",
        "user_supplies": "An independent local grounding judge; dataset must_abstain expectations for optional abstention scoring.",
        "application_emits": "The generated response and source chunks for each case, using the same material as groundedness. An explicit empty evidence array represents no retrieved evidence.",
        "minimum": "Extraction reviewed in a separate model pass and source comparison for every case. Abstention rates additionally require judge-observed abstention and expected must_abstain cases. Failed cases prevent full-run scores.",
        "source": "Independent local semantic judge results over the response and supplied sources; unsupported does not necessarily mean factually false.",
    },
    "security": {
        "title": "Security behavior",
        "user_supplies": "An approved security test pack with expected attack and detection outcomes, including positive and negative controls.",
        "application_emits": "Observed attack result, observed detection or block result, opaque evidence ID, and integrity flag.",
        "minimum": "At least one positive and one negative detection control with observed results. Run only in an approved test tenant.",
        "source": "Approved security test pack and redacted local adapter or telemetry evidence.",
    },
    "trajectory": {
        "title": "Agent trajectory",
        "user_supplies": "Expected milestones for successful completion of each evaluated workflow.",
        "application_emits": "Ordered redacted milestones, action count, redundant actions, and policy, scope, or tool-misuse events.",
        "minimum": "At least one correlated trace with one or more expected milestones. A browser navigation trace is not an agent trajectory.",
        "source": "Redacted local agent trace or framework telemetry.",
    },
    "tool_use": {
        "title": "Tool-use quality",
        "user_supplies": "Expected or allowed opaque tool names for each case.",
        "application_emits": "Observed tool names plus authorization, result-validity, opaque evidence ID, and integrity flag for every case.",
        "minimum": "At least one labelled tool-use case. Coverage is meaningful only when expected and observed tool sets are tied to the same case IDs.",
        "source": "Redacted local tool trace and expectation map.",
    },
    "rag": {
        "title": "RAG quality",
        "user_supplies": "Approved relevant document IDs for the evaluated question or decision.",
        "application_emits": "Retrieved IDs, cited IDs, and answer-claim support evidence without document content.",
        "minimum": "At least one case with a non-empty relevant set, retrieval result, citations, and claim-support evidence.",
        "source": "Local retrieval trace, citation metadata, and redacted evidence.",
    },
    "robustness": {
        "title": "Robustness",
        "user_supplies": "A labelled baseline plus controlled paraphrase, perturbation, and repeat variants of the same task.",
        "application_emits": "Correctness, predicted label, and confidence for each baseline and variant.",
        "minimum": "One baseline with at least one controlled variant. Include paraphrase, perturbation, and repeat variants for complete variation coverage.",
        "source": "Local perturbation pack and decision endpoint or adapter results.",
    },
    "judge_agreement": {
        "title": "Judge agreement",
        "user_supplies": "The approved judge identities and the cases they independently review.",
        "application_emits": "A verdict and confidence from each distinct judge for the same case.",
        "minimum": "At least two distinct judges for at least one common case. Agreement measures consistency, not correctness.",
        "source": "Local or customer-approved private judge outputs.",
    },
    "reproducibility": {
        "title": "Repeatability",
        "user_supplies": "A decision to rerun the same labelled cases with the same approved configuration.",
        "application_emits": "One verdict per case for each distinct local run ID.",
        "minimum": "At least two independent runs of at least one common case. Repeatability measures stability, not correctness.",
        "source": "Repeated local-run result records.",
    },
    "cost_efficiency": {
        "title": "Cost and latency",
        "user_supplies": "An approved local price rate only if the provider does not report cost directly.",
        "application_emits": "Redacted per-case token, request, retry, tool-call, cache, fallback, cost, latency, and timeout metadata.",
        "minimum": "One complete usage observation for every labelled case. Partial cost coverage is not used to estimate the missing cases.",
        "source": "Local provider usage metadata or instrumentation.",
    },
}

for _metric_name, _requirement in METRIC_REQUIREMENTS.items():
    _requirement["title"] = metric_title(_metric_name)

_MEASUREMENT_FIELD = {
    "groundedness": "claims", "hallucination": "claims",
    **{name: name for name in _ADVANCED_DIMENSIONS if name not in {"groundedness", "hallucination"}},
}
_TELEMETRY_GAPS = {
    "groundedness": "Expose generated response text and retrieved source chunks locally; opaque claim IDs alone cannot establish semantic groundedness.",
    "hallucination": "Emit claim records and abstention outcomes that match every local unsupported-claim or required-abstention control.",
    "security": "Emit security_control records with expected and observed attack/detection flags for both a positive and a negative detection control.",
    "trajectory": "Set telemetry.trajectory.required_milestones and emit correlated redacted trace events with esx.milestone where they occur.",
    "tool_use": "Set telemetry.tool_use.expected_tools_by_case for every dataset case and emit controlled tool_call records for those case IDs.",
    "rag": "Set telemetry.rag.relevant_document_ids and emit retrieval, citation, and claim-support records with opaque document and evidence IDs.",
    "robustness": "Set telemetry.robustness.baseline_case_id and emit baseline plus paraphrase, perturbation, or repeat robustness_observation records.",
    "judge_agreement": "Emit at least two judge_decision records from distinct esx.judge_id values for one common case.",
    "reproducibility": "Emit at least two run_decision records from distinct esx.run_id values for one common case.",
    "cost_efficiency": "Emit token or cost usage and duration metadata for every dataset case, with esx.case_id on each record.",
}


def _contains_placeholder(value: object) -> bool:
    """Keep generated examples from being mistaken for measured evidence."""
    return "REPLACE_WITH_" in json.dumps(value, sort_keys=True)


def _advanced_measurement_status(
    dimension: str, raw_measurements: object, case_ids: set[str],
    ground_truth: dict[str, Any] | None = None,
) -> tuple[str, list[str]]:
    """Validate one advanced measurement using the runner's real schema rules."""
    field = _MEASUREMENT_FIELD[dimension]
    if not isinstance(raw_measurements, dict) or field not in raw_measurements:
        return "evidence_incomplete", [f"Missing measurements.{field}."]
    if _contains_placeholder(raw_measurements[field]):
        return "evidence_incomplete", [f"Replace every REPLACE_WITH_* value in measurements.{field} with observed local metadata."]

    # Use the same normalizers as a real run so preflight and execution cannot
    # disagree about a required field or an invalid value.
    from .local_metrics import (
        _agreement, claims_metrics, hallucination_metrics, rag_metrics, robustness_metrics,
        security_metrics, tool_use_metrics, trajectory_metrics,
    )
    from .runner import RunnerError, _normalise_measurements

    try:
        normalised = _normalise_measurements(
            {"measurements": {field: raw_measurements[field]}},
            adapter_type="command_json_v2", required_dimensions=[dimension],
        )
    except RunnerError as exc:
        return "evidence_incomplete", [str(exc)]
    value = normalised[field]
    metric = {
        "groundedness": lambda: claims_metrics(value, ground_truth),
        "hallucination": lambda: hallucination_metrics(value, ground_truth),
        "security": lambda: security_metrics(value),
        "trajectory": lambda: trajectory_metrics(value),
        "tool_use": lambda: tool_use_metrics(value),
        "rag": lambda: rag_metrics(value),
        "robustness": lambda: robustness_metrics(value),
        "judge_agreement": lambda: _agreement(value, "judge_id", "judge_count", ""),
        "reproducibility": lambda: _agreement(value, "run_id", "run_count", ""),
    }.get(dimension)
    if dimension == "cost_efficiency":
        observations = value["observations"]
        observed_ids = {item["case_id"] for item in observations}
        if observed_ids != case_ids:
            missing = sorted(case_ids - observed_ids)
            unexpected = sorted(observed_ids - case_ids)
            problems = []
            if missing:
                problems.append("Missing cost observations for " + ", ".join(missing) + ".")
            if unexpected:
                problems.append("Cost observations reference unknown cases: " + ", ".join(unexpected) + ".")
            return "evidence_incomplete", problems
        return "evidence_ready", []
    if metric is None:
        return "evidence_incomplete", [f"No preflight validator is available for {dimension}."]
    result = metric()
    if result.get("measurement_status") != "measured":
        return "evidence_incomplete", [str(result.get("reason", "The supplied evidence does not satisfy this metric's minimum."))]
    return "evidence_ready", []


def _metric_entry(
    metric: str, status: str, missing: list[str], *, source: str, case_coverage: str,
) -> dict[str, object]:
    requirement = METRIC_REQUIREMENTS[metric]
    return {
        "metric": metric,
        "title": requirement["title"],
        "status": status,
        "source": source,
        "case_coverage": case_coverage,
        "missing": missing,
        "user_supplies": requirement["user_supplies"],
        "application_emits": requirement["application_emits"],
        "minimum": requirement["minimum"],
    }


def inspect_evidence_preflight(
    config: dict[str, Any], *, telemetry_path: str | Path | None = None,
    measurements_path: str | Path | None = None,
    ground_truth_path: str | Path | None = None,
    grounding_material_path: str | Path | None = None,
) -> dict[str, object]:
    """Report whether local inputs can produce each requested score before a run.

    This does not execute the target application. A `ready_to_collect` result
    means PRE-D has a valid local plan but still needs observed application
    output. `evidence_ready` means the supplied advanced artifact already
    validates against the exact schema and metric formula prerequisites.
    """
    evaluation = config.get("evaluation") if isinstance(config.get("evaluation"), dict) else {}
    dataset = config.get("dataset") if isinstance(config.get("dataset"), dict) else {}
    adapter = config.get("adapter") if isinstance(config.get("adapter"), dict) else {}
    required = [item for item in evaluation.get("required_dimensions", []) if isinstance(item, str)]
    cases = [item for item in dataset.get("cases", []) if isinstance(item, dict)]
    case_ids = {item["case_id"] for item in cases if isinstance(item.get("case_id"), str)}
    labels = {item["expected_label"] for item in cases if isinstance(item.get("expected_label"), str)}
    adapter_type = adapter.get("type") if isinstance(adapter.get("type"), str) else "unknown"
    plan_errors: list[str] = []
    try:
        from .runner import RunnerError, _validate_config

        _validate_config(config)
    except RunnerError as exc:
        plan_errors.append(str(exc))
    telemetry_file = Path(telemetry_path) if telemetry_path else None
    measurements_file = Path(measurements_path) if measurements_path else None
    ground_truth_file = Path(ground_truth_path) if ground_truth_path else None
    grounding_material_file = Path(grounding_material_path) if grounding_material_path else None
    ground_truth: dict[str, Any] | None = None
    ground_truth_error: str | None = None
    if ground_truth_file:
        try:
            ground_truth = read_ground_truth(ground_truth_file)
            validate_ground_truth_case_ids(ground_truth, case_ids)
        except RunnerError as exc:
            ground_truth_error = str(exc)
    raw_measurements: object = None
    measurement_file_error: str | None = None
    if measurements_file:
        try:
            raw_measurements = json.loads(measurements_file.read_text(encoding="utf-8"))
        except OSError:
            measurement_file_error = f"Local measurement file was not found: {measurements_file}"
        except json.JSONDecodeError:
            measurement_file_error = f"Local measurement file is not valid JSON: {measurements_file}"

    telemetry_measurements: dict[str, object] = {}
    telemetry_error: str | None = None
    if telemetry_file and not telemetry_file.is_file():
        telemetry_error = f"Redacted telemetry file was not found: {telemetry_file}"
    elif telemetry_file:
        try:
            from .telemetry import derive_telemetry_measurements

            telemetry_policy = config.get("telemetry") if isinstance(config.get("telemetry"), dict) else None
            telemetry_measurements, _provenance = derive_telemetry_measurements(
                telemetry_file, required_dimensions=required, case_ids=sorted(case_ids), policy=telemetry_policy,
            )
        except OSError:
            telemetry_error = f"Redacted telemetry file was not found: {telemetry_file}"

    entries: list[dict[str, object]] = []
    for metric in required:
        if metric not in METRIC_REQUIREMENTS:
            continue
        if metric == "workflow_coverage":
            if adapter_type != "browser_journey":
                entries.append(_metric_entry(metric, "not_applicable", ["Workflow coverage applies only to a browser_journey plan."], source="browser", case_coverage="0/%d" % len(cases)))
            else:
                entries.append(_metric_entry(metric, "ready_to_collect", [], source="local browser runner", case_coverage=f"{len(cases)}/{len(cases)} declared journeys"))
            continue
        if metric in {"classification", "confidence"}:
            if adapter_type == "browser_journey":
                entries.append(_metric_entry(metric, "not_applicable", ["A browser plan observes workflow signals, not model labels or genuine confidence."], source="browser", case_coverage="0/%d decision cases" % len(cases)))
            elif len(labels) < 2:
                entries.append(_metric_entry(metric, "evidence_incomplete", ["Add labelled cases with at least two distinct expected_label values."], source="local decision adapter or endpoint", case_coverage=f"{len(cases)} cases / {len(labels)} expected classes"))
            else:
                entries.append(_metric_entry(metric, "ready_to_collect", ["Run the decision adapter or endpoint so it returns one label and genuine 0-1 confidence for every case."], source="local decision adapter or endpoint", case_coverage=f"{len(cases)} cases / {len(labels)} expected classes"))
            continue
        if metric == "decision_evidence":
            evidence_cases = [case for case in cases if "expected_evidence_ids" in case]
            abstention_cases = [case for case in cases if "must_abstain" in case]
            missing = []
            if not evidence_cases and not abstention_cases:
                missing.append("Add expected_evidence_ids and/or must_abstain to at least one labelled decision case.")
            if adapter_type == "browser_journey":
                missing.append("Use a local decision endpoint or adapter; browser signals cannot return evidence IDs or abstention state.")
            if adapter_type == "http_json_target":
                if evidence_cases and not isinstance(adapter.get("response_evidence_ids_path"), str):
                    missing.append("Set adapter.response_evidence_ids_path for observed evidence IDs.")
                if abstention_cases and not isinstance(adapter.get("response_abstained_path"), str):
                    missing.append("Set adapter.response_abstained_path for the observed abstained flag.")
            status = "evidence_incomplete" if missing else "ready_to_collect"
            entries.append(_metric_entry(metric, status, missing, source="local decision adapter or endpoint", case_coverage=f"{len(evidence_cases) + len(abstention_cases)}/{len(cases)} cases with an evidence or abstention expectation"))
            continue
        if metric in {"groundedness", "hallucination"}:
            missing = []
            assurance = config.get("assurance", {})
            assurance = assurance if isinstance(assurance, dict) else {}
            judge = assurance.get("grounding_judge")
            if judge is None:
                missing.append("Configure assurance.grounding_judge as an independent local command judge.")
            else:
                try:
                    from .semantic_grounding import _validate_judge

                    _validate_judge(
                        judge, target_command=adapter.get("command"),
                        subject_id=evaluation.get("agent_id"),
                    )
                except RunnerError as exc:
                    missing.append(str(exc))
            material_ready = False
            if grounding_material_file:
                try:
                    from .semantic_grounding import read_grounding_material

                    read_grounding_material(grounding_material_file, case_ids=case_ids)
                    material_ready = True
                except RunnerError as exc:
                    missing.append(str(exc))
            automatic_capture = (
                adapter_type == "command_json_v2"
                or (
                    adapter_type == "http_json_target"
                    and isinstance(adapter.get("response_text_path"), str)
                    and isinstance(adapter.get("response_grounding_evidence_path"), str)
                )
            )
            if not material_ready and not automatic_capture:
                missing.append(
                    "Add a grounding-material file or configure an adapter that returns response text and retrieved source chunks."
                )
            status = "evidence_incomplete" if missing else ("evidence_ready" if material_ready else "ready_to_collect")
            source = "local grounding-material file" if material_ready else "local adapter response capture"
            entries.append(_metric_entry(
                metric, status, missing, source=source,
                case_coverage=f"{len(case_ids)}/{len(case_ids)} cases required",
            ))
            continue

        field = _MEASUREMENT_FIELD[metric]
        sources: list[tuple[str, object]] = []
        if isinstance(raw_measurements, dict) and field in raw_measurements:
            sources.append(("local adapter measurement file", raw_measurements))
        if field in telemetry_measurements:
            sources.append(("redacted local telemetry", telemetry_measurements))
        if len(sources) > 1:
            entries.append(_metric_entry(metric, "evidence_incomplete", ["Choose one source for this metric. A real run rejects conflicting adapter and telemetry measurements."], source="conflicting local sources", case_coverage=f"{len(case_ids)} labelled cases"))
            continue
        if sources:
            source, raw = sources[0]
            status, missing = _advanced_measurement_status(metric, raw, case_ids, ground_truth)
            if metric == "hallucination" and ground_truth_error:
                status, missing = "evidence_incomplete", [ground_truth_error]
            elif metric == "hallucination" and ground_truth is None:
                status, missing = "evidence_incomplete", [
                    "Add a valid local ground-truth.json file; target-declared claim support is not independently verified."
                ]
            entries.append(_metric_entry(metric, status, missing, source=source, case_coverage=f"{len(case_ids)} labelled cases"))
            continue
        missing = []
        if metric == "hallucination":
            if ground_truth_error:
                missing.append(ground_truth_error)
            elif ground_truth is None:
                missing.append("Add a valid local ground-truth.json file with positive and negative claim controls.")
        if measurement_file_error:
            missing.append(measurement_file_error)
        if telemetry_error:
            missing.append(telemetry_error)
        if adapter_type == "command_json_v2":
            missing.append(f"Have the adapter return measurements.{field}, or provide a completed local measurement file with --measurements.")
        if not telemetry_file:
            missing.append(_TELEMETRY_GAPS[metric])
        elif not telemetry_error:
            missing.append(_TELEMETRY_GAPS[metric])
        entries.append(_metric_entry(metric, "evidence_incomplete", missing, source="no complete local evidence source", case_coverage=f"{len(case_ids)} labelled cases"))

    if plan_errors:
        for entry in entries:
            entry["status"] = "plan_invalid"
            entry["missing"] = [*plan_errors, "Correct the local plan before validating this metric's evidence."]

    status_counts: dict[str, int] = {}
    for entry in entries:
        status = str(entry["status"])
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "schema_version": "pre-d-local-evidence-preflight-1.0",
        "mode": "pre_execution_validation",
        "notice": "No target application was invoked. This validates local prerequisites only; scores are calculated only after a real run returns matching observed evidence.",
        "connection": {"adapter_type": adapter_type, "telemetry_path": str(telemetry_file) if telemetry_file else None, "measurements_path": str(measurements_file) if measurements_file else None, "ground_truth_path": str(ground_truth_file) if ground_truth_file else None, "grounding_material_path": str(grounding_material_file) if grounding_material_file else None},
        "dataset": {"case_count": len(cases), "case_ids": sorted(case_ids), "expected_class_count": len(labels)},
        "plan_errors": plan_errors,
        "summary": status_counts,
        "metrics": entries,
    }


def metric_names(metrics: dict[str, Any], required_dimensions: object = None) -> list[str]:
    """Return active dimensions, falling back to all metrics for old reports."""
    requested = [
        item for item in required_dimensions
        if isinstance(item, str)
    ] if isinstance(required_dimensions, list) else []
    if requested:
        names = [name for name in METRIC_ORDER if name in requested]
        names.extend(name for name in requested if name not in names)
        return names
    names = [name for name in METRIC_ORDER if name in metrics]
    names.extend(name for name in metrics if name not in names)
    return names


def _status(metric: object, *, requested: bool) -> str:
    if isinstance(metric, dict):
        status = str(metric.get("measurement_status", "not_measurable"))
        # calculate_local_metrics returns every supported dimension. A dimension
        # omitted from the plan is not an evidence failure; it was not requested.
        if not requested and status == "not_measurable":
            return "not_requested"
        return status
    return "not_measurable" if requested else "not_requested"


def build_measurement_readiness(
    metrics: dict[str, Any], required_dimensions: object = None,
) -> list[dict[str, str]]:
    """Describe, per metric, exactly what creates a real local result."""
    requested = {
        item for item in required_dimensions
        if isinstance(item, str)
    } if isinstance(required_dimensions, list) else set(metrics)
    entries: list[dict[str, str]] = []
    for name in metric_names(metrics, required_dimensions):
        metric = metrics.get(name)
        status = _status(metric, requested=name in requested)
        requirement = METRIC_REQUIREMENTS.get(name, {
            "title": name.replace("_", " ").title(),
            "user_supplies": "A customer-approved local expectation.",
            "application_emits": "Compatible redacted local evidence.",
            "minimum": "A complete, validated local evidence set.",
            "source": "Local adapter or telemetry evidence.",
        })
        reason = ""
        if isinstance(metric, dict) and isinstance(metric.get("reason"), str):
            reason = metric["reason"]
        trust_status = (
            str(metric.get("trust_status", "missing"))
            if isinstance(metric, dict) else "missing"
        )
        if status == "measured":
            if isinstance(metric, dict) and metric.get("representativeness") == "non_representative":
                next_step = "Replace the all-zero usage observations with representative local execution telemetry before using this result as a decision input."
            elif trust_status == "declared":
                next_step = "This metric is structurally valid but target-declared. Do not present it as independently verified without a supported local validation source."
            else:
                next_step = "This metric was calculated from locally verified evidence. Review its sample size and limitations before using it as a decision input."
        elif status == "not_applicable":
            next_step = "This plan does not collect this evidence type. Use the matching local connection or test pack before expecting this score."
        elif status == "not_requested":
            next_step = "Add this metric to evaluation.required_dimensions only after its evidence contract is ready."
        else:
            next_step = "Supply the expectation and observed redacted evidence described below, then rerun locally."
        entries.append({
            "metric": name,
            "title": requirement["title"],
            "status": status,
            "trust_status": trust_status,
            "reason": reason,
            "user_supplies": requirement["user_supplies"],
            "application_emits": requirement["application_emits"],
            "minimum": requirement["minimum"],
            "source": (
                str(metric.get("evidence_source"))
                if isinstance(metric, dict) and metric.get("evidence_source") else requirement["source"]
            ),
            "next_step": next_step,
        })
    return entries


def render_evidence_requirements_markdown(config: dict[str, Any]) -> str:
    """Create a plan-specific, readable local evidence checklist."""
    evaluation = config.get("evaluation", {})
    evaluation = evaluation if isinstance(evaluation, dict) else {}
    adapter = config.get("adapter", {})
    adapter = adapter if isinstance(adapter, dict) else {}
    required = evaluation.get("required_dimensions", [])
    entries = build_measurement_readiness({}, required)
    connection = str(adapter.get("type", "unknown"))
    lines = [
        "# PRE-D Local Evidence Requirements",
        "",
        "This plan-specific checklist states what PRE-D needs before it will calculate each requested score. All inputs and calculations remain local. Use opaque identifiers in telemetry and result metadata. Semantic grounding and hallucination require responses and source text through the separate local grounding-material path; that content is omitted from reports. Keep credentials and cookies out of evaluation evidence.",
        "",
        f"- **Connection:** `{connection}`",
        f"- **Requested metrics:** {', '.join(entry['title'] for entry in entries) or 'none'}",
        "",
        "Each metric requires its own compatible evidence. Classification uses labelled expectations and observed decisions; semantic metrics use response/source comparison by the configured local judge. Missing prerequisites produce `EVIDENCE NEEDED`. Optional sub-metrics with no denominator remain unscored.",
        "",
    ]
    for entry in entries:
        lines.extend([
            f"## {entry['title']}",
            "",
            f"**You define:** {entry['user_supplies']}",
            "",
            f"**Your application emits:** {entry['application_emits']}",
            "",
            f"**Minimum for a real result:** {entry['minimum']}",
            "",
            f"**Local evidence path:** {entry['source']}",
            "",
        ])
    lines.extend([
        "## Next step",
        "",
        "Review this file before the first run. Then run `esx-eval evidence-check --config ./esx-eval.json` to validate the actual local files and see the exact fields or case IDs that are still missing. For a decision scorecard, connect a loopback decision endpoint or local adapter that returns labels and genuine confidence. For advanced metrics, add redacted local telemetry or a v2 adapter measurement contract. The report will show this same checklist with the current evidence status after every run.",
        "",
    ])
    return "\n".join(lines)
