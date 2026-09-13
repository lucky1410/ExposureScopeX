"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";

import { apiFetch } from "../../../../lib/api";

type JsonRecord = Record<string, unknown>;

type EvaluationDetail = {
  id: string;
  name: string;
  evaluated_agent_id: string;
  evaluated_agent_version: string;
  evaluator_agent_id: string;
  evaluator_version: string;
  dataset_version: string;
  project_key: string;
  dataset: JsonRecord;
  release_decision: "pass" | "fail" | "inconclusive";
  created_at: string;
  metrics: JsonRecord;
  input_summary: JsonRecord;
  calculation_assurance: JsonRecord;
  source_sha256: string;
  reports: Partial<Record<"docx" | "pdf", JsonRecord>>;
};

function record(value: unknown): JsonRecord {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as JsonRecord
    : {};
}

function records(value: unknown): JsonRecord[] {
  return Array.isArray(value) ? value.map(record) : [];
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function number(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function percentage(value: unknown): string {
  const numeric = number(value);
  return numeric === null ? "Not measured" : `${(numeric * 100).toFixed(1)}%`;
}

function score(value: unknown): string {
  const numeric = number(value);
  return numeric === null ? "--" : numeric.toFixed(3);
}

function usd(value: unknown): string {
  const numeric = number(value);
  return numeric === null ? "Not measured" : `$${numeric.toFixed(6)}`;
}

function display(value: unknown): string {
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number") return Number.isInteger(value) ? String(value) : value.toFixed(3);
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.length ? value.join(", ") : "None";
  return "Not measured";
}

function title(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function gateState(value: unknown): string {
  if (value === true) return "Pass";
  if (value === false) return "Fail";
  return "Not measurable";
}

function gateValue(gate: JsonRecord, value: unknown): string {
  if (typeof value !== "number") return display(value);
  const name = String(gate.name ?? "");
  if (name.includes("cost")) return usd(value);
  return name === "minimum_sample_size" || name === "minimum_class_count" || name.includes("latency")
    ? display(value)
    : percentage(value);
}

function measurementState(metric: JsonRecord): string {
  return metric.measurement_status === "measured" ? "Measured" : "Not measurable";
}

function releaseSummary(decision: EvaluationDetail["release_decision"]): string {
  if (decision === "pass") return "Every required check met its release threshold for this exact evaluation set.";
  if (decision === "fail") return "At least one required check did not meet its release threshold. Review the failed gates before release.";
  return "The evaluation is missing a required measurement or could not produce a reliable release decision.";
}

function dimensionDecision(gates: JsonRecord[], dimension: string): "pass" | "fail" | "inconclusive" | "not_measured" {
  const matching = gates.filter((gate) => String(gate.dimension ?? "") === dimension);
  if (!matching.length) return "not_measured";
  if (matching.some((gate) => gate.passed === false)) return "fail";
  if (matching.every((gate) => gate.passed === true)) return "pass";
  return "inconclusive";
}

function decisionLabel(value: ReturnType<typeof dimensionDecision>): string {
  if (value === "not_measured") return "Not measured";
  return value.toUpperCase();
}

export default function EvaluationResultPage() {
  const { evaluationId } = useParams<{ evaluationId: string }>();
  const [result, setResult] = useState<EvaluationDetail | null>(null);
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState<"pdf" | "docx" | null>(null);

  async function downloadReport(format: "pdf" | "docx") {
    setError("");
    setDownloading(format);
    try {
      const response = await apiFetch(`/api/v3/evaluations/${evaluationId}/reports/download/${format}`);
      if (!response.ok) {
        const body = await response.json().catch(() => null) as { detail?: unknown } | null;
        throw new Error(typeof body?.detail === "string" ? body.detail : `Report export failed (${response.status})`);
      }
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = href;
      link.download = `exposurescopex-pre-release-${evaluationId}.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(href);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Report export failed");
    } finally {
      setDownloading(null);
    }
  }

  useEffect(() => {
    let active = true;
    apiFetch(`/api/v3/evaluations/${evaluationId}`)
      .then(async (response) => {
        const body = await response.json();
        if (!response.ok) throw new Error(typeof body.detail === "string" ? body.detail : "Evaluation result is unavailable");
        if (active) setResult(body as EvaluationDetail);
      })
      .catch((reason: Error) => {
        if (active) setError(reason.message);
      });
    return () => { active = false; };
  }, [evaluationId]);

  if (error) {
    return <main className="workspacePage evaluationReportPage"><Link className="backLink" href="/ai-evaluator">BACK TO AI ASSURANCE</Link><p className="formError">{error}</p></main>;
  }
  if (!result) {
    return <main className="workspacePage evaluationReportPage"><Link className="backLink" href="/ai-evaluator">BACK TO AI ASSURANCE</Link><p className="reportLoading">Loading immutable pre-release result...</p></main>;
  }

  const metrics = record(result.metrics);
  const classification = record(metrics.classification);
  const confidence = record(metrics.confidence);
  const assurance = record(result.calculation_assurance);
  const input = record(result.input_summary);
  const dataset = record(result.dataset);
  const trace = record(input.trace);
  const liveAdapter = record(input.live_adapter);
  const clientRunner = record(input.client_runner);
  const labels = strings(classification.labels);
  const matrix = record(classification.confusion_matrix);
  const perClass = record(classification.per_class);
  const gateDetails = records(metrics.gate_details);
  const roles = record(metrics.role_results);
  const assuranceStatus = String(assurance.status ?? "not_recomputed");
  const evidenceDimensions = [
    ["Evidence grounding", record(metrics.groundedness), ["claim_count", "supported_claim_rate", "unsupported_claim_rate", "citation_validity_rate", "evidence_integrity_rate"]],
    ["Security verdict", record(metrics.security), ["case_count", "attack_outcome_accuracy", "attack_success_rate", "detection_rate", "false_detection_rate", "evidence_coverage"]],
    ["Trajectory policy", record(metrics.trajectory), ["score", "milestone_coverage", "action_efficiency", "policy_compliant", "missing_milestones", "scope_violations", "tool_misuse_events"]],
    ["RAG quality", record(metrics.rag), ["k", "context_precision", "recall_at_k", "mean_reciprocal_rank", "citation_validity", "faithfulness", "uncited_relevant_documents"]],
    ["Robustness", record(metrics.robustness), ["case_count", "variation_coverage", "missing_variation_types", "by_variation_type", "accuracy", "consistency", "worst_confidence_drop", "failed_case_ids"]],
    ["Cross-model agreement", record(metrics.judge_agreement), ["case_count", "judge_count", "pairwise_agreement", "unanimous_case_rate", "disagreement_case_ids"]],
    ["Repeatability", record(metrics.reproducibility), ["case_count", "run_count", "pairwise_agreement", "unanimous_case_rate", "disagreement_case_ids"]],
    ["Cost and efficiency", record(metrics.cost_efficiency), ["cost_source", "case_count", "total_cost_usd", "cost_per_case_usd", "cost_per_correct_case_usd", "input_tokens", "output_tokens", "total_tokens", "requests_per_case", "retry_count", "tool_call_count", "cache_hit_rate", "fallback_rate", "timeout_rate", "median_latency_ms", "p95_latency_ms", "max_latency_ms"]],
  ] as const;
  const metricHighlights = [
    { id: "classification", name: "Decision quality", question: "Did it make the correct decision?", value: percentage(classification.accuracy), detail: `Macro F1 ${score(classification.macro_f1)} across ${display(classification.sample_size)} labelled cases.` },
    { id: "confidence", name: "Confidence", question: "Was confidence aligned with accuracy?", value: `ECE ${percentage(confidence.expected_calibration_error)}`, detail: `Lower is better. Brier score ${score(confidence.correctness_brier_score)}.` },
    { id: "groundedness", name: "Grounding", question: "Were claims supported by evidence?", value: percentage(record(metrics.groundedness).supported_claim_rate), detail: `${percentage(record(metrics.groundedness).unsupported_claim_rate)} unsupported claims.` },
    { id: "security", name: "Security controls", question: "Were attack outcomes detected correctly?", value: percentage(record(metrics.security).detection_rate), detail: `${percentage(record(metrics.security).false_detection_rate)} false detections.` },
    { id: "trajectory", name: "Agent behavior", question: "Did the agent follow its allowed path?", value: display(record(metrics.trajectory).policy_compliant), detail: `${percentage(record(metrics.trajectory).milestone_coverage)} required milestones reached.` },
    { id: "rag", name: "RAG quality", question: "Did retrieval support the answer?", value: percentage(record(metrics.rag).faithfulness), detail: `Precision ${percentage(record(metrics.rag).context_precision)}. Recall@K ${percentage(record(metrics.rag).recall_at_k)}.` },
    { id: "robustness", name: "Robustness", question: "Did it stay reliable when inputs changed?", value: percentage(record(metrics.robustness).consistency), detail: `${percentage(record(metrics.robustness).variation_coverage)} variation coverage across ${display(record(metrics.robustness).case_count)} cases.` },
    { id: "judge_agreement", name: "Judge agreement", question: "Did independent judges agree?", value: percentage(record(metrics.judge_agreement).pairwise_agreement), detail: `${display(record(metrics.judge_agreement).judge_count)} judges compared.` },
    { id: "reproducibility", name: "Repeatability", question: "Did repeated runs agree?", value: percentage(record(metrics.reproducibility).pairwise_agreement), detail: `${display(record(metrics.reproducibility).run_count)} runs compared.` },
    { id: "cost_efficiency", name: "Cost and efficiency", question: "Did it stay within the declared operating budget?", value: usd(record(metrics.cost_efficiency).cost_per_case_usd), detail: `P95 ${display(record(metrics.cost_efficiency).p95_latency_ms)} ms. ${percentage(record(metrics.cost_efficiency).timeout_rate)} timeouts.` },
  ];
  const isSynthetic = dataset.classification === "synthetic";

  return (
    <main className="workspacePage evaluationReportPage">
      <Link className="backLink" href="/ai-evaluator">BACK TO AI ASSURANCE</Link>
      <header className="pageHeader compactHeader">
        <div><p className="kicker">PRE-RELEASE ASSURANCE / IMMUTABLE SCORECARD</p><h1>{result.name}</h1><p>Deterministic release evidence for {result.evaluated_agent_id} on the declared labelled dataset.</p></div>
        <b className={`decision-${result.release_decision} resultDecision`}>{result.release_decision}</b>
      </header>

      <section className={`releaseOverview release-${result.release_decision}`} aria-label="Release decision summary">
        <div><span>RELEASE DECISION</span><strong>{result.release_decision === "pass" ? "Ready for the declared release gate" : result.release_decision === "fail" ? "Release gate blocked" : "More evidence is required"}</strong><p>{releaseSummary(result.release_decision)}</p></div>
        <div><span>WHAT THIS SCORE MEANS</span><p>{isSynthetic ? "This is a synthetic fixture. It proves the evaluation workflow and metric contract, not real-world production performance." : "This score applies only to the declared dataset version and test population. It should be read with that scope in mind."}</p><div className="releaseOverviewActions"><a href="#metric-results">Read metric results</a><a href="#decision-gates">See release gates</a></div></div>
      </section>

      <section className="resultIdentity" aria-label="Evaluation identity">
        <div><span>SUBJECT</span><strong>{result.evaluated_agent_id}</strong><small>v{result.evaluated_agent_version}</small></div>
        <div><span>DATASET</span><strong>{result.dataset_version}</strong><small>{new Date(result.created_at).toLocaleString()}</small></div>
        <div><span>EVALUATOR</span><strong>{result.evaluator_agent_id}</strong><small>v{result.evaluator_version}</small></div>
        <div><span>RELEASE</span><strong>{String(metrics.release_decision ?? result.release_decision).toUpperCase()}</strong><small>{percentage(metrics.measurement_coverage)} required coverage</small></div>
      </section>

      <section className="resultIdentity resultGovernance" aria-label="Evaluation governance">
        <div><span>PROJECT</span><strong>{result.project_key}</strong><small>Workspace-scoped evaluation program</small></div>
        <div><span>DATA CLASSIFICATION</span><strong>{display(dataset.classification)}</strong><small>{display(dataset.status)} dataset</small></div>
        <div><span>DATASET PROVENANCE</span><strong>{display(dataset.name)}</strong><small>{display(dataset.source_reference)}</small></div>
        <div><span>INTEGRATION</span><strong>{display(input.integration_mode)}</strong><small>{display(input.subject_type)} subject</small></div>
      </section>

      <section className="resultScoreboard" aria-label="Evaluation headline metrics">
        <div><span>OVERALL SCORE</span><strong>{score(metrics.overall_score)}</strong><small>Mean of measured dimensions</small></div>
        <div><span>CLASSIFICATION ACCURACY</span><strong>{percentage(classification.accuracy)}</strong><small>{display(classification.sample_size)} labelled pairs</small></div>
        <div><span>MACRO F1</span><strong>{score(classification.macro_f1)}</strong><small>Equal weight per class</small></div>
        <div><span>CALIBRATION ECE</span><strong>{percentage(confidence.expected_calibration_error)}</strong><small>{score(confidence.correctness_brier_score)} correctness Brier</small></div>
      </section>

      <section className={`assuranceBrief assurance-${assuranceStatus}`}>
        <div><span>CALCULATION CHECK</span><strong>{assuranceStatus === "verified" ? "Scores recomputed successfully" : "Calculation needs review"}</strong><p>{display(assurance.reason)}</p></div>
        <p><strong>What this confirms:</strong> the scorecard has not changed since it was calculated. <strong>What it does not confirm:</strong> that the chosen test cases represent all production behavior.</p>
        <details className="technicalDetails"><summary>View integrity hashes and calculation proof</summary><div className="assuranceFacts"><div><span>INPUT SNAPSHOT</span><code>{display(assurance.input_manifest_sha256)}</code></div><div><span>STORED METRICS</span><code>{display(assurance.stored_metrics_sha256)}</code></div><div><span>RECOMPUTED METRICS</span><code>{display(assurance.recomputed_metrics_sha256)}</code></div><div><span>FULL EVALUATION</span><code>{result.source_sha256}</code></div></div></details>
      </section>

      <section className="resultSection">
        <header><div><p className="kicker">INPUT COVERAGE</p><h2>What was evaluated</h2></div><p>This page reveals counts and provenance, not submitted raw labels or evidence text.</p></header>
        <div className="inputCoverageGrid">
          <div><span>LABELLED PAIRS</span><strong>{display(input.labelled_pairs)}</strong></div><div><span>PREDICTIONS</span><strong>{display(input.predictions)}</strong></div><div><span>CONFIDENCES</span><strong>{display(input.confidence_values)}</strong></div><div><span>CLAIMS</span><strong>{display(input.claim_count)}</strong></div><div><span>SECURITY CONTROLS</span><strong>{display(input.security_case_count)}</strong><small>{display(input.expected_detection_controls)} positive controls</small></div><div><span>TRAJECTORY</span><strong>{display(input.observed_milestone_count)} / {display(input.required_milestone_count)}</strong><small>observed / required milestones</small></div>
          <div><span>TRACE AGENTS</span><strong>{display(trace.agent_count)}</strong><small>{display(trace.redaction_status)} provenance</small></div><div><span>TRACE EVENTS</span><strong>{display(trace.verified_event_count)} / {display(trace.event_count)}</strong><small>verified / declared events</small></div>
        </div>
      </section>

      {liveAdapter.present === true && <section className="resultSection">
        <header><div><p className="kicker">LIVE ADAPTER PROVENANCE</p><h2>Controlled endpoint invocation</h2></div><p>The endpoint and bearer token remain undisclosed. Only integrity references and result metadata are retained.</p></header>
        <div className="assuranceFacts"><div><span>ADAPTER</span><strong>{display(liveAdapter.adapter_name)}</strong><small>{display(liveAdapter.adapter_type)}</small></div><div><span>CASES</span><strong>{display(liveAdapter.case_count)}</strong><small>{display(liveAdapter.duration_ms)} ms</small></div><div><span>REQUEST SNAPSHOT</span><code>{display(liveAdapter.request_sha256)}</code></div><div><span>RESPONSE SNAPSHOT</span><code>{display(liveAdapter.response_sha256)}</code></div><div><span>ENDPOINT FINGERPRINT</span><code>{display(liveAdapter.endpoint_sha256)}</code></div><div><span>NETWORK POLICY</span><strong>{display(liveAdapter.network_policy_version)}</strong></div></div>
      </section>}

      {clientRunner.present === true && <section className="resultSection">
        <header><div><p className="kicker">CLIENT-RUNNER PROVENANCE</p><h2>Customer-controlled execution</h2></div><p>The adapter executed outside ExposureScopeX. Test inputs, model output, source code, and secrets were not retained by this control plane.</p></header>
        <div className="assuranceFacts"><div><span>IDENTITY</span><strong>{display(clientRunner.identity_name)}</strong><small>{display(clientRunner.identity_type)}</small></div><div><span>RUNNER VERSION</span><strong>{display(clientRunner.runner_version)}</strong><small>package {display(clientRunner.package_id)}</small></div><div><span>IDENTITY FINGERPRINT</span><code>{display(clientRunner.identity_fingerprint)}</code></div><div><span>PACKAGE SNAPSHOT</span><code>{display(clientRunner.package_sha256)}</code></div><div><span>EXECUTION SNAPSHOT</span><code>{display(clientRunner.execution_sha256)}</code></div><div><span>SOURCE ATTESTATION</span><code>{display(clientRunner.source_attestation_sha256)}</code></div></div>
      </section>}

      <section className="resultSection" id="decision-gates">
        <header><div><p className="kicker">RELEASE GATES</p><h2>Why this decision was made</h2></div><p>{gateDetails.filter((gate) => gate.passed === true).length} of {gateDetails.length} required checks passed. Missing measurement is never treated as a pass.</p></header>
        <details className="technicalDetails gateDetails"><summary>View all {gateDetails.length} release checks and policy thresholds</summary><div className="resultTableWrap"><table className="resultTable"><thead><tr><th>Dimension</th><th>Check</th><th>Observed</th><th>Required</th><th>Result</th></tr></thead><tbody>{gateDetails.map((gate) => <tr key={String(gate.name)}><td>{title(String(gate.dimension ?? ""))}</td><td>{title(String(gate.name ?? ""))}</td><td>{gateValue(gate, gate.actual)}</td><td>{String(gate.operator ?? "")} {gateValue(gate, gate.threshold)}</td><td><b className={`gate-${String(gate.passed)}`}>{gateState(gate.passed)}</b></td></tr>)}</tbody></table></div></details>
      </section>

      <section className="resultSection" id="metric-results">
        <header><div><p className="kicker">RESULTS BY AREA</p><h2>What the evaluation found</h2></div><p>Each card answers one practical question. Open the technical detail only when you need the underlying measurements.</p></header>
        <div className="metricHighlights">{metricHighlights.map((item) => { const decision = dimensionDecision(gateDetails, item.id); return <article key={item.id} className={`metricHighlight metric-${decision}`}><div><span>{item.name}</span><b>{decisionLabel(decision)}</b></div><p>{item.question}</p><strong>{item.value}</strong><small>{item.detail}</small></article>; })}</div>
      </section>

      <details className="advancedMetrics">
        <summary><span>TECHNICAL DETAIL</span> Open confusion matrices, per-class metrics, role outcomes, and raw measurement breakdowns</summary>
        <div className="advancedMetricsBody">

      <section className="resultSplit">
        <div className="resultSection classificationSection"><header><div><p className="kicker">CLASSIFICATION</p><h2>Confusion matrix</h2></div><p>Rows are expected labels. Columns are predicted labels.</p></header>{labels.length ? <div className="resultTableWrap"><table className="resultTable matrixTable"><thead><tr><th>Expected / predicted</th>{labels.map((label) => <th key={label}>{label}</th>)}</tr></thead><tbody>{labels.map((actual) => <tr key={actual}><th>{actual}</th>{labels.map((predicted) => <td key={predicted}>{display(record(matrix[actual])[predicted])}</td>)}</tr>)}</tbody></table></div> : <p className="notMeasured">{display(classification.reason)}</p>}</div>
        <div className="resultSection classificationSection"><header><div><p className="kicker">CALIBRATION</p><h2>Confidence reliability</h2></div><p>Predicted-label confidence compared with observed correctness.</p></header><div className="calibrationStats"><div><span>BRIER SCORE</span><strong>{score(confidence.correctness_brier_score)}</strong><small>Lower is better</small></div><div><span>EXPECTED CALIBRATION ERROR</span><strong>{percentage(confidence.expected_calibration_error)}</strong><small>Lower is better</small></div></div><div className="resultTableWrap"><table className="resultTable compactTable"><thead><tr><th>Confidence band</th><th>Cases</th><th>Accuracy</th><th>Average confidence</th></tr></thead><tbody>{records(confidence.bins).map((bin) => <tr key={`${bin.lower}-${bin.upper}`}><td>{percentage(bin.lower)} to {percentage(bin.upper)}</td><td>{display(bin.count)}</td><td>{percentage(bin.accuracy)}</td><td>{percentage(bin.average_confidence)}</td></tr>)}</tbody></table></div></div>
      </section>

      <section className="resultSection"><header><div><p className="kicker">PER-CLASS PERFORMANCE</p><h2>Accuracy breakdown</h2></div><p>Macro metrics treat each labelled class equally, even if class sizes differ.</p></header><div className="resultTableWrap"><table className="resultTable"><thead><tr><th>Class</th><th>Support</th><th>Precision</th><th>Recall</th><th>F1</th><th>False-positive rate</th></tr></thead><tbody>{labels.map((label) => { const item = record(perClass[label]); return <tr key={label}><td>{label}</td><td>{display(item.support)}</td><td>{percentage(item.precision)}</td><td>{percentage(item.recall)}</td><td>{score(item.f1)}</td><td>{percentage(item.false_positive_rate)}</td></tr>; })}</tbody></table></div></section>

      <section className="resultSection"><header><div><p className="kicker">ROLE OUTCOMES</p><h2>Evidence, security, and policy</h2></div><p>These three roles determine whether evidence, security controls, and agent behavior meet release requirements.</p></header><div className="roleOutcomeGrid">{Object.entries(roles).map(([roleId, role]) => { const item = record(role); return <article key={roleId}><span>{title(roleId)}</span><strong>{String(item.verdict ?? "inconclusive").toUpperCase()}</strong><small>{String(item.implementation ?? "")}</small><p>{String(item.measurement_status ?? "not_measurable").replaceAll("_", " ")}</p></article>; })}</div></section>

      <section className="dimensionGrid">{evidenceDimensions.map(([name, metric, fields]) => <article key={name} className="dimensionCard"><header><span>{name}</span><b>{measurementState(metric)}</b></header>{metric.measurement_status === "measured" ? <dl>{fields.map((field) => <div key={field}><dt>{title(field)}</dt><dd>{field.includes("cost_usd") ? usd(metric[field]) : field.includes("rate") || field.includes("accuracy") || field.includes("coverage") || field.includes("recall") || field.includes("precision") || field.includes("drop") || field === "score" || field === "faithfulness" || field === "consistency" ? percentage(metric[field]) : field.includes("latency_ms") ? `${display(metric[field])} ms` : display(metric[field])}</dd></div>)}</dl> : <p>{display(metric.reason)}</p>}</article>)}</section>
        </div>
      </details>

      <section className="resultSection exportSection"><header><div><p className="kicker">EXPORT</p><h2>Formal report files</h2></div><p>The interactive scorecard is the fastest review surface; exports retain the signed-off document presentation.</p></header><div className="exportActions"><button className="secondaryAction" disabled={!result.reports.pdf || downloading !== null} onClick={() => downloadReport("pdf")}>{downloading === "pdf" ? "PREPARING PDF" : "EXPORT PDF"}</button><button className="secondaryAction" disabled={!result.reports.docx || downloading !== null} onClick={() => downloadReport("docx")}>{downloading === "docx" ? "PREPARING DOCX" : "EXPORT DOCX"}</button></div></section>
    </main>
  );
}
