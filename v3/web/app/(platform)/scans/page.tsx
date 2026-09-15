"use client";

import { useEffect, useState } from "react";

import { API, apiFetch } from "../../../lib/api";

type Stage = {
  id: string;
  position: number;
  adapter: string;
  required: boolean;
  status: string;
  attempt: number;
  timeout_seconds: number;
  started_at?: string;
  finished_at?: string;
  heartbeat_at?: string;
  live_output?: string;
  last_output_at?: string;
  output_sequence?: number;
  error_code?: string;
  error_detail?: string;
};

type Scan = {
  id: string;
  assessment_id: string;
  assessment_name: string;
  target: string;
  mode: string;
  status: string;
  cancel_requested_at?: string;
  progress_percent: number;
  current_stage?: string;
  finding_count: number;
  observation_count: number;
  artifact_count: number;
  created_at: string;
  stages: Stage[];
};

type Report = {
  scan_id: string;
  assessment_id: string;
  status: string;
  manifest: {
    outputs?: Record<string, unknown>;
  };
};

const terminalStates = ["complete", "partial", "succeeded", "failed", "timed_out", "skipped", "blocked", "cancelled"];
const stageFailureMessage: Record<string, string> = {
  TARGET_TLS_SNI_REJECTED: "The HTTPS endpoint rejected this hostname during TLS SNI negotiation. Use the service's canonical HTTPS hostname or correct its TLS configuration. Verification was not bypassed.",
  TARGET_TLS_ERROR: "The HTTPS handshake failed before an HTTP response was available. Check the exact URL and the service TLS configuration; verification was not bypassed.",
};

function elapsed(start?: string, end?: string) {
  if (!start) return "Not started";
  const endTime = end ? new Date(end).getTime() : Date.now();
  const seconds = Math.max(0, Math.floor((endTime - new Date(start).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function freshness(value?: string) {
  if (!value) return "Awaiting first output";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  return seconds < 60 ? `${seconds}s ago` : `${Math.floor(seconds / 60)}m ${seconds % 60}s ago`;
}

export default function ScansPage() {
  const [assessmentId, setAssessmentId] = useState<string | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [updatedAt, setUpdatedAt] = useState<Date>();
  const [error, setError] = useState("");
  const [cancelling, setCancelling] = useState<string | null>(null);

  async function refresh() {
    const [scanResponse, reportResponse] = await Promise.all([
      apiFetch("/api/v3/scans", { cache: "no-store" }),
      apiFetch("/api/v3/reports", { cache: "no-store" }),
    ]);
    if (!scanResponse.ok) throw new Error("Live execution data is unavailable");
    setScans(await scanResponse.json());
    setReports(reportResponse.ok ? await reportResponse.json() : []);
    setUpdatedAt(new Date());
    setError("");
  }

  async function cancelScan(scanId: string) {
    setCancelling(scanId);
    setError("");
    try {
      const response = await apiFetch(`/api/v3/scans/${scanId}/cancel`, { method: "POST" });
      const payload = await response.json().catch(() => null) as { detail?: string } | null;
      if (!response.ok) throw new Error(payload?.detail ?? "Unable to cancel scan");
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to cancel scan");
    } finally {
      setCancelling(null);
    }
  }

  useEffect(() => {
    setAssessmentId(new URLSearchParams(window.location.search).get("assessment_id"));
    refresh().catch((reason: Error) => setError(reason.message));
    const timer = window.setInterval(() => refresh().catch((reason: Error) => setError(reason.message)), 2000);
    return () => window.clearInterval(timer);
  }, []);

  const visible = assessmentId ? scans.filter((scan) => scan.assessment_id === assessmentId) : scans;
  const running = visible.filter((scan) => ["queued", "running"].includes(scan.status)).length;

  return (
    <main className="workspacePage">
      <header className="pageHeader compactHeader">
        <div><p className="kicker">DETERMINISTIC EXECUTION</p><h1>Scan operations</h1><p>Live worker state from PostgreSQL. No estimated or fabricated progress.</p></div>
        <div className="liveIndicator"><i className={running ? "pulseDot" : "stateDot"} /><span>{running ? `${running} ACTIVE` : "NO ACTIVE RUNS"}</span></div>
      </header>

      <section className="scanToolbar">
        <div><span>LIVE REFRESH</span><strong>2 seconds</strong></div>
        <div><span>LAST UPDATE</span><strong>{updatedAt ? updatedAt.toLocaleTimeString() : "Connecting"}</strong></div>
        <div><span>FILTER</span><strong>{assessmentId ? "Selected assessment" : "All assessments"}</strong></div>
        <button className="secondaryAction" onClick={() => refresh()}>REFRESH NOW</button>
      </section>

      {error && <p className="formError">{error}</p>}
      <section className="scanStack">
        {visible.length === 0 ? <div className="emptyState scanEmpty"><strong>No scan runs found</strong><span>Start an assessment to create its immutable execution record.</span></div> : visible.map((scan) => {
          const report = reports.find((item) => item.scan_id === scan.id);
          const terminal = ["complete", "partial", "failed", "blocked", "cancelled"].includes(scan.status);
          return <article className="scanCard" key={scan.id}>
            <header className="scanCardHead">
              <div><span className={`statusLabel status-${scan.status}`}><i />{scan.status}</span><h2>{scan.assessment_name}</h2><p>{scan.target}</p></div>
              <div className="scanFacts"><span>{scan.mode} PROFILE</span><strong>{scan.finding_count} findings</strong><small>{scan.observation_count} observations · {scan.artifact_count} evidence artifacts{scan.cancel_requested_at ? ` · cancel requested ${freshness(scan.cancel_requested_at)}` : ""}</small></div>
            </header>
            <div className="progressMeta"><span>{scan.cancel_requested_at && !terminalStates.includes(scan.status) ? `CANCELLATION REQUESTED${scan.current_stage ? `: ${scan.current_stage}` : ""}` : scan.current_stage ? `RUNNING: ${scan.current_stage}` : terminalStates.includes(scan.status) ? "EXECUTION CLOSED" : "WAITING FOR WORKER"}</span><strong>{scan.progress_percent}%</strong></div>
            <div className="progressTrack" role="progressbar" aria-valuenow={scan.progress_percent} aria-valuemin={0} aria-valuemax={100}><i style={{ width: `${scan.progress_percent}%` }} /></div>
            {["queued", "running"].includes(scan.status) && <div className="ledgerTools"><button className="textAction" disabled={cancelling === scan.id} onClick={() => cancelScan(scan.id)}>{cancelling === scan.id ? "CANCELLING" : "CANCEL SCAN"}</button></div>}
            {terminal && <section className="scanReportActions" aria-label={`Reports for ${scan.assessment_name}`}>
              <div><span>REPORTS</span><strong>{report ? "Decision, inventory, and evidence are ready." : "Preparing the retained report package..."}</strong><small>{report ? "Review coverage before treating the assessment as a security conclusion." : "The download links will appear automatically when report generation finishes."}</small></div>
              {report && <div className="reportDownloads"><a className={report.manifest.outputs?.pdf ? "" : "downloadUnavailable"} href={report.manifest.outputs?.pdf ? `${API}/api/v3/reports/${scan.id}/download/pdf` : undefined}>ASSESSMENT PDF</a><a href={`${API}/api/v3/assessments/${report.assessment_id}/assets/export`}>ASSET INVENTORY CSV</a><a className={report.manifest.outputs?.evidence ? "" : "downloadUnavailable"} href={report.manifest.outputs?.evidence ? `${API}/api/v3/reports/${scan.id}/download/evidence` : undefined}>TECHNICAL EVIDENCE ZIP</a></div>}
            </section>}
            <div className="stageTimeline">
              {scan.stages.map((stage) => (
                <div className={`stageRun stageRun-${stage.status}`} key={stage.id}>
                  <span className="stagePosition">{String(stage.position).padStart(2, "0")}</span>
                  <div className="stageRunName"><strong>{stage.adapter}</strong><small>{stage.required ? "Required" : "Optional"} · attempt {stage.attempt || 0}</small></div>
                  <span className="stageDuration">{elapsed(stage.started_at, stage.finished_at)}</span>
                  <span className="stageState">{stage.status.replace("_", " ")}</span>
                  {(stage.error_detail || stage.error_code) && <p>{stage.error_code && stageFailureMessage[stage.error_code] ? stageFailureMessage[stage.error_code] : stage.error_detail || stage.error_code}</p>}
                  {stage.status === "running" && <div className="liveOutput" aria-live="polite">
                    <header><strong>LIVE TOOL OUTPUT</strong><span>Output {freshness(stage.last_output_at)} · heartbeat {freshness(stage.heartbeat_at)}</span></header>
                    <pre>{stage.live_output || "Process active; waiting for the tool to emit output."}</pre>
                  </div>}
                </div>
              ))}
            </div>
          </article>
        })}
      </section>
    </main>
  );
}
