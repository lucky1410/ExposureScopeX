"use client";

import { ChangeEvent, FormEvent, useEffect, useRef, useState } from "react";
import Link from "next/link";

import { apiFetch } from "../../../lib/api";

type Assessment = { id: string; name: string; target: string; authorization_confirmed: boolean; status: string };
type Monitor = { id: string; assessment_id: string; assessment_name: string; hostname?: string; cadence_hours: number; status: "active" | "paused" | "blocked"; next_run_at: string; last_run_at?: string; last_error?: string };
type Finding = { id: string; title: string; hostname?: string; severity: string; validation_status: string; lifecycle_status: string; lifecycle_note?: string; last_seen_at: string };
type AuditEvent = { id: number; event_type: string; target_type: string; actor_name?: string; occurred_at: string; payload: Record<string, unknown> };
type Quality = { validation: Record<string, number>; measured_validation_count: number; observed_false_positive_rate: number | null; rate_note: string; corpora: Array<{ id: string; name: string; version: string; classification: string; status: string; case_count: number }> };
type Integration = { id: string; name: string; integration_type: string; status: string; event_types: string[]; created_at: string };

function text(value: string) { return value.replaceAll("_", " "); }
function date(value?: string) { return value ? new Date(value).toLocaleString() : "Not recorded"; }

export default function OperationsPage() {
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [monitors, setMonitors] = useState<Monitor[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [quality, setQuality] = useState<Quality | null>(null);
  const [audits, setAudits] = useState<AuditEvent[]>([]);
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [message, setMessage] = useState("");
  const [working, setWorking] = useState("");
  const corpusInput = useRef<HTMLInputElement>(null);

  async function refresh() {
    const requests = await Promise.all([
      apiFetch("/api/v3/assessments", { cache: "no-store" }),
      apiFetch("/api/v3/exposure/dashboard", { cache: "no-store" }),
      apiFetch("/api/v3/exposure/findings", { cache: "no-store" }),
      apiFetch("/api/v3/exposure/quality", { cache: "no-store" }),
      apiFetch("/api/v3/exposure/audit-events", { cache: "no-store" }),
      apiFetch("/api/v3/exposure/integrations", { cache: "no-store" }),
    ]);
    const [assessmentResponse, dashboardResponse, findingResponse, qualityResponse, auditResponse, integrationResponse] = requests;
    if (!assessmentResponse.ok || !dashboardResponse.ok || !findingResponse.ok || !qualityResponse.ok) throw new Error("Exposure operations are temporarily unavailable");
    setAssessments(await assessmentResponse.json() as Assessment[]);
    setMonitors(((await dashboardResponse.json()) as { monitors: Monitor[] }).monitors);
    setFindings(((await findingResponse.json()) as { findings: Finding[] }).findings);
    setQuality(await qualityResponse.json() as Quality);
    setAudits(auditResponse.ok ? ((await auditResponse.json()) as { events: AuditEvent[] }).events : []);
    setIntegrations(integrationResponse.ok ? ((await integrationResponse.json()) as { integrations: Integration[] }).integrations : []);
  }

  useEffect(() => { refresh().catch((reason: Error) => setMessage(reason.message)); }, []);

  async function createMonitor(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setWorking("monitor"); setMessage("");
    const form = new FormData(event.currentTarget);
    try {
      const response = await apiFetch("/api/v3/exposure/monitors", { method: "POST", body: JSON.stringify({ assessment_id: form.get("assessment_id"), cadence_hours: Number(form.get("cadence_hours")) }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? "Monitor could not be created");
      setMessage("Monitor enabled. The runner will re-check scope and authorization before each dispatch.");
      await refresh();
    } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Monitor could not be created"); }
    finally { setWorking(""); }
  }

  async function setMonitor(monitor: Monitor, status: "active" | "paused") {
    setWorking(monitor.id); setMessage("");
    try {
      const response = await apiFetch(`/api/v3/exposure/monitors/${monitor.id}`, { method: "PATCH", body: JSON.stringify({ status }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? "Monitor could not be updated");
      setMessage(`Monitor ${status}.`); await refresh();
    } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Monitor could not be updated"); }
    finally { setWorking(""); }
  }

  async function updateFinding(finding: Finding, lifecycle_status: string) {
    const note = window.prompt(`Why should "${finding.title}" be marked ${text(lifecycle_status)}?`);
    if (!note) return;
    setWorking(finding.id); setMessage("");
    try {
      const response = await apiFetch(`/api/v3/exposure/findings/${finding.id}`, { method: "PATCH", body: JSON.stringify({ lifecycle_status, note }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? "Finding lifecycle could not be updated");
      setMessage("Finding lifecycle updated with a documented rationale."); await refresh();
    } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Finding lifecycle could not be updated"); }
    finally { setWorking(""); }
  }

  async function importCorpus(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]; if (!file) return;
    setWorking("corpus"); setMessage("");
    try {
      const content = await file.text();
      const parsed = JSON.parse(content) as Omit<Quality["corpora"][number], "id" | "case_count" | "status"> & { cases: unknown[] };
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(content)))).map((value) => value.toString(16).padStart(2, "0")).join("");
      const response = await apiFetch("/api/v3/exposure/validation-corpora", { method: "POST", body: JSON.stringify({ ...parsed, source_sha256: digest }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? "Validation corpus could not be registered");
      setMessage(`Registered ${result.case_count} validation cases. Metrics remain explicitly scoped to reviewed data.`); await refresh();
    } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Validation corpus could not be registered"); }
    finally { event.target.value = ""; setWorking(""); }
  }

  async function createIntegration(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setWorking("integration"); setMessage("");
    const form = new FormData(event.currentTarget);
    const integration_type = String(form.get("integration_type"));
    try {
      const response = await apiFetch("/api/v3/exposure/integrations", { method: "POST", body: JSON.stringify({
        name: form.get("name"), integration_type, endpoint_url: form.get("endpoint_url") || null,
        signing_secret: form.get("signing_secret") || null,
        event_types: ["asset.discovered", "asset.changed", "finding.opened", "finding.resolved", "scan.completed", "monitor.blocked"],
        configuration: { connector_scope: integration_type === "cloud_inventory" || integration_type === "dns_attestation" ? "customer-attested" : "event-delivery" },
      }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? "Integration could not be saved");
      setMessage(`${result.name} is configured. Secrets are encrypted at rest and never returned to the browser.`); event.currentTarget.reset(); await refresh();
    } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Integration could not be saved"); }
    finally { setWorking(""); }
  }

  const authorizedAssessments = assessments.filter((assessment) => assessment.authorization_confirmed);
  const trackedFindings = findings.filter((finding) => ["open", "needs_revalidation"].includes(finding.lifecycle_status));

  return <main className="workspacePage operationsPage">
    <header className="operationsHero"><div><p className="kicker">EXPOSURE OPERATIONS</p><h1>Keep the signal<br /><em>useful over time.</em></h1><p>Monitoring, lifecycle decisions, validation measurement, integrations, and audit evidence are kept together without turning an assessment into an unbounded scanner.</p></div><Link className="primaryAction contentAction" href="/assessments/new">+ NEW ASSESSMENT</Link></header>
    {message && <p className="inventoryMessage" role="status">{message}</p>}

    <section className="operationsGrid" id="monitoring"><article className="operationsCard monitorControl"><header><p className="kicker">CONTINUOUS DISCOVERY</p><h2>Monitor approved scope</h2><p>Each due run is stopped if authorization or the validated scope no longer holds.</p></header><form onSubmit={createMonitor}><label>Assessment<select name="assessment_id" required defaultValue=""><option value="" disabled>Select authorized assessment</option>{authorizedAssessments.map((assessment) => <option value={assessment.id} key={assessment.id}>{assessment.name} · {assessment.target}</option>)}</select></label><label>Cadence<select name="cadence_hours" defaultValue="168"><option value="24">Every 24 hours</option><option value="72">Every 3 days</option><option value="168">Weekly</option><option value="720">Monthly</option></select></label><button className="primaryAction" disabled={working === "monitor" || !authorizedAssessments.length}>{working === "monitor" ? "SAVING" : "ENABLE MONITOR"}</button></form><div className="managedRows">{monitors.length ? monitors.map((monitor) => <div key={monitor.id}><span className={`monitorState monitorState-${monitor.status}`} /><div><strong>{monitor.hostname ?? monitor.assessment_name}</strong><small>{text(monitor.status)} · every {monitor.cadence_hours}h · next {date(monitor.next_run_at)}{monitor.last_error ? ` · ${monitor.last_error}` : ""}</small></div>{monitor.status === "active" ? <button className="textAction" disabled={working === monitor.id} onClick={() => setMonitor(monitor, "paused")}>PAUSE</button> : monitor.status === "paused" ? <button className="textAction" disabled={working === monitor.id} onClick={() => setMonitor(monitor, "active")}>RESUME</button> : <b>BLOCKED</b>}</div>) : <p className="quietState">No scheduled monitor yet.</p>}</div></article>

      <article className="operationsCard qualityControl"><header><p className="kicker">VALIDATION QUALITY</p><h2>Measure false positives honestly</h2><p>{quality?.rate_note ?? "Loading validation measurement..."}</p></header><div className="qualityNumbers"><div><span>CONFIRMED</span><strong>{quality?.validation.confirmed ?? "-"}</strong></div><div><span>REJECTED</span><strong>{quality?.validation.rejected ?? "-"}</strong></div><div><span>MEASURED RATE</span><strong>{quality?.observed_false_positive_rate === null || quality?.observed_false_positive_rate === undefined ? "--" : `${(quality.observed_false_positive_rate * 100).toFixed(1)}%`}</strong></div></div><div className="corpusList">{quality?.corpora.length ? quality.corpora.map((corpus) => <div key={corpus.id}><strong>{corpus.name} <small>v{corpus.version}</small></strong><span>{corpus.case_count} cases · {corpus.classification} · {corpus.status}</span></div>) : <p className="quietState">No validation corpus registered. This prevents misleading performance claims.</p>}</div><input ref={corpusInput} className="visuallyHidden" type="file" accept="application/json,.json" onChange={importCorpus} /><button className="secondaryAction" disabled={working === "corpus"} onClick={() => corpusInput.current?.click()}>{working === "corpus" ? "IMPORTING" : "IMPORT VERSIONED CORPUS"}</button><a className="inlineDownload" href="/validation-corpus-template.json" download>Download corpus template</a></article></section>

    <section className="operationsCard findingControl" id="findings"><header><div><p className="kicker">FINDING LIFECYCLE</p><h2>Resolve the decision, not just the alert</h2><p>Only evidence-linked findings appear here. A completed monitoring run can resolve a finding conservatively; analyst decisions always retain a rationale.</p></div><Link href="/findings">Raw scan findings</Link></header>{trackedFindings.length ? <div className="findingLifecycleRows">{trackedFindings.slice(0, 12).map((finding) => <div key={finding.id}><span className={`severityFlag severity-${finding.severity}`}>{finding.severity}</span><div><strong>{finding.title}</strong><small>{finding.hostname ?? "No correlated asset"} · {finding.validation_status} · last observed {date(finding.last_seen_at)}</small></div><span className="lifecycleBadge">{text(finding.lifecycle_status)}</span><div className="lifecycleActions"><button className="textAction" disabled={working === finding.id} onClick={() => updateFinding(finding, "accepted_risk")}>ACCEPT RISK</button><button className="textAction" disabled={working === finding.id} onClick={() => updateFinding(finding, "dismissed")}>DISMISS</button></div></div>)}</div> : <div className="quietState large">No open lifecycle findings. This does not mean no risk exists; it means no current evidence-backed non-informational finding is tracked.</div>}</section>

    <section className="operationsGrid integrationGrid"><article className="operationsCard"><header><p className="kicker">CONNECTORS & ALERTING</p><h2>Attach trusted operational paths</h2><p>Webhooks and SIEM destinations use encrypted signing secrets, HTTPS-only production egress, DNS resolution checks, no redirects, and a durable retry outbox.</p></header><form className="integrationForm" onSubmit={createIntegration}><label>Name<input name="name" required placeholder="Security operations webhook" /></label><label>Connector type<select name="integration_type" defaultValue="webhook"><option value="webhook">Signed webhook</option><option value="siem">SIEM webhook</option><option value="cloud_inventory">Cloud inventory attestation</option><option value="dns_attestation">DNS ownership attestation</option></select></label><label>Endpoint URL <small>Required for webhook/SIEM</small><input name="endpoint_url" type="url" placeholder="https://security.example.com/events" /></label><label>Signing secret <small>Required for webhook/SIEM</small><input name="signing_secret" type="password" autoComplete="new-password" /></label><button className="primaryAction" disabled={working === "integration"}>{working === "integration" ? "SAVING" : "CONFIGURE CONNECTOR"}</button></form><div className="connectorList">{integrations.length ? integrations.map((integration) => <div key={integration.id}><strong>{integration.name}</strong><span>{text(integration.integration_type)} · {text(integration.status)}</span></div>) : <p className="quietState">No operational connector configured.</p>}</div></article>
      <article className="operationsCard auditControl" id="audit"><header><p className="kicker">APPEND-ONLY AUDIT</p><h2>Know who changed what</h2><p>Client-visible governance events are immutable. Exportable technical evidence remains attached to the underlying assessment record.</p></header><div className="auditRows">{audits.length ? audits.slice(0, 8).map((event) => <div key={event.id}><span>{date(event.occurred_at)}</span><strong>{text(event.event_type)}</strong><small>{event.actor_name ?? "System"} · {text(event.target_type)}</small></div>) : <p className="quietState">Audit history is available to workspace owners and admins.</p>}</div></article></section>
  </main>;
}
