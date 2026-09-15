"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { apiFetch } from "../../../lib/api";

type Assessment = { id: string; name: string; target: string; mode: string; status: string; service_tier?: string; created_at: string };
type ExposureFinding = { lifecycle_status: string; severity: string; count: number };
type Monitor = { id: string; assessment_name: string; hostname?: string; cadence_hours: number; status: string; next_run_at: string };
type AssetEvent = { id: number; event_type: string; hostname: string; occurred_at: string };
type ExposureDashboard = {
  workspace: { name: string; role: string };
  assets: Record<string, number>;
  findings: ExposureFinding[];
  monitors: Monitor[];
  recent_asset_events: AssetEvent[];
  next_step: string;
};

const terminal = new Set(["complete", "partial", "failed", "cancelled", "blocked"]);
const needsReview = new Set(["partial", "failed", "blocked", "cancelled"]);

function display(value: string) { return value.replaceAll("_", " "); }
function formatDate(value: string) { return new Date(value).toLocaleString(); }

export default function AssessmentsPage() {
  const [dashboard, setDashboard] = useState<ExposureDashboard | null>(null);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [message, setMessage] = useState("");

  async function refresh() {
    const [dashboardResponse, assessmentResponse] = await Promise.all([
      apiFetch("/api/v3/exposure/dashboard", { cache: "no-store" }),
      apiFetch("/api/v3/assessments", { cache: "no-store" }),
    ]);
    if (!dashboardResponse.ok || !assessmentResponse.ok) throw new Error("Assessment workspace is temporarily unavailable");
    setDashboard(await dashboardResponse.json() as ExposureDashboard);
    setAssessments(await assessmentResponse.json() as Assessment[]);
    setMessage("");
  }

  useEffect(() => {
    refresh().catch((reason: Error) => setMessage(reason.message));
    const timer = window.setInterval(() => refresh().catch(() => undefined), 5000);
    return () => window.clearInterval(timer);
  }, []);

  const openFindings = dashboard?.findings.filter((finding) => ["open", "needs_revalidation"].includes(finding.lifecycle_status)) ?? [];
  const priorityFindings = openFindings.filter((finding) => ["critical", "high"].includes(finding.severity)).reduce((total, item) => total + item.count, 0);
  const activeAssessments = assessments.filter((assessment) => !terminal.has(assessment.status));
  const candidateAssets = dashboard?.assets.candidate ?? 0;
  const monitoredAssets = dashboard?.monitors.filter((monitor) => monitor.status === "active").length ?? 0;
  const nextAction = candidateAssets > 0
    ? { title: "Confirm newly discovered assets", body: `${candidateAssets} candidate asset${candidateAssets === 1 ? " is" : "s are"} waiting for an ownership decision.`, href: "/assets", action: "Review inventory" }
    : priorityFindings > 0
      ? { title: "Review validated risk lifecycle", body: `${priorityFindings} open critical or high finding${priorityFindings === 1 ? "" : "s"} need a documented owner decision.`, href: "/operations#findings", action: "Open lifecycle" }
      : activeAssessments[0]
        ? { title: "Watch evidence collection", body: `${activeAssessments[0].name} is still collecting bounded evidence.`, href: `/scans?assessment_id=${activeAssessments[0].id}`, action: "View live scan" }
        : { title: dashboard?.next_step ?? "Create your first scoped assessment", body: "Discovery, monitoring, and assessment remain separate so scope never becomes an assumption.", href: "/assessments/new", action: "New assessment" };

  return (
    <main className="workspacePage exposureDashboardPage">
      <header className="dashboardHero exposureHero">
        <div><p className="kicker">ASSESSMENT SCANS / {dashboard?.workspace.name ?? "WORKSPACE"}</p><h1>Your exposure, with<br /><em>the context to act.</em></h1><p>Track what was discovered, what the customer confirmed, what changed, and what evidence supports each assessment decision.</p></div>
        <div className="heroDecision"><span>RECOMMENDED NEXT STEP</span><strong>{nextAction.title}</strong><p>{nextAction.body}</p><Link href={nextAction.href}>{nextAction.action} <b>&rarr;</b></Link></div>
      </header>

      {message && <p className="formError" role="alert">{message}</p>}

      <section className="dashboardStats exposureStats" aria-label="Assessment posture">
        <Link href="/assets"><span>ACTIVE ASSETS</span><strong>{((dashboard?.assets.verified ?? 0) + (dashboard?.assets.client_declared ?? 0)) || "-"}</strong><small>{candidateAssets} candidate{candidateAssets === 1 ? "" : "s"} remain unverified</small></Link>
        <Link href="/operations#findings"><span>OPEN PRIORITY FINDINGS</span><strong>{priorityFindings}</strong><small>Lifecycle-managed, not raw scanner output</small></Link>
        <Link href="/operations#monitoring"><span>CONTINUOUS MONITORS</span><strong>{monitoredAssets}</strong><small>Authorization is re-checked before dispatch</small></Link>
        <a href="#assessment-history"><span>ACTIVE ASSESSMENTS</span><strong>{activeAssessments.length}</strong><small>Coverage and evidence remain linked to each run</small></a>
      </section>

      <section className="exposureCommandGrid">
        <article className="exposurePriorityPanel">
          <header><div><p className="kicker">ASSESSMENT WORKLIST</p><h2>Make the next decision clear</h2></div><Link href="/assessments/new">+ NEW ASSESSMENT</Link></header>
          {assessments.length === 0 ? <div className="dashboardEmpty"><strong>Start with one known asset</strong><span>Create a scoped assessment, then discover and confirm candidates before any host is contacted.</span></div> : <div className="exposureWorklist">{assessments.slice(0, 5).map((assessment) => <Link href={`/scans?assessment_id=${assessment.id}`} key={assessment.id}><span className={`worklistStatus worklistStatus-${assessment.status}`} /><span><strong>{assessment.name}</strong><small>{assessment.target}</small></span><em>{assessment.service_tier === "authorized_deep" ? "AUTHORIZED DEEP" : assessment.mode.toUpperCase()}</em><b className={needsReview.has(assessment.status) ? "review" : ""}>{needsReview.has(assessment.status) ? "REVIEW" : display(assessment.status)}</b><i>&rarr;</i></Link>)}</div>}
        </article>
        <aside className="exposureSignalPanel"><p className="kicker">ASSESSMENT SIGNAL</p><h2>What this component knows.</h2><div><strong>{dashboard?.assets.verified ?? 0}</strong><span>verified assets</span></div><div><strong>{dashboard?.assets.client_declared ?? 0}</strong><span>client-declared seeds</span></div><div><strong>{candidateAssets}</strong><span>unconfirmed candidates</span></div><p>Candidate discovery is useful evidence, not proof of ownership. This workspace keeps that distinction visible.</p><Link href="/assets">View asset correlation <b>&rarr;</b></Link></aside>
      </section>

      <section className="exposureLowerGrid">
        <article className="timelinePanel"><header><div><p className="kicker">CHANGE TIMELINE</p><h2>Recent asset events</h2></div><Link href="/operations#audit">Audit history</Link></header>{dashboard?.recent_asset_events.length ? <div className="eventTimeline">{dashboard.recent_asset_events.slice(0, 5).map((event) => <div key={event.id}><span className={`eventDot event-${event.event_type.split(".")[1] ?? "observed"}`} /><div><strong>{display(event.event_type)}</strong><small>{event.hostname} · {formatDate(event.occurred_at)}</small></div></div>)}</div> : <div className="timelineEmpty">No asset events yet. Discovery and review events will appear here once a scoped assessment exists.</div>}</article>
        <article className="monitorPanel"><header><div><p className="kicker">CONTINUOUS COVERAGE</p><h2>Approved monitors</h2></div><Link href="/operations#monitoring">Manage monitors</Link></header>{dashboard?.monitors.length ? <div className="monitorRows">{dashboard.monitors.slice(0, 4).map((monitor) => <div key={monitor.id}><span className={`monitorState monitorState-${monitor.status}`} /><div><strong>{monitor.hostname ?? monitor.assessment_name}</strong><small>Every {monitor.cadence_hours}h · next {formatDate(monitor.next_run_at)}</small></div><b>{display(monitor.status)}</b></div>)}</div> : <div className="timelineEmpty">No recurring monitor is active. Create one only for a still-authorized assessment.</div>}</article>
      </section>

      <section className="clientJourney" aria-label="Assessment scan workflow">
        <article><span>01</span><p className="kicker">DISCOVER</p><h2>Build a reviewable surface.</h2><p>Start from customer-declared seeds and public evidence. The platform records source, time, confidence, and relationships.</p><Link href="/assets">Open inventory <b>&rarr;</b></Link></article>
        <article><span>02</span><p className="kicker">CONFIRM</p><h2>Keep ownership explicit.</h2><p>Only customer-confirmed assets enter assessment scope. DNS and cloud evidence are retained as attestations, not guesses.</p><Link href="/assets">Review ownership <b>&rarr;</b></Link></article>
        <article><span>03</span><p className="kicker">ASSESS</p><h2>Prove the decision.</h2><p>Use a bounded external assessment now, or a separately authorized deep review lane when test scope is ready.</p><Link href="/assessments/new">New assessment <b>&rarr;</b></Link></article>
      </section>

      <section className="assessmentLedger clientLedger" id="assessment-history">
        <div className="ledgerHeader"><div><p className="kicker">ASSESSMENT HISTORY</p><h2>Runs, coverage, and evidence</h2><p>Each result retains its scope, execution status, coverage, and report artifacts.</p></div><div className="ledgerTools"><button className="textAction" onClick={() => refresh()}>REFRESH LIST</button></div></div>
        <div className="tableHead"><span>ASSESSMENT</span><span>PROFILE</span><span>STATUS</span><span>RISK</span><span>CREATED</span><span>ACTION</span></div>
        {assessments.length === 0 ? <div className="emptyState"><strong>Your first assessment starts here</strong><span>Discover public hostnames first, or create an authorized assessment when scope is ready.</span><Link href="/assessments/new">Start assessment</Link></div> : assessments.map((assessment) => <article className="assessmentRow" key={assessment.id}><div className="assessmentIdentity"><span className="targetGlyph">{assessment.name.slice(0, 2).toUpperCase()}</span><div><strong>{assessment.name}</strong><small>{assessment.target}</small></div></div><span className="profileLabel">{assessment.service_tier === "authorized_deep" ? "deep" : assessment.mode}</span><span className={`statusLabel status-${assessment.status}`}><i />{assessment.status}</span><span className="riskPending">--</span><time>{formatDate(assessment.created_at)}</time><Link className="rowAction rowActionLink" href={`/scans?assessment_id=${assessment.id}`} aria-label={`View scans for ${assessment.name}`}>VIEW</Link></article>)}
      </section>
    </main>
  );
}
