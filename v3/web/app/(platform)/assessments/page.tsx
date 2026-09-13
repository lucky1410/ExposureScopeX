"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { apiFetch } from "../../../lib/api";

type Assessment = {
  id: string;
  name: string;
  target: string;
  mode: string;
  status: string;
  created_at: string;
};

const profiles = [
  { name: "Light", detail: "Low-impact baseline", use: "Fast exposure and configuration review" },
  { name: "Medium", detail: "Broader validated coverage", use: "Standard authorized assessment" },
  { name: "Aggressive", detail: "Maximum non-exploitative depth", use: "Controlled test environments" },
];

export default function AssessmentsPage() {
  const [items, setItems] = useState<Assessment[]>([]);
  const [message, setMessage] = useState("Lifecycle state refreshes from PostgreSQL every five seconds.");

  async function refresh() {
    const response = await apiFetch("/api/v3/assessments", { cache: "no-store" });
    if (!response.ok) throw new Error("Unable to load assessments");
    setItems(await response.json());
  }

  useEffect(() => {
    refresh().catch((error: Error) => setMessage(error.message));
    const timer = window.setInterval(() => refresh().catch(() => undefined), 5000);
    return () => window.clearInterval(timer);
  }, []);

  const active = items.filter((item) => ["queued", "running"].includes(item.status)).length;
  const final = items.filter((item) => item.status === "complete").length;
  const degraded = items.filter((item) => ["partial", "failed", "cancelled", "blocked"].includes(item.status)).length;

  return (
    <main className="workspacePage">
      <header className="pageHeader">
        <div><p className="kicker">ASSESSMENT OPERATIONS</p><h1>Assessments</h1><p>Plan, execute, validate, and report every authorized security assessment.</p></div>
        <div className="pageActions"><Link className="secondaryAction contentAction" href="/assessments/new">IMPORT SCOPE FILE</Link><Link className="primaryAction contentAction" href="/assessments/new">+ New assessment</Link></div>
      </header>

      <section className="metricRow" aria-label="Assessment summary">
        <div><span>TOTAL</span><strong>{items.length}</strong></div><div><span>ACTIVE</span><strong>{active}</strong></div><div><span>FINAL</span><strong>{final}</strong></div><div><span>PARTIAL / FAILED / BLOCKED</span><strong>{degraded}</strong></div>
      </section>

      <section className="profileOverview" aria-label="Available assessment profiles">
        <div className="profileOverviewIntro"><span>SCAN PROFILES</span><strong>Choose depth by operational tolerance</strong></div>
        {profiles.map((profile, index) => (
          <Link href={`/assessments/new?mode=${profile.name.toLowerCase()}`} key={profile.name} className="profileOverviewCard">
            <span>0{index + 1}</span><strong>{profile.name}</strong><small>{profile.detail}</small><em>{profile.use}</em>
          </Link>
        ))}
      </section>

      <section className="assessmentLedger">
        <div className="ledgerHeader"><div><h2>Execution ledger</h2><p>{message}</p></div><div className="ledgerTools"><button className="filterControl">ALL STATUSES</button><button className="textAction" onClick={() => refresh()}>REFRESH</button></div></div>
        <div className="tableHead"><span>ASSESSMENT</span><span>PROFILE</span><span>STATUS</span><span>RISK</span><span>CREATED</span><span>ACTION</span></div>
        {items.length === 0 ? <div className="emptyState"><strong>No assessments yet</strong><span>Create an authorized assessment to establish the first execution record.</span><Link href="/assessments/new">Create assessment</Link></div> : items.map((item) => (
          <article className="assessmentRow" key={item.id}>
            <div className="assessmentIdentity"><span className="targetGlyph">{item.name.slice(0, 2).toUpperCase()}</span><div><strong>{item.name}</strong><small>{item.target}</small></div></div>
            <span className="profileLabel">{item.mode}</span>
            <span className={`statusLabel status-${item.status}`}><i />{item.status}</span>
            <span className="riskPending">--</span>
            <time>{new Date(item.created_at).toLocaleString()}</time>
            <Link className="rowAction rowActionLink" href={`/scans?assessment_id=${item.id}`} aria-label={`View scans for ${item.name}`}>VIEW</Link>
          </article>
        ))}
      </section>
    </main>
  );
}
