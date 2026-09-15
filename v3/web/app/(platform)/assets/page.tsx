"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { apiFetch } from "../../../lib/api";

type Asset = {
  id: string;
  assessment_id: string;
  assessment_name: string;
  assessment_mode: string;
  hostname: string;
  canonical_target: string;
  asset_type: string;
  discovery_sources: string[];
  ownership_status: "client_declared" | "candidate" | "approved" | "excluded";
  ownership_confidence: number;
  assessment_status: string;
  client_status: string;
  latest_scan_id?: string;
  latest_scan_status?: string;
  first_seen_at: string;
  last_seen_at: string;
  review_note?: string;
};

type Dashboard = {
  summary: {
    asset_count: number;
    ownership: Record<string, number>;
    assessment_status: Record<string, number>;
    coverage: Record<string, number>;
    candidate_review_count: number;
    coverage_issue_count: number;
  };
  findings: Array<{ validation_status: string; severity: string; count: number }>;
};

type ExposureAsset = {
  id: string;
  hostname: string;
  canonical_target: string;
  ownership_status: "candidate" | "client_declared" | "verified" | "excluded";
  ownership_confidence: number;
  discovery_sources: string[];
  relationship_count: number;
  observation_count: number;
  last_seen_at: string;
  last_verified_at?: string;
  latest_finding_status?: string;
  latest_finding_severity?: string;
};

type Filter = "all" | "review" | "approved" | "assessed" | "excluded";

function label(value: string) {
  return value.replaceAll("_", " ");
}

function date(value?: string) {
  return value ? new Date(value).toLocaleString() : "Not observed";
}

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [exposureAssets, setExposureAssets] = useState<ExposureAsset[]>([]);
  const [filter, setFilter] = useState<Filter>("all");
  const [message, setMessage] = useState("");
  const [working, setWorking] = useState<string | null>(null);

  async function refresh() {
    const [assetsResponse, dashboardResponse, exposureResponse] = await Promise.all([
      apiFetch("/api/v3/assets", { cache: "no-store" }),
      apiFetch("/api/v3/assessment-scans/dashboard", { cache: "no-store" }),
      apiFetch("/api/v3/exposure/assets", { cache: "no-store" }),
    ]);
    if (!assetsResponse.ok || !dashboardResponse.ok || !exposureResponse.ok) throw new Error("The asset inventory is temporarily unavailable");
    setAssets((await assetsResponse.json()).assets as Asset[]);
    setDashboard(await dashboardResponse.json() as Dashboard);
    setExposureAssets((await exposureResponse.json()).assets as ExposureAsset[]);
    setMessage("");
  }

  useEffect(() => {
    refresh().catch((reason: Error) => setMessage(reason.message));
  }, []);

  async function discover(asset: Asset) {
    setWorking(asset.id); setMessage("");
    try {
      const response = await apiFetch(`/api/v3/assessments/${asset.assessment_id}/assets/discover`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ limit: 100 }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail ?? "Passive discovery could not complete");
      setMessage(payload.next_step ?? "Candidate assets were refreshed for review.");
      await refresh();
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Passive discovery could not complete");
    } finally { setWorking(null); }
  }

  async function review(asset: Asset, ownershipStatus: "approved" | "excluded") {
    if (ownershipStatus === "approved" && !window.confirm(`Confirm written authorization to safely assess ${asset.hostname}. No exploit attempts will be made.`)) return;
    setWorking(asset.id); setMessage("");
    try {
      const response = await apiFetch(`/api/v3/assessments/${asset.assessment_id}/assets/${asset.id}`, {
        method: "PATCH", headers: { "content-type": "application/json" },
        body: JSON.stringify({ ownership_status: ownershipStatus, authorization_confirmed: ownershipStatus === "approved" }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail ?? "Asset review could not be saved");
      setMessage(`${asset.hostname} is now ${label(ownershipStatus)}.`);
      await refresh();
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Asset review could not be saved");
    } finally { setWorking(null); }
  }

  async function start(asset: Asset) {
    if (!window.confirm(`Start the approved non-exploitative assessment for ${asset.canonical_target}?`)) return;
    setWorking(asset.id); setMessage("");
    try {
      const response = await apiFetch(`/api/v3/assessments/${asset.assessment_id}/assets/${asset.id}/start`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ authorization_confirmed: true }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail ?? "Assessment could not be queued");
      setMessage(`${asset.hostname} was queued. Live activity is available in Scan operations.`);
      await refresh();
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Assessment could not be queued");
    } finally { setWorking(null); }
  }

  async function verifyExposureAsset(asset: ExposureAsset, ownership_status: "verified" | "excluded") {
    const action = ownership_status === "verified" ? "verify ownership" : "exclude";
    if (!window.confirm(`Record a ${action} decision for ${asset.hostname}? This retains a client-review audit event.`)) return;
    setWorking(asset.id); setMessage("");
    try {
      const response = await apiFetch(`/api/v3/exposure/assets/${asset.id}/ownership`, {
        method: "PATCH", headers: { "content-type": "application/json" },
        body: JSON.stringify({ ownership_status, verification_method: "written_authorization", note: `Client review completed from asset inventory on ${new Date().toLocaleDateString()}.` }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail ?? "Asset ownership could not be updated");
      setMessage(`${asset.hostname} is now ${ownership_status}.`); await refresh();
    } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Asset ownership could not be updated"); }
    finally { setWorking(null); }
  }

  const visibleAssets = assets.filter((asset) => {
    if (filter === "review") return asset.ownership_status === "candidate";
    if (filter === "approved") return ["approved", "client_declared"].includes(asset.ownership_status) && asset.assessment_status !== "assessed";
    if (filter === "assessed") return asset.assessment_status === "assessed" || asset.assessment_status === "blocked";
    if (filter === "excluded") return asset.ownership_status === "excluded";
    return true;
  });
  const validatedFindings = dashboard?.findings
    .filter((finding) => finding.validation_status === "confirmed")
    .reduce((total, finding) => total + finding.count, 0) ?? 0;

  return (
    <main className="workspacePage assetInventoryPage">
      <header className="dashboardHero assetHero">
        <div><p className="kicker">ASSESSMENT SCANS / ASSET INVENTORY</p><h1>See your external surface.<br /><em>Decide what to trust.</em></h1><p>Discovery identifies candidates. Only client-approved assets can enter a non-exploitative assessment.</p></div>
        <div className="heroDecision"><span>INVENTORY RULE</span><strong>Discovery is not ownership.</strong><p>Every candidate carries source evidence, a confidence signal, and a review state before it is assessed.</p><Link href="/assessments/new">Start a review <b>&rarr;</b></Link></div>
      </header>

      {message && <p className="inventoryMessage" role="status">{message}</p>}

      <section className="dashboardStats assetStats" aria-label="Asset inventory summary">
        <div><span>TRACKED ASSETS</span><strong>{dashboard?.summary.asset_count ?? "-"}</strong><small>Declared and discovered records</small></div>
        <button onClick={() => setFilter("review")}><span>NEEDS REVIEW</span><strong>{dashboard?.summary.candidate_review_count ?? "-"}</strong><small>Candidate ownership decisions</small></button>
        <button onClick={() => setFilter("approved")}><span>APPROVED TO ASSESS</span><strong>{(dashboard?.summary.ownership.approved ?? 0) + (dashboard?.summary.ownership.client_declared ?? 0)}</strong><small>Safe execution is permitted</small></button>
        <button onClick={() => setFilter("assessed")}><span>VALIDATED FINDINGS</span><strong>{validatedFindings}</strong><small>Evidence-confirmed only</small></button>
      </section>

      <section className="correlatedInventory">
        <header><div><p className="kicker">ORGANIZATION INVENTORY</p><h2>Correlate once. Review once.</h2><p>One durable asset record connects discoveries, assessment history, relationships, and lifecycle evidence across the workspace.</p></div><Link href="/operations#monitoring">Open operations <b>&rarr;</b></Link></header>
        {exposureAssets.length ? <div className="correlatedRows">{exposureAssets.slice(0, 7).map((asset) => <article key={asset.id}><span className={`assetState assetState-${asset.ownership_status}`}>{label(asset.ownership_status)}</span><div><strong>{asset.hostname}</strong><small>{asset.discovery_sources.join(" | ") || "Source not recorded"}</small></div><div><span>GRAPH</span><strong>{asset.relationship_count} relation{asset.relationship_count === 1 ? "" : "s"}</strong><small>{asset.observation_count} evidence record{asset.observation_count === 1 ? "" : "s"}</small></div><div><span>RISK</span><strong>{asset.latest_finding_severity ? `${asset.latest_finding_severity} ${label(asset.latest_finding_status ?? "finding")}` : "No tracked finding"}</strong><small>Seen {date(asset.last_seen_at)}</small></div><div className="correlatedActions">{asset.ownership_status === "candidate" && <><button className="textAction" disabled={working === asset.id} onClick={() => verifyExposureAsset(asset, "excluded")}>EXCLUDE</button><button className="primaryAction compactAction" disabled={working === asset.id} onClick={() => verifyExposureAsset(asset, "verified")}>VERIFY</button></>}{asset.ownership_status !== "candidate" && <span>{asset.last_verified_at ? `Reviewed ${date(asset.last_verified_at)}` : "Awaiting verification"}</span>}</div></article>)}</div> : <div className="emptyState"><strong>No durable assets yet</strong><span>Create an assessment to establish a client-declared seed, then use passive discovery to add candidates.</span></div>}
      </section>

      <section className="inventoryWorkspace">
        <header><div><p className="kicker">OWNERSHIP AND COVERAGE</p><h2>Review the inventory before running checks</h2><p>Coverage issues: {dashboard?.summary.coverage_issue_count ?? 0}. A missing or blocked check is never treated as a clean result.</p></div><div className="inventoryFilters" role="group" aria-label="Filter assets">{(["all", "review", "approved", "assessed", "excluded"] as Filter[]).map((item) => <button key={item} className={filter === item ? "active" : ""} onClick={() => setFilter(item)}>{item === "all" ? "ALL" : item === "review" ? "REVIEW" : item.toUpperCase()}</button>)}</div></header>
        {visibleAssets.length === 0 ? <div className="emptyState"><strong>No assets in this view</strong><span>Create an assessment, then run passive discovery from its client-declared seed.</span></div> : <div className="assetRows">{visibleAssets.map((asset) => <article key={asset.id} className={`assetRow assetRow-${asset.ownership_status}`}><div className="assetIdentity"><span className={`assetState assetState-${asset.ownership_status}`}>{label(asset.ownership_status)}</span><h3>{asset.hostname}</h3><p>{asset.canonical_target}</p><small>{asset.discovery_sources.join(" | ") || "Source not recorded"}</small></div><div className="assetFact"><span>OWNERSHIP</span><strong>{asset.ownership_confidence}% confidence</strong><small>{asset.client_status}</small></div><div className="assetFact"><span>LAST OBSERVED</span><strong>{date(asset.last_seen_at)}</strong><small>First seen {date(asset.first_seen_at)}</small></div><div className="assetFact"><span>ASSESSMENT</span><strong>{asset.latest_scan_status ? label(asset.latest_scan_status) : label(asset.assessment_status)}</strong><small>{asset.review_note || "No analyst note"}</small></div><div className="assetActions">{asset.ownership_status === "client_declared" && <button className="textAction" disabled={working === asset.id} onClick={() => discover(asset)}>{working === asset.id ? "DISCOVERING" : "DISCOVER CANDIDATES"}</button>}{asset.ownership_status === "candidate" && <><button className="textAction" disabled={working === asset.id} onClick={() => review(asset, "excluded")}>EXCLUDE</button><button className="primaryAction compactAction" disabled={working === asset.id} onClick={() => review(asset, "approved")}>APPROVE</button></>}{["approved", "client_declared"].includes(asset.ownership_status) && asset.assessment_status !== "assessed" && <button className="primaryAction compactAction" disabled={working === asset.id} onClick={() => start(asset)}>{working === asset.id ? "QUEUING" : "ASSESS"}</button>}{asset.latest_scan_id && <Link className="textAction" href={`/scans?assessment_id=${asset.assessment_id}`}>VIEW RUN</Link>}</div></article>)}</div>}
      </section>
    </main>
  );
}
