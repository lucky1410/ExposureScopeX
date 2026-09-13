import Link from "next/link";
import { notFound } from "next/navigation";

const modules: Record<string, { title: string; kicker: string; description: string; capabilities: string[]; status: string }> = {
  dashboard: { title: "Command dashboard", kicker: "OPERATIONAL OVERVIEW", description: "The unified posture and execution overview will aggregate validated assessment data without inventing risk signals.", capabilities: ["Assessment health", "Active execution", "Finding severity", "Evidence integrity"], status: "Foundation queued" },
  findings: { title: "Findings", kicker: "VALIDATED OBSERVATIONS", description: "Normalized, evidence-backed security observations with lifecycle state and remediation ownership.", capabilities: ["Finding identity", "Severity and confidence", "Evidence linkage", "Remediation workflow"], status: "Data API ready" },
  assets: { title: "Asset inventory", kicker: "AUTHORIZED SURFACE", description: "The durable inventory of in-scope applications, APIs, hosts, and identities discovered during assessments.", capabilities: ["Scope provenance", "Service inventory", "Ownership", "Exposure history"], status: "Schema design queued" },
  vulnerabilities: { title: "Vulnerabilities", kicker: "TECHNICAL RISK", description: "A deduplicated vulnerability register built only from validated scanner observations.", capabilities: ["CVE and CWE mapping", "Affected assets", "Validation state", "Remediation status"], status: "Normalization queued" },
  "risk-paths": { title: "Risk paths", kicker: "CORRELATION", description: "Non-exploitative attack-path correlation across confirmed assets and findings.", capabilities: ["Dependency graph", "Reachability", "Control gaps", "Priority rationale"], status: "Future assessment phase" },
  evidence: { title: "Evidence vault", kicker: "FORENSIC CHAIN", description: "Immutable source artifacts, real screenshots, terminal output, timestamps, and cryptographic integrity records.", capabilities: ["SHA-256 verification", "Source attribution", "Capture timestamps", "Finding traceability"], status: "Artifact API ready" },
  reports: { title: "Reports", kicker: "CLIENT DELIVERABLES", description: "Per-run final, partial, failed, and cancelled reports assembled from recorded evidence and execution state.", capabilities: ["DOCX and PDF", "Methodology", "Findings and proof", "Skipped and failed stages"], status: "Manifest generation ready" },
  agents: { title: "Agent registry", kicker: "MULTI-AGENT CONTROL", description: "Bounded specialist agents with explicit responsibilities, contracts, and deterministic scanner separation.", capabilities: ["Planning agent", "Execution coordinator", "Evidence validator", "Quality evaluator"], status: "Architecture defined" },
  benchmarks: { title: "Benchmark lab", kicker: "MEASURABLE QUALITY", description: "Repeatable validation against known targets to measure precision, recall, F-score, coverage, and evidence quality.", capabilities: ["Golden datasets", "Regression runs", "False-positive review", "Coverage gates"], status: "Harness queued" },
  runtime: { title: "Runtime", kicker: "PLATFORM HEALTH", description: "Worker leases, queue health, adapter readiness, and operational diagnostics without shell access from the browser.", capabilities: ["Runner health", "Queue depth", "Lease recovery", "Adapter inventory"], status: "Health API ready" },
  settings: { title: "Platform settings", kicker: "GOVERNANCE", description: "Authorization, assessment policy, identity, retention, and integration controls.", capabilities: ["Scan authorization", "Profile policy", "Evidence retention", "Access control"], status: "Policy design queued" },
};

export default async function ModulePage({ params }: { params: Promise<{ module: string }> }) {
  const { module } = await params;
  const content = modules[module];
  if (!content) notFound();
  return (
    <main className="workspacePage">
      <header className="pageHeader"><div><p className="kicker">{content.kicker}</p><h1>{content.title}</h1><p>{content.description}</p></div><span className="moduleStatus">{content.status}</span></header>
      <section className="moduleCanvas">
        <div className="moduleLead"><span>MODULE CONTRACT</span><h2>Built deliberately, never presented as complete before it is verifiable.</h2><p>This destination is active so the platform navigation remains coherent. Its listed capabilities are the implementation boundary, not fabricated operational data.</p><Link className="primaryAction contentAction" href={module === "findings" ? "/scans" : "/assessments"}>{module === "findings" ? "View live scan data" : "Return to assessments"}</Link></div>
        <div className="capabilityList">{content.capabilities.map((capability, index) => <div key={capability}><span>0{index + 1}</span><strong>{capability}</strong><small>{index === 0 ? "Core capability" : "Planned capability"}</small></div>)}</div>
      </section>
    </main>
  );
}
