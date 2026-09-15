import Link from "next/link";

export default function DashboardPage() {
  return (
    <main className="workspacePage dashboardPage">
      <header className="clientPageHero">
        <div><p className="kicker">EXPOSURESCOPEX / SECURITY PLATFORM</p><h1>One platform.<br /><em>Clear security decisions.</em></h1><p>Choose the component that fits the work: external assessment, local AI assurance, or evidence-backed reporting.</p></div>
        <div className="heroActionPanel"><span>PRIMARY WORKFLOW</span><strong>Assessment scans</strong><p>Discover, confirm, assess, monitor, and manage the evidence lifecycle from one purpose-built workspace.</p><Link className="primaryAction contentAction" href="/assessments">Open assessment scans</Link></div>
      </header>
      <section className="componentLaunches" aria-label="ExposureScopeX components">
        <article><p className="kicker">01 / ASSESS</p><h2>Assessment scans</h2><p>External discovery, ownership review, coverage, lifecycle, and client-ready evidence.</p><Link href="/assessments">Open dashboard <b>&rarr;</b></Link></article>
        <article><p className="kicker">02 / PRE-D</p><h2>Evaluate AI before release.</h2><p>Use the local-first runner to validate an AI system without sending its results to the platform.</p><Link href="/ai-evaluator">Open PRE-D <b>&rarr;</b></Link></article>
        <article><p className="kicker">03 / DECIDE</p><h2>Reports and evidence</h2><p>Download the evidence and reports that explain exactly what was checked and what remains unknown.</p><Link href="/reports">Open reports <b>&rarr;</b></Link></article>
      </section>
    </main>
  );
}
