"use client";

import Link from "next/link";
import { ChangeEvent, FormEvent, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";

import { apiFetch } from "../../../../lib/api";

type Preview = {
  plan_version: string;
  mode: string;
  estimated_seconds: number;
  safety_class: string;
  stages: Array<{ adapter: string; timeout_seconds: number; required: boolean }>;
  coverage_contract: {
    methodology_version: string;
    coverage: Record<string, { depth: string; level: number }>;
  };
  current_claim: string;
  non_goals: string[];
  warnings: string[];
};

type Scope = {
  target: string;
  authorization_id: string;
  authorization_expires_at: string;
  allowed_paths: string[];
  excluded_paths: string[];
  allowed_ports: number[];
  credential_reference: string | null;
  source_format: "csv" | "json";
  source_sha256: string;
  validation_token: string;
};

type PassiveInventory = {
  target: string;
  target_hostname: string;
  inventory: {
    status: string;
    source?: string;
    reason?: string;
    discovered_count?: number;
    subdomains: string[];
    limitations?: string;
  };
  next_step: string;
};

const profileCopy = {
  light: ["High-quality external security review", "Bounded, deterministic, and non-exploitative", "Best for frequent public attack-surface assurance"],
  medium: ["Broader validated app coverage", "Adds deeper inventory and corroboration", "Best for standard authorized assessment"],
  aggressive: ["Maximum approved non-exploitative depth", "Widest controlled coverage boundary", "Best for high-assurance test environments"],
};

export default function NewAssessmentPage() {
  const router = useRouter();
  const [mode, setMode] = useState<keyof typeof profileCopy>("light");
  const [serviceTier, setServiceTier] = useState<"external_baseline" | "authorized_deep">("external_baseline");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [message, setMessage] = useState("");
  const [working, setWorking] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);
  const [scope, setScope] = useState<Scope | null>(null);
  const [publicTarget, setPublicTarget] = useState("");
  const [publicInventory, setPublicInventory] = useState<PassiveInventory | null>(null);
  const [publicInventoryMessage, setPublicInventoryMessage] = useState("");
  const [publicInventoryWorking, setPublicInventoryWorking] = useState(false);
  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => {
    const requestedMode = new URLSearchParams(window.location.search).get("mode");
    if (requestedMode && requestedMode in profileCopy) setMode(requestedMode as keyof typeof profileCopy);
    if (new URLSearchParams(window.location.search).get("tier") === "authorized_deep") {
      setServiceTier("authorized_deep");
      if (!requestedMode || requestedMode === "light") setMode("medium");
    }
  }, []);

  function payload(form: HTMLFormElement) {
    const data = new FormData(form);
    const authentication = authenticated ? {
      login_url: data.get("login_url"),
      username: data.get("auth_username"),
      password: data.get("auth_password"),
      username_selector: data.get("username_selector"),
      password_selector: data.get("password_selector"),
      submit_selector: data.get("submit_selector"),
    } : null;
    return {
      name: data.get("name"),
      target: data.get("target"),
      mode,
      service_tier: serviceTier,
      authorization_confirmed: data.get("authorization") === "on",
      authentication,
      scope,
    };
  }

  async function importScope(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setWorking(true); setMessage(""); setPreview(null);
    try {
      const content = await file.text();
      const response = await apiFetch("/api/v3/scope-files/validate", {
        method: "POST", body: JSON.stringify({ filename: file.name, content }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(typeof result.detail === "string" ? result.detail : "Scope validation failed");
      const validated = result as Scope;
      setScope(validated);
      const target = formRef.current?.elements.namedItem("target") as HTMLInputElement | null;
      if (target) target.value = validated.target;
      setMessage(`Validated ${validated.source_format.toUpperCase()} scope ${validated.authorization_id}. Rules will be bound to this assessment.`);
    } catch (error) {
      setScope(null);
      setMessage(error instanceof Error ? error.message : "Scope validation failed");
    } finally { setWorking(false); event.target.value = ""; }
  }

  async function loadPreview(form: HTMLFormElement) {
    setWorking(true); setMessage("");
    try {
      const response = await apiFetch("/api/v3/assessments/preview", { method: "POST", body: JSON.stringify(payload(form)) });
      const result = await response.json();
      if (!response.ok) throw new Error(typeof result.detail === "string" ? result.detail : "Preview failed");
      setPreview(result);
    } catch (error) { setMessage(error instanceof Error ? error.message : "Preview failed"); }
    finally { setWorking(false); }
  }

  async function runPublicInventory() {
    setPublicInventoryWorking(true); setPublicInventoryMessage(""); setPublicInventory(null);
    try {
      const response = await apiFetch("/api/v3/assessments/passive-inventory", {
        method: "POST", body: JSON.stringify({ target: publicTarget }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(typeof result.detail === "string" ? result.detail : "Public inventory could not be completed");
      setPublicInventory(result as PassiveInventory);
    } catch (error) {
      setPublicInventoryMessage(error instanceof Error ? error.message : "Public inventory could not be completed");
    } finally { setPublicInventoryWorking(false); }
  }

  function usePublicDiscoveryAsSeed() {
    const target = formRef.current?.elements.namedItem("target") as HTMLInputElement | null;
    if (!target || !publicInventory) return;
    target.value = publicInventory.target;
    formRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    target.focus();
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setWorking(true); setMessage("");
    try {
      const response = await apiFetch("/api/v3/assessments", { method: "POST", body: JSON.stringify(payload(event.currentTarget)) });
      const assessment = await response.json();
      if (!response.ok) throw new Error(typeof assessment.detail === "string" ? assessment.detail : "Assessment creation failed");
      const dispatch = await apiFetch(`/api/v3/assessments/${assessment.id}/scans`, { method: "POST" });
      const scan = await dispatch.json();
      if (!dispatch.ok) throw new Error(typeof scan.detail === "string" ? scan.detail : "Scan dispatch failed");
      router.push(`/scans?assessment_id=${assessment.id}`); router.refresh();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Assessment creation failed"); }
    finally { setWorking(false); }
  }

  return (
    <main className="workspacePage newAssessmentPage">
      <header className="pageHeader compactHeader"><div><Link className="backLink" href="/assessments">← Assessments</Link><p className="kicker">NEW EXECUTION</p><h1>Configure assessment</h1><p>Define scope and review the immutable plan before any network action occurs.</p></div></header>
      <section className="publicInventoryPanel" aria-labelledby="public-inventory-title">
        <div className="publicInventoryLead"><p className="kicker">PUBLIC EXTERNAL VIEW</p><h2 id="public-inventory-title">Discover public subdomains</h2><p>Uses certificate-transparency records only. It does not contact the target, resolve a hostname, crawl pages, probe ports, or test vulnerabilities.</p></div>
        <div className="publicInventoryAction"><label>Domain or URL<input type="url" value={publicTarget} onChange={(event) => setPublicTarget(event.target.value)} placeholder="https://example.com" /></label><button className="secondaryAction" type="button" disabled={publicInventoryWorking || !publicTarget} onClick={runPublicInventory}>{publicInventoryWorking ? "DISCOVERING..." : "DISCOVER PUBLIC HOSTS"}</button></div>
        {publicInventoryMessage && <p className="formError publicInventoryMessage" role="alert">{publicInventoryMessage}</p>}
        {publicInventory && <div className="publicInventoryResult"><div><span>STATUS</span><strong>{publicInventory.inventory.status}</strong></div><div><span>PUBLIC HOSTS</span><strong>{publicInventory.inventory.discovered_count ?? publicInventory.inventory.subdomains.length}</strong></div><div><span>SOURCE</span><strong>{publicInventory.inventory.source || "Unavailable"}</strong></div><p>{publicInventory.inventory.limitations || publicInventory.next_step}</p>{publicInventory.inventory.reason && <p className="formError">{publicInventory.inventory.reason}</p>}<details><summary>Show discovered public hostnames</summary><div className="publicHostnameList">{publicInventory.inventory.subdomains.length ? publicInventory.inventory.subdomains.map((hostname) => <code key={hostname}>{hostname}</code>) : <span>No eligible descendant hostnames were returned.</span>}</div></details><small>{publicInventory.next_step}</small><button className="secondaryAction" type="button" onClick={usePublicDiscoveryAsSeed}>USE AS AUTHORIZED ASSESSMENT SEED</button></div>}
      </section>
      <form className="assessmentBuilder" onSubmit={submit} ref={formRef}>
        <div className="builderMain">
          <section className="builderSection"><div className="sectionIndex">01</div><div className="sectionBody"><div className="sectionHeading"><h2>Authorized scope file</h2><p>Optional but recommended. Upload one CSV or JSON declaration; it is validated, checksummed, and enforced by every scan stage.</p></div><div className="fieldGrid"><label>Scope file<input type="file" accept=".json,.csv,application/json,text/csv" onChange={importScope} disabled={working} /></label><div className="scopeFileHelp"><strong>One asset per assessment</strong><small>Required fields: target, authorization ID, expiry, allowed paths, exclusions, ports, and an optional opaque credential reference.</small><a href="/scope-file-template.json" download>Download JSON template</a><a href="/scope-file-template.csv" download>Download CSV template</a></div></div>{scope && <div className="authorizationCard"><span><strong>Scope validated: {scope.authorization_id}</strong><small>Expires {new Date(scope.authorization_expires_at).toLocaleString()} · ports {scope.allowed_ports.join(", ")} · paths {scope.allowed_paths.join(", ")}{scope.excluded_paths.length ? ` · exclusions ${scope.excluded_paths.join(", ")}` : ""}{scope.credential_reference ? " · credential reference retained" : ""}</small></span></div>}</div></section>
          <section className="builderSection"><div className="sectionIndex">02</div><div className="sectionBody"><div className="sectionHeading"><h2>Client workflow</h2><p>Choose the service lane first. Both lanes remain non-exploitative until deeper checks are separately released and approved.</p></div><div className="profileGrid serviceTierGrid"><button className={`profileChoice ${serviceTier === "external_baseline" ? "profileChoiceActive" : ""}`} type="button" onClick={() => { setServiceTier("external_baseline"); setPreview(null); }}><span>Continuous external</span><small>Quality public surface and configuration evidence</small><small>Scope file recommended; exact origin is enforced</small></button><button className={`profileChoice ${serviceTier === "authorized_deep" ? "profileChoiceActive" : ""}`} type="button" onClick={() => { setServiceTier("authorized_deep"); if (mode === "light") setMode("medium"); setPreview(null); }}><span>Authorized deep review</span><small>Separate approval lane for a reviewed test environment</small><small>Requires a validated scope file and medium/aggressive plan</small></button></div></div></section>
          <section className="builderSection"><div className="sectionIndex">03</div><div className="sectionBody"><div className="sectionHeading"><h2>Target configuration</h2><p>Name the engagement and define the exact authorized target.</p></div><div className="fieldGrid"><label>Engagement name<input name="name" placeholder="External web assessment" required /></label><label>Target URL<input name="target" type="url" placeholder="https://example.com" required /></label></div></div></section>
          <section className="builderSection"><div className="sectionIndex">04</div><div className="sectionBody"><div className="sectionHeading"><h2>Assessment profile</h2><p>Profiles control coverage and resource budgets, not finding severity. Light is a quality external review, not a basic scan.</p></div><div className="profileGrid">{(Object.keys(profileCopy) as Array<keyof typeof profileCopy>).map((item) => <button className={`profileChoice ${mode === item ? "profileChoiceActive" : ""}`} type="button" key={item} disabled={serviceTier === "authorized_deep" && item === "light"} onClick={() => { setMode(item); setPreview(null); }}><span>{item}</span>{profileCopy[item].map((line) => <small key={line}>{line}</small>)}</button>)}</div></div></section>
          <section className="builderSection"><div className="sectionIndex">05</div><div className="sectionBody"><div className="sectionHeading"><h2>Authenticated coverage</h2><p>Optionally establish a scoped test-user session. Credentials are encrypted and never written to evidence or logs.</p></div><label className="authorizationCard"><input type="checkbox" checked={authenticated} onChange={(event) => setAuthenticated(event.target.checked)} /><span><strong>Use authorized test credentials</strong><small>The login URL must use the same scheme, hostname, and port as the assessment target.</small></span></label>{authenticated && <div className="authFieldGrid"><label>Login URL<input name="login_url" type="url" required placeholder="https://app.example.com/login" /></label><label>Username<input name="auth_username" required autoComplete="off" /></label><label>Password<input name="auth_password" type="password" required autoComplete="new-password" /></label><label>Username selector<input name="username_selector" required defaultValue={'input[name="username"]'} /></label><label>Password selector<input name="password_selector" required defaultValue={'input[type="password"]'} /></label><label>Submit selector<input name="submit_selector" required defaultValue={'button[type="submit"], input[type="submit"]'} /></label></div>}</div></section>
          <section className="builderSection"><div className="sectionIndex">06</div><div className="sectionBody"><div className="sectionHeading"><h2>Authorization gate</h2><p>Execution remains blocked until authorization is explicitly confirmed.</p></div><label className="authorizationCard"><input name="authorization" type="checkbox" required /><span><strong>Written authorization confirmed</strong><small>I confirm authority to perform the selected non-exploitative assessment against this exact target.</small></span></label></div></section>
        </div>
        <aside className="builderAside"><div className="previewPanel"><div className="previewHead"><p className="kicker">EXECUTION PREVIEW</p><h2>{preview ? `${preview.mode} plan` : "Resolve before dispatch"}</h2></div>{preview ? <><div className="previewMetrics"><div><span>PLAN</span><strong>{preview.plan_version}</strong></div><div><span>MAX BUDGET</span><strong>{Math.ceil(preview.estimated_seconds / 60)}m</strong></div></div><p className="safetyNote">{preview.safety_class.replaceAll("_", " ")}</p><div className="authorizationCard"><span><strong>Current release claim</strong><small>{preview.current_claim}</small></span></div><div className="stageList">{preview.stages.map((stage, index) => <div key={stage.adapter}><span>{String(index + 1).padStart(2, "0")}</span><div><strong>{stage.adapter.replaceAll("_", " ")}</strong><small>{stage.required ? "Required" : "Optional"} · {stage.timeout_seconds}s deadline</small></div></div>)}</div><div className="scopeFileHelp"><strong>Methodology depth</strong><small>{Object.entries(preview.coverage_contract.coverage).map(([family, detail]) => `${family.replaceAll("_", " ")}: ${detail.depth.replaceAll("_", " ")}`).join(" · ")}</small></div><div className="scopeFileHelp"><strong>Explicit non-goals</strong>{preview.non_goals.map((item) => <small key={item}>{item}</small>)}</div>{preview.warnings.length > 0 && <div className="scopeFileHelp"><strong>Dispatch warnings</strong>{preview.warnings.map((item) => <small key={item}>{item}</small>)}</div>}</> : <p className="previewEmpty">Preview resolves tool order, stage deadlines, safety class, current release claim, and expected coverage without starting a scan.</p>}{message && <p className="formError" role="alert">{message}</p>}<button className="secondaryAction fullAction" type="button" disabled={working} onClick={(event) => loadPreview(event.currentTarget.form!)}>Preview execution</button><button className="primaryAction fullAction" disabled={working}>{working ? "Working..." : "Create and start"}</button></div></aside>
      </form>
    </main>
  );
}
