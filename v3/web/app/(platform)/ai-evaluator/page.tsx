"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import type { ChangeEvent, FormEvent } from "react";

import {
  apiFetch,
  setEvaluatorOrganization,
} from "../../../lib/api";

type EvaluatorDescriptor = {
  version: string;
  deployment: string;
  scanner_control: boolean;
  assessment_scan_integration: boolean;
  roles: { id: string; purpose: string }[];
  enterprise_controls?: string[];
  supported_subject_types?: string[];
  supported_integration_modes?: string[];
  semantic_judge: {
    status: "ready" | "disabled" | "misconfigured";
    provider: string;
    model?: string;
    detail?: string;
    tools_enabled: boolean;
  };
};

type WorkspaceReference = {
  id: string;
  name: string;
  slug: string;
  membership_role: "owner" | "admin" | "analyst" | "viewer";
};

type EvaluatorProject = {
  id: string;
  key: string;
  name: string;
  description: string;
  status: "active" | "archived";
};

type EvaluatorDataset = {
  id: string;
  project_key: string;
  name: string;
  version: string;
  classification: "synthetic" | "public" | "internal" | "restricted";
  source_sha256: string;
  source_reference: string;
  status: "draft" | "approved" | "retired";
};

type EvaluatorLiveAdapter = {
  id: string;
  project_key: string;
  name: string;
  adapter_type: "http_json_v1";
  endpoint_sha256: string;
  status: "draft" | "approved" | "disabled";
};

type EvaluatorClientIdentity = {
  id: string;
  project_key: string;
  name: string;
  identity_type: "ed25519";
  key_fingerprint: string;
  status: "draft" | "approved" | "disabled";
};

type EvaluatorGitHubIntegration = {
  id: string;
  project_key: string;
  name: string;
  repository: string;
  workflow_ref: string;
  oidc_audience: string;
  status: "draft" | "approved" | "disabled";
};

type Workspace = {
  organization: WorkspaceReference;
  projects: EvaluatorProject[];
  datasets: EvaluatorDataset[];
  live_adapters: EvaluatorLiveAdapter[];
  client_identities: EvaluatorClientIdentity[];
  github_integrations: EvaluatorGitHubIntegration[];
};

type AuditEvent = {
  event_type: string;
  target_type: string;
  occurred_at: string;
  actor_name: string;
};

type EvaluatorView = "start" | "run" | "results" | "setup";
type RunMethod = "manifest" | "local" | "live" | "semantic";

function viewFromHash(hash: string): EvaluatorView {
  if (["run", "run-manifest", "live-evaluation", "client-delivery"].includes(hash)) return "run";
  if (hash === "results" || hash === "setup") return hash;
  return "start";
}

type Evaluation = {
  id: string;
  name: string;
  evaluated_agent_id: string;
  dataset_version: string;
  release_decision: "pass" | "fail" | "inconclusive";
  metrics: {
    overall_score?: number;
    measurement_coverage?: number;
    classification?: { macro_f1?: number };
  };
  reports?: Partial<Record<"docx" | "pdf", { content_sha256: string }>>;
};

type SemanticRun = {
  id: string;
  name: string;
  subject_id: string;
  dataset_version: string;
  provider: string;
  requested_model: string;
  status: "running" | "completed" | "failed";
  result?: { human_review_required?: boolean };
  error_code?: string;
};

const qualityDimensions = [
  ["Classification", "Confusion matrix, precision, recall, F1 and false-positive rate"],
  ["Security", "Attack success, detection and negative-control rates"],
  ["Grounding", "Hallucination, evidence support and citation validity"],
  ["Calibration", "Brier score and expected calibration error"],
  ["RAG", "Faithfulness, context precision and recall at K"],
  ["Trajectory", "Correctness, tool misuse, scope and policy violations"],
  ["Robustness", "Paraphrases, perturbations and repeated runs"],
  ["Agreement", "Cross-model judge agreement and reproducibility"],
  ["Cost and efficiency", "Cost, tokens, retries, cache, fallbacks and latency"],
];

function apiError(body: { detail?: unknown }, fallback: string) {
  if (typeof body.detail === "string") return body.detail;
  if (body.detail && typeof body.detail === "object" && "message" in body.detail) {
    return String(body.detail.message);
  }
  return fallback;
}

export default function AiEvaluatorPage() {
  const [descriptor, setDescriptor] = useState<EvaluatorDescriptor | null>(null);
  const [evaluations, setEvaluations] = useState<Evaluation[]>([]);
  const [semanticRuns, setSemanticRuns] = useState<SemanticRun[]>([]);
  const [workspace, setWorkspace] = useState<Workspace | null>(null);
  const [workspaces, setWorkspaces] = useState<WorkspaceReference[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [manifest, setManifest] = useState("");
  const [manifestName, setManifestName] = useState("");
  const [semanticManifest, setSemanticManifest] = useState("");
  const [semanticManifestName, setSemanticManifestName] = useState("");
  const [submitState, setSubmitState] = useState("");
  const [platformCheckState, setPlatformCheckState] = useState("");
  const [platformCheckResult, setPlatformCheckResult] = useState<string | null>(null);
  const [semanticSubmitState, setSemanticSubmitState] = useState("");
  const [reportGeneration, setReportGeneration] = useState<string | null>(null);
  const [reportDownload, setReportDownload] = useState<string | null>(null);
  const [projectKey, setProjectKey] = useState("");
  const [projectName, setProjectName] = useState("");
  const [projectDescription, setProjectDescription] = useState("");
  const [datasetProjectKey, setDatasetProjectKey] = useState("default");
  const [datasetName, setDatasetName] = useState("");
  const [datasetVersion, setDatasetVersion] = useState("");
  const [datasetClassification, setDatasetClassification] = useState<EvaluatorDataset["classification"]>("synthetic");
  const [datasetSourceReference, setDatasetSourceReference] = useState("");
  const [datasetSourceSha256, setDatasetSourceSha256] = useState("");
  const [adapterProjectKey, setAdapterProjectKey] = useState("default");
  const [adapterName, setAdapterName] = useState("");
  const [adapterEndpointUrl, setAdapterEndpointUrl] = useState("");
  const [adapterApiToken, setAdapterApiToken] = useState("");
  const [clientIdentityProjectKey, setClientIdentityProjectKey] = useState("default");
  const [clientIdentityName, setClientIdentityName] = useState("");
  const [clientPublicKey, setClientPublicKey] = useState("");
  const [githubProjectKey, setGithubProjectKey] = useState("default");
  const [githubIntegrationName, setGithubIntegrationName] = useState("");
  const [githubRepository, setGithubRepository] = useState("");
  const [githubWorkflowRef, setGithubWorkflowRef] = useState("");
  const [liveAdapterId, setLiveAdapterId] = useState("");
  const [liveManifest, setLiveManifest] = useState("");
  const [liveManifestName, setLiveManifestName] = useState("");
  const [liveSubmitState, setLiveSubmitState] = useState("");
  const [governanceState, setGovernanceState] = useState("");
  const [error, setError] = useState("");
  const [activeView, setActiveView] = useState<EvaluatorView>("start");
  const [runMethod, setRunMethod] = useState<RunMethod>("manifest");

  async function load() {
    const [descriptorResponse, evaluationResponse, semanticResponse, workspaceResponse] = await Promise.all([
      apiFetch("/api/v3/evaluator"),
      apiFetch("/api/v3/evaluations"),
      apiFetch("/api/v3/evaluator/semantic-runs"),
      apiFetch("/api/v3/evaluator/workspace"),
    ]);
    if (!descriptorResponse.ok || !evaluationResponse.ok || !semanticResponse.ok || !workspaceResponse.ok) {
      throw new Error("AI assurance control plane is unavailable");
    }
    setDescriptor(await descriptorResponse.json());
    setEvaluations(await evaluationResponse.json());
    setSemanticRuns(await semanticResponse.json());
    const nextWorkspace = await workspaceResponse.json() as Workspace;
    setWorkspace(nextWorkspace);
    setDatasetProjectKey((current) => current || nextWorkspace.projects[0]?.key || "default");
    setAdapterProjectKey((current) => current || nextWorkspace.projects[0]?.key || "default");
    setClientIdentityProjectKey((current) => current || nextWorkspace.projects[0]?.key || "default");
    setGithubProjectKey((current) => current || nextWorkspace.projects[0]?.key || "default");
    setLiveAdapterId((current) => current || nextWorkspace.live_adapters.find((item) => item.status === "approved")?.id || "");
    if (nextWorkspace.organization.membership_role === "owner" || nextWorkspace.organization.membership_role === "admin") {
      const auditResponse = await apiFetch("/api/v3/evaluator/audit-events");
      setAuditEvents(auditResponse.ok ? await auditResponse.json() : []);
    } else {
      setAuditEvents([]);
    }
  }

  async function loadWorkspaces() {
    const response = await apiFetch("/api/v3/evaluator/workspaces");
    if (!response.ok) throw new Error("AI assurance workspace directory is unavailable");
    setWorkspaces(await response.json());
  }

  useEffect(() => {
    setActiveView(viewFromHash(window.location.hash.slice(1)));
    Promise.all([load(), loadWorkspaces()]).catch((reason: Error) => setError(reason.message));
  }, []);

  async function chooseManifest(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setManifestName(file.name);
    setManifest(await file.text());
    setSubmitState("");
  }

  async function runDeterministicEvaluation() {
    setError("");
    setSubmitState("Validating manifest...");
    try {
      const parsed = JSON.parse(manifest) as { project_key?: unknown; dataset_version?: unknown };
      ensureApprovedDataset(parsed.project_key, parsed.dataset_version);
      const response = await apiFetch("/api/v3/evaluations", {
        method: "POST",
        body: manifest,
      });
      const body = await response.json();
      if (!response.ok) throw new Error(apiError(body, "Evaluation failed"));
      setSubmitState(`Evaluation completed: ${body.release_decision}`);
      await load();
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "Evaluation failed";
      setSubmitState("");
      setError(message);
    }
  }

  async function runPlatformCheck() {
    setError("");
    setPlatformCheckState("Loading the synthetic platform check...");
    setPlatformCheckResult(null);
    try {
      const fixtureResponse = await fetch("/fixtures/evaluator-smoke-1.0.json", { cache: "no-store" });
      if (!fixtureResponse.ok) throw new Error("The built-in platform check is unavailable");
      const fixture = await fixtureResponse.text();
      const parsed = JSON.parse(fixture) as { project_key?: unknown; dataset_version?: unknown };
      ensureApprovedDataset(parsed.project_key, parsed.dataset_version);
      const response = await apiFetch("/api/v3/evaluations", { method: "POST", body: fixture });
      const body = await response.json();
      if (!response.ok) throw new Error(apiError(body, "Platform check failed"));
      setPlatformCheckState(`Platform check completed: ${body.release_decision}.`);
      setPlatformCheckResult(String(body.id));
      await load();
    } catch (reason) {
      setPlatformCheckState("");
      setError(reason instanceof Error ? reason.message : "Platform check failed");
    }
  }

  async function chooseSemanticManifest(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setSemanticManifestName(file.name);
    setSemanticManifest(await file.text());
    setSemanticSubmitState("");
  }

  async function runSemanticEvaluation() {
    setError("");
    setSemanticSubmitState("Verifying evidence and invoking independent judge...");
    try {
      const parsed = JSON.parse(semanticManifest) as { project_key?: unknown; dataset_version?: unknown };
      ensureApprovedDataset(parsed.project_key, parsed.dataset_version);
      const response = await apiFetch("/api/v3/evaluator/semantic-runs", {
        method: "POST",
        body: semanticManifest,
      });
      const body = await response.json();
      if (!response.ok) throw new Error(apiError(body, "Semantic evaluation failed"));
      const review = body.result?.human_review_required ? "review required" : "no review flags";
      setSemanticSubmitState(`Semantic evaluation completed: ${review}`);
      await load();
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "Semantic evaluation failed";
      setSemanticSubmitState("");
      setError(message);
    }
  }

  async function generateReport(evaluationId: string) {
    setError("");
    setReportGeneration(evaluationId);
    try {
      const response = await apiFetch(`/api/v3/evaluations/${evaluationId}/reports`, {
        method: "POST",
      });
      const body = await response.json();
      if (!response.ok) throw new Error(apiError(body, "Evaluator report generation failed"));
      await load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Evaluator report generation failed");
    } finally {
      setReportGeneration(null);
    }
  }

  async function downloadReport(evaluationId: string, format: "pdf" | "docx") {
    setError("");
    const downloadId = `${evaluationId}:${format}`;
    setReportDownload(downloadId);
    try {
      const response = await apiFetch(`/api/v3/evaluations/${evaluationId}/reports/download/${format}`);
      if (!response.ok) {
        const body = await response.json().catch(() => null) as { detail?: unknown } | null;
        throw new Error(apiError(body ?? {}, `Report export failed (${response.status})`));
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
      setReportDownload(null);
    }
  }

  function ensureApprovedDataset(projectValue: unknown, datasetValue: unknown) {
    const selectedProject = typeof projectValue === "string" ? projectValue : "default";
    const selectedVersion = typeof datasetValue === "string" ? datasetValue : "";
    const dataset = workspace?.datasets.find(
      (item) => item.project_key === selectedProject && item.version === selectedVersion,
    );
    if (!dataset) {
      throw new Error(`Dataset ${selectedVersion || "version"} is not registered in project ${selectedProject}. Register and approve it before running a release evaluation.`);
    }
    if (dataset.status !== "approved") {
      throw new Error(`Dataset ${selectedVersion} is ${dataset.status}. An owner or administrator must approve it before this evaluation can run.`);
    }
  }

  async function switchWorkspace(organizationId: string) {
    setError("");
    setEvaluatorOrganization(organizationId);
    try {
      await Promise.all([load(), loadWorkspaces()]);
      setGovernanceState("Workspace switched. Evaluations and datasets are isolated to this organization.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Workspace switch failed");
    }
  }

  async function createProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setGovernanceState("Creating governed project...");
    try {
      const response = await apiFetch("/api/v3/evaluator/projects", {
        method: "POST",
        body: JSON.stringify({ key: projectKey, name: projectName, description: projectDescription }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(apiError(body, "Project creation failed"));
      setProjectKey("");
      setProjectName("");
      setProjectDescription("");
      setDatasetProjectKey(body.key);
      setGovernanceState(`Project ${body.key} is active and ready for governed datasets.`);
      await load();
    } catch (reason) {
      setGovernanceState("");
      setError(reason instanceof Error ? reason.message : "Project creation failed");
    }
  }

  async function chooseDatasetSource(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
    const sha256 = Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
    setDatasetSourceSha256(sha256);
    setDatasetSourceReference(file.name);
    if (!datasetVersion && file.name.endsWith(".json")) {
      try {
        const parsed = JSON.parse(await file.text()) as { dataset_version?: unknown; project_key?: unknown; name?: unknown };
        if (typeof parsed.dataset_version === "string") setDatasetVersion(parsed.dataset_version);
        if (typeof parsed.project_key === "string") setDatasetProjectKey(parsed.project_key);
        if (!datasetName && typeof parsed.name === "string") setDatasetName(`${parsed.name} dataset`);
      } catch {
        // A source package may be binary or a non-manifest JSON file; its hash remains valid provenance.
      }
    }
  }

  async function registerDataset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setGovernanceState("Registering dataset provenance...");
    try {
      const response = await apiFetch("/api/v3/evaluator/datasets", {
        method: "POST",
        body: JSON.stringify({
          project_key: datasetProjectKey,
          name: datasetName,
          version: datasetVersion,
          classification: datasetClassification,
          source_sha256: datasetSourceSha256,
          source_reference: datasetSourceReference,
        }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(apiError(body, "Dataset registration failed"));
      setDatasetName("");
      setDatasetVersion("");
      setDatasetSourceReference("");
      setDatasetSourceSha256("");
      setGovernanceState(`Dataset ${body.version} is registered as a draft. It cannot be used until approved.`);
      await load();
    } catch (reason) {
      setGovernanceState("");
      setError(reason instanceof Error ? reason.message : "Dataset registration failed");
    }
  }

  async function approveDataset(datasetId: string, datasetVersionValue: string) {
    setError("");
    setGovernanceState(`Approving ${datasetVersionValue}...`);
    try {
      const response = await apiFetch(`/api/v3/evaluator/datasets/${datasetId}/approve`, { method: "POST" });
      const body = await response.json();
      if (!response.ok) throw new Error(apiError(body, "Dataset approval failed"));
      setGovernanceState(`Dataset ${body.version} is approved and can be used for release evaluations.`);
      await load();
    } catch (reason) {
      setGovernanceState("");
      setError(reason instanceof Error ? reason.message : "Dataset approval failed");
    }
  }

  async function registerLiveAdapter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setGovernanceState("Encrypting and registering adapter configuration...");
    try {
      const response = await apiFetch("/api/v3/evaluator/live-adapters", {
        method: "POST",
        body: JSON.stringify({
          project_key: adapterProjectKey,
          name: adapterName,
          endpoint_url: adapterEndpointUrl,
          api_token: adapterApiToken,
        }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(apiError(body, "Live adapter registration failed"));
      setAdapterName("");
      setAdapterEndpointUrl("");
      setAdapterApiToken("");
      setGovernanceState(`Adapter ${body.name} is registered as a draft. Its token is encrypted and cannot be displayed again.`);
      await load();
    } catch (reason) {
      setGovernanceState("");
      setError(reason instanceof Error ? reason.message : "Live adapter registration failed");
    }
  }

  async function changeAdapterLifecycle(adapterId: string, adapterNameValue: string, action: "approve" | "disable") {
    setError("");
    setGovernanceState(`${action === "approve" ? "Approving" : "Disabling"} ${adapterNameValue}...`);
    try {
      const response = await apiFetch(`/api/v3/evaluator/live-adapters/${adapterId}/${action}`, { method: "POST" });
      const body = await response.json();
      if (!response.ok) throw new Error(apiError(body, `Adapter ${action} failed`));
      setGovernanceState(`Adapter ${body.name} is ${body.status}.`);
      await load();
    } catch (reason) {
      setGovernanceState("");
      setError(reason instanceof Error ? reason.message : "Adapter lifecycle change failed");
    }
  }

  async function registerClientIdentity(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setGovernanceState("Registering public signing key...");
    try {
      const response = await apiFetch("/api/v3/evaluator/client-identities", {
        method: "POST",
        body: JSON.stringify({
          project_key: clientIdentityProjectKey,
          name: clientIdentityName,
          public_key: clientPublicKey.trim(),
        }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(apiError(body, "Client identity registration failed"));
      setClientIdentityName("");
      setClientPublicKey("");
      setGovernanceState(`Client identity ${body.name} is a draft. Only the public key was registered; approve it before accepting packages.`);
      await load();
    } catch (reason) {
      setGovernanceState("");
      setError(reason instanceof Error ? reason.message : "Client identity registration failed");
    }
  }

  async function changeClientIdentityLifecycle(identityId: string, identityName: string, action: "approve" | "disable") {
    setError("");
    setGovernanceState(`${action === "approve" ? "Approving" : "Disabling"} ${identityName}...`);
    try {
      const response = await apiFetch(`/api/v3/evaluator/client-identities/${identityId}/${action}`, { method: "POST" });
      const body = await response.json();
      if (!response.ok) throw new Error(apiError(body, `Client identity ${action} failed`));
      setGovernanceState(`Client identity ${body.name} is ${body.status}.`);
      await load();
    } catch (reason) {
      setGovernanceState("");
      setError(reason instanceof Error ? reason.message : "Client identity lifecycle change failed");
    }
  }

  async function registerGitHubIntegration(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setGovernanceState("Registering pinned GitHub Actions workflow...");
    try {
      const response = await apiFetch("/api/v3/evaluator/github-integrations", {
        method: "POST",
        body: JSON.stringify({
          project_key: githubProjectKey,
          name: githubIntegrationName,
          repository: githubRepository.trim(),
          workflow_ref: githubWorkflowRef.trim(),
        }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(apiError(body, "GitHub integration registration failed"));
      setGithubIntegrationName("");
      setGithubRepository("");
      setGithubWorkflowRef("");
      setGovernanceState(`GitHub workflow ${body.name} is a draft. Approval is required before OIDC submissions are trusted.`);
      await load();
    } catch (reason) {
      setGovernanceState("");
      setError(reason instanceof Error ? reason.message : "GitHub integration registration failed");
    }
  }

  async function changeGitHubIntegrationLifecycle(integrationId: string, integrationName: string, action: "approve" | "disable") {
    setError("");
    setGovernanceState(`${action === "approve" ? "Approving" : "Disabling"} ${integrationName}...`);
    try {
      const response = await apiFetch(`/api/v3/evaluator/github-integrations/${integrationId}/${action}`, { method: "POST" });
      const body = await response.json();
      if (!response.ok) throw new Error(apiError(body, `GitHub integration ${action} failed`));
      setGovernanceState(`GitHub integration ${body.name} is ${body.status}.`);
      await load();
    } catch (reason) {
      setGovernanceState("");
      setError(reason instanceof Error ? reason.message : "GitHub integration lifecycle change failed");
    }
  }

  async function chooseLiveManifest(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setLiveManifestName(file.name);
    setLiveManifest(await file.text());
    setLiveSubmitState("");
  }

  async function runLiveEvaluation() {
    setError("");
    setLiveSubmitState("Validating approved adapter and dispatching bounded test cases...");
    try {
      if (!liveAdapterId) throw new Error("Select an approved live adapter first.");
      const adapter = workspace?.live_adapters.find((item) => item.id === liveAdapterId);
      if (!adapter || adapter.status !== "approved") throw new Error("The selected live adapter is not approved.");
      const parsed = JSON.parse(liveManifest) as { project_key?: unknown; dataset_version?: unknown };
      ensureApprovedDataset(parsed.project_key, parsed.dataset_version);
      const response = await apiFetch("/api/v3/evaluator/live-runs", {
        method: "POST",
        body: JSON.stringify({ ...parsed, adapter_id: liveAdapterId }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(apiError(body, "Live adapter evaluation failed"));
      setLiveSubmitState(`Live evaluation completed: ${body.release_decision}`);
      await load();
    } catch (reason) {
      setLiveSubmitState("");
      setError(reason instanceof Error ? reason.message : "Live adapter evaluation failed");
    }
  }

  function openView(view: EvaluatorView) {
    setActiveView(view);
    window.history.replaceState(null, "", `#${view}`);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function openRunMethod(method: RunMethod) {
    setRunMethod(method);
    openView("run");
  }

  const semanticStatus = descriptor?.semantic_judge.status ?? "disabled";
  const canManageGovernance = workspace?.organization.membership_role === "owner" || workspace?.organization.membership_role === "admin";
  const canRegisterDataset = canManageGovernance || workspace?.organization.membership_role === "analyst";
  const approvedDatasetCount = workspace?.datasets.filter((item) => item.status === "approved").length ?? 0;
  const approvedAdapters = workspace?.live_adapters.filter((item) => item.status === "approved") ?? [];
  const fixtureDataset = workspace?.datasets.find((item) => item.project_key === "default" && item.version === "customer-prompt-safety-1.0" && item.status === "approved");
  const fixtureIdentity = workspace?.client_identities.find((item) => item.project_key === "default" && item.status === "approved");
  const latestFixture = evaluations.find((item) => item.dataset_version === "customer-prompt-safety-1.0");

  return (
    <main className="workspacePage">
      <header className="pageHeader">
        <div><p className="kicker">AI ASSURANCE & OBSERVABILITY / PRE-RELEASE</p><h1>Pre-release Evaluator</h1><p>Test model, RAG, and agent releases against labelled benchmarks, adversarial cases, immutable evidence, and versioned release gates.</p></div>
        <div className="evaluatorHeaderControls"><label className="workspacePicker"><span>WORKSPACE</span><select value={workspace?.organization.id ?? ""} onChange={(event) => switchWorkspace(event.target.value)}>{workspaces.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label><span className={`moduleStatus evaluatorStatus-${semanticStatus}`}>Semantic judge: {semanticStatus}</span></div>
      </header>
      {error && <p className="formError">{error}</p>}

      <section className="agentSummary evaluatorSummary">
        <div><span>ENGINE</span><strong>v{descriptor?.version ?? "--"}</strong></div>
        <div><span>METRIC RUNS</span><strong>{evaluations.length}</strong></div>
        <div><span>ADVISORY REVIEWS</span><strong>{semanticRuns.length}</strong></div>
        <div><span>OPERATING MODE</span><strong>PRE-RELEASE ONLY</strong><small>No production telemetry or SOC activity</small></div>
      </section>

      <nav className="evaluatorNav" aria-label="AI assurance workspace">
        <button type="button" className={activeView === "start" ? "active" : ""} onClick={() => openView("start")}>START HERE</button>
        <button type="button" className={activeView === "run" ? "active" : ""} onClick={() => openView("run")}>RUN A TEST</button>
        <button type="button" className={activeView === "results" ? "active" : ""} onClick={() => openView("results")}>RESULTS ({evaluations.length})</button>
        <button type="button" className={activeView === "setup" ? "active" : ""} onClick={() => openView("setup")}>SETUP</button>
      </nav>

      {activeView === "start" && <>
      <section className="evaluatorWorkflow" aria-label="How to use pre-release AI assurance">
        <header><p className="kicker">PRE-RELEASE WORKFLOW</p><h2>Connect, test, decide</h2><p>Test one declared AI-system version against versioned, labelled quality and security cases. This evaluator is separate from application assessment scanning, production telemetry, and SOC operations.</p></header>
        <div className="evaluatorWorkflowCards">
          <button type="button" onClick={() => openRunMethod("manifest")}><span>01 / BENCHMARK</span><strong>Score a labelled test pack</strong><p>Use a versioned benchmark when its evaluation records can be shared with ExposureScopeX.</p><small>Best for: controlled fixtures and release baselines</small></button>
          <button type="button" onClick={() => openRunMethod("local")}><span>02 / LOCAL OR CI</span><strong>Run beside the AI system</strong><p>Test private models, RAG, and agents in the customer environment. Private inputs and outputs remain there.</p><small>Best for: internal systems and multi-agent workflows</small></button>
          <button type="button" onClick={() => openRunMethod("live")}><span>03 / APPROVED API</span><strong>Test a deployed endpoint</strong><p>Send bounded test cases to an approved HTTPS adapter with an encrypted credential.</p><small>Best for: release candidates behind an API</small></button>
        </div>
        <div className="platformCheck"><div><span>FASTEST FIRST TEST</span><strong>Run the pre-release self-check</strong><p>Use this before connecting a real AI system. It verifies scoring, release gates, and the decision report with safe synthetic data.</p></div><div><button className="primaryAction" disabled={platformCheckState.startsWith("Loading")} onClick={runPlatformCheck}>{platformCheckState.startsWith("Loading") ? "RUNNING CHECK" : "RUN SELF-CHECK"}</button><p aria-live="polite">{platformCheckState || "No Python, API key, model, or security scan is required."}</p>{platformCheckResult && <Link href={`/ai-evaluator/${platformCheckResult}`}>OPEN SELF-CHECK RESULT</Link>}</div></div>
        {fixtureDataset && fixtureIdentity ? <div className="fixtureReady"><div><span>RUNNER VERIFICATION</span><strong>Validate a local runner when you are ready</strong><p>The included full-metric fixture exercises the same signed result path used by a customer-owned adapter. It uses synthetic data only.</p></div><div className="fixtureCommands"><span>Before you run it</span><small>Install a versioned runner from the verified GitHub Release, then use Setup to confirm the dataset and public identity are approved.</small><a href="https://github.com/lucky1410/ExposureScopeX/releases" target="_blank" rel="noreferrer">OPEN VERIFIED RUNNER RELEASES</a><button type="button" className="secondaryAction" onClick={() => openView("setup")}>OPEN SETUP</button>{latestFixture && <Link href={`/ai-evaluator/${latestFixture.id}`}>VIEW THE LAST FIXTURE RESULT</Link>}</div></div> : <div className="fixtureSetupRequired"><strong>Fixture setup required</strong><span>Open Setup and approve both the synthetic dataset and one client-runner signing identity before running the local fixture.</span><button type="button" className="secondaryAction" onClick={() => openView("setup")}>OPEN SETUP</button></div>}
      </section>

      <section className="evaluatorBoundary">
        <div><span>WHAT IT TESTS</span><strong>AI behavior before release</strong><p>Scores declared quality, RAG, agent, and security cases for one dataset and system version.</p></div>
        <div><span>WHAT STAYS LOCAL</span><strong>Private system material</strong><p>Inputs, model outputs, source code, tool results, and private keys are not stored by the control plane.</p></div>
        <div><span>WHAT A DECISION MEANS</span><strong>Measured release readiness</strong><p>A pass applies to this exact dataset and policy. It is evidence for a decision, not a claim of universal safety.</p></div>
      </section>

      </>}

      {activeView === "setup" && <section className="registrySection governanceSection" id="governance">
        <header><div><p className="kicker">SETUP AND GOVERNANCE</p><h2>Prepare a trustworthy evaluation</h2><p>Set up a project, approve a dataset version, then register a delivery method only when you need one. All actions are limited to this workspace and your role.</p></div></header>
        <div className="governanceOverview">
          <div><span>ORGANIZATION</span><strong>{workspace?.organization.name ?? "Loading"}</strong><small>{workspace?.organization.slug ?? "--"}</small></div>
          <div><span>YOUR ROLE</span><strong>{workspace?.organization.membership_role ?? "--"}</strong><small>Role determines approval authority</small></div>
          <div><span>ACTIVE PROJECTS</span><strong>{workspace?.projects.filter((item) => item.status === "active").length ?? 0}</strong><small>Separate subjects, owners, and policies</small></div>
          <div><span>APPROVED DATASETS</span><strong>{approvedDatasetCount}</strong><small>Only these can produce release decisions</small></div>
        </div>
        <details className="governanceDetails">
          <summary><span>WORKSPACE SETUP</span> Open projects, dataset approval, client-runner identity, API adapter, and GitHub controls</summary>
        <div className="datasetLedger">
          <div className="datasetLedgerHeader"><strong>Dataset registry</strong><small>Source hashes are recorded for provenance. Raw customer data is not shown in this control plane.</small></div>
          {workspace?.datasets.length ? workspace.datasets.map((item) => <div className="datasetRow" key={item.id}><div><strong>{item.name}</strong><small>{item.project_key} · {item.version} · {item.classification}</small><code>{item.source_sha256}</code></div><span className={`datasetStatus dataset-${item.status}`}>{item.status}</span>{item.status === "draft" && canManageGovernance ? <button className="textAction" onClick={() => approveDataset(item.id, item.version)}>APPROVE</button> : <span className="datasetAction">{item.status === "draft" ? "APPROVAL REQUIRED" : "LOCKED"}</span>}</div>) : <p className="datasetEmpty">No governed dataset is registered. Register an immutable source package before attempting a release evaluation.</p>}
        </div>
        <div className="datasetLedger">
          <div className="datasetLedgerHeader"><strong>Live adapter registry</strong><small>Only approved `http_json_v1` endpoints can receive bounded test inputs. URLs and bearer tokens are never shown after registration.</small></div>
          {workspace?.live_adapters.length ? workspace.live_adapters.map((item) => <div className="datasetRow" key={item.id}><div><strong>{item.name}</strong><small>{item.project_key} · {item.adapter_type} · endpoint fingerprint</small><code>{item.endpoint_sha256}</code></div><span className={`datasetStatus dataset-${item.status}`}>{item.status}</span>{canManageGovernance && item.status === "draft" ? <button className="textAction" onClick={() => changeAdapterLifecycle(item.id, item.name, "approve")}>APPROVE</button> : canManageGovernance && item.status === "approved" ? <button className="textAction" onClick={() => changeAdapterLifecycle(item.id, item.name, "disable")}>DISABLE</button> : <span className="datasetAction">{item.status === "draft" ? "APPROVAL REQUIRED" : "LOCKED"}</span>}</div>) : <p className="datasetEmpty">No live adapter is registered. Add one only after its endpoint and egress path are approved.</p>}
        </div>
        <div className="datasetLedger">
          <div className="datasetLedgerHeader"><strong>Client-runner signing identities</strong><small>Customer-owned runners sign result packages with Ed25519. ExposureScopeX stores and approves only their public keys.</small></div>
          {workspace?.client_identities.length ? workspace.client_identities.map((item) => <div className="datasetRow" key={item.id}><div><strong>{item.name}</strong><small>{item.project_key} · {item.identity_type} · client controlled</small><small>Runner identity ID: <code>{item.id}</code></small><code>{item.key_fingerprint}</code></div><span className={`datasetStatus dataset-${item.status}`}>{item.status}</span>{canManageGovernance && item.status === "draft" ? <button className="textAction" onClick={() => changeClientIdentityLifecycle(item.id, item.name, "approve")}>APPROVE</button> : canManageGovernance && item.status === "approved" ? <button className="textAction" onClick={() => changeClientIdentityLifecycle(item.id, item.name, "disable")}>DISABLE</button> : <span className="datasetAction">{item.status === "draft" ? "APPROVAL REQUIRED" : "LOCKED"}</span>}</div>) : <p className="datasetEmpty">No local or external CI signing identity is registered.</p>}
        </div>
        <div className="datasetLedger">
          <div className="datasetLedgerHeader"><strong>GitHub Actions trust</strong><small>Only the exact approved repository and workflow can submit a result through short-lived GitHub OIDC. No ExposureScopeX secret is stored in GitHub.</small></div>
          {workspace?.github_integrations.length ? workspace.github_integrations.map((item) => <div className="datasetRow" key={item.id}><div><strong>{item.name}</strong><small>{item.project_key} · {item.repository} · OIDC audience {item.oidc_audience}</small><code>{item.workflow_ref}</code></div><span className={`datasetStatus dataset-${item.status}`}>{item.status}</span>{canManageGovernance && item.status === "draft" ? <button className="textAction" onClick={() => changeGitHubIntegrationLifecycle(item.id, item.name, "approve")}>APPROVE</button> : canManageGovernance && item.status === "approved" ? <button className="textAction" onClick={() => changeGitHubIntegrationLifecycle(item.id, item.name, "disable")}>DISABLE</button> : <span className="datasetAction">{item.status === "draft" ? "APPROVAL REQUIRED" : "LOCKED"}</span>}</div>) : <p className="datasetEmpty">No GitHub Actions workflow is trusted for this workspace.</p>}
        </div>
        {governanceState && <p className="governanceState">{governanceState}</p>}
        {canManageGovernance && <form className="governanceForm projectForm" onSubmit={createProject}><strong>New evaluation project</strong><input required value={projectKey} onChange={(event) => setProjectKey(event.target.value)} placeholder="project-key" pattern="[a-z][a-z0-9-]{1,62}" /><input required value={projectName} onChange={(event) => setProjectName(event.target.value)} placeholder="Project name" /><input value={projectDescription} onChange={(event) => setProjectDescription(event.target.value)} placeholder="Purpose and ownership boundary" /><button className="secondaryAction">CREATE PROJECT</button></form>}
        {canRegisterDataset && <form className="governanceForm datasetForm" onSubmit={registerDataset}><strong>Register dataset provenance</strong><select value={datasetProjectKey} onChange={(event) => setDatasetProjectKey(event.target.value)}>{workspace?.projects.filter((item) => item.status === "active").map((item) => <option key={item.id} value={item.key}>{item.key}</option>)}</select><input required value={datasetName} onChange={(event) => setDatasetName(event.target.value)} placeholder="Dataset name" /><input required value={datasetVersion} onChange={(event) => setDatasetVersion(event.target.value)} placeholder="Immutable dataset version" /><select value={datasetClassification} onChange={(event) => setDatasetClassification(event.target.value as EvaluatorDataset["classification"])}><option value="synthetic">Synthetic</option><option value="public">Public</option><option value="internal">Internal</option><option value="restricted">Restricted</option></select><label className="hashPicker"><input type="file" onChange={chooseDatasetSource} /><span>Hash source package</span></label><input required value={datasetSourceReference} onChange={(event) => setDatasetSourceReference(event.target.value)} placeholder="Source package reference" /><input required value={datasetSourceSha256} onChange={(event) => setDatasetSourceSha256(event.target.value)} placeholder="SHA-256 of source package" pattern="[a-f0-9]{64}" /><button className="secondaryAction">REGISTER DATASET</button><small>Registration records provenance only. An owner or administrator must approve a draft before it can gate a release.</small></form>}
        {canManageGovernance && <form className="governanceForm adapterForm" onSubmit={registerLiveAdapter}><strong>Register approved live endpoint</strong><select value={adapterProjectKey} onChange={(event) => setAdapterProjectKey(event.target.value)}>{workspace?.projects.filter((item) => item.status === "active").map((item) => <option key={item.id} value={item.key}>{item.key}</option>)}</select><input required value={adapterName} onChange={(event) => setAdapterName(event.target.value)} placeholder="Adapter name" /><input required type="url" value={adapterEndpointUrl} onChange={(event) => setAdapterEndpointUrl(event.target.value)} placeholder="https://gateway.example.com/evaluate" /><input required type="password" autoComplete="new-password" value={adapterApiToken} onChange={(event) => setAdapterApiToken(event.target.value)} placeholder="Bearer token" /><button className="secondaryAction">REGISTER ADAPTER</button><small>HTTPS is required in production. The endpoint URL is fingerprinted and the bearer token is encrypted at rest; both are replacement-only after registration.</small></form>}
        {canManageGovernance && <form className="governanceForm clientIdentityForm" onSubmit={registerClientIdentity}><strong>Register client-runner public key</strong><select value={clientIdentityProjectKey} onChange={(event) => setClientIdentityProjectKey(event.target.value)}>{workspace?.projects.filter((item) => item.status === "active").map((item) => <option key={item.id} value={item.key}>{item.key}</option>)}</select><input required value={clientIdentityName} onChange={(event) => setClientIdentityName(event.target.value)} placeholder="Developer laptop or CI identity" /><input required value={clientPublicKey} onChange={(event) => setClientPublicKey(event.target.value)} placeholder="Base64 Ed25519 public key" /><button className="secondaryAction">REGISTER PUBLIC KEY</button><small>Run <code>esx-eval keygen --private-key .\secrets\esx-evaluator.key</code> locally and paste only the returned public key here. Never upload the private key.</small></form>}
        {canManageGovernance && <form className="governanceForm githubIntegrationForm" onSubmit={registerGitHubIntegration}><strong>Trust a pinned GitHub Actions workflow</strong><select value={githubProjectKey} onChange={(event) => setGithubProjectKey(event.target.value)}>{workspace?.projects.filter((item) => item.status === "active").map((item) => <option key={item.id} value={item.key}>{item.key}</option>)}</select><input required value={githubIntegrationName} onChange={(event) => setGithubIntegrationName(event.target.value)} placeholder="GitHub integration name" /><input required value={githubRepository} onChange={(event) => setGithubRepository(event.target.value)} placeholder="owner/repository" /><input required value={githubWorkflowRef} onChange={(event) => setGithubWorkflowRef(event.target.value)} placeholder="owner/repository/.github/workflows/evaluate.yml@refs/heads/main" /><button className="secondaryAction">REGISTER GITHUB TRUST</button><small>The workflow must request <code>id-token: write</code>. ExposureScopeX checks GitHub's signature, exact repository, exact workflow reference, commit, and run identifier on every submission.</small></form>}
        {canManageGovernance && <div className="auditTrail"><div><strong>Recent governance trail</strong><small>Append-only audit events are visible to owners and administrators.</small></div>{auditEvents.length ? auditEvents.slice(0, 5).map((event) => <p key={`${event.occurred_at}-${event.event_type}`}><time>{new Date(event.occurred_at).toLocaleString()}</time><span>{event.event_type.replaceAll("_", " ")}</span><small>{event.actor_name}</small></p>) : <p className="auditEmpty">No evaluator governance events recorded in this workspace yet.</p>}</div>}
        </details>
      </section>}

      {activeView === "run" && <>
      <section className="runMethodPicker" aria-label="Choose a test method">
        <div><span>STEP 1</span><strong>How is the AI system available?</strong><p>Choose one method. You can return and select another later.</p></div>
        <div role="tablist" aria-label="Test method">
          <button type="button" role="tab" aria-selected={runMethod === "manifest"} className={runMethod === "manifest" ? "active" : ""} onClick={() => setRunMethod("manifest")}>BENCHMARK FILE</button>
          <button type="button" role="tab" aria-selected={runMethod === "local"} className={runMethod === "local" ? "active" : ""} onClick={() => setRunMethod("local")}>LOCAL OR CI</button>
          <button type="button" role="tab" aria-selected={runMethod === "live"} className={runMethod === "live" ? "active" : ""} onClick={() => setRunMethod("live")}>APPROVED API</button>
          <button type="button" role="tab" aria-selected={runMethod === "semantic"} className={runMethod === "semantic" ? "active" : ""} onClick={() => setRunMethod("semantic")}>ADVISORY REVIEW</button>
        </div>
      </section>

      {runMethod === "local" && <section className="registrySection clientRunnerGuide" id="client-delivery">
        <header><div><p className="kicker">LOCAL AND CI RUNNER</p><h2>Test customer-owned systems without moving their data</h2><p>Use the runner for models, RAG applications, agent services, and multi-agent workflows. It invokes an adapter in the customer environment and publishes only selected scores, redacted metric records, and integrity metadata when a shared decision is needed.</p></div></header>
        <div className="clientRunnerSteps">
          <div><span>01 / INSTALL VERIFIED RELEASE</span><strong>Download the signed runner</strong><a href="https://github.com/lucky1410/ExposureScopeX/releases" target="_blank" rel="noreferrer">OPEN GITHUB RELEASES</a><small>Download the versioned wheel, verify its SHA-256 and GitHub build attestation, then install it. The exact commands are in the release notes and runner guide.</small></div>
          <div><span>02 / CREATE AND RUN</span><strong>Create a runnable local test</strong><code>esx-eval init --directory .\my-agent-evaluation --agent-id support-agent --subject-version 2.4.0</code><small>Creates 20 labelled placeholders, a guide, and <code>local_adapter.py</code>. Connect its single <code>evaluate_case()</code> function to the local model or agent, replace the placeholders, then run beside the AI system. Prompts, outputs, source files, tool results, stderr, and private keys remain local.</small></div>
          <div><span>03 / OPTIONAL SHARED DECISION</span><strong>Publish redacted evidence</strong><code>esx-eval upload --api-url http://localhost:8001 --package out.json --response-out result.json</code><small>Register and approve the dataset and public runner key in Setup to display a governed result and formal report. GitHub Actions can use federated identity instead.</small></div>
        </div>
      </section>}

      {runMethod === "manifest" && <section className="registrySection evaluatorLauncher" id="run-manifest">
        <header><div><p className="kicker">DIRECT BENCHMARK</p><h2>Run a labelled pre-release test pack</h2><p>Upload a versioned JSON manifest when labelled results can be evaluated in ExposureScopeX. Its project and dataset version must already be approved.</p></div></header>
        <div className="evaluatorLaunchBody">
          <label className="manifestPicker">
            <input type="file" accept="application/json,.json" onChange={chooseManifest} />
            <span>{manifestName || "Choose evaluation JSON"}</span>
            <small>Local file · immutable dataset version · no assessment linkage</small>
          </label>
          <button className="primaryAction" disabled={!manifest} onClick={runDeterministicEvaluation}>Run evaluation</button>
          <p>{submitState || "The semantic judge is configured separately and never receives data unless its dedicated API is called."}</p>
        </div>
      </section>}

      {runMethod === "live" && <section className="registrySection evaluatorLauncher" id="live-evaluation">
        <header><div><p className="kicker">MANAGED ENDPOINT</p><h2>Run a live pre-release API test</h2><p>ExposureScopeX sends bounded test cases only to an approved adapter. It retains label results and integrity hashes, never the submitted test input or remote response body.</p></div></header>
        <div className="evaluatorLaunchBody">
          <label className="manifestPicker">
            <input type="file" accept="application/json,.json" onChange={chooseLiveManifest} />
            <span>{liveManifestName || "Choose live test JSON"}</span>
            <small>Cases + expected labels · classification and calibration only</small>
          </label>
          <select aria-label="Approved live adapter" value={liveAdapterId} onChange={(event) => setLiveAdapterId(event.target.value)} disabled={approvedAdapters.length === 0}>{approvedAdapters.length ? approvedAdapters.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.project_key}</option>) : <option value="">No approved adapter</option>}</select>
          <button className="primaryAction" disabled={!liveManifest || !liveAdapterId} onClick={runLiveEvaluation}>Run live evaluation</button>
          <p>{liveSubmitState || "The adapter contract accepts a JSON object per case and returns exactly one predicted label plus confidence per case. Other dimensions remain explicit manifest or trace evaluations."}</p>
        </div>
      </section>}

      {runMethod === "semantic" && <section className="registrySection evaluatorLauncher">
        <header><div><h2>Run an advisory semantic review</h2><p>Submit hash-verified claims, evidence excerpts, and an optional agent trajectory. This path never receives assessment data automatically and cannot override deterministic release gates.</p></div></header>
        <div className="evaluatorLaunchBody">
          <label className="manifestPicker">
            <input type="file" accept="application/json,.json" onChange={chooseSemanticManifest} />
            <span>{semanticManifestName || "Choose semantic evaluation JSON"}</span>
            <small>{descriptor?.semantic_judge.provider ?? "disabled"} · {descriptor?.semantic_judge.model || "no model configured"}</small>
          </label>
          <button className="primaryAction" disabled={!semanticManifest || semanticStatus !== "ready"} onClick={runSemanticEvaluation}>Run semantic review</button>
          <p>{semanticSubmitState || (semanticStatus === "ready" ? "The request will be audited by subject, dataset, model, prompt, hashes, and provider request ID." : "Configure the semantic judge to enable live review; offline replay remains available without a model key.")}</p>
        </div>
      </section>}

      </>}

      {activeView === "start" && <section className="qualityPanel">
        <div className="qualityIntro"><span>PRE-RELEASE TEST AREAS</span><h2>Nine checks for AI quality, safety, security, and efficiency.</h2><p>Each check needs the right labels or redacted records. If a required measurement is missing, the release decision is inconclusive, never silently passed.</p><small>{descriptor?.semantic_judge.detail}</small></div>
        <div className="qualityGrid">{qualityDimensions.map(([name, description], index) => <div key={name}><span>{String(index + 1).padStart(2, "0")}</span><strong>{name}</strong><small>{description}</small></div>)}</div>
      </section>}

      {activeView === "results" && <>
      <section className="registrySection evaluationSection">
        <header><div><h2>Pre-release decisions</h2><p>Deterministic scores pinned to an evaluated AI system, dataset, policy, and assurance-engine version.</p></div></header>
        {evaluations.length === 0 ? <div className="emptyState"><strong>No metric evaluations yet</strong><span>Use the synthetic fixture to establish the first reproducible baseline.</span></div> : evaluations.map((item) => (
          <article className="evaluationRow" key={item.id}><div><strong>{item.name}</strong><small>{item.evaluated_agent_id} · dataset {item.dataset_version}</small><div className="evaluatorReportDownloads"><Link href={`/ai-evaluator/${item.id}`}>VIEW RESULTS</Link>{item.reports?.pdf && <button disabled={reportDownload !== null} onClick={() => downloadReport(item.id, "pdf")}>{reportDownload === `${item.id}:pdf` ? "PDF..." : "PDF"}</button>}{item.reports?.docx && <button disabled={reportDownload !== null} onClick={() => downloadReport(item.id, "docx")}>{reportDownload === `${item.id}:docx` ? "DOCX..." : "DOCX"}</button>}{item.reports?.pdf && item.reports?.docx ? <span className="reportReady">REPORT READY</span> : <button disabled={reportGeneration === item.id} onClick={() => generateReport(item.id)}>{reportGeneration === item.id ? "BUILDING" : "GENERATE REPORT"}</button>}</div></div><span>F1 {item.metrics.classification?.macro_f1?.toFixed(3) ?? "--"}</span><span>Coverage {item.metrics.measurement_coverage?.toFixed(3) ?? "--"}</span><span>Score {item.metrics.overall_score?.toFixed(3) ?? "--"}</span><b className={`decision-${item.release_decision}`}>{item.release_decision}</b></article>
        ))}
      </section>

      <section className="registrySection evaluationSection">
        <header><div><h2>Semantic judge audit</h2><p>Model, dataset, status, and review disposition remain traceable for every invocation.</p></div></header>
        {semanticRuns.length === 0 ? <div className="emptyState"><strong>No semantic runs yet</strong><span>The offline replay fixture can verify this path before any model is configured.</span></div> : semanticRuns.map((item) => (
          <article className="evaluationRow semanticRunRow" key={item.id}><div><strong>{item.name}</strong><small>{item.subject_id} · dataset {item.dataset_version}</small></div><span>{item.provider}</span><span>{item.requested_model}</span><span>{item.result?.human_review_required ? "Review required" : "No flags"}</span><b className={`decision-${item.status === "completed" ? "pass" : item.status === "failed" ? "fail" : "inconclusive"}`}>{item.error_code || item.status}</b></article>
        ))}
      </section>
      </>}
    </main>
  );
}
