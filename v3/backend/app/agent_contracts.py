from __future__ import annotations

from typing import Final, Literal
from uuid import UUID

from pydantic import BaseModel, Field


class AgentManifest(BaseModel):
    id: str
    name: str
    domain: str
    version: str
    runtime: Literal["deterministic", "ai", "hybrid", "evaluator"]
    safety_class: str
    capabilities: list[str]
    accepts: list[str]
    emits: list[str]
    logical_roles: list[str] = Field(default_factory=list)
    may_control_scanners: bool = False
    status: Literal["active", "planned"]


class EvidenceReference(BaseModel):
    artifact_id: UUID
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class AgentHandoff(BaseModel):
    contract_version: Literal["1.0"] = "1.0"
    assessment_id: UUID
    scan_id: UUID
    producer_agent: str
    consumer_agent: str
    message_type: Literal[
        "observation", "work_request", "validation_decision", "exception", "result"
    ]
    scope_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    idempotency_key: str = Field(min_length=16, max_length=160)
    correlation_id: UUID
    causation_id: UUID | None = None
    payload_schema: str
    payload: dict
    evidence: list[EvidenceReference] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0, le=1)
    safety_class: str


AGENT_REGISTRY: Final[tuple[AgentManifest, ...]] = (
    AgentManifest(id="scope_authorization", name="Scope and Authorization Agent", domain="control", version="1.0.0", runtime="deterministic", safety_class="control_only", capabilities=["scope_normalization", "authorization_gate", "policy_decision"], accepts=["assessment_request"], emits=["scope_decision"], status="active"),
    AgentManifest(id="assessment_planner", name="Assessment Planning Agent", domain="control", version="1.0.0", runtime="deterministic", safety_class="control_only", capabilities=["profile_resolution", "execution_dag"], accepts=["scope_decision"], emits=["execution_plan"], status="active"),
    AgentManifest(id="execution_supervisor", name="Execution Supervisor", domain="control", version="1.0.0", runtime="deterministic", safety_class="orchestration", capabilities=["leases", "retries", "timeouts", "cancellation"], accepts=["execution_plan", "work_request"], emits=["work_unit", "lifecycle_event"], may_control_scanners=True, status="active"),
    AgentManifest(id="asm_discovery", name="Attack Surface Discovery Agent", domain="asm", version="1.0.0", runtime="deterministic", safety_class="passive_bounded", capabilities=["seed_attribution", "dns_discovery", "exposure_drift"], accepts=["work_unit"], emits=["asset_observation", "work_request"], status="planned"),
    AgentManifest(id="dast_assessment", name="DAST Assessment Agent", domain="appsec", version="1.0.0", runtime="deterministic", safety_class="non_exploitative", capabilities=["web_profiling", "safe_crawl", "template_assessment"], accepts=["work_unit", "asset_observation"], emits=["candidate_finding", "artifact"], may_control_scanners=True, status="active"),
    AgentManifest(id="sast_analysis", name="SAST Analysis Agent", domain="appsec", version="1.0.0", runtime="deterministic", safety_class="offline_analysis", capabilities=["source_analysis", "dataflow_observation"], accepts=["repository_manifest"], emits=["candidate_finding", "component_relationship"], status="planned"),
    AgentManifest(id="sca_sbom", name="SCA and SBOM Agent", domain="appsec", version="1.0.0", runtime="deterministic", safety_class="offline_analysis", capabilities=["sbom_generation", "dependency_vulnerability_mapping"], accepts=["repository_manifest", "image_manifest"], emits=["component_observation", "candidate_finding"], status="planned"),
    AgentManifest(id="iast_import", name="IAST Telemetry Agent", domain="appsec", version="1.0.0", runtime="deterministic", safety_class="telemetry_import", capabilities=["runtime_trace_import", "code_route_linkage"], accepts=["iast_telemetry"], emits=["runtime_observation"], status="planned"),
    AgentManifest(id="api_assessment", name="API Assessment Agent", domain="appsec", version="1.0.0", runtime="deterministic", safety_class="non_exploitative", capabilities=["schema_inventory", "safe_api_checks"], accepts=["work_unit", "api_schema"], emits=["endpoint_observation", "candidate_finding"], may_control_scanners=True, status="planned"),
    AgentManifest(id="configuration_audit", name="Configuration and Passive Audit Agent", domain="infrastructure", version="1.0.0", runtime="deterministic", safety_class="read_only", capabilities=["tls_audit", "header_audit", "configuration_review"], accepts=["work_unit", "configuration_manifest"], emits=["candidate_finding", "artifact"], may_control_scanners=True, status="active"),
    AgentManifest(id="cloud_posture", name="Cloud and Container Posture Agent", domain="infrastructure", version="1.0.0", runtime="deterministic", safety_class="read_only", capabilities=["cloud_posture", "container_scan", "iac_review", "kubernetes_posture"], accepts=["cloud_manifest", "image_manifest", "iac_manifest"], emits=["resource_observation", "candidate_finding"], status="planned"),
    AgentManifest(id="ai_trust", name="External AI Compliance and Trust Agent", domain="ai_security", version="1.0.0", runtime="hybrid", safety_class="evaluation_only", capabilities=["rag_evaluation", "trajectory_evaluation", "governance_mapping", "robustness_evaluation"], accepts=["ai_system_manifest", "evaluation_dataset"], emits=["evaluation_observation", "control_gap"], status="planned"),
    AgentManifest(id="finding_normalizer", name="Finding Normalization Agent", domain="assurance", version="1.0.0", runtime="deterministic", safety_class="offline_analysis", capabilities=["parsing", "fingerprinting", "deduplication"], accepts=["candidate_finding", "artifact"], emits=["normalized_finding"], status="active"),
    AgentManifest(id="evidence_validator", name="Independent Evidence Validation Agent", domain="assurance", version="1.0.0", runtime="deterministic", safety_class="evaluation_only", capabilities=["hash_verification", "scope_attribution", "claim_support"], accepts=["normalized_finding"], emits=["validation_decision"], status="active"),
    AgentManifest(id="ai_quality_evaluator", name="AI Assurance Pre-release Evaluation Service", domain="quality", version="1.5.0", runtime="evaluator", safety_class="evaluation_only", capabilities=["confusion_matrix", "false_positive_rate", "confidence_calibration", "attack_detection_metrics", "evidence_grounding", "semantic_entailment", "trajectory_evaluation", "redacted_trace_verification", "rag_evaluation", "robustness_testing", "cross_model_agreement", "reproducibility", "cost_efficiency", "explicit_not_measurable"], accepts=["labelled_evaluation_dataset", "semantic_evaluation_material", "redacted_agent_trace", "redacted_usage_measurements", "evaluation_policy"], emits=["quality_evaluation", "semantic_judge_run", "role_verdicts", "release_decision"], logical_roles=["evidence_grounding", "security_verdict", "trajectory_policy"], status="active"),
    AgentManifest(id="reporting", name="Reporting Agent", domain="delivery", version="1.0.0", runtime="deterministic", safety_class="render_only", capabilities=["docx", "pdf", "evidence_manifest"], accepts=["validated_fact_set", "quality_evaluation"], emits=["report_artifact"], status="active"),
)


def registry_payload() -> list[dict]:
    return [agent.model_dump(mode="json") for agent in AGENT_REGISTRY]


def registered_agent(agent_id: str) -> AgentManifest | None:
    return next((agent for agent in AGENT_REGISTRY if agent.id == agent_id), None)
