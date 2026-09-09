"""Shared assessment scan runtime helpers."""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.database import async_session_factory
from app.models.assessment import Assessment
from app.models.scan import Scan
from app.models.notification import Notification
from app.models.user import User

from app.services.open_source_catalog import build_tool_plan
from app.services.execution_policy import resolve_execution_policy
from app.services.scan_profiles import merge_scan_inputs

logger = logging.getLogger(__name__)


EXECUTION_STAGE_CATALOG = (
    ("preflight", "Preflight and scope validation", 2, None),
    ("passive_recon", "Certificate transparency and passive discovery", 8, "enum"),
    ("enumeration", "Asset and subdomain enumeration", 15, "enum"),
    ("dns_recon", "DNS, IPv4, IPv6, and provider correlation", 25, "enum"),
    ("osint", "Public intelligence and ownership attribution", 32, "enum"),
    ("port_scan", "Port and service discovery", 40, "scan"),
    ("ssl_tls", "TLS, certificate, headers, and email security", 50, "scan"),
    ("cloud", "Cloud exposure correlation", 57, "cloud"),
    ("crawler", "Web crawling and endpoint discovery", 63, "crawl"),
    ("web_testing", "Web and business-logic surface testing", 70, "scan"),
    ("api_security", "API inventory and security tests", 76, "scan"),
    ("screenshots", "Visual surface capture", 80, "screenshots"),
    ("nuclei", "Nuclei official and community template coverage", 85, "scan"),
    ("cve_correlation", "CVE, KEV, and exploitability correlation", 90, "cve"),
    ("exploitation", "Authorized safe exploit validation", 92, "exploit"),
    ("reporting", "Evidence-first report generation", 95, "report"),
    ("ingesting_results", "Result normalization and evidence ingestion", 98, None),
    ("attack_path", "Relationship and attack-path calculation", 99, None),
    ("historical_diff", "Asset and exposure drift calculation", 99, None),
)

SPECIALIZED_STAGE_CATALOGS = {
    "repository": (
        ("preflight", "Repository URL and scope validation", 2),
        ("repo_inventory", "Safe repository clone and inventory", 15),
        ("secrets", "Git history and secret detection", 40),
        ("dependencies", "Dependency and vulnerability correlation", 65),
        ("sbom", "CycloneDX software bill of materials", 82),
        ("provenance", "Supply-chain and provenance evidence", 90),
        ("reporting", "Evidence-first report generation", 95),
        ("ingesting_results", "Result normalization and evidence ingestion", 98),
        ("attack_path", "Relationship and attack-path calculation", 99),
        ("historical_diff", "Repository and dependency drift", 99),
    ),
    "image": (
        ("preflight", "Image reference and registry validation", 2),
        ("image_inventory", "Container image inventory and metadata", 20),
        ("image_vulnerability", "Primary image scan with Trivy", 48),
        ("image_sbom", "Secondary SBOM inventory with Syft", 72),
        ("image_correlation", "Secondary correlation with Grype", 86),
        ("reporting", "Evidence-first report generation", 95),
        ("ingesting_results", "Result normalization and evidence ingestion", 98),
        ("attack_path", "Image, package, and registry attack-path calculation", 99),
        ("historical_diff", "Image drift and package change detection", 99),
    ),
    "mcp": (
        ("preflight", "Endpoint, scope, and transport validation", 2),
        ("mcp_discovery", "Protocol negotiation and capability discovery", 15),
        ("mcp_protocol", "Parser, version, method, and transport tests", 32),
        ("mcp_auth", "Authentication, authorization, and origin tests", 48),
        ("mcp_inventory", "Tool, resource, prompt, and task inventory", 62),
        ("mcp_isolation", "State, cache, task, and identity isolation tests", 75),
        ("mcp_semantic", "Tool metadata and capability-chain analysis", 88),
        ("mcp_drift", "Capability and policy drift", 92),
        ("reporting", "Evidence-first report generation", 95),
        ("ingesting_results", "Result normalization and evidence ingestion", 98),
        ("attack_path", "MCP capability attack-path calculation", 99),
    ),
    "asn": (
        ("preflight", "ASN validation and scope preparation", 2),
        ("asn_inventory", "RDAP autonomous-system inventory", 15),
        ("prefix_inventory", "IPv4 and IPv6 announced-prefix discovery", 40),
        ("routing_correlation", "Routing and ownership correlation", 70),
        ("reporting", "Evidence-first report generation", 95),
        ("ingesting_results", "Prefix normalization and graph ingestion", 98),
        ("attack_path", "Reachability and attack-path calculation", 99),
        ("historical_diff", "Routing and prefix drift", 99),
    ),
    "cloud_account": (
        ("preflight", "Cloud account validation and authorization checks", 2),
        ("cloud_inventory", "Cloud account and public resource inventory", 18),
        ("cspm_primary", "Primary CSPM execution with Prowler", 45),
        ("cspm_secondary", "Secondary posture validation with ScoutSuite", 62),
        ("iam_analysis", "IAM and privilege-path correlation", 76),
        ("compliance", "Compliance framework normalization", 88),
        ("reporting", "Evidence-first report generation", 95),
        ("ingesting_results", "Result normalization and evidence ingestion", 98),
        ("attack_path", "Cloud relationship and attack-path calculation", 99),
        ("historical_diff", "Cloud drift and exposure change detection", 99),
    ),
    "kubernetes": (
        ("preflight", "Manifest URL and scope validation", 2),
        ("manifest_inventory", "Kubernetes object inventory", 22),
        ("misconfiguration_scan", "Kubernetes configuration analysis", 58),
        ("secret_scan", "Embedded secret detection", 76),
        ("rbac_analysis", "RBAC and workload privilege review", 88),
        ("reporting", "Evidence-first report generation", 95),
        ("ingesting_results", "Result normalization and ingestion", 98),
    ),
    "android": (
        ("preflight", "APK URL and scope validation", 2),
        ("artifact_inventory", "APK archive inventory", 20),
        ("manifest_analysis", "Android manifest and configuration review", 45),
        ("secret_scan", "Embedded secret detection", 65),
        ("dependencies", "Application dependency correlation", 80),
        ("endpoint_inventory", "Embedded endpoint inventory", 90),
        ("reporting", "Evidence-first report generation", 95),
        ("ingesting_results", "Result normalization and ingestion", 98),
    ),
    "ios": (
        ("preflight", "IPA URL and scope validation", 2),
        ("artifact_inventory", "IPA archive inventory", 20),
        ("plist_analysis", "iOS property-list and entitlement review", 45),
        ("secret_scan", "Embedded secret detection", 65),
        ("dependencies", "Application dependency correlation", 80),
        ("endpoint_inventory", "Embedded endpoint inventory", 90),
        ("reporting", "Evidence-first report generation", 95),
        ("ingesting_results", "Result normalization and ingestion", 98),
    ),
    "organization": (
        ("preflight", "Organization seed validation and attribution scope", 2),
        ("brand_seeds", "Brand, domain, and repository seed normalization", 18),
        ("domain_discovery", "Domain and hostname expansion", 45),
        ("repo_discovery", "Repository and package discovery", 62),
        ("ownership", "Ownership and trust-surface attribution", 80),
        ("reporting", "Evidence-first report generation", 95),
        ("ingesting_results", "Result normalization and evidence ingestion", 98),
        ("attack_path", "Relationship and attack-path calculation", 99),
        ("historical_diff", "Seed and attribution drift", 99),
    ),
}


def build_execution_manifest(profile: dict) -> list[dict]:
    """Build a truthful persisted stage plan from the resolved scan profile."""
    target_type = profile.get("target_type", "domain")
    specialized = SPECIALIZED_STAGE_CATALOGS.get(target_type)
    if specialized:
        return [{
            "id": stage_id,
            "label": label,
            "planned": True,
            "status": "pending",
            "progress": progress,
            "attempts": 0,
            "started_at": None,
            "completed_at": None,
            "message": None,
        } for stage_id, label, progress in specialized]
    phases = profile.get("phases") or {}
    flags = profile.get("flags") or {}
    strategy = profile.get("scan_strategy", "active")
    stages: list[dict] = []
    for stage_id, label, progress, gate in EXECUTION_STAGE_CATALOG:
        if gate in phases:
            planned = bool(phases.get(gate))
        elif gate in flags:
            planned = bool(flags.get(gate))
        else:
            planned = True
        if strategy in {"inventory", "import"} and stage_id in {
            "port_scan", "ssl_tls", "crawler", "web_testing", "api_security",
            "screenshots", "nuclei", "exploitation",
        }:
            planned = False
        stages.append({
            "id": stage_id,
            "label": label,
            "planned": planned,
            "status": "pending" if planned else "skipped",
            "progress": progress,
            "attempts": 0,
            "started_at": None,
            "completed_at": None,
            "message": None,
        })
    return stages


def advance_execution_manifest(
    metadata: dict,
    stage_id: str,
    *,
    status: str = "running",
    message: str | None = None,
    now: datetime | None = None,
) -> dict:
    """Advance one stage without allowing completed work to regress."""
    timestamp = (now or datetime.now(timezone.utc)).isoformat()
    updated = dict(metadata or {})
    manifest = [dict(item) for item in updated.get("execution_manifest") or []]
    target_index = next((index for index, item in enumerate(manifest) if item.get("id") == stage_id), None)
    if target_index is None:
        return updated

    for index, item in enumerate(manifest):
        if not item.get("planned"):
            continue
        if index < target_index and item.get("status") in {"pending", "running"}:
            item["status"] = "completed"
            item["completed_at"] = item.get("completed_at") or timestamp

    target = manifest[target_index]
    previous_status = target.get("status")
    if previous_status not in {"completed", "skipped"}:
        target["status"] = status
        if status == "running" and previous_status != "running":
            target["attempts"] = int(target.get("attempts") or 0) + 1
            target["started_at"] = target.get("started_at") or timestamp
        if status in {"completed", "failed", "cancelled", "warning"}:
            target["completed_at"] = timestamp
        if message:
            target["message"] = message[:1000]
    updated["execution_manifest"] = manifest
    return updated


def finalize_execution_manifest(metadata: dict, final_status: str) -> dict:
    """Finalize remaining planned stages at scan termination."""
    updated = dict(metadata or {})
    manifest = [dict(item) for item in updated.get("execution_manifest") or []]
    timestamp = datetime.now(timezone.utc).isoformat()
    for item in manifest:
        if not item.get("planned") or item.get("status") in {"completed", "skipped", "warning"}:
            continue
        if final_status == "completed":
            item["status"] = "completed"
        elif item.get("status") == "running":
            item["status"] = "cancelled" if final_status == "cancelled" else "failed"
        else:
            item["status"] = "cancelled" if final_status == "cancelled" else "not_run"
        item["completed_at"] = timestamp
    updated["execution_manifest"] = manifest
    return updated


def calculate_work_progress(metadata: dict, reported_progress: int | None, status: str) -> tuple[int, dict]:
    """Convert manifest state into bounded per-target work-unit progress."""
    manifest = [item for item in (metadata.get("execution_manifest") or []) if item.get("planned")]
    target_count = max(1, int((metadata.get("execution_policy") or {}).get("target_count") or 1))
    total_units = max(1, len(manifest) * target_count)
    completed_stages = sum(item.get("status") in {"completed", "warning", "skipped"} for item in manifest)
    running_stages = sum(item.get("status") == "running" for item in manifest)
    completed_units = min(total_units, completed_stages * target_count)
    if running_stages:
        completed_units = min(total_units, completed_units + max(1, target_count // 10))
    if status == "completed":
        completed_units = total_units
    weighted = int((completed_units / total_units) * 100)
    if status in {"queued", "created"}:
        weighted = 0
    elif status == "running":
        weighted = min(99, max(weighted, min(int(reported_progress or 0), 5)))
    else:
        weighted = min(100, max(weighted, int(reported_progress or 0)))
    return weighted, {
        "total": total_units,
        "completed": completed_units,
        "target_count": target_count,
        "planned_stages": len(manifest),
    }


def build_scan_metadata(
    *,
    assessment_id: str,
    scan_mode: str,
    target_type: str,
    phases: dict | None,
    flags: dict | None,
) -> dict:
    """Create normalized scan metadata stored alongside a scan execution."""
    # Imported rows belong to the assessment inventory, not every execution
    # record. Keeping them here made each progress update rewrite a huge JSON blob.
    target_count = max(1, len((flags or {}).get("_imported_targets") or []))
    execution_policy = resolve_execution_policy(
        scan_mode,
        target_type,
        target_count=target_count,
    )
    runtime_flags = {
        key: value for key, value in (flags or {}).items() if not key.startswith("_")
    }
    requested_scans = [
        str(item).strip()
        for item in ((flags or {}).get("_requested_scans") or [])
        if str(item).strip()
    ]
    profile = merge_scan_inputs(scan_mode, target_type, phases, runtime_flags)
    return {
        "assessment_id": assessment_id,
        "profile": profile,
        "mode": scan_mode,
        "target_type": target_type,
        "phases_requested": profile["phases"],
        "flags_requested": profile["flags"],
        "utilities": profile["utilities"],
        "nuclei_tags": profile["nuclei_tags"],
        "business_logic": profile["business_logic"],
        "pipeline": profile.get("pipeline", []),
        "scan_strategy": profile.get("scan_strategy", "active"),
        "tool_plan": build_tool_plan(
            target_type=target_type,
            scan_mode=scan_mode,
            utilities=profile["utilities"],
            requested_scans=requested_scans,
        ),
        "execution_manifest": build_execution_manifest(profile),
        "execution_policy": execution_policy,
        "telemetry": {
            "elapsed_seconds": 0,
            "eta_seconds": None,
            "stage_durations": {},
            "artifact_bytes": 0,
            "work_units": {"total": 0, "completed": 0, "target_count": target_count},
        },
        "attempt": 1,
        "last_heartbeat_at": None,
    }


def run_assessment_scan_in_thread(assessment_id: str, org_id: str, scan_id: str) -> str:
    """Fallback local execution when Celery is unavailable."""
    from app.services.celery_app import execute_assessment_scan

    def _runner():
        try:
            execute_assessment_scan(assessment_id, org_id, scan_id=scan_id)
        except Exception:
            logger.exception("Threaded assessment scan failed: assessment=%s scan=%s", assessment_id, scan_id)

    thread = threading.Thread(target=_runner, daemon=True, name=f"assessment-scan-{scan_id[:8]}")
    thread.start()
    return f"thread-{scan_id[:8]}"


async def reconcile_interrupted_thread_scans() -> int:
    """Fail local fallback scans that cannot survive a backend restart."""
    async with async_session_factory() as session:
        scans = (
            await session.execute(
                select(Scan).where(
                    Scan.status.in_(["queued", "running"]),
                    Scan.celery_task_id.like("thread-%"),
                )
            )
        ).scalars().all()
        for scan in scans:
            scan.status = "failed"
            scan.current_phase = "interrupted"
            scan.error_message = "Local fallback execution was interrupted by a backend restart. Start a new scan."
            scan.completed_at = datetime.now(timezone.utc)
            assessment = await session.get(Assessment, scan.assessment_id)
            if assessment and assessment.status == "running":
                assessment.status = "failed"
            if assessment:
                recipients = (
                    await session.execute(
                        select(User.id).where(
                            User.org_id == assessment.org_id,
                            User.is_active.is_(True),
                            User.role.in_(["admin", "manager"]),
                        )
                    )
                ).scalars().all()
                for user_id in recipients:
                    session.add(Notification(
                        user_id=user_id,
                        type="alert",
                        title="Scan worker heartbeat lost",
                        message=f"{assessment.name} stopped because its local fallback worker was interrupted by a backend restart.",
                        severity="high",
                        entity_type="assessment",
                        entity_id=assessment.id,
                    ))
        if scans:
            await session.commit()
        return len(scans)


async def reconcile_stale_scans(stale_after_minutes: int = 10) -> int:
    """Fail orphaned queued/running scans whose workers stopped heartbeating."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=stale_after_minutes)
    async with async_session_factory() as session:
        scans = (
            await session.execute(
                select(Scan).where(
                    Scan.status == "running",
                    Scan.heartbeat_at.is_not(None),
                    Scan.heartbeat_at < cutoff,
                )
            )
        ).scalars().all()
        for scan in scans:
            scan.status = "failed"
            scan.current_phase = "worker_lost"
            scan.error_message = (
                f"No worker heartbeat was received for more than {stale_after_minutes} minutes. "
                "The execution was stopped safely and can be retried."
            )
            scan.completed_at = datetime.now(timezone.utc)
            scan.scan_metadata = finalize_execution_manifest(scan.scan_metadata or {}, "failed")
            from app.models.scan_runtime import ScanEvent

            session.add(ScanEvent(
                scan_id=scan.id,
                event_type="worker_lost",
                status="failed",
                phase="worker_lost",
                progress=scan.progress,
                message=scan.error_message,
                payload={"stale_after_minutes": stale_after_minutes, "retry_available": True},
            ))
            assessment = await session.get(Assessment, scan.assessment_id)
            if assessment and assessment.status == "running":
                assessment.status = "failed"
        if scans:
            await session.commit()
        return len(scans)
