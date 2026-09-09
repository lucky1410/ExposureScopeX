"""Persist normalized graph edges, scan snapshots, drift, and attack paths."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.asset_graph import AssetRelation, AssetSnapshot, AttackPath, ExposureEvent
from app.models.finding import Finding
from app.models.port import Port


GRAPH_NAMESPACE = uuid.UUID("ec5ec8c1-d0a0-445d-bac4-b4abfc70970d")


def asset_state_fingerprint(state: dict) -> str:
    encoded = json.dumps(state, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def diff_asset_states(previous: dict | None, current: dict) -> dict:
    if previous is None:
        return {"change_type": "new", "added": current, "removed": {}, "changed": {}}
    added = {key: value for key, value in current.items() if key not in previous}
    removed = {key: value for key, value in previous.items() if key not in current}
    changed = {
        key: {"before": previous[key], "after": value}
        for key, value in current.items()
        if key in previous and previous[key] != value
    }
    return {
        "change_type": "changed" if added or removed or changed else "unchanged",
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def _stable_id(kind: str, *parts: object) -> uuid.UUID:
    return uuid.uuid5(GRAPH_NAMESPACE, ":".join([kind, *(str(part) for part in parts)]))


async def persist_scan_graph(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    assessment_id: uuid.UUID,
    scan_id: uuid.UUID,
    assets: list[Asset],
) -> dict:
    """Persist graph and drift records idempotently for one completed scan."""
    now = datetime.now(timezone.utc)
    unique_assets = {asset.id: asset for asset in assets}.values()
    ports = (
        await session.execute(select(Port).where(Port.scan_id == scan_id))
    ).scalars().all()
    findings = (
        await session.execute(select(Finding).where(Finding.scan_id == scan_id))
    ).scalars().all()
    ports_by_asset: dict[uuid.UUID, list[dict]] = {}
    findings_by_asset: dict[uuid.UUID, list[dict]] = {}
    for port in ports:
        ports_by_asset.setdefault(port.asset_id, []).append({
            "port": port.port_number,
            "protocol": port.protocol,
            "service": port.service_name,
            "version": port.service_version,
        })
    for finding in findings:
        if finding.asset_id:
            findings_by_asset.setdefault(finding.asset_id, []).append({
                "source": finding.source,
                "template_id": finding.template_id,
                "severity": finding.severity,
                "title": finding.title,
            })

    relations_added = 0
    snapshots_added = 0
    drift_events = 0
    for asset in unique_assets:
        if asset.parent_id:
            relation_type = (asset.metadata_ or {}).get("relation_type", "discovered_from")
            relation_id = _stable_id("relation", scan_id, asset.parent_id, asset.id, relation_type)
            if await session.get(AssetRelation, relation_id) is None:
                session.add(AssetRelation(
                    id=relation_id,
                    assessment_id=assessment_id,
                    scan_id=scan_id,
                    source_asset_id=asset.parent_id,
                    target_asset_id=asset.id,
                    relation_type=relation_type,
                    confidence=90,
                    evidence={"source": (asset.metadata_ or {}).get("source", "scan")},
                    first_seen=now,
                    last_seen=now,
                ))
                relations_added += 1

        state = {
            "canonical_key": asset.canonical_key,
            "value": asset.value,
            "asset_type": asset.asset_type,
            "is_live": asset.is_live,
            "owner": asset.owner,
            "ownership_status": asset.ownership_status,
            "ports": sorted(ports_by_asset.get(asset.id, []), key=lambda item: (item["port"], item["protocol"])),
            "findings": sorted(findings_by_asset.get(asset.id, []), key=lambda item: (item["severity"], item["title"])),
        }
        fingerprint = asset_state_fingerprint(state)
        snapshot_id = _stable_id("snapshot", asset.id, scan_id)
        if await session.get(AssetSnapshot, snapshot_id) is not None:
            continue
        previous = (
            await session.execute(
                select(AssetSnapshot)
                .where(and_(AssetSnapshot.asset_id == asset.id, AssetSnapshot.scan_id != scan_id))
                .order_by(AssetSnapshot.observed_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        delta = diff_asset_states(previous.state if previous else None, state)
        session.add(AssetSnapshot(
            id=snapshot_id,
            asset_id=asset.id,
            scan_id=scan_id,
            fingerprint=fingerprint,
            state=state,
            observed_at=now,
        ))
        snapshots_added += 1
        if delta["change_type"] != "unchanged":
            event_type = "asset.new" if delta["change_type"] == "new" else "asset.changed"
            session.add(ExposureEvent(
                id=_stable_id("event", scan_id, asset.id, event_type),
                org_id=org_id,
                assessment_id=assessment_id,
                scan_id=scan_id,
                asset_id=asset.id,
                event_type=event_type,
                severity="INFO",
                payload={"asset": asset.value, "delta": delta},
                observed_at=now,
            ))
            drift_events += 1
            previous_ports = {
                (item.get("port"), item.get("protocol"))
                for item in (previous.state.get("ports", []) if previous else [])
            }
            for port in state["ports"]:
                port_key = (port.get("port"), port.get("protocol"))
                if port_key in previous_ports:
                    continue
                session.add(ExposureEvent(
                    id=_stable_id("event", scan_id, asset.id, "service.new", *port_key),
                    org_id=org_id,
                    assessment_id=assessment_id,
                    scan_id=scan_id,
                    asset_id=asset.id,
                    event_type="service.new",
                    severity="INFO",
                    payload={"asset": asset.value, **port},
                    observed_at=now,
                ))
                drift_events += 1
            if asset.asset_type == "mcp" and not previous:
                session.add(ExposureEvent(
                    id=_stable_id("event", scan_id, asset.id, "mcp.server.new"),
                    org_id=org_id,
                    assessment_id=assessment_id,
                    scan_id=scan_id,
                    asset_id=asset.id,
                    event_type="mcp.server.new",
                    severity="HIGH",
                    payload={"asset": asset.value, "inventory": (asset.metadata_ or {}).get("mcp_summary", {})},
                    observed_at=now,
                ))
                drift_events += 1

    attack_paths_added = 0
    for finding in findings:
        if finding.severity not in {"CRITICAL", "HIGH"} or not finding.asset_id:
            continue
        path_id = _stable_id("attack-path", scan_id, finding.asset_id, finding.id)
        if await session.get(AttackPath, path_id) is not None:
            continue
        asset = next((item for item in unique_assets if item.id == finding.asset_id), None)
        if not asset:
            continue
        score = finding.risk_score or (95 if finding.severity == "CRITICAL" else 75)
        session.add(AttackPath(
            id=path_id,
            assessment_id=assessment_id,
            scan_id=scan_id,
            title=f"Internet-exposed {asset.value} to {finding.title}"[:500],
            severity=finding.severity,
            risk_score=score,
            nodes=[
                {"id": "internet", "type": "external", "label": "Internet"},
                {"id": str(asset.id), "type": asset.asset_type, "label": asset.value},
                {"id": str(finding.id), "type": "finding", "label": finding.title},
            ],
            edges=[
                {"source": "internet", "target": str(asset.id), "relation": "reachable"},
                {"source": str(asset.id), "target": str(finding.id), "relation": "exposes"},
            ],
            evidence=finding.evidence,
        ))
        session.add(ExposureEvent(
            id=_stable_id("event", scan_id, finding.asset_id, "attackpath.created", finding.id),
            org_id=org_id,
            assessment_id=assessment_id,
            scan_id=scan_id,
            asset_id=finding.asset_id,
            event_type="attackpath.created",
            severity=finding.severity,
            payload={"asset": asset.value, "finding": finding.title, "risk_score": float(score)},
            observed_at=now,
        ))
        if finding.source in {"gitleaks", "trivy-secret"}:
            session.add(ExposureEvent(
                id=_stable_id("event", scan_id, finding.id, "secret.discovered"),
                org_id=org_id,
                assessment_id=assessment_id,
                scan_id=scan_id,
                asset_id=finding.asset_id,
                event_type="secret.discovered",
                severity=finding.severity,
                payload={"asset": asset.value, "finding": finding.title},
                observed_at=now,
            ))
        attack_paths_added += 1

    await session.flush()
    return {
        "relations_added": relations_added,
        "snapshots_added": snapshots_added,
        "drift_events": drift_events,
        "attack_paths_added": attack_paths_added,
    }
