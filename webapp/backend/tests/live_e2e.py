"""Destructive-to-temporary-records live E2E smoke test for a deployed stack.

Run inside the backend image on the Compose internal network. The test uses
reserved example assets and scans only the user's local ExposureScopeX UI.
"""

from __future__ import annotations

import hashlib
import asyncio
import os
import secrets
import sys
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from io import BytesIO

import httpx
from sqlalchemy import delete, select, text

from app.database import async_session_factory
from app.models.audit_log import AuditLog
from app.models.assessment import Assessment
from app.models.auth_session import AuthSession
from app.models.user import User
from app.security import get_password_hash


BASE_URL = os.getenv("ESX_E2E_BASE_URL", "http://backend:8000/api/v1")
EMAIL = os.getenv("ESX_E2E_EMAIL", "admin@exposurescopex.local")
PASSWORD = os.getenv("ESX_E2E_PASSWORD") or os.getenv("BOOTSTRAP_ADMIN_PASSWORD")
LOCAL_TARGET = os.getenv("ESX_E2E_LOCAL_TARGET", "http://host.docker.internal:3001/login")
TERMINAL_SCAN_STATES = {"completed", "partial", "failed", "cancelled"}
ACTIVE_TEMPORARY_USER_ID: str | None = None


def require(response: httpx.Response, expected: int | tuple[int, ...], step: str) -> httpx.Response:
    allowed = (expected,) if isinstance(expected, int) else expected
    if response.status_code not in allowed:
        detail = response.text[:500].replace("\n", " ")
        raise AssertionError(f"{step}: expected {allowed}, got {response.status_code}: {detail}")
    print(f"PASS {step} [{response.status_code}]", flush=True)
    return response


def poll_report(client: httpx.Client, assessment_id: str, report_id: str, timeout: int = 90) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = require(
            client.get("/reports", params={"assessment_id": assessment_id}),
            200,
            "list reports",
        ).json()
        report = next((item for item in rows if item["id"] == report_id), None)
        if report and report["status"] in {"ready", "failed", "cancelled"}:
            return report
        time.sleep(0.5)
    raise AssertionError(f"report {report_id} did not reach a terminal state")


def poll_scan(
    client: httpx.Client,
    scan_id: str,
    *,
    wait_for_evidence: bool,
    require_terminal_evidence: bool = False,
    timeout: int = 180,
) -> dict:
    deadline = time.monotonic() + timeout
    latest: dict = {}
    while time.monotonic() < deadline:
        latest = require(client.get(f"/assessments/scan-executions/{scan_id}"), 200, "read scan detail").json()
        has_evidence = bool(latest.get("events") or latest.get("tool_runs") or latest.get("progress", 0) > 0)
        if wait_for_evidence and has_evidence:
            return latest
        if require_terminal_evidence and latest.get("status") in TERMINAL_SCAN_STATES:
            has_terminal_evidence = bool(
                latest.get("tool_runs")
                and (latest.get("scan_metadata") or {}).get("worker_manifest")
            )
            if has_terminal_evidence:
                return latest
        elif not wait_for_evidence and latest.get("status") in TERMINAL_SCAN_STATES:
            return latest
        if latest.get("status") in TERMINAL_SCAN_STATES and not require_terminal_evidence:
            return latest
        time.sleep(1)
    raise AssertionError(f"scan {scan_id} did not make expected progress; latest={latest.get('status')}")


async def create_temporary_user(suffix: str) -> tuple[str, str, str]:
    email = f"e2e-{suffix}@exposurescopex.local"
    password = f"E2E-{secrets.token_urlsafe(24)}-aA1!"
    async with async_session_factory() as db:
        owner = await db.scalar(select(User).where(User.email == EMAIL, User.is_active.is_(True)))
        if owner is None:
            owner = await db.scalar(select(User).where(User.is_active.is_(True)).order_by(User.created_at))
        if owner is None:
            raise RuntimeError("No active tenant user exists for E2E bootstrap")
        user = User(
            org_id=owner.org_id,
            email=email,
            username=f"e2e-{suffix}",
            password_hash=get_password_hash(password),
            role="admin",
            is_active=True,
        )
        db.add(user)
        await db.commit()
        return email, password, str(user.id)


async def remove_temporary_user(user_id: str) -> None:
    async with async_session_factory() as db:
        # All product records are removed through their APIs first. These rows
        # are test identity residue and can be safely removed afterward.
        await db.execute(delete(AuthSession).where(AuthSession.user_id == uuid.UUID(user_id)))
        await db.execute(delete(AuditLog).where(AuditLog.user_id == uuid.UUID(user_id)))
        await db.execute(text("DELETE FROM notifications WHERE user_id = :user_id"), {"user_id": user_id})
        await db.execute(text("DELETE FROM user_favorites WHERE user_id = :user_id"), {"user_id": user_id})
        await db.execute(delete(User).where(User.id == uuid.UUID(user_id)))
        await db.commit()


async def remove_orphaned_test_users() -> int:
    async with async_session_factory() as db:
        candidates = (await db.execute(
            select(User.id).where(User.email.like("e2e-%@exposurescopex.local"))
        )).scalars().all()
        removable: list[str] = []
        for user_id in candidates:
            assessment_count = await db.scalar(
                select(Assessment.id).where(Assessment.created_by == user_id).limit(1)
            )
            if assessment_count is None:
                removable.append(str(user_id))
    for user_id in removable:
        await remove_temporary_user(user_id)
    return len(removable)


def run_journey() -> int:
    global ACTIVE_TEMPORARY_USER_ID
    suffix = uuid.uuid4().hex[:10]
    email = EMAIL
    password = PASSWORD
    temporary_user_id: str | None = None
    if not password:
        stale_count = asyncio.run(remove_orphaned_test_users())
        if stale_count:
            print(f"PASS removed {stale_count} orphaned E2E identity", flush=True)
        email, password, temporary_user_id = asyncio.run(create_temporary_user(suffix))
        ACTIVE_TEMPORARY_USER_ID = temporary_user_id
        print("PASS temporary E2E identity created", flush=True)

    assessment_ids: list[str] = []
    report_ids: list[str] = []
    schedule_ids: list[str] = []
    authorization_ids: list[str] = []
    inventory_ip = f"11.22.33.{(int(suffix[:4], 16) % 200) + 1}"

    with httpx.Client(base_url=BASE_URL, timeout=30.0, follow_redirects=False) as client:
        login = require(client.post("/auth/login", json={"email": email, "password": password}), 200, "login").json()
        client.headers["Authorization"] = f"Bearer {login['access_token']}"

        try:
            me = require(client.get("/auth/me"), 200, "authenticated identity").json()
            assert me["email"].lower() == email.lower()

            csrf = client.cookies.get("csrf_token")
            refreshed = require(
                client.post("/auth/refresh", json={}, headers={"X-CSRF-Token": csrf or ""}),
                200,
                "refresh rotation",
            ).json()
            client.headers["Authorization"] = f"Bearer {refreshed['access_token']}"

            csv_content = (
                "Public Host,Environment,Asset Owner,Notes\n"
                "app.example.test,production,AppSec,primary web property\n"
                f"{inventory_ip},production,Network,public address\n"
                "https://api.example.test/v1,staging,API Team,service endpoint\n"
                "APP.EXAMPLE.TEST,production,AppSec,duplicate normalized host\n"
            )
            imported = require(
                client.post(
                    "/assessments/import",
                    files={"file": ("arbitrary-export.csv", csv_content, "text/csv")},
                ),
                201,
                "flexible CSV normalization",
            ).json()
            assert imported["added"] == 3, imported
            assert imported["skipped"] == 1, imported
            assert not imported["errors"], imported

            assessment_payload = {
                "name": f"E2E multi-asset {suffix}",
                "description": "Temporary live E2E validation record",
                "target": imported["imported_targets"][0]["target"],
                "target_type": imported["imported_targets"][0]["target_type"],
                "scan_mode": "light",
                "imported_targets": imported["imported_targets"],
                "auto_start": False,
            }
            assessment = require(client.post("/assessments", json=assessment_payload), 201, "create one multi-asset assessment").json()
            assessment_id = assessment["id"]
            assessment_ids.append(assessment_id)
            assert assessment["target_type"] == "file"

            assets = require(client.get("/assets", params={"assessment_id": assessment_id, "page_size": 100}), 200, "assessment asset scope").json()
            assert assets["total"] == 3, assets
            assert {item["value"] for item in assets["items"]} == {
                "app.example.test", inventory_ip, "https://api.example.test/v1"
            }

            findings = require(client.get("/findings", params={"assessment_id": assessment_id}), 200, "assessment finding scope").json()
            assert findings["total"] == 0

            schedule = require(
                client.post(
                    "/assessments/schedules",
                    json={
                        "assessment_id": assessment_id,
                        "name": f"E2E schedule {suffix}",
                        "timezone": "Asia/Kolkata",
                        "interval_minutes": 1440,
                        "window_start": "01:00",
                        "window_end": "04:00",
                        "missed_run_policy": "skip",
                        "overlap_policy": "skip",
                        "is_active": True,
                    },
                ),
                201,
                "create recurring schedule",
            ).json()
            schedule_ids.append(schedule["id"])
            assert schedule["window_start"] == "01:00" and schedule["missed_run_policy"] == "skip"
            paused = require(client.patch(f"/assessments/schedules/{schedule['id']}", json={"is_active": False}), 200, "pause schedule").json()
            assert paused["is_active"] is False
            resumed = require(client.patch(f"/assessments/schedules/{schedule['id']}", json={"is_active": True}), 200, "resume schedule").json()
            assert resumed["is_active"] is True
            require(client.get(f"/assessments/schedules/{schedule['id']}/history"), 200, "schedule history")

            for report_format in ("html", "markdown", "sarif", "csv", "json"):
                report = require(
                    client.post(
                        "/reports/generate",
                        json={
                            "assessment_id": assessment_id,
                            "format": report_format,
                            "title": f"E2E {report_format} {suffix}",
                        },
                    ),
                    201,
                    f"queue {report_format} report",
                ).json()
                report_ids.append(report["id"])
                terminal = poll_report(client, assessment_id, report["id"])
                assert terminal["status"] == "ready", terminal.get("error")
                download = require(client.get(f"/reports/{report['id']}/download"), 200, f"download {report_format} report")
                digest = hashlib.sha256(download.content).hexdigest()
                assert digest == terminal["sha256"] == download.headers["X-Content-SHA256"]
                assert len(download.content) == terminal["file_size"] > 0

            valid_until = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            authorization = require(
                client.post(
                    "/settings/scan-authorizations",
                    json={
                        "target": LOCAL_TARGET,
                        "authorization_type": "full",
                        "valid_until": valid_until,
                        "notes": f"Temporary local E2E authorization {suffix}",
                    },
                ),
                201,
                "authorize local target",
            ).json()
            authorization_ids.append(authorization["id"])

            live_payload = {
                "name": f"E2E local scan {suffix}",
                "description": "Scans only the local ExposureScopeX login surface",
                "target": LOCAL_TARGET,
                "target_type": "url",
                "scan_mode": "light",
                "phases": {"enum": False, "scan": True, "cloud": False, "exploit": False, "report": True},
                "flags": {"crawl": False, "screenshots": False, "cve": False, "no_osint": True},
                "requested_utilities": ["headers", "httpx"],
                "auto_start": True,
            }
            preview = require(client.post("/assessments/execution-preview", json=live_payload), 200, "execution preview").json()
            assert preview["target_count"] == 1 and preview["tool_plan"]
            live_assessment = require(client.post("/assessments", json=live_payload), 201, "dispatch local scan").json()
            live_assessment_id = live_assessment["id"]
            assessment_ids.append(live_assessment_id)

            scans = require(client.get(f"/assessments/{live_assessment_id}/scans"), 200, "list dispatched scans").json()
            assert len(scans) == 1
            scan_id = scans[0]["id"]
            detail = poll_scan(client, scan_id, wait_for_evidence=True)
            assert detail.get("events") or detail.get("tool_runs") or detail.get("progress", 0) > 0

            scoped = require(client.get("/findings", params={"assessment_id": live_assessment_id, "scan_id": scan_id, "page_size": 100}), 200, "scan-scoped findings").json()
            assert all(item["scan_id"] == scan_id for item in scoped["items"])

            if detail["status"] not in TERMINAL_SCAN_STATES:
                require(client.post(f"/assessments/{live_assessment_id}/cancel"), 200, "cancel active scan")
                detail = poll_scan(
                    client,
                    scan_id,
                    wait_for_evidence=False,
                    require_terminal_evidence=True,
                )
            elif not detail.get("tool_runs") or not (detail.get("scan_metadata") or {}).get("worker_manifest"):
                detail = poll_scan(
                    client,
                    scan_id,
                    wait_for_evidence=False,
                    require_terminal_evidence=True,
                    timeout=30,
                )
            assert detail["status"] in TERMINAL_SCAN_STATES
            assert detail.get("tool_runs"), "scan reached terminal state without recorded tool execution"
            assert any(
                item.get("tool") == "orchestrator"
                and item.get("external_id", "").startswith("orchestrator-")
                for item in detail["tool_runs"]
            ), "scan is missing its durable orchestrator command record"
            assert (detail.get("scan_metadata") or {}).get("worker_manifest"), "worker manifest was not persisted"
            print(f"PASS scan recorded {len(detail['tool_runs'])} tool run(s) and worker provenance", flush=True)

            report_deadline = time.monotonic() + 30
            automatic_report = (detail.get("scan_metadata") or {}).get("automatic_report") or {}
            while not automatic_report.get("id") and time.monotonic() < report_deadline:
                time.sleep(0.5)
                detail = require(client.get(f"/assessments/scan-executions/{scan_id}"), 200, "wait for automatic report").json()
                automatic_report = (detail.get("scan_metadata") or {}).get("automatic_report") or {}
            assert automatic_report.get("id"), "terminal scan did not queue its automatic DOCX report"
            report_ids.append(automatic_report["id"])
            terminal_report = poll_report(client, live_assessment_id, automatic_report["id"])
            assert terminal_report["status"] == "ready", terminal_report.get("error")
            document = require(client.get(f"/reports/{automatic_report['id']}/download"), 200, "download automatic DOCX report")
            assert document.content.startswith(b"PK")
            with zipfile.ZipFile(BytesIO(document.content)) as archive:
                assert "word/document.xml" in archive.namelist()
            print("PASS terminal scan generated a valid automatic DOCX report", flush=True)

            if detail["status"] in {"failed", "cancelled"}:
                retried = require(client.post(f"/assessments/scan-executions/{scan_id}/retry"), 200, "retry terminal scan").json()
                retry_id = retried["id"]
                time.sleep(0.5)
                require(client.post(f"/assessments/{live_assessment_id}/cancel"), (200, 409), "cancel retry safely")
                retry_detail = poll_scan(client, retry_id, wait_for_evidence=False)
                assert retry_detail["status"] in TERMINAL_SCAN_STATES

            audit = require(client.get("/settings/audit-logs", params={"page_size": 200}), 200, "audit search").json()
            assert audit["total"] > 0
            exported_audit = require(client.get("/settings/audit-logs/export"), 200, "audit CSV export")
            assert exported_audit.text.startswith("created_at,action")

        finally:
            for report_id in reversed(report_ids):
                response = client.delete(f"/reports/{report_id}")
                if response.status_code not in {204, 404}:
                    print(f"WARN report cleanup {report_id}: {response.status_code}", flush=True)
            for schedule_id in reversed(schedule_ids):
                response = client.delete(f"/assessments/schedules/{schedule_id}")
                if response.status_code not in {204, 404}:
                    print(f"WARN schedule cleanup {schedule_id}: {response.status_code}", flush=True)
            for assessment_id in reversed(assessment_ids):
                current = client.get(f"/assessments/{assessment_id}")
                if current.status_code == 200 and current.json().get("status") == "running":
                    client.post(f"/assessments/{assessment_id}/cancel")
                    time.sleep(1)
                response = client.delete(f"/assessments/{assessment_id}")
                if response.status_code not in {204, 404}:
                    print(f"WARN assessment cleanup {assessment_id}: {response.status_code}", flush=True)
            for authorization_id in reversed(authorization_ids):
                response = client.delete(f"/settings/scan-authorizations/{authorization_id}")
                if response.status_code not in {204, 404}:
                    print(f"WARN authorization cleanup {authorization_id}: {response.status_code}", flush=True)

    if temporary_user_id:
        asyncio.run(remove_temporary_user(temporary_user_id))
        ACTIVE_TEMPORARY_USER_ID = None
        print("PASS temporary E2E identity removed", flush=True)

    print("PASS live E2E journey completed and temporary records cleaned", flush=True)
    return 0


def main() -> int:
    global ACTIVE_TEMPORARY_USER_ID
    try:
        return run_journey()
    finally:
        if ACTIVE_TEMPORARY_USER_ID:
            asyncio.run(remove_temporary_user(ACTIVE_TEMPORARY_USER_ID))
            ACTIVE_TEMPORARY_USER_ID = None
            print("PASS temporary E2E identity removed after failure", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
