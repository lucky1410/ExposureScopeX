"""Submit one hardened Kubernetes Job for each assessment scan."""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.request
from typing import Callable

from app.config import settings

TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


class KubernetesExecutionError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def _request(method: str, path: str, payload: dict | None = None) -> dict:
    try:
        token = open(TOKEN_PATH, encoding="utf-8").read().strip()
    except OSError as exc:
        raise KubernetesExecutionError("Kubernetes service-account token is unavailable") from exc
    url = f"https://kubernetes.default.svc{path}"
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    context = ssl.create_default_context(cafile=CA_PATH)
    try:
        with urllib.request.urlopen(request, timeout=30, context=context) as response:
            data = response.read()
            return json.loads(data) if data else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise KubernetesExecutionError(
            f"Kubernetes API returned {exc.code}: {detail}", status_code=exc.code
        ) from exc


def _job_name(scan_id: str) -> str:
    return f"exsx-scan-{scan_id.replace('-', '')[:16]}"


def _job_manifest(assessment_id: str, org_id: str, scan_id: str, task_id: str) -> dict:
    name = _job_name(scan_id)
    env_from = [{"secretRef": {"name": settings.SCAN_JOB_SECRET_NAME}}]
    if settings.SCAN_JOB_CONFIG_MAP:
        env_from.append({"configMapRef": {"name": settings.SCAN_JOB_CONFIG_MAP}})
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "namespace": settings.SCAN_JOB_NAMESPACE,
            "labels": {"app.kubernetes.io/name": "exposurescopex-scanner", "exposurescopex.io/scan-id": scan_id},
        },
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": settings.SCAN_JOB_ACTIVE_DEADLINE_SECONDS,
            "ttlSecondsAfterFinished": 3600,
            "template": {
                "metadata": {"labels": {"app.kubernetes.io/name": "exposurescopex-scanner", "exposurescopex.io/scan-id": scan_id}},
                "spec": {
                    "serviceAccountName": settings.SCAN_JOB_SERVICE_ACCOUNT,
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 65532,
                        "runAsGroup": 20,
                        "fsGroup": 20,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [{
                        "name": "scanner",
                        "image": settings.SCAN_JOB_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "-c"],
                        "args": [
                            "import sys; from app.services.celery_app import execute_assessment_scan; "
                            "result=execute_assessment_scan(sys.argv[1],sys.argv[2],scan_id=sys.argv[3],task_id=sys.argv[4]); "
                            "raise SystemExit(0 if result.get('status') in {'completed','cancelled','ignored'} else 1)",
                            assessment_id,
                            org_id,
                            scan_id,
                            task_id,
                        ],
                        "env": [{"name": "EXSX_ISOLATED_JOB", "value": "1"}, {"name": "SCAN_EXECUTOR", "value": "process"}],
                        "envFrom": env_from,
                        "resources": {
                            "requests": {"cpu": "500m", "memory": "1Gi", "ephemeral-storage": "1Gi"},
                            "limits": {"cpu": "4", "memory": "6Gi", "ephemeral-storage": "10Gi"},
                        },
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "capabilities": {
                                "drop": ["ALL"],
                                **({"add": ["NET_RAW"]} if settings.SCAN_JOB_ALLOW_NET_RAW else {}),
                            },
                        },
                        "volumeMounts": [
                            {"name": "results", "mountPath": "/app/results"},
                            {"name": "runtime", "mountPath": "/app/runtime"},
                            {"name": "tmp", "mountPath": "/tmp"},
                        ],
                    }],
                    "volumes": [
                        {"name": "results", "persistentVolumeClaim": {"claimName": settings.SCAN_JOB_RESULTS_PVC}},
                        {"name": "runtime", "emptyDir": {"sizeLimit": "4Gi"}},
                        {"name": "tmp", "emptyDir": {"sizeLimit": "512Mi"}},
                    ],
                },
            },
        },
    }


def execute_in_kubernetes_job(
    assessment_id: str,
    org_id: str,
    scan_id: str,
    *,
    task_id: str,
    cancel_requested: Callable[[], bool] | None = None,
    heartbeat: Callable[[], None] | None = None,
) -> dict:
    namespace = settings.SCAN_JOB_NAMESPACE
    name = _job_name(scan_id)
    base_path = f"/apis/batch/v1/namespaces/{namespace}/jobs"
    try:
        _request("POST", base_path, _job_manifest(assessment_id, org_id, scan_id, task_id))
    except KubernetesExecutionError as exc:
        if exc.status_code != 409:
            raise
        _request("GET", f"{base_path}/{name}")
    started = time.monotonic()
    last_heartbeat = 0.0
    while True:
        if heartbeat and time.monotonic() - last_heartbeat >= 30:
            heartbeat()
            last_heartbeat = time.monotonic()
        if cancel_requested and cancel_requested():
            _request("DELETE", f"{base_path}/{name}?propagationPolicy=Foreground", {"kind": "DeleteOptions", "apiVersion": "v1", "propagationPolicy": "Foreground"})
            return {"status": "cancelled", "executor": "kubernetes", "job_name": name}
        job = _request("GET", f"{base_path}/{name}")
        status = job.get("status") or {}
        if int(status.get("succeeded") or 0) > 0:
            return {"status": "completed", "executor": "kubernetes", "job_name": name}
        if int(status.get("failed") or 0) > 0:
            conditions = status.get("conditions") or []
            reason = next((item.get("message") for item in conditions if item.get("type") == "Failed"), "isolated scan job failed")
            raise KubernetesExecutionError(str(reason))
        if time.monotonic() - started > settings.SCAN_JOB_ACTIVE_DEADLINE_SECONDS + 300:
            raise KubernetesExecutionError("Timed out waiting for isolated scan job completion")
        time.sleep(5)
