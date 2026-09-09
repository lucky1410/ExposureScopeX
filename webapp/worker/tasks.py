"""Celery tasks for running ExposureScopeX scans."""

import json
import os
import subprocess
import time
from pathlib import Path

import redis

from worker.celery_app import celery_app

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


def get_redis():
    return redis.from_url(REDIS_URL)


def publish_progress(scan_id: str, phase: str, progress: int, message: str):
    """Publish scan progress to Redis for WebSocket streaming."""
    r = get_redis()
    event = json.dumps({
        "type": "scan_progress",
        "scan_id": scan_id,
        "phase": phase,
        "progress": progress,
        "message": message,
        "timestamp": time.time(),
    })
    r.publish(f"scan_progress:{scan_id}", event)
    r.set(f"scan:{scan_id}:progress", event, ex=3600)


@celery_app.task(bind=True, name="worker.tasks.run_scan")
def run_scan(self, scan_id: str, target: str, target_type: str,
             scan_mode: str = "medium", phases: list = None,
             flags: dict = None):
    """Execute an ExposureScopeX scan via subprocess.

    Args:
        scan_id: UUID of the scan record in PostgreSQL
        target: Target to scan (domain, IP, CIDR, URL)
        target_type: Type of target (domain, ip, cidr, url)
        scan_mode: Scan mode (light, medium, aggressive)
        phases: List of phases to run (enum, scan, cloud, report)
        flags: Additional flags (passive_only, stealth, etc.)
    """
    phases = phases or ["enum", "scan", "cloud", "report"]
    flags = flags or {}

    results_dir = Path("/app/results") / f"{scan_id}"
    results_dir.mkdir(parents=True, exist_ok=True)

    # Build command
    cmd = ["bash", "/app/exposurescopex.sh"]
    cmd.extend(["-d", target])
    cmd.extend(["-m", scan_mode])
    cmd.extend(["-o", str(results_dir / "report")])
    cmd.append("--auto")

    # Add phase flags
    phase_map = {"enum": "-e", "scan": "-s", "cloud": "-c",
                 "exploit": "-x", "report": "-r"}
    for phase in phases:
        if phase in phase_map:
            cmd.append(phase_map[phase])

    # Add optional flags
    if flags.get("passive_only"):
        cmd.append("--passive-only")
    if flags.get("stealth"):
        cmd.append("--stealth")
    if flags.get("screenshots"):
        cmd.append("--screenshots")
    if flags.get("cve"):
        cmd.append("--cve")
    if flags.get("crawl"):
        cmd.append("--crawl")
    if flags.get("no_osint"):
        cmd.append("--no-osint")

    publish_progress(scan_id, "starting", 0, f"Starting scan of {target}")

    try:
        env = os.environ.copy()
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd="/app",
            env=env,
        )

        log_lines = []
        current_phase = "initializing"

        for line in iter(process.stdout.readline, ""):
            line = line.strip()
            if not line:
                continue
            log_lines.append(line)

            # Detect phase changes from log output
            if "[*] Phase" in line or "[*] Running" in line:
                if "enumeration" in line.lower():
                    current_phase = "enumeration"
                    publish_progress(scan_id, current_phase, 10, line)
                elif "dns" in line.lower():
                    current_phase = "dns_recon"
                    publish_progress(scan_id, current_phase, 20, line)
                elif "osint" in line.lower():
                    current_phase = "osint"
                    publish_progress(scan_id, current_phase, 30, line)
                elif "port" in line.lower() or "nmap" in line.lower():
                    current_phase = "port_scan"
                    publish_progress(scan_id, current_phase, 40, line)
                elif "ssl" in line.lower() or "tls" in line.lower():
                    current_phase = "ssl_check"
                    publish_progress(scan_id, current_phase, 50, line)
                elif "cloud" in line.lower():
                    current_phase = "cloud"
                    publish_progress(scan_id, current_phase, 60, line)
                elif "crawl" in line.lower():
                    current_phase = "crawler"
                    publish_progress(scan_id, current_phase, 65, line)
                elif "web" in line.lower():
                    current_phase = "web_test"
                    publish_progress(scan_id, current_phase, 70, line)
                elif "nuclei" in line.lower() or "vuln" in line.lower():
                    current_phase = "vuln_scan"
                    publish_progress(scan_id, current_phase, 85, line)
                elif "report" in line.lower():
                    current_phase = "reporting"
                    publish_progress(scan_id, current_phase, 95, line)

        process.wait()

        if process.returncode == 0:
            publish_progress(scan_id, "completed", 100, "Scan completed successfully")
            return {
                "status": "completed",
                "scan_id": scan_id,
                "results_dir": str(results_dir),
                "log_lines": len(log_lines),
            }
        else:
            publish_progress(scan_id, "failed", -1,
                           f"Scan failed with exit code {process.returncode}")
            return {
                "status": "failed",
                "scan_id": scan_id,
                "error": f"Exit code {process.returncode}",
                "log": "\n".join(log_lines[-50:]),
            }

    except Exception as e:
        publish_progress(scan_id, "failed", -1, f"Scan error: {str(e)}")
        raise
