"""Import real ExposureScopeX scan results from the filesystem into PostgreSQL.

Scans the results/ directory for session folders, parses each output file,
and populates the database with real assessment/asset/finding data.
Idempotent: uses deterministic UUIDs based on session directory names.
"""

import logging
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from sqlalchemy import select

from app.config import settings
from app.database import async_session_factory
from app.models.assessment import Assessment
from app.models.asset import Asset
from app.models.dns_record import DnsRecord
from app.models.finding import Finding
from app.models.http_header import HttpHeader
from app.models.notification import Notification
from app.models.port import Port
from app.models.resource import Resource
from app.models.scan import Scan
from app.models.technology import Technology
from app.models.tls_certificate import TlsCertificate
from app.models.user import Organization, User
from app.models.vulnerability import Vulnerability
from app.security import get_password_hash
from app.services.parsers.arjun_parser import parse_arjun_results
from app.services.parsers.nmap_parser import parse_nmap_xml
from app.services.parsers.dns_parser import parse_dns_recon
from app.services.parsers.ssl_parser import parse_ssl_results
from app.services.parsers.headers_parser import parse_http_headers
from app.services.parsers.nuclei_parser import parse_nuclei_results
from app.services.parsers.cloud_parser import parse_cloud_buckets, parse_cloud_results
from app.services.parsers.subdomain_parser import parse_subdomains
from app.services.parsers.ffuf_parser import parse_ffuf_results
from app.services.parsers.nikto_parser import parse_nikto
from app.services.parsers.email_parser import parse_email_security
from app.services.parsers.api_security_parser import parse_api_security
from app.services.parsers.sqlmap_parser import parse_sqlmap_results

logger = logging.getLogger("exposurescopex.importer")

# Fixed namespace for deterministic UUIDs
NS = uuid.UUID("b2c3d4e5-f6a7-8901-bcde-f12345678901")

ORG_ID = uuid.uuid5(NS, "org-real")
USER_ID = uuid.uuid5(NS, "user-admin")


def _uid(name: str) -> uuid.UUID:
    """Generate a deterministic UUID5 from a seed name."""
    return uuid.uuid5(NS, name)


def _detect_target_from_dirname(dirname: str) -> tuple[str, str]:
    """Extract target and type from session directory name.

    Examples:
        'cricut.com_20260522_001507' -> ('cricut.com', 'domain')
        'batch_20260114_172916' -> ('batch', 'file')
        '192.168.1.0_24_20260101_...' -> ('192.168.1.0/24', 'cidr')
    """
    # Pattern: target_YYYYMMDD_HHMMSS
    match = re.match(r'^(.+?)_(\d{8}_\d{6})$', dirname)
    if not match:
        return dirname, "domain"

    raw_target = match.group(1)

    if raw_target == "batch":
        return "batch", "file"

    # CIDR: underscores back to slashes
    if re.match(r'^\d+\.\d+\.\d+\.\d+_\d+$', raw_target):
        return raw_target.replace('_', '/'), "cidr"

    # IP
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', raw_target):
        return raw_target, "ip"

    return raw_target, "domain"


def _parse_timestamp_from_dirname(dirname: str) -> datetime:
    """Extract timestamp from directory name like 'cricut.com_20260522_001507'."""
    match = re.search(r'(\d{8})_(\d{6})$', dirname)
    if match:
        date_str = match.group(1)
        time_str = match.group(2)
        try:
            return datetime.strptime(f"{date_str}{time_str}", "%Y%m%d%H%M%S").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _count_severity(findings: list[dict]) -> dict[str, int]:
    """Count findings by severity."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def _calculate_risk_score(counts: dict[str, int]) -> Decimal:
    """Calculate a risk score from severity counts (0-100 scale)."""
    score = (
        counts.get("CRITICAL", 0) * 10
        + counts.get("HIGH", 0) * 7
        + counts.get("MEDIUM", 0) * 4
        + counts.get("LOW", 0) * 1
    )
    return Decimal(str(min(score, 100)))


def _discover_sessions(results_dir: Path) -> list[Path]:
    """Find all scan session directories in results/."""
    if not results_dir.is_dir():
        return []
    sessions = []
    for entry in sorted(results_dir.iterdir()):
        if entry.is_dir() and re.match(r'.+_\d{8}_\d{6}$', entry.name):
            sessions.append(entry)
    return sessions


def _infer_phases(session_dir: Path) -> dict:
    """Infer which scan phases ran based on which output files exist."""
    files = {f.name for f in session_dir.iterdir() if f.is_file()}
    return {
        "enum": "subdomains.txt" in files,
        "dns": "dns_recon.txt" in files,
        "osint": "osint_results.txt" in files or "passive_recon.txt" in files,
        "scan": "nmap_scan.txt" in files or "nmap_scan.xml" in files,
        "ssl": "ssl_results.txt" in files,
        "cloud": "cloud_results.txt" in files or "cloud_buckets.txt" in files,
        "crawl": "katana_crawl.txt" in files,
        "web": any(
            f.startswith("nikto_")
            or f.startswith("feroxbuster")
            or f.startswith("ffuf_")
            or f.startswith("arjun_")
            or f == "sqlmap_results.csv"
            for f in files
        ),
        "api": "api_security.txt" in files,
        "vuln": "nuclei_results.txt" in files,
        "report": "report.md" in files,
    }


async def import_real_data(results_dir: str = "/app/results") -> None:
    """Import all scan sessions from results/ into PostgreSQL.

    Idempotent: checks if org already exists before importing.
    """
    if not settings.BOOTSTRAP_ADMIN_PASSWORD or len(settings.BOOTSTRAP_ADMIN_PASSWORD) < 12:
        raise RuntimeError("BOOTSTRAP_ADMIN_PASSWORD must contain at least 12 characters")
    results_path = Path(results_dir)
    if not results_path.is_dir():
        logger.warning(f"Results directory not found: {results_dir}")
        return

    sessions = _discover_sessions(results_path)
    if not sessions:
        logger.warning(f"No scan sessions found in {results_dir}")
        return

    logger.info(f"Found {len(sessions)} scan session(s) to import")

    async with async_session_factory() as session:
        # Check if already imported
        existing = await session.execute(
            select(Organization).where(Organization.id == ORG_ID)
        )
        if existing.scalar_one_or_none():
            logger.info("Real data already imported, skipping")
            return

        # --- Organization ---
        org = Organization(
            id=ORG_ID,
            name="ExposureScopeX",
            slug="exposurescopex",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(org)

        # --- Admin User ---
        admin = User(
            id=USER_ID,
            org_id=ORG_ID,
            email="admin@exposurescopex.local",
            username="admin",
            password_hash=get_password_hash(settings.BOOTSTRAP_ADMIN_PASSWORD),
            role="admin",
            is_active=True,
            last_login=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(admin)

        # --- Seed resources from JSON ---
        await _seed_resources(session, results_path)

        await session.flush()

        # --- Process each scan session (each in its own savepoint) ---
        all_findings_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for scan_session in sessions:
            logger.info(f"Importing session: {scan_session.name}")
            try:
                async with session.begin_nested():
                    counts = await _import_session(session, scan_session)
                    for k, v in counts.items():
                        all_findings_count[k] = all_findings_count.get(k, 0) + v
            except Exception as e:
                logger.error(f"Failed to import session {scan_session.name}: {e}")
                continue

        # --- Notifications ---
        session.add(Notification(
            id=_uid("notif-import-complete"),
            user_id=USER_ID,
            type="system",
            title="Real scan data imported successfully",
            message=f"Imported {len(sessions)} scan sessions with "
                    f"{sum(all_findings_count.values())} total findings.",
            severity="info",
            is_read=False,
        ))

        await session.commit()
        logger.info(
            f"Import complete: {len(sessions)} sessions, "
            f"{sum(all_findings_count.values())} findings"
        )


async def _import_session(session, scan_dir: Path) -> dict[str, int]:
    """Import a single scan session directory. Returns severity counts."""
    dirname = scan_dir.name
    target, target_type = _detect_target_from_dirname(dirname)
    timestamp = _parse_timestamp_from_dirname(dirname)
    phases = _infer_phases(scan_dir)

    assessment_id = _uid(f"assessment-{dirname}")
    scan_id = _uid(f"scan-{dirname}")

    # Collect all findings from all parsers
    all_findings: list[dict] = []

    # --- Parse all available output files ---
    subdomains = parse_subdomains(scan_dir / "subdomains.txt")
    nmap_hosts = parse_nmap_xml(scan_dir / "nmap_scan.xml")
    dns_records = parse_dns_recon(scan_dir / "dns_recon.txt")
    ssl_data = parse_ssl_results(scan_dir / "ssl_results.txt")
    header_blocks = parse_http_headers(scan_dir / "http_headers.txt")
    nuclei_findings = parse_nuclei_results(scan_dir / "nuclei_results.txt")
    cloud_buckets = parse_cloud_buckets(scan_dir / "cloud_buckets.txt")
    cloud_findings = parse_cloud_results(scan_dir / "cloud_results.txt")
    email_data = parse_email_security(scan_dir / "email_security.txt")
    api_findings = parse_api_security(scan_dir / "api_security.txt")
    ffuf_findings = [
        {
            "severity": "LOW" if item.get("status") in {401, 403} else "INFO",
            "title": f"Content discovery hit: {item.get('url')}",
            "url": item.get("url") or f"https://{target}",
            "source": "ffuf",
            "template_id": "ffuf-content-discovery",
            "evidence": f"Input: {item.get('input')}; status: {item.get('status')}; length: {item.get('length')}",
        }
        for report_path in scan_dir.glob("ffuf_*.json")
        for item in parse_ffuf_results(report_path)
    ]
    arjun_findings = [
        {
            "severity": "INFO",
            "title": f"Parameter discovered: {item.get('parameter')}",
            "url": item.get("url") or f"https://{target}",
            "source": "arjun",
            "template_id": "arjun-parameter-discovery",
            "evidence": f"Method: {item.get('method')}; parameter: {item.get('parameter')}",
        }
        for report_path in scan_dir.glob("arjun_*.json")
        for item in parse_arjun_results(report_path)
    ]
    sqlmap_findings = [
        {
            "severity": "HIGH",
            "title": f"SQL injection signal on parameter {item.get('parameter')}",
            "url": item.get("url") or f"https://{target}",
            "source": "sqlmap",
            "template_id": "sqlmap-sqli",
            "evidence": f"Place: {item.get('place')}; parameter: {item.get('parameter')}; techniques: {item.get('techniques')}",
        }
        for item in parse_sqlmap_results(scan_dir / "sqlmap_results.csv")
    ]

    # Parse all nikto files
    nikto_findings: list[dict] = []
    for nikto_file in scan_dir.glob("nikto_*.txt"):
        nikto_data = parse_nikto(nikto_file)
        if nikto_data and nikto_data.get("findings"):
            for f in nikto_data["findings"]:
                nikto_findings.append({
                    "severity": "MEDIUM",
                    "title": f.get("description", "Nikto finding")[:500],
                    "url": f"https://{nikto_data.get('target', target)}:{nikto_data.get('port', 443)}",
                    "source": "nikto",
                    "template_id": None,
                    "evidence": f.get("reference", ""),
                })

    # Aggregate all findings
    all_findings.extend(nuclei_findings)
    all_findings.extend(cloud_findings)
    all_findings.extend(nikto_findings)
    all_findings.extend(api_findings)
    all_findings.extend(ffuf_findings)
    all_findings.extend(arjun_findings)
    all_findings.extend(sqlmap_findings)

    # SSL findings
    if ssl_data and ssl_data.get("findings"):
        for f in ssl_data["findings"]:
            all_findings.append({
                "severity": f["severity"],
                "title": f["title"],
                "url": f"https://{target}",
                "source": "ssl_check",
                "template_id": None,
                "evidence": "",
            })

    # Email security findings
    if email_data and email_data.get("findings"):
        for f in email_data["findings"]:
            all_findings.append({
                "severity": f.get("severity", "INFO"),
                "title": f.get("title", "Email security finding"),
                "url": f"https://{target}",
                "source": "email_security",
                "template_id": None,
                "evidence": "",
            })

    # Header findings
    for block in header_blocks:
        for f in block.get("findings", []):
            all_findings.append({
                "severity": f["severity"],
                "title": f["title"],
                "url": block.get("url", f"https://{target}"),
                "source": "http_headers",
                "template_id": None,
                "evidence": "",
            })

    # Cloud bucket findings
    for bucket in cloud_buckets:
        all_findings.append({
            "severity": bucket["severity"],
            "title": f"{bucket['bucket_type']} bucket {bucket['access']}: {bucket['url']}",
            "url": bucket["url"],
            "source": "cloud",
            "template_id": None,
            "evidence": "",
        })

    severity_counts = _count_severity(all_findings)
    risk_score = _calculate_risk_score(severity_counts)

    # --- Create Assessment ---
    assessment_name = f"{target} Scan" if target != "batch" else f"Batch Scan {dirname.split('_')[1]}"
    assessment = Assessment(
        id=assessment_id,
        org_id=ORG_ID,
        created_by=USER_ID,
        name=assessment_name,
        description=f"Imported from scan session {dirname}",
        target=target,
        target_type=target_type,
        status="completed",
        scan_mode="medium",
        phases=phases,
        flags={"imported": True},
        is_demo=False,
        risk_score=risk_score,
        created_at=timestamp,
        updated_at=timestamp,
    )
    session.add(assessment)

    # --- Create Scan ---
    scan = Scan(
        id=scan_id,
        assessment_id=assessment_id,
        session_dir=str(scan_dir),
        status="completed",
        current_phase="report",
        progress=100,
        started_at=timestamp,
        completed_at=timestamp,
        scan_metadata={
            "mode": "medium",
            "phases": phases,
            "files": [f.name for f in scan_dir.iterdir() if f.is_file()],
        },
        is_demo=False,
        created_at=timestamp,
        updated_at=timestamp,
    )
    session.add(scan)

    await session.flush()

    # --- Create Assets ---
    asset_map: dict[str, uuid.UUID] = {}

    # Root domain/target asset
    root_asset_id = _uid(f"asset-{dirname}-{target}")
    root_asset = Asset(
        id=root_asset_id,
        assessment_id=assessment_id,
        asset_type="domain" if target_type == "domain" else target_type,
        value=target,
        parent_id=None,
        is_live=True,
        first_seen=timestamp,
        last_seen=timestamp,
        metadata={"source": "scan_target"},
        is_demo=False,
        created_at=timestamp,
        updated_at=timestamp,
    )
    session.add(root_asset)
    asset_map[target] = root_asset_id

    # Subdomain assets
    for sub in subdomains:
        if sub == target:
            continue
        sub_id = _uid(f"asset-{dirname}-{sub}")
        sub_asset = Asset(
            id=sub_id,
            assessment_id=assessment_id,
            asset_type="subdomain",
            value=sub,
            parent_id=root_asset_id,
            is_live=True,
            first_seen=timestamp,
            last_seen=timestamp,
            metadata={"source": "enumeration"},
            is_demo=False,
            created_at=timestamp,
            updated_at=timestamp,
        )
        session.add(sub_asset)
        asset_map[sub] = sub_id

    # IP assets from nmap
    for host in nmap_hosts:
        ip = host.get("ip", "")
        if ip and ip not in asset_map:
            ip_id = _uid(f"asset-{dirname}-{ip}")
            ip_asset = Asset(
                id=ip_id,
                assessment_id=assessment_id,
                asset_type="ip",
                value=ip,
                parent_id=root_asset_id,
                is_live=True,
                first_seen=timestamp,
                last_seen=timestamp,
                metadata={"source": "nmap", "hostname": host.get("hostname", "")},
                is_demo=False,
                created_at=timestamp,
                updated_at=timestamp,
            )
            session.add(ip_asset)
            asset_map[ip] = ip_id

    await session.flush()

    # --- DNS Records (deduplicated) ---
    seen_dns: set[str] = set()
    for rec in dns_records:
        dedup = f"{rec['record_type']}|{rec['value']}"
        if dedup in seen_dns:
            continue
        seen_dns.add(dedup)
        rec_id = _uid(f"dns-{dirname}-{rec['record_type']}-{rec['value'][:100]}")
        dns = DnsRecord(
            id=rec_id,
            asset_id=root_asset_id,
            record_type=rec["record_type"],
            value=rec["value"],
            priority=rec.get("priority"),
            ttl=rec.get("ttl"),
            first_seen=timestamp,
            last_seen=timestamp,
            is_demo=False,
            created_at=timestamp,
            updated_at=timestamp,
        )
        session.add(dns)

    # --- Ports ---
    for host in nmap_hosts:
        ip = host.get("ip", "")
        asset_id = asset_map.get(ip, root_asset_id)
        for port_data in host.get("ports", []):
            port_id = _uid(f"port-{dirname}-{ip}-{port_data['port']}-{port_data['protocol']}")
            port = Port(
                id=port_id,
                asset_id=asset_id,
                scan_id=scan_id,
                port_number=port_data["port"],
                protocol=port_data["protocol"],
                state=port_data.get("state", "open"),
                service_name=port_data.get("service"),
                service_version=port_data.get("product", ""),
                banner=port_data.get("version", ""),
                first_seen=timestamp,
                last_seen=timestamp,
                is_demo=False,
                created_at=timestamp,
                updated_at=timestamp,
            )
            session.add(port)

            # Technology from service detection
            product = port_data.get("product", "")
            if product:
                tech_id = _uid(f"tech-{dirname}-{ip}-{product}")
                tech = Technology(
                    id=tech_id,
                    asset_id=asset_id,
                    name=product,
                    version=port_data.get("version", ""),
                    category=_categorize_service(port_data.get("service", "")),
                    source="nmap",
                    confidence=90,
                    is_demo=False,
                    created_at=timestamp,
                    updated_at=timestamp,
                )
                session.add(tech)

    # --- TLS Certificate ---
    if ssl_data and ssl_data.get("subject_cn"):
        cert_id = _uid(f"tls-{dirname}-{ssl_data['subject_cn']}")
        cert = TlsCertificate(
            id=cert_id,
            asset_id=root_asset_id,
            subject_cn=ssl_data.get("subject_cn"),
            issuer=ssl_data.get("issuer"),
            not_before=ssl_data.get("not_before"),
            not_after=ssl_data.get("not_after"),
            fingerprint_sha256=ssl_data.get("fingerprint_sha256"),
            protocols=ssl_data.get("protocols", []),
            weak_protocols=ssl_data.get("weak_protocols", []),
            is_demo=False,
            created_at=timestamp,
            updated_at=timestamp,
        )
        session.add(cert)

    # --- HTTP Headers ---
    for block in header_blocks:
        url = block.get("url", f"https://{target}")
        hdr_id = _uid(f"hdr-{dirname}-{url[:100]}")
        hdr = HttpHeader(
            id=hdr_id,
            asset_id=root_asset_id,
            url=url,
            headers=block.get("present_headers", {}),
            missing_headers=block.get("missing_headers", []),
            cors_policy=block.get("cors_policy"),
            server_header=block.get("server_header"),
            is_demo=False,
            checked_at=timestamp,
            created_at=timestamp,
            updated_at=timestamp,
        )
        session.add(hdr)

    # --- Findings ---
    seen_finding_keys: set[str] = set()
    for i, finding_data in enumerate(all_findings):
        # Dedup key
        dedup_key = f"{finding_data.get('source', 'unknown')}|{finding_data.get('template_id', '')}|{finding_data.get('url', '')}"
        if dedup_key in seen_finding_keys:
            continue
        seen_finding_keys.add(dedup_key)

        title = finding_data.get("title", "Unknown finding")[:500]
        finding_id = _uid(f"finding-{dirname}-{i}-{title[:50]}")

        # Try to match finding URL to an asset
        finding_url = finding_data.get("url", "")
        asset_id = _match_url_to_asset(finding_url, asset_map, root_asset_id)

        finding = Finding(
            id=finding_id,
            assessment_id=assessment_id,
            scan_id=scan_id,
            asset_id=asset_id,
            vulnerability_id=None,
            source=finding_data.get("source", "unknown"),
            template_id=finding_data.get("template_id"),
            severity=finding_data.get("severity", "INFO").upper(),
            title=title,
            description=finding_data.get("description", ""),
            url=finding_url[:2000] if finding_url else None,
            evidence=finding_data.get("evidence", ""),
            status="new",
            first_seen=timestamp,
            last_seen=timestamp,
            is_demo=False,
            created_at=timestamp,
            updated_at=timestamp,
        )
        session.add(finding)

    await session.flush()

    logger.info(
        f"  Session {dirname}: {len(asset_map)} assets, {len(dns_records)} DNS records, "
        f"{len(seen_finding_keys)} findings "
        f"(C:{severity_counts['CRITICAL']} H:{severity_counts['HIGH']} "
        f"M:{severity_counts['MEDIUM']} L:{severity_counts['LOW']} I:{severity_counts['INFO']})"
    )

    return severity_counts


def _match_url_to_asset(
    url: str, asset_map: dict[str, uuid.UUID], default: uuid.UUID
) -> uuid.UUID:
    """Try to match a finding URL/IP to a known asset."""
    if not url:
        return default

    # Extract hostname from URL
    hostname = url
    hostname = re.sub(r'^https?://', '', hostname)
    hostname = hostname.split('/')[0]
    hostname = hostname.split(':')[0]

    # Direct match
    if hostname in asset_map:
        return asset_map[hostname]

    # Check if any asset value is a substring
    for asset_val, asset_id in asset_map.items():
        if asset_val in hostname or hostname in asset_val:
            return asset_id

    return default


def _categorize_service(service_name: str) -> str:
    """Categorize a service name into a technology category."""
    service_name = service_name.lower()
    categories = {
        "http": "Web Server",
        "https": "Web Server",
        "ssh": "Remote Access",
        "ftp": "File Transfer",
        "smtp": "Email",
        "dns": "DNS",
        "mysql": "Database",
        "postgresql": "Database",
        "redis": "Cache",
        "mongodb": "Database",
        "elasticsearch": "Search",
    }
    return categories.get(service_name, "Other")


async def _seed_resources(session, results_path: Path) -> None:
    """Seed security resources from JSON file if available."""
    import json

    # Try multiple locations for the resources JSON
    candidates = [
        results_path.parent / "seed" / "security_resources.json",
        Path("/app/seed/security_resources.json"),
    ]

    resources_file = None
    for candidate in candidates:
        if candidate.is_file():
            resources_file = candidate
            break

    if not resources_file:
        logger.info("No security_resources.json found, skipping resource seeding")
        return

    try:
        with open(resources_file) as f:
            data = json.load(f)

        count = 0
        for category_data in data:
            category = category_data.get("category", "General")
            for item in category_data.get("items", []):
                res_id = _uid(f"resource-{item['name']}")
                resource = Resource(
                    id=res_id,
                    category=category,
                    subcategory=item.get("subcategory"),
                    name=item["name"],
                    description=item.get("description", ""),
                    url=item.get("url"),
                    icon=item.get("icon"),
                    tags=item.get("tags", []),
                    is_featured=item.get("is_featured", False),
                    display_order=count,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
                session.add(resource)
                count += 1

        logger.info(f"Seeded {count} security resources")
    except Exception as e:
        logger.warning(f"Failed to seed resources: {e}")
