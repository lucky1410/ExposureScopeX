"""Seed deterministic demo data for the ExposureScopeX platform.

Uses uuid5 with a fixed namespace so that every call produces the same UUIDs,
making the seeder fully idempotent (re-running it is a no-op).
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from sqlalchemy import select

from app.config import settings
from app.database import async_session_factory
from app.models.api_key import ApiKey
from app.models.assessment import Assessment
from app.models.asset import Asset
from app.models.dns_record import DnsRecord
from app.models.finding import Finding
from app.models.http_header import HttpHeader
from app.models.investigation import Evidence, Investigation, InvestigationFinding, Note
from app.models.notification import Notification
from app.models.port import Port
from app.models.resource import Resource
from app.models.scan import Scan
from app.models.technology import Technology
from app.models.tls_certificate import TlsCertificate
from app.models.user import Organization, User
from app.models.vulnerability import Vulnerability
from app.security import get_password_hash

logger = logging.getLogger("exposurescopex.seed")

# Fixed namespace for deterministic UUIDs
NS = uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")


def _uid(name: str) -> uuid.UUID:
    """Generate a deterministic UUID5 from a seed name."""
    return uuid.uuid5(NS, name)


# Pre-computed IDs
ORG_ID = _uid("org-demo")
USER_ID = _uid("user-admin")
ASSESSMENT_ID = _uid("assessment-acme")
SCAN1_ID = _uid("scan-1")
SCAN2_ID = _uid("scan-2")
INVESTIGATION_ID = _uid("investigation-redis")

NOW = datetime.now(timezone.utc)
WEEK_AGO = NOW - timedelta(days=7)


async def seed_demo_data() -> None:
    """Seed all demo data. Idempotent -- skips if the org already exists."""
    if not settings.BOOTSTRAP_ADMIN_PASSWORD or len(settings.BOOTSTRAP_ADMIN_PASSWORD) < 12:
        raise RuntimeError("BOOTSTRAP_ADMIN_PASSWORD must contain at least 12 characters")
    async with async_session_factory() as session:
        # Check if already seeded
        existing = await session.execute(
            select(Organization).where(Organization.id == ORG_ID)
        )
        if existing.scalar_one_or_none():
            logger.info("Demo data already exists, skipping seed")
            return

        # --- Organization ---
        org = Organization(
            id=ORG_ID,
            name="ExposureScopeX Demo",
            slug="exposurescopex-demo",
            created_at=WEEK_AGO,
            updated_at=NOW,
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
            last_login=NOW,
            created_at=WEEK_AGO,
            updated_at=NOW,
        )
        session.add(admin)

        # --- Assessment ---
        assessment = Assessment(
            id=ASSESSMENT_ID,
            org_id=ORG_ID,
            created_by=USER_ID,
            name="AcmeCorp External Assessment",
            description="Full external attack surface assessment of acmecorp.com including subdomain enumeration, port scanning, vulnerability detection, and cloud misconfiguration checks.",
            target="acmecorp.com",
            target_type="domain",
            status="completed",
            scan_mode="medium",
            phases={"enum": True, "scan": True, "cloud": True, "report": True},
            flags={"cve": True, "crawl": True, "screenshots": True},
            is_demo=True,
            risk_score=Decimal("78.50"),
            created_at=WEEK_AGO,
            updated_at=NOW,
        )
        session.add(assessment)

        # --- Scans ---
        scan1 = Scan(
            id=SCAN1_ID,
            assessment_id=ASSESSMENT_ID,
            status="completed",
            current_phase="report",
            progress=100,
            started_at=WEEK_AGO,
            completed_at=WEEK_AGO + timedelta(hours=2),
            scan_metadata={"mode": "medium", "phases_completed": 12},
            is_demo=True,
            created_at=WEEK_AGO,
            updated_at=WEEK_AGO + timedelta(hours=2),
        )
        scan2 = Scan(
            id=SCAN2_ID,
            assessment_id=ASSESSMENT_ID,
            status="completed",
            current_phase="report",
            progress=100,
            started_at=NOW - timedelta(hours=3),
            completed_at=NOW - timedelta(hours=1),
            scan_metadata={"mode": "medium", "phases_completed": 12, "rescan": True},
            is_demo=True,
            created_at=NOW - timedelta(hours=3),
            updated_at=NOW - timedelta(hours=1),
        )
        session.add_all([scan1, scan2])

        # --- Assets (15 total) ---
        asset_defs = [
            ("acmecorp.com", "domain", None, True),
            ("www.acmecorp.com", "subdomain", "acmecorp.com", True),
            ("api.acmecorp.com", "subdomain", "acmecorp.com", True),
            ("staging.acmecorp.com", "subdomain", "acmecorp.com", True),
            ("mail.acmecorp.com", "subdomain", "acmecorp.com", True),
            ("vpn.acmecorp.com", "subdomain", "acmecorp.com", True),
            ("dev.acmecorp.com", "subdomain", "acmecorp.com", True),
            ("blog.acmecorp.com", "subdomain", "acmecorp.com", True),
            ("admin.acmecorp.com", "subdomain", "acmecorp.com", True),
            ("shop.acmecorp.com", "subdomain", "acmecorp.com", True),
            ("203.0.113.10", "ip", None, True),
            ("203.0.113.11", "ip", None, True),
            ("203.0.113.12", "ip", None, True),
            ("cdn.acmecorp.com", "subdomain", "acmecorp.com", True),
            ("status.acmecorp.com", "subdomain", "acmecorp.com", True),
        ]

        assets: dict[str, Asset] = {}
        for value, atype, parent_val, is_live in asset_defs:
            aid = _uid(f"asset-{value}")
            parent_id = _uid(f"asset-{parent_val}") if parent_val else None
            asset = Asset(
                id=aid,
                assessment_id=ASSESSMENT_ID,
                asset_type=atype,
                value=value,
                parent_id=parent_id,
                is_live=is_live,
                first_seen=WEEK_AGO,
                last_seen=NOW,
                metadata_={"source": "enumeration"},
                is_demo=True,
                created_at=WEEK_AGO,
                updated_at=NOW,
            )
            session.add(asset)
            assets[value] = asset

        # --- DNS Records ---
        dns_defs = [
            ("acmecorp.com", "A", "203.0.113.10", None, 300),
            ("acmecorp.com", "MX", "mail.acmecorp.com", 10, 3600),
            ("acmecorp.com", "MX", "mail2.acmecorp.com", 20, 3600),
            ("acmecorp.com", "NS", "ns1.acmedns.com", None, 86400),
            ("acmecorp.com", "NS", "ns2.acmedns.com", None, 86400),
            ("acmecorp.com", "TXT", "v=spf1 include:_spf.acmecorp.com ~all", None, 3600),
            ("acmecorp.com", "TXT", "v=DMARC1; p=quarantine; rua=mailto:dmarc@acmecorp.com", None, 3600),
            ("acmecorp.com", "SOA", "ns1.acmedns.com admin.acmecorp.com 2024010101 3600 900 604800 86400", None, 86400),
            ("acmecorp.com", "CAA", '0 issue "letsencrypt.org"', None, 3600),
            ("www.acmecorp.com", "A", "203.0.113.10", None, 300),
            ("api.acmecorp.com", "A", "203.0.113.11", None, 300),
            ("staging.acmecorp.com", "A", "203.0.113.12", None, 300),
            ("mail.acmecorp.com", "A", "203.0.113.10", None, 300),
            ("dev.acmecorp.com", "A", "203.0.113.12", None, 300),
        ]

        for asset_val, rtype, rvalue, priority, ttl in dns_defs:
            dns = DnsRecord(
                id=_uid(f"dns-{asset_val}-{rtype}-{rvalue}"),
                asset_id=_uid(f"asset-{asset_val}"),
                record_type=rtype,
                value=rvalue,
                priority=priority,
                ttl=ttl,
                first_seen=WEEK_AGO,
                last_seen=NOW,
                is_demo=True,
                created_at=WEEK_AGO,
                updated_at=NOW,
            )
            session.add(dns)

        # --- Ports ---
        port_defs = [
            ("www.acmecorp.com", 80, "tcp", "http", "Apache httpd 2.4.41"),
            ("www.acmecorp.com", 443, "tcp", "https", "Apache httpd 2.4.41"),
            ("api.acmecorp.com", 443, "tcp", "https", "nginx 1.18.0"),
            ("api.acmecorp.com", 9200, "tcp", "elasticsearch", "Elasticsearch 7.10.2"),
            ("staging.acmecorp.com", 443, "tcp", "https", "nginx 1.18.0"),
            ("staging.acmecorp.com", 6379, "tcp", "redis", "Redis 6.2.6"),
            ("mail.acmecorp.com", 25, "tcp", "smtp", "Postfix"),
            ("mail.acmecorp.com", 443, "tcp", "https", "nginx 1.18.0"),
            ("dev.acmecorp.com", 80, "tcp", "http", "Node.js"),
            ("dev.acmecorp.com", 3306, "tcp", "mysql", "MySQL 8.0.32"),
            ("dev.acmecorp.com", 22, "tcp", "ssh", "OpenSSH 8.9p1"),
            ("admin.acmecorp.com", 8080, "tcp", "http-proxy", "Apache Tomcat 9.0.65"),
            ("acmecorp.com", 80, "tcp", "http", "Apache httpd 2.4.41"),
            ("acmecorp.com", 443, "tcp", "https", "Apache httpd 2.4.41"),
        ]

        for asset_val, port_num, proto, svc_name, svc_ver in port_defs:
            port = Port(
                id=_uid(f"port-{asset_val}-{port_num}-{proto}"),
                asset_id=_uid(f"asset-{asset_val}"),
                scan_id=SCAN2_ID,
                port_number=port_num,
                protocol=proto,
                state="open",
                service_name=svc_name,
                service_version=svc_ver,
                first_seen=WEEK_AGO,
                last_seen=NOW,
                is_demo=True,
                created_at=WEEK_AGO,
                updated_at=NOW,
            )
            session.add(port)

        # --- Technologies ---
        tech_defs = [
            ("www.acmecorp.com", "Apache", "2.4.41", "Web Server", "nmap", 95),
            ("www.acmecorp.com", "WordPress", "5.9", "CMS", "whatweb", 90),
            ("www.acmecorp.com", "PHP", "8.1", "Programming Language", "whatweb", 85),
            ("api.acmecorp.com", "nginx", "1.18.0", "Web Server", "nmap", 95),
            ("api.acmecorp.com", "Node.js", "18", "Runtime", "whatweb", 80),
            ("api.acmecorp.com", "Elasticsearch", "7.10", "Search Engine", "nmap", 90),
            ("staging.acmecorp.com", "nginx", "1.18.0", "Web Server", "nmap", 95),
            ("staging.acmecorp.com", "Redis", "6.2", "Cache/Database", "nmap", 90),
            ("dev.acmecorp.com", "MySQL", "8.0", "Database", "nmap", 95),
            ("dev.acmecorp.com", "Node.js", "18", "Runtime", "whatweb", 80),
            ("shop.acmecorp.com", "React", None, "Frontend Framework", "whatweb", 75),
            ("admin.acmecorp.com", "Apache Tomcat", "9.0.65", "Application Server", "nmap", 90),
        ]

        for asset_val, name, version, category, source, confidence in tech_defs:
            tech = Technology(
                id=_uid(f"tech-{asset_val}-{name}-{version}"),
                asset_id=_uid(f"asset-{asset_val}"),
                name=name,
                version=version,
                category=category,
                source=source,
                confidence=confidence,
                is_demo=True,
                created_at=WEEK_AGO,
                updated_at=NOW,
            )
            session.add(tech)

        # --- TLS Certificates ---
        tls_defs = [
            {
                "asset": "www.acmecorp.com",
                "cn": "*.acmecorp.com",
                "issuer": "Let's Encrypt Authority X3",
                "not_before": NOW - timedelta(days=60),
                "not_after": NOW + timedelta(days=30),
                "key_size": 2048,
                "algo": "sha256WithRSAEncryption",
                "sans": ["*.acmecorp.com", "acmecorp.com"],
                "protocols": ["TLSv1.2", "TLSv1.3"],
                "weak": [],
            },
            {
                "asset": "staging.acmecorp.com",
                "cn": "staging.acmecorp.com",
                "issuer": "Self-Signed",
                "not_before": NOW - timedelta(days=400),
                "not_after": NOW - timedelta(days=35),  # EXPIRED
                "key_size": 2048,
                "algo": "sha256WithRSAEncryption",
                "sans": ["staging.acmecorp.com"],
                "protocols": ["TLSv1.0", "TLSv1.1", "TLSv1.2"],
                "weak": ["TLSv1.0", "TLSv1.1"],
            },
            {
                "asset": "dev.acmecorp.com",
                "cn": "dev.acmecorp.com",
                "issuer": "Self-Signed",
                "not_before": NOW - timedelta(days=180),
                "not_after": NOW + timedelta(days=185),
                "key_size": 1024,  # WEAK key
                "algo": "sha1WithRSAEncryption",  # WEAK algo
                "sans": ["dev.acmecorp.com"],
                "protocols": ["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2"],
                "weak": ["SSLv3", "TLSv1.0", "TLSv1.1"],
            },
            {
                "asset": "api.acmecorp.com",
                "cn": "api.acmecorp.com",
                "issuer": "DigiCert SHA2 Extended Validation Server CA",
                "not_before": NOW - timedelta(days=90),
                "not_after": NOW + timedelta(days=275),
                "key_size": 4096,
                "algo": "sha256WithRSAEncryption",
                "sans": ["api.acmecorp.com"],
                "protocols": ["TLSv1.2", "TLSv1.3"],
                "weak": [],
            },
        ]

        for t in tls_defs:
            tls = TlsCertificate(
                id=_uid(f"tls-{t['asset']}"),
                asset_id=_uid(f"asset-{t['asset']}"),
                subject_cn=t["cn"],
                issuer=t["issuer"],
                not_before=t["not_before"],
                not_after=t["not_after"],
                fingerprint_sha256=_uid(f"fp-{t['asset']}").hex,
                key_size=t["key_size"],
                signature_algo=t["algo"],
                sans=t["sans"],
                protocols=t["protocols"],
                weak_protocols=t["weak"],
                is_demo=True,
                created_at=WEEK_AGO,
                updated_at=NOW,
            )
            session.add(tls)

        # --- HTTP Headers ---
        header_defs = [
            {
                "asset": "www.acmecorp.com",
                "url": "https://www.acmecorp.com",
                "headers": {
                    "Server": "Apache/2.4.41",
                    "X-Powered-By": "PHP/8.1",
                    "Content-Type": "text/html; charset=UTF-8",
                },
                "missing": ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options", "Strict-Transport-Security"],
                "cors": "*",
                "server": "Apache/2.4.41",
            },
            {
                "asset": "api.acmecorp.com",
                "url": "https://api.acmecorp.com",
                "headers": {
                    "Server": "nginx/1.18.0",
                    "X-Frame-Options": "DENY",
                    "X-Content-Type-Options": "nosniff",
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                },
                "missing": ["Content-Security-Policy"],
                "cors": "https://www.acmecorp.com",
                "server": "nginx/1.18.0",
            },
        ]

        for h in header_defs:
            hdr = HttpHeader(
                id=_uid(f"hdr-{h['asset']}"),
                asset_id=_uid(f"asset-{h['asset']}"),
                url=h["url"],
                headers=h["headers"],
                missing_headers=h["missing"],
                cors_policy=h["cors"],
                server_header=h["server"],
                is_demo=True,
                checked_at=NOW,
                created_at=WEEK_AGO,
                updated_at=NOW,
            )
            session.add(hdr)

        # --- Vulnerabilities (8 real CVEs) ---
        vuln_defs = [
            {
                "cve": "CVE-2021-44228",
                "title": "Apache Log4Shell Remote Code Execution",
                "desc": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.",
                "severity": "CRITICAL",
                "cvss": Decimal("10.00"),
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "epss": Decimal("0.97565"),
                "epss_pct": Decimal("0.99960"),
                "is_kev": True,
                "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "https://logging.apache.org/log4j/2.x/security.html"],
                "cwes": ["CWE-917", "CWE-502"],
            },
            {
                "cve": "CVE-2023-44487",
                "title": "HTTP/2 Rapid Reset Attack (DDoS)",
                "desc": "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.",
                "severity": "HIGH",
                "cvss": Decimal("7.50"),
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "epss": Decimal("0.72180"),
                "epss_pct": Decimal("0.98120"),
                "is_kev": True,
                "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
                "cwes": ["CWE-400"],
            },
            {
                "cve": "CVE-2024-3094",
                "title": "XZ Utils Backdoor (liblzma)",
                "desc": "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code.",
                "severity": "CRITICAL",
                "cvss": Decimal("10.00"),
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "epss": Decimal("0.17230"),
                "epss_pct": Decimal("0.96350"),
                "is_kev": False,
                "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"],
                "cwes": ["CWE-506"],
            },
            {
                "cve": "CVE-2023-22515",
                "title": "Atlassian Confluence Broken Access Control",
                "desc": "Atlassian has been made aware of an issue reported by a handful of customers where external attackers may have exploited a previously unknown vulnerability in publicly accessible Confluence Data Center and Server instances to create unauthorized Confluence administrator accounts and access Confluence instances.",
                "severity": "CRITICAL",
                "cvss": Decimal("9.80"),
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "epss": Decimal("0.96630"),
                "epss_pct": Decimal("0.99810"),
                "is_kev": True,
                "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2023-22515"],
                "cwes": ["CWE-284"],
            },
            {
                "cve": "CVE-2021-41773",
                "title": "Apache HTTP Server Path Traversal",
                "desc": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives.",
                "severity": "HIGH",
                "cvss": Decimal("7.50"),
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "epss": Decimal("0.97490"),
                "epss_pct": Decimal("0.99950"),
                "is_kev": True,
                "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
                "cwes": ["CWE-22"],
            },
            {
                "cve": "CVE-2023-23397",
                "title": "Microsoft Outlook Elevation of Privilege",
                "desc": "Microsoft Outlook Elevation of Privilege Vulnerability allows an attacker to send a specially crafted email that triggers automatically when retrieved and processed by the Outlook client. This could lead to exploitation BEFORE the email is viewed in the Preview Pane.",
                "severity": "CRITICAL",
                "cvss": Decimal("9.80"),
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "epss": Decimal("0.92140"),
                "epss_pct": Decimal("0.99380"),
                "is_kev": True,
                "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2023-23397"],
                "cwes": ["CWE-294"],
            },
            {
                "cve": "CVE-2021-26855",
                "title": "Microsoft Exchange Server ProxyLogon SSRF",
                "desc": "Microsoft Exchange Server Remote Code Execution Vulnerability. This is a server-side request forgery (SSRF) vulnerability in Exchange which allowed the attacker to send arbitrary HTTP requests and authenticate as the Exchange server.",
                "severity": "CRITICAL",
                "cvss": Decimal("9.80"),
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "epss": Decimal("0.97530"),
                "epss_pct": Decimal("0.99960"),
                "is_kev": True,
                "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-26855"],
                "cwes": ["CWE-918"],
            },
            {
                "cve": "CVE-2024-21762",
                "title": "Fortinet FortiOS Out-of-Bound Write",
                "desc": "A out-of-bounds write in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, 6.0.0 through 6.0.17 allows attacker to execute unauthorized code or commands via specifically crafted requests.",
                "severity": "CRITICAL",
                "cvss": Decimal("9.80"),
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "epss": Decimal("0.16450"),
                "epss_pct": Decimal("0.96110"),
                "is_kev": True,
                "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2024-21762"],
                "cwes": ["CWE-787"],
            },
        ]

        vuln_ids = {}
        for v in vuln_defs:
            vid = _uid(f"vuln-{v['cve']}")
            vuln = Vulnerability(
                id=vid,
                cve_id=v["cve"],
                title=v["title"],
                description=v["desc"],
                severity=v["severity"],
                cvss_score=v["cvss"],
                cvss_vector=v["cvss_vector"],
                epss_score=v["epss"],
                epss_percentile=v["epss_pct"],
                is_kev=v["is_kev"],
                references=v["refs"],
                cwe_ids=v["cwes"],
                is_demo=True,
                created_at=WEEK_AGO,
                updated_at=NOW,
            )
            session.add(vuln)
            vuln_ids[v["cve"]] = vid

        # --- Findings (50 total: 5 CRITICAL, 10 HIGH, 15 MEDIUM, 12 LOW, 8 INFO) ---
        findings_defs = []

        # 5 CRITICAL
        findings_defs.extend([
            ("CRITICAL", "Log4Shell RCE in Elasticsearch", "api.acmecorp.com", "CVE-2021-44228", "nuclei", "CVE-2021-44228", "https://api.acmecorp.com:9200", "JNDI lookup injection confirmed via ${jndi:ldap://...} payload in User-Agent header"),
            ("CRITICAL", "XZ Utils Backdoor Detected", "dev.acmecorp.com", "CVE-2024-3094", "nuclei", "CVE-2024-3094", "https://dev.acmecorp.com", "xz-utils version 5.6.1 detected via package enumeration"),
            ("CRITICAL", "Confluence Admin Bypass", "admin.acmecorp.com", "CVE-2023-22515", "nuclei", "CVE-2023-22515", "https://admin.acmecorp.com:8080/setup/setupadministrator.action", "Unauthenticated admin account creation endpoint accessible"),
            ("CRITICAL", "Exchange ProxyLogon SSRF", "mail.acmecorp.com", "CVE-2021-26855", "nuclei", "CVE-2021-26855", "https://mail.acmecorp.com/ecp/", "Exchange Server SSRF via /ecp/ endpoint"),
            ("CRITICAL", "FortiOS Out-of-Bound Write", "vpn.acmecorp.com", "CVE-2024-21762", "nuclei", "CVE-2024-21762", "https://vpn.acmecorp.com:443", "FortiOS SSL VPN vulnerable to pre-auth RCE"),
        ])

        # 10 HIGH
        findings_defs.extend([
            ("HIGH", "HTTP/2 Rapid Reset Vulnerability", "www.acmecorp.com", "CVE-2023-44487", "nuclei", "CVE-2023-44487", "https://www.acmecorp.com", "Server supports HTTP/2 and is vulnerable to rapid reset attack"),
            ("HIGH", "Apache Path Traversal", "www.acmecorp.com", "CVE-2021-41773", "nuclei", "CVE-2021-41773", "https://www.acmecorp.com/icons/.%2e/%2e%2e/etc/passwd", "Path traversal confirmed - /etc/passwd readable"),
            ("HIGH", "Exposed Redis (No Auth)", "staging.acmecorp.com", None, "nuclei", "exposed-redis", "redis://staging.acmecorp.com:6379", "Redis instance accessible without authentication. INFO command returns server version 6.2.6"),
            ("HIGH", "Exposed Elasticsearch Cluster", "api.acmecorp.com", None, "nuclei", "exposed-elasticsearch", "https://api.acmecorp.com:9200/_cluster/health", "Elasticsearch cluster health endpoint publicly accessible returning green status"),
            ("HIGH", "Expired TLS Certificate", "staging.acmecorp.com", None, "ssl_check", "ssl-expired", "https://staging.acmecorp.com", "Certificate expired 35 days ago (self-signed)"),
            ("HIGH", "MySQL Exposed to Internet", "dev.acmecorp.com", None, "nuclei", "exposed-mysql", "mysql://dev.acmecorp.com:3306", "MySQL port 3306 accessible from internet"),
            ("HIGH", "Weak TLS Configuration (SSLv3)", "dev.acmecorp.com", None, "ssl_check", "ssl-weak-protocol", "https://dev.acmecorp.com", "SSLv3 enabled - vulnerable to POODLE attack"),
            ("HIGH", "WordPress XML-RPC Enabled", "www.acmecorp.com", None, "nuclei", "wordpress-xmlrpc", "https://www.acmecorp.com/xmlrpc.php", "XML-RPC endpoint enabled, vulnerable to brute force amplification"),
            ("HIGH", "Open SSH with Password Auth", "dev.acmecorp.com", None, "nuclei", "ssh-password-auth", "ssh://dev.acmecorp.com:22", "SSH server accepts password authentication (keyboard-interactive enabled)"),
            ("HIGH", "Server Header Disclosure", "www.acmecorp.com", None, "ssl_check", "server-header-disclosure", "https://www.acmecorp.com", "Server header reveals Apache/2.4.41 with PHP/8.1"),
        ])

        # 15 MEDIUM
        findings_defs.extend([
            ("MEDIUM", "Missing Content-Security-Policy", "www.acmecorp.com", None, "ssl_check", "missing-csp", "https://www.acmecorp.com", "No Content-Security-Policy header found"),
            ("MEDIUM", "Missing X-Frame-Options", "www.acmecorp.com", None, "ssl_check", "missing-xfo", "https://www.acmecorp.com", "No X-Frame-Options header - clickjacking possible"),
            ("MEDIUM", "Missing X-Content-Type-Options", "www.acmecorp.com", None, "ssl_check", "missing-xcto", "https://www.acmecorp.com", "No X-Content-Type-Options header"),
            ("MEDIUM", "Missing HSTS Header", "www.acmecorp.com", None, "ssl_check", "missing-hsts", "https://www.acmecorp.com", "No Strict-Transport-Security header"),
            ("MEDIUM", "Wildcard CORS Policy", "www.acmecorp.com", None, "ssl_check", "cors-wildcard", "https://www.acmecorp.com", "Access-Control-Allow-Origin: * allows any origin"),
            ("MEDIUM", "Directory Listing Enabled", "blog.acmecorp.com", None, "nuclei", "directory-listing", "https://blog.acmecorp.com/wp-content/uploads/", "Apache directory listing enabled for uploads directory"),
            ("MEDIUM", "WordPress Version Disclosure", "www.acmecorp.com", None, "whatweb", "wordpress-version", "https://www.acmecorp.com", "WordPress 5.9 detected via generator meta tag"),
            ("MEDIUM", "PHP Version Disclosure", "www.acmecorp.com", None, "whatweb", "php-version", "https://www.acmecorp.com", "PHP/8.1 disclosed in X-Powered-By header"),
            ("MEDIUM", "Missing CSP on API", "api.acmecorp.com", None, "ssl_check", "missing-csp-api", "https://api.acmecorp.com", "No Content-Security-Policy header on API endpoint"),
            ("MEDIUM", "Weak SSL Key Size (1024)", "dev.acmecorp.com", None, "ssl_check", "weak-key-size", "https://dev.acmecorp.com", "RSA key size 1024 bits is below recommended minimum of 2048"),
            ("MEDIUM", "SHA-1 Signature Algorithm", "dev.acmecorp.com", None, "ssl_check", "sha1-signature", "https://dev.acmecorp.com", "Certificate uses deprecated sha1WithRSAEncryption"),
            ("MEDIUM", "Tomcat Default Error Page", "admin.acmecorp.com", None, "nuclei", "tomcat-default-error", "https://admin.acmecorp.com:8080/nonexistent", "Apache Tomcat default error page reveals version 9.0.65"),
            ("MEDIUM", "Git Repository Exposed", "dev.acmecorp.com", None, "nuclei", "git-exposed", "https://dev.acmecorp.com/.git/HEAD", ".git directory accessible - source code may be downloadable"),
            ("MEDIUM", "Backup File Found", "www.acmecorp.com", None, "nuclei", "backup-file", "https://www.acmecorp.com/wp-config.php.bak", "WordPress config backup file accessible"),
            ("MEDIUM", "Sensitive S3 Bucket", "cdn.acmecorp.com", None, "cloud", "s3-public-read", "https://acmecorp-assets.s3.amazonaws.com", "S3 bucket has public read access enabled"),
        ])

        # 12 LOW
        findings_defs.extend([
            ("LOW", "HTTP to HTTPS Redirect", "acmecorp.com", None, "ssl_check", "http-redirect", "http://acmecorp.com", "HTTP redirects to HTTPS (good) but redirect chain is 2 hops"),
            ("LOW", "Cookie Without Secure Flag", "www.acmecorp.com", None, "nuclei", "cookie-no-secure", "https://www.acmecorp.com", "Session cookie missing Secure flag"),
            ("LOW", "Cookie Without HttpOnly Flag", "www.acmecorp.com", None, "nuclei", "cookie-no-httponly", "https://www.acmecorp.com", "Session cookie missing HttpOnly flag"),
            ("LOW", "SPF Record Soft Fail", "acmecorp.com", None, "dns_recon", "spf-softfail", "acmecorp.com", "SPF record uses ~all (soft fail) instead of -all (hard fail)"),
            ("LOW", "Outdated jQuery Version", "www.acmecorp.com", None, "whatweb", "outdated-jquery", "https://www.acmecorp.com", "jQuery 3.3.1 detected - known vulnerabilities exist"),
            ("LOW", "robots.txt Reveals Paths", "www.acmecorp.com", None, "crawl", "robots-paths", "https://www.acmecorp.com/robots.txt", "robots.txt discloses /admin/, /staging-api/, /internal/ paths"),
            ("LOW", "Deprecated TLS 1.0 Enabled", "staging.acmecorp.com", None, "ssl_check", "tls10-enabled", "https://staging.acmecorp.com", "TLS 1.0 still enabled (deprecated as of 2020)"),
            ("LOW", "Deprecated TLS 1.1 Enabled", "staging.acmecorp.com", None, "ssl_check", "tls11-enabled", "https://staging.acmecorp.com", "TLS 1.1 still enabled (deprecated as of 2020)"),
            ("LOW", "Email Address Disclosure", "www.acmecorp.com", None, "crawl", "email-disclosure", "https://www.acmecorp.com/contact", "admin@acmecorp.com found in page source"),
            ("LOW", "Internal IP Address Disclosure", "api.acmecorp.com", None, "nuclei", "internal-ip", "https://api.acmecorp.com/health", "Response body contains internal IP 10.0.1.42"),
            ("LOW", "DNS Zone Transfer Possible", "acmecorp.com", None, "dns_recon", "zone-transfer", "acmecorp.com", "AXFR zone transfer partially successful on ns1.acmedns.com"),
            ("LOW", "DMARC Quarantine Policy", "acmecorp.com", None, "dns_recon", "dmarc-quarantine", "acmecorp.com", "DMARC policy is quarantine instead of reject"),
        ])

        # 8 INFO
        findings_defs.extend([
            ("INFO", "Subdomain Discovered: cdn.acmecorp.com", "cdn.acmecorp.com", None, "enumeration", "subdomain-found", "cdn.acmecorp.com", "Discovered via crt.sh certificate transparency"),
            ("INFO", "Subdomain Discovered: status.acmecorp.com", "status.acmecorp.com", None, "enumeration", "subdomain-found-status", "status.acmecorp.com", "Discovered via subfinder"),
            ("INFO", "Technology: React Frontend", "shop.acmecorp.com", None, "whatweb", "tech-react", "https://shop.acmecorp.com", "React.js frontend framework detected"),
            ("INFO", "Wayback Machine URLs Found", "www.acmecorp.com", None, "osint", "wayback-urls", "https://web.archive.org/web/*/www.acmecorp.com/*", "247 archived URLs found in Wayback Machine"),
            ("INFO", "Shodan Host Data Available", "203.0.113.10", None, "osint", "shodan-host", "https://www.shodan.io/host/203.0.113.10", "Host indexed by Shodan with 3 open ports"),
            ("INFO", "CAA Record Present", "acmecorp.com", None, "dns_recon", "caa-present", "acmecorp.com", "CAA record restricts certificate issuance to letsencrypt.org"),
            ("INFO", "DMARC Record Present", "acmecorp.com", None, "dns_recon", "dmarc-present", "acmecorp.com", "DMARC record configured with reporting"),
            ("INFO", "ASN Information: AS12345", "203.0.113.10", None, "dns_recon", "asn-info", "203.0.113.10", "ASN: AS12345 (AcmeCorp Inc.) - 203.0.113.0/24"),
        ])

        # Create all findings with deterministic IDs
        finding_objects = []
        for idx, (severity, title, asset_val, cve, source, template_id, url, evidence) in enumerate(findings_defs):
            fid = _uid(f"finding-{idx}-{template_id}")
            vuln_id = vuln_ids.get(cve) if cve else None

            # Distribute creation times across the week
            offset_hours = (idx * 4) % (7 * 24)
            created_time = WEEK_AGO + timedelta(hours=offset_hours)

            # Risk scores based on severity
            risk_map = {"CRITICAL": Decimal("95.00"), "HIGH": Decimal("75.00"), "MEDIUM": Decimal("50.00"), "LOW": Decimal("25.00"), "INFO": Decimal("5.00")}

            finding = Finding(
                id=fid,
                assessment_id=ASSESSMENT_ID,
                scan_id=SCAN1_ID if idx < 25 else SCAN2_ID,
                asset_id=_uid(f"asset-{asset_val}"),
                vulnerability_id=vuln_id,
                source=source,
                template_id=template_id,
                severity=severity,
                title=title,
                description=evidence,
                url=url,
                evidence=evidence,
                status="new" if idx < 40 else "confirmed",
                risk_score=risk_map.get(severity, Decimal("50.00")),
                first_seen=created_time,
                last_seen=NOW,
                is_demo=True,
                created_at=created_time,
                updated_at=NOW,
            )
            session.add(finding)
            finding_objects.append(finding)

        # --- Investigation ---
        investigation = Investigation(
            id=INVESTIGATION_ID,
            org_id=ORG_ID,
            created_by=USER_ID,
            title="Exposed Redis on Staging",
            description="Redis instance on staging.acmecorp.com:6379 is accessible without authentication from the public internet. Investigating potential data exposure and lateral movement risk.",
            status="in_progress",
            priority="high",
            assigned_to=USER_ID,
            created_at=NOW - timedelta(days=2),
            updated_at=NOW,
        )
        session.add(investigation)

        # Link the Redis finding to the investigation
        redis_finding_id = _uid("finding-7-exposed-redis")
        inv_finding = InvestigationFinding(
            investigation_id=INVESTIGATION_ID,
            finding_id=redis_finding_id,
        )
        session.add(inv_finding)

        # Evidence
        ev1 = Evidence(
            id=_uid("evidence-1"),
            investigation_id=INVESTIGATION_ID,
            type="log",
            title="Redis INFO output",
            content="redis_version:6.2.6\nconnected_clients:3\nused_memory:1024000\nkeyspace: db0:keys=47,expires=12",
            created_by=USER_ID,
            created_at=NOW - timedelta(days=1),
            updated_at=NOW - timedelta(days=1),
        )
        ev2 = Evidence(
            id=_uid("evidence-2"),
            investigation_id=INVESTIGATION_ID,
            type="note",
            title="Network analysis",
            content="Redis port 6379 is bound to 0.0.0.0 instead of 127.0.0.1. No firewall rules restricting access. Cloud security group allows all inbound traffic on this port.",
            created_by=USER_ID,
            created_at=NOW - timedelta(hours=18),
            updated_at=NOW - timedelta(hours=18),
        )
        session.add_all([ev1, ev2])

        # Notes
        note1 = Note(
            id=_uid("note-1"),
            investigation_id=INVESTIGATION_ID,
            content="Confirmed Redis is accessible without authentication. Contains session tokens and cached API responses. Immediate remediation required.",
            created_by=USER_ID,
            created_at=NOW - timedelta(days=1),
            updated_at=NOW - timedelta(days=1),
        )
        note2 = Note(
            id=_uid("note-2"),
            investigation_id=INVESTIGATION_ID,
            content="Notified DevOps team. Temporary fix: added iptables rule to block external access. Permanent fix: bind to localhost + add requirepass directive.",
            created_by=USER_ID,
            created_at=NOW - timedelta(hours=6),
            updated_at=NOW - timedelta(hours=6),
        )
        session.add_all([note1, note2])

        # --- Notifications ---
        notif_defs = [
            ("scan_complete", "Scan Completed", "AcmeCorp External Assessment scan completed successfully. 50 findings discovered.", "info", "assessment", ASSESSMENT_ID),
            ("finding", "Critical: Log4Shell RCE Detected", "Log4Shell (CVE-2021-44228) remote code execution vulnerability found on api.acmecorp.com:9200", "critical", "finding", _uid("finding-0-CVE-2021-44228")),
            ("finding", "Critical: XZ Backdoor Detected", "XZ Utils backdoor (CVE-2024-3094) detected on dev.acmecorp.com", "critical", "finding", _uid("finding-1-CVE-2024-3094")),
            ("alert", "Exposed Redis Instance", "Unauthenticated Redis instance found on staging.acmecorp.com:6379 - investigation created", "high", "investigation", INVESTIGATION_ID),
            ("system", "Welcome to ExposureScopeX", "Your attack surface management platform is ready. Start by reviewing the demo assessment.", "info", None, None),
        ]

        for idx, (ntype, title, message, severity, entity_type, entity_id) in enumerate(notif_defs):
            notif = Notification(
                id=_uid(f"notif-{idx}"),
                user_id=USER_ID,
                type=ntype,
                title=title,
                message=message,
                severity=severity,
                is_read=idx >= 3,
                entity_type=entity_type,
                entity_id=entity_id,
                created_at=NOW - timedelta(hours=idx * 2),
                updated_at=NOW - timedelta(hours=idx * 2),
            )
            session.add(notif)

        # --- Resources (80+ across categories) ---
        _seed_resources(session)

        await session.commit()
        logger.info("Demo data seeded: 1 org, 1 user, 1 assessment, 2 scans, 15 assets, 50 findings, 8 vulns, 80+ resources")


def _seed_resources(session) -> None:
    """Seed 80+ security resources across categories."""
    resources = [
        # --- Reconnaissance ---
        ("Reconnaissance", "Subdomain Enumeration", "Subfinder", "Fast passive subdomain enumeration tool by ProjectDiscovery", "https://github.com/projectdiscovery/subfinder", "Globe", ["subdomain", "passive", "enumeration"], True, 1),
        ("Reconnaissance", "Subdomain Enumeration", "Amass", "In-depth attack surface mapping and asset discovery by OWASP", "https://github.com/owasp-amass/amass", "Globe", ["subdomain", "owasp", "enumeration"], True, 2),
        ("Reconnaissance", "Subdomain Enumeration", "Assetfinder", "Find domains and subdomains potentially related to a given domain", "https://github.com/tomnomnom/assetfinder", "Globe", ["subdomain", "passive"], False, 3),
        ("Reconnaissance", "DNS Analysis", "dnsx", "Fast and multi-purpose DNS toolkit", "https://github.com/projectdiscovery/dnsx", "Globe", ["dns", "resolution"], False, 4),
        ("Reconnaissance", "DNS Analysis", "MassDNS", "High-performance DNS stub resolver for bulk lookups", "https://github.com/blechschmidt/massdns", "Globe", ["dns", "bulk"], False, 5),
        ("Reconnaissance", "Certificate Transparency", "crt.sh", "Certificate transparency log search engine", "https://crt.sh", "Shield", ["certificates", "passive", "transparency"], True, 6),
        ("Reconnaissance", "WHOIS", "WHOIS Lookup", "Domain registration and ownership information", "https://www.whois.com", "FileText", ["whois", "registration"], False, 7),
        ("Reconnaissance", "Technology Detection", "Wappalyzer", "Identify technologies on websites", "https://www.wappalyzer.com", "Layers", ["technology", "fingerprint"], True, 8),
        ("Reconnaissance", "Technology Detection", "WhatWeb", "Next generation web scanner identifying websites", "https://github.com/urbanadventurer/WhatWeb", "Layers", ["technology", "fingerprint"], False, 9),
        ("Reconnaissance", "Web Archives", "Wayback Machine", "Internet Archive's web page capture history", "https://web.archive.org", "Clock", ["archive", "history"], False, 10),

        # --- Scanning ---
        ("Scanning", "Port Scanning", "Nmap", "Network exploration and security auditing utility", "https://nmap.org", "Radar", ["port", "network", "audit"], True, 1),
        ("Scanning", "Port Scanning", "Masscan", "Internet-scale port scanner at 10M packets/sec", "https://github.com/robertdavidgraham/masscan", "Radar", ["port", "fast", "scale"], True, 2),
        ("Scanning", "Port Scanning", "RustScan", "Modern port scanner - fast, extensible, adaptive", "https://github.com/RustScan/RustScan", "Radar", ["port", "fast", "rust"], False, 3),
        ("Scanning", "Vulnerability Scanning", "Nuclei", "Fast and customizable vulnerability scanner based on YAML templates", "https://github.com/projectdiscovery/nuclei", "Target", ["vulnerability", "templates", "fast"], True, 4),
        ("Scanning", "Vulnerability Scanning", "Nikto", "Web server scanner which performs comprehensive tests", "https://github.com/sullo/nikto", "Target", ["web", "vulnerability"], False, 5),
        ("Scanning", "SSL/TLS", "testssl.sh", "Testing TLS/SSL encryption on any port", "https://github.com/drwetter/testssl.sh", "Lock", ["ssl", "tls", "encryption"], True, 6),
        ("Scanning", "SSL/TLS", "SSLyze", "Fast and powerful SSL/TLS scanning library and CLI tool", "https://github.com/nabla-c0d3/sslyze", "Lock", ["ssl", "tls", "python"], False, 7),
        ("Scanning", "Web Application", "Wapiti", "Web application vulnerability scanner", "https://wapiti-scanner.github.io", "Bug", ["web", "vulnerability", "scanner"], False, 8),
        ("Scanning", "Web Application", "OWASP ZAP", "Open-source web application security scanner", "https://www.zaproxy.org", "Bug", ["web", "owasp", "proxy"], True, 9),
        ("Scanning", "Web Application", "Burp Suite Community", "Web vulnerability scanner and proxy", "https://portswigger.net/burp/communitydownload", "Bug", ["web", "proxy", "manual"], False, 10),

        # --- OSINT ---
        ("OSINT", "Search Engines", "Shodan", "Search engine for Internet-connected devices", "https://www.shodan.io", "Search", ["iot", "devices", "search"], True, 1),
        ("OSINT", "Search Engines", "Censys", "Search engine for understanding internet assets", "https://censys.io", "Search", ["certificates", "hosts", "search"], True, 2),
        ("OSINT", "Search Engines", "GreyNoise", "Understanding internet noise and targeted attacks", "https://www.greynoise.io", "Search", ["noise", "threat-intel"], False, 3),
        ("OSINT", "Threat Intelligence", "VirusTotal", "File, URL, IP, and domain analysis", "https://www.virustotal.com", "Shield", ["malware", "analysis", "reputation"], True, 4),
        ("OSINT", "Threat Intelligence", "AlienVault OTX", "Open Threat Exchange - crowd-sourced threat data", "https://otx.alienvault.com", "Shield", ["threat-intel", "ioc", "community"], False, 5),
        ("OSINT", "Threat Intelligence", "MITRE ATT&CK", "Knowledge base of adversary tactics and techniques", "https://attack.mitre.org", "Shield", ["framework", "tactics", "techniques"], True, 6),
        ("OSINT", "Data Breaches", "Have I Been Pwned", "Check if email/phone is in a data breach", "https://haveibeenpwned.com", "AlertTriangle", ["breach", "email", "credential"], True, 7),
        ("OSINT", "Data Breaches", "DeHashed", "Credential search engine and breach database", "https://dehashed.com", "AlertTriangle", ["breach", "credentials"], False, 8),
        ("OSINT", "Code Search", "GitHub Code Search", "Search code across GitHub repositories", "https://github.com/search", "Code", ["code", "secrets", "leaks"], False, 9),
        ("OSINT", "Code Search", "TruffleHog", "Find and verify credentials in git repositories", "https://github.com/trufflesecurity/trufflehog", "Code", ["secrets", "git", "credentials"], True, 10),

        # --- Web Testing ---
        ("Web Testing", "Directory Brute-Force", "Feroxbuster", "Fast, recursive content discovery tool written in Rust", "https://github.com/epi052/feroxbuster", "FolderSearch", ["directory", "brute-force", "rust"], True, 1),
        ("Web Testing", "Directory Brute-Force", "Dirsearch", "Web path scanner", "https://github.com/maurosoria/dirsearch", "FolderSearch", ["directory", "brute-force", "python"], False, 2),
        ("Web Testing", "Directory Brute-Force", "Gobuster", "Directory/file & DNS busting tool", "https://github.com/OJ/gobuster", "FolderSearch", ["directory", "dns", "go"], False, 3),
        ("Web Testing", "Crawling", "Katana", "Next-generation crawling and spidering framework", "https://github.com/projectdiscovery/katana", "Spider", ["crawl", "spider", "fast"], True, 4),
        ("Web Testing", "Crawling", "GoSpider", "Fast web spider for discovery", "https://github.com/jaeles-project/gospider", "Spider", ["crawl", "spider", "go"], False, 5),
        ("Web Testing", "SQL Injection", "SQLMap", "Automatic SQL injection and database takeover tool", "https://sqlmap.org", "Database", ["sqli", "database", "injection"], True, 6),
        ("Web Testing", "XSS", "Dalfox", "Parameter analysis and XSS scanning tool", "https://github.com/hahwul/dalfox", "Zap", ["xss", "parameter", "fuzzing"], True, 7),
        ("Web Testing", "Parameter Discovery", "Arjun", "HTTP parameter discovery suite", "https://github.com/s0md3v/Arjun", "Search", ["parameters", "hidden", "discovery"], False, 8),
        ("Web Testing", "API Testing", "Postman", "API development and testing platform", "https://www.postman.com", "Send", ["api", "testing", "collaboration"], False, 9),
        ("Web Testing", "Fuzzing", "ffuf", "Fast web fuzzer written in Go", "https://github.com/ffuf/ffuf", "Zap", ["fuzzing", "web", "go"], True, 10),

        # --- Cloud Security ---
        ("Cloud Security", "AWS", "ScoutSuite", "Multi-cloud security auditing tool", "https://github.com/nccgroup/ScoutSuite", "Cloud", ["aws", "azure", "gcp", "audit"], True, 1),
        ("Cloud Security", "AWS", "Prowler", "AWS & Azure security assessment, auditing, and hardening", "https://github.com/prowler-cloud/prowler", "Cloud", ["aws", "azure", "compliance"], True, 2),
        ("Cloud Security", "AWS", "CloudSploit", "Cloud security posture management scans", "https://github.com/aquasecurity/cloudsploit", "Cloud", ["aws", "azure", "gcp", "scans"], False, 3),
        ("Cloud Security", "Kubernetes", "kube-hunter", "Hunt for security weaknesses in Kubernetes clusters", "https://github.com/aquasecurity/kube-hunter", "Container", ["kubernetes", "security", "audit"], True, 4),
        ("Cloud Security", "Kubernetes", "Trivy", "Comprehensive security scanner for containers and K8s", "https://github.com/aquasecurity/trivy", "Container", ["container", "vulnerability", "sbom"], True, 5),
        ("Cloud Security", "Infrastructure", "Terraform Scanner", "tfsec - Security scanner for Terraform code", "https://github.com/aquasecurity/tfsec", "FileCode", ["terraform", "iac", "security"], False, 6),
        ("Cloud Security", "S3 Buckets", "S3Scanner", "Scan for open S3 buckets and dump the contents", "https://github.com/sa7mon/S3Scanner", "Database", ["s3", "bucket", "aws"], False, 7),
        ("Cloud Security", "Infrastructure", "Checkov", "Static analysis for infrastructure as code", "https://github.com/bridgecrewio/checkov", "FileCode", ["iac", "terraform", "cloudformation"], False, 8),
        ("Cloud Security", "Container", "Grype", "Vulnerability scanner for container images and filesystems", "https://github.com/anchore/grype", "Container", ["container", "vulnerability", "sbom"], False, 9),
        ("Cloud Security", "Multi-Cloud", "CloudMapper", "Analyze AWS environments for security issues", "https://github.com/duo-labs/cloudmapper", "Map", ["aws", "visualization", "network"], False, 10),

        # --- Exploitation ---
        ("Exploitation", "Frameworks", "Metasploit Framework", "World's most used penetration testing framework", "https://www.metasploit.com", "Crosshair", ["exploitation", "framework", "modules"], True, 1),
        ("Exploitation", "Password Attacks", "Hydra", "Fast and flexible network login cracker", "https://github.com/vanhauser-thc/thc-hydra", "Key", ["brute-force", "password", "network"], True, 2),
        ("Exploitation", "Password Attacks", "John the Ripper", "Password security auditing and recovery tool", "https://www.openwall.com/john/", "Key", ["password", "cracking", "audit"], False, 3),
        ("Exploitation", "Password Attacks", "Hashcat", "Advanced password recovery utility", "https://hashcat.net/hashcat/", "Key", ["password", "gpu", "cracking"], False, 4),
        ("Exploitation", "Wordlists", "SecLists", "Collection of security assessment lists", "https://github.com/danielmiessler/SecLists", "List", ["wordlists", "payloads", "fuzzing"], True, 5),
        ("Exploitation", "Reverse Shells", "RevShells", "Reverse shell command generator", "https://www.revshells.com", "Terminal", ["reverse-shell", "generator"], False, 6),
        ("Exploitation", "Post-Exploitation", "LinPEAS", "Linux Privilege Escalation Awesome Script", "https://github.com/carlospolop/PEASS-ng", "Terminal", ["privilege-escalation", "linux", "enumeration"], False, 7),
        ("Exploitation", "Proof of Concept", "ExploitDB", "Archive of public exploits and vulnerable software", "https://www.exploit-db.com", "Database", ["exploits", "cve", "poc"], True, 8),

        # --- Reporting ---
        ("Reporting", "Templates", "PTES", "Penetration Testing Execution Standard", "http://www.pentest-standard.org", "FileText", ["standard", "methodology", "template"], True, 1),
        ("Reporting", "Templates", "OWASP Testing Guide", "Comprehensive web app security testing guide", "https://owasp.org/www-project-web-security-testing-guide/", "FileText", ["owasp", "methodology", "web"], True, 2),
        ("Reporting", "Vulnerability Databases", "NVD", "National Vulnerability Database by NIST", "https://nvd.nist.gov", "Database", ["cve", "vulnerability", "nist"], True, 3),
        ("Reporting", "Vulnerability Databases", "CISA KEV Catalog", "Known Exploited Vulnerabilities catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "AlertTriangle", ["kev", "cisa", "exploited"], True, 4),
        ("Reporting", "Risk Scoring", "CVSS Calculator", "Common Vulnerability Scoring System v3.1 calculator", "https://www.first.org/cvss/calculator/3.1", "Calculator", ["cvss", "scoring", "risk"], False, 5),
        ("Reporting", "Risk Scoring", "EPSS", "Exploit Prediction Scoring System", "https://www.first.org/epss/", "TrendingUp", ["epss", "prediction", "probability"], False, 6),
        ("Reporting", "Compliance", "CIS Benchmarks", "Center for Internet Security configuration benchmarks", "https://www.cisecurity.org/cis-benchmarks", "ClipboardCheck", ["compliance", "hardening", "benchmarks"], False, 7),
        ("Reporting", "Compliance", "NIST Cybersecurity Framework", "Framework for improving critical infrastructure cybersecurity", "https://www.nist.gov/cyberframework", "ClipboardCheck", ["nist", "framework", "compliance"], False, 8),

        # --- Learning ---
        ("Learning", "Training Platforms", "HackTheBox", "Online cybersecurity training platform", "https://www.hackthebox.com", "GraduationCap", ["training", "labs", "ctf"], True, 1),
        ("Learning", "Training Platforms", "TryHackMe", "Learn cybersecurity through hands-on exercises", "https://tryhackme.com", "GraduationCap", ["training", "beginner", "guided"], True, 2),
        ("Learning", "Training Platforms", "PortSwigger Web Security Academy", "Free web security training", "https://portswigger.net/web-security", "GraduationCap", ["web", "training", "free"], True, 3),
        ("Learning", "Bug Bounty", "HackerOne", "Bug bounty and vulnerability disclosure platform", "https://www.hackerone.com", "Bug", ["bug-bounty", "disclosure", "platform"], True, 4),
        ("Learning", "Bug Bounty", "Bugcrowd", "Crowdsourced cybersecurity platform", "https://www.bugcrowd.com", "Bug", ["bug-bounty", "crowdsourced"], False, 5),
        ("Learning", "Certifications", "OSCP", "Offensive Security Certified Professional", "https://www.offsec.com/courses/pen-200/", "Award", ["certification", "offensive", "practical"], True, 6),
        ("Learning", "Certifications", "CEH", "Certified Ethical Hacker by EC-Council", "https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/", "Award", ["certification", "ethical-hacker"], False, 7),
        ("Learning", "References", "PayloadsAllTheThings", "Useful payloads and bypass techniques", "https://github.com/swisskyrepo/PayloadsAllTheThings", "Book", ["payloads", "cheatsheet", "reference"], True, 8),
        ("Learning", "References", "HackTricks", "Hacking tricks and methodology wiki", "https://book.hacktricks.xyz", "Book", ["methodology", "wiki", "tricks"], True, 9),
        ("Learning", "CTF", "CTFtime", "Capture The Flag competition tracker", "https://ctftime.org", "Flag", ["ctf", "competitions", "teams"], False, 10),
    ]

    for idx, (category, subcategory, name, desc, url, icon, tags, featured, order) in enumerate(resources):
        resource = Resource(
            id=_uid(f"resource-{idx}-{name}"),
            category=category,
            subcategory=subcategory,
            name=name,
            description=desc,
            url=url,
            icon=icon,
            tags=tags,
            is_featured=featured,
            display_order=order,
            created_at=WEEK_AGO,
            updated_at=NOW,
        )
        session.add(resource)
