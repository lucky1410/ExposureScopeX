"""Parsers for ExposureScopeX scan output files.

Each parser reads a specific file format produced by the ExposureScopeX CLI
and returns structured Python dicts/lists suitable for database ingestion.
All parsers are synchronous, use only stdlib, and handle missing/empty/malformed
files gracefully.
"""
from .arjun_parser import parse_arjun_results
from .api_security_parser import parse_api_security
from .cloud_parser import parse_cloud_buckets, parse_cloud_results
from .cspm_parser import parse_prowler_ocsf, parse_scoutsuite_report
from .dns_parser import parse_dns_recon
from .email_parser import parse_email_security
from .ffuf_parser import parse_ffuf_results
from .headers_parser import parse_http_headers
from .nikto_parser import parse_nikto
from .nmap_parser import parse_nmap_xml
from .nuclei_parser import parse_nuclei_results
from .ssl_parser import parse_ssl_results
from .subdomain_parser import parse_subdomains
from .sqlmap_parser import parse_sqlmap_results

__all__ = [
    "parse_arjun_results",
    "parse_api_security",
    "parse_cloud_buckets",
    "parse_cloud_results",
    "parse_prowler_ocsf",
    "parse_scoutsuite_report",
    "parse_dns_recon",
    "parse_email_security",
    "parse_ffuf_results",
    "parse_http_headers",
    "parse_nikto",
    "parse_nmap_xml",
    "parse_nuclei_results",
    "parse_ssl_results",
    "parse_subdomains",
    "parse_sqlmap_results",
]
