"""Parse nmap XML scan output."""
import logging
import re
from defusedxml import ElementTree as ET
from pathlib import Path

logger = logging.getLogger("exposurescopex.parsers")


def parse_nmap_xml(filepath: Path) -> list[dict]:
    """Parse nmap XML and return list of host dicts with ports.

    Args:
        filepath: Path to nmap_scan.xml file.

    Returns:
        List of host dicts, each containing ip, hostname, and ports list.
        Example::

            [{"ip": "99.86.182.76",
              "hostname": "server-99-86-182-76.blr50.r.cloudfront.net",
              "ports": [
                  {"port": 80, "protocol": "tcp", "state": "open",
                   "service": "http", "product": "Amazon CloudFront httpd",
                   "version": "", "tunnel": ""}
              ]}]
    """
    filepath = Path(filepath)
    if not filepath.exists():
        logger.debug("nmap XML file not found: %s", filepath)
        return []

    if filepath.stat().st_size == 0:
        logger.debug("nmap XML file is empty: %s", filepath)
        return []

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as exc:
        # Nmap writes complete <host> records incrementally but only closes the
        # document at shutdown. Recover completed hosts after a timeout instead
        # of discarding an otherwise useful partial batch.
        content = filepath.read_text(encoding="utf-8", errors="replace")
        fragments = re.findall(r"<host\b[^>]*>.*?</host>", content, flags=re.DOTALL)
        if not fragments:
            logger.debug("Failed to parse nmap XML %s: %s", filepath, exc)
            return []
        try:
            root = ET.fromstring("<nmaprun>" + "".join(fragments) + "</nmaprun>")
        except ET.ParseError:
            logger.debug("Failed to recover partial nmap XML %s: %s", filepath, exc)
            return []
    hosts: list[dict] = []

    for host_el in root.iter("host"):
        # Skip hosts that are not up
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state", "") != "up":
            continue

        # IP address
        ip = ""
        for addr_el in host_el.findall("address"):
            addrtype = addr_el.get("addrtype", "")
            if addrtype in ("ipv4", "ipv6"):
                ip = addr_el.get("addr", "").strip()
                break

        if not ip:
            logger.debug("Host element without IP address, skipping")
            continue

        # Hostname
        hostname = ""
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hostname_el = hostnames_el.find("hostname")
            if hostname_el is not None:
                hostname = hostname_el.get("name", "").strip()

        # Ports
        ports: list[dict] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                try:
                    port_number = int(port_el.get("portid", "0"))
                except (ValueError, TypeError):
                    logger.debug("Invalid port number in nmap XML, skipping")
                    continue

                protocol = port_el.get("protocol", "tcp").strip()

                # Port state
                state = "unknown"
                state_el = port_el.find("state")
                if state_el is not None:
                    state = state_el.get("state", "unknown").strip()

                # Service info
                service_name = ""
                product = ""
                version = ""
                tunnel = ""
                service_el = port_el.find("service")
                if service_el is not None:
                    service_name = service_el.get("name", "").strip()
                    product = service_el.get("product", "").strip()
                    version = service_el.get("version", "").strip()
                    tunnel = service_el.get("tunnel", "").strip()

                ports.append({
                    "port": port_number,
                    "protocol": protocol,
                    "state": state,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "tunnel": tunnel,
                })

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "ports": ports,
        })

    logger.debug("Parsed %d hosts from nmap XML: %s", len(hosts), filepath)
    return hosts
