"""Nmap artifact parsing regression tests."""
import tempfile
import unittest
from pathlib import Path

from app.services.parsers.nmap_parser import parse_nmap_xml


HOST = """<host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" product="nginx" version="1.25"/></port></ports></host>"""


class NmapParserTests(unittest.TestCase):
    def test_parses_complete_document(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nmap.xml"
            path.write_text(f"<nmaprun>{HOST}</nmaprun>", encoding="utf-8")
            hosts = parse_nmap_xml(path)
        self.assertEqual(hosts[0]["ip"], "192.0.2.10")
        self.assertEqual(hosts[0]["ports"][0]["port"], 443)

    def test_recovers_completed_hosts_from_truncated_document(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nmap.xml"
            path.write_text(f"<nmaprun>{HOST}<host>", encoding="utf-8")
            hosts = parse_nmap_xml(path)
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["ports"][0]["service"], "https")


if __name__ == "__main__":
    unittest.main()
