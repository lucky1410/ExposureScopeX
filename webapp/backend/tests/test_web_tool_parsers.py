import csv
import json
import tempfile
import unittest
from pathlib import Path

from app.services.parsers.arjun_parser import parse_arjun_results
from app.services.parsers.ffuf_parser import parse_ffuf_results
from app.services.parsers.sqlmap_parser import parse_sqlmap_results
from app.services.scan_result_ingestion import _collect_findings


class WebToolParserTests(unittest.TestCase):
    def test_parse_ffuf_results(self):
        fixture = {
            "results": [
                {
                    "input": {"FUZZ": "admin"},
                    "status": 403,
                    "length": 1234,
                    "words": 87,
                    "lines": 12,
                    "url": "https://example.com/admin",
                    "content-type": "text/html",
                }
            ]
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ffuf_example.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            parsed = parse_ffuf_results(path)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["input"], "admin")
        self.assertEqual(parsed[0]["status"], 403)

    def test_parse_arjun_results(self):
        fixture = {
            "https://example.com/search": {
                "method": "GET",
                "params": ["q", "debug"],
            }
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "arjun_example.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            parsed = parse_arjun_results(path)
        self.assertEqual({item["parameter"] for item in parsed}, {"q", "debug"})
        self.assertTrue(all(item["method"] == "GET" for item in parsed))

    def test_parse_sqlmap_results(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sqlmap_results.csv"
            with path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(["Target URL", "Place", "Parameter", "Technique(s)", "Note(s)"])
                writer.writerow(["https://example.com/item?id=1", "GET", "id", "boolean-based blind", "suspected injectable"])
            parsed = parse_sqlmap_results(path)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["parameter"], "id")
        self.assertIn("boolean-based", parsed[0]["techniques"])

    def test_collect_findings_ingests_extended_web_outputs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "ffuf_one.json").write_text(json.dumps({
                "results": [{"input": {"FUZZ": "admin"}, "status": 403, "length": 10, "words": 2, "lines": 1, "url": "https://example.com/admin"}]
            }), encoding="utf-8")
            (root / "arjun_one.json").write_text(json.dumps({
                "https://example.com/api": {"method": "GET", "params": ["token"]}
            }), encoding="utf-8")
            with (root / "sqlmap_results.csv").open("w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(["Target URL", "Place", "Parameter", "Technique(s)", "Note(s)"])
                writer.writerow(["https://example.com/item?id=1", "GET", "id", "error-based", "confirmed"])
            findings = _collect_findings(root, "example.com")
        sources = {item["source"] for item in findings}
        self.assertIn("ffuf", sources)
        self.assertIn("arjun", sources)
        self.assertIn("sqlmap", sources)


if __name__ == "__main__":
    unittest.main()
