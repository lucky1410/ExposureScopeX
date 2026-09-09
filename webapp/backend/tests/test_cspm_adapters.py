import json
import tempfile
import unittest
from pathlib import Path

from app.services.assessment_runtime import build_execution_manifest, build_scan_metadata
from app.services.open_source_catalog import build_tool_plan, get_open_source_tool_catalog
from app.services.parsers.cspm_parser import parse_prowler_ocsf, parse_scoutsuite_report


class OpenSourceCatalogTests(unittest.TestCase):
    def test_catalog_exposes_bundled_and_optional_cspm_tools(self):
        catalog = get_open_source_tool_catalog()
        scanners = {item["id"]: item for item in catalog["scanners"]}
        self.assertIn("prowler", scanners)
        self.assertIn("scoutsuite", scanners)
        self.assertIn("ffuf", scanners)
        self.assertIn("arjun", scanners)
        self.assertIn("nikto", scanners)
        self.assertIn("sqlmap", scanners)
        self.assertEqual(scanners["prowler"]["status"], "bundled")
        self.assertEqual(scanners["scoutsuite"]["status"], "optional")
        self.assertFalse(scanners["scoutsuite"]["bundled"])

    def test_cloud_account_plan_prefers_cspm_adapters(self):
        plan = build_tool_plan(
            target_type="cloud_account",
            scan_mode="medium",
            utilities=["prowler", "scoutsuite"],
            requested_scans=["cloud"],
        )
        ids = [item["tool_id"] for item in plan]
        self.assertIn("prowler", ids)
        self.assertIn("scoutsuite", ids)

    def test_image_plan_prefers_sbom_and_correlation_adapters(self):
        plan = build_tool_plan(
            target_type="image",
            scan_mode="aggressive",
            utilities=["trivy", "syft", "grype"],
            requested_scans=[],
        )
        ids = [item["tool_id"] for item in plan]
        self.assertIn("trivy", ids)
        self.assertIn("syft", ids)
        self.assertIn("grype", ids)

    def test_web_plan_surfaces_extended_web_testing_tools(self):
        plan = build_tool_plan(
            target_type="url",
            scan_mode="aggressive",
            utilities=[],
            requested_scans=["web"],
        )
        ids = [item["tool_id"] for item in plan]
        self.assertIn("ffuf", ids)
        self.assertIn("arjun", ids)
        self.assertIn("nikto", ids)

    def test_sqlmap_only_appears_when_operator_requested(self):
        baseline = build_tool_plan(
            target_type="url",
            scan_mode="medium",
            utilities=[],
            requested_scans=[],
        )
        requested = build_tool_plan(
            target_type="url",
            scan_mode="medium",
            utilities=["sqlmap"],
            requested_scans=[],
        )
        self.assertNotIn("sqlmap", [item["tool_id"] for item in baseline])
        self.assertIn("sqlmap", [item["tool_id"] for item in requested])


class RuntimeCloudTests(unittest.TestCase):
    def test_cloud_account_manifest_has_cspm_stages(self):
        manifest = build_execution_manifest({
            "target_type": "cloud_account",
        })
        ids = [item["id"] for item in manifest]
        self.assertIn("cloud_inventory", ids)
        self.assertIn("cspm_primary", ids)
        self.assertIn("compliance", ids)

    def test_scan_metadata_includes_tool_plan(self):
        metadata = build_scan_metadata(
            assessment_id="0b7e40ce-64fc-4b05-8e59-7a1dc7ec4cb4",
            scan_mode="medium",
            target_type="cloud_account",
            phases={"cloud": True},
            flags={"_requested_scans": ["cloud"]},
        )
        self.assertTrue(metadata["tool_plan"])
        self.assertEqual(metadata["tool_plan"][0]["tool_id"], "prowler")

    def test_image_manifest_has_inventory_and_sbom_stages(self):
        manifest = build_execution_manifest({
            "target_type": "image",
        })
        ids = [item["id"] for item in manifest]
        self.assertIn("image_inventory", ids)
        self.assertIn("image_sbom", ids)
        self.assertIn("image_correlation", ids)


class CspmParserTests(unittest.TestCase):
    def test_parse_prowler_ocsf(self):
        fixture = [{
            "severity": "High",
            "status_code": "FAIL",
            "message": "Security group allows 0.0.0.0/0",
            "cloud": {"provider": "aws"},
            "metadata": {"event_code": "ec2_securitygroup_allow_ingress_from_internet_to_all_ports"},
            "finding_info": {"title": "Security group open to the internet", "desc": "Ingress from everywhere"},
            "resources": [{"uid": "sg-123", "name": "prod-edge", "type": "AwsEc2SecurityGroup"}],
        }]
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "prowler-output.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            parsed = parse_prowler_ocsf(path)
        self.assertEqual(parsed["summary"]["provider"], "aws")
        self.assertEqual(len(parsed["findings"]), 1)
        self.assertEqual(parsed["findings"][0]["source"], "prowler")
        self.assertEqual(len(parsed["resources"]), 1)

    def test_parse_scoutsuite_js_report(self):
        fixture = """scoutsuite_results =
{"provider":"aws","services":{"ec2":{}},"issues":[{"level":"danger","description":"Public S3 bucket","rationale":"Bucket allows public reads","resource":"bucket-a"}]}
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "scoutsuite_results_test.js"
            path.write_text(fixture, encoding="utf-8")
            parsed = parse_scoutsuite_report(path)
        self.assertEqual(parsed["summary"]["provider"], "aws")
        self.assertEqual(parsed["summary"]["services"], 1)
        self.assertEqual(parsed["findings"][0]["source"], "scoutsuite")


if __name__ == "__main__":
    unittest.main()
