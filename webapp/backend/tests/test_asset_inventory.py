"""Target normalization and scan-planning tests."""

import unittest
from types import SimpleNamespace

from app.api.v1.assessments import (
    _assessment_authorization_targets,
    _build_batch_target_label,
    _dedupe_imported_targets,
)
from app.services.asset_inventory import build_seed_metadata, infer_root_domain, normalize_target
from app.services.intake_parser import parse_csv_row
from app.services.scan_planning import build_scan_plan
from app.services.celery_app import _scan_phase_from_line
from app.services.validation import ValidationError


class AssetInventoryTests(unittest.TestCase):
    def test_normalize_domain(self) -> None:
        normalized = normalize_target("App.Example.com", "domain")
        self.assertEqual(normalized.normalized_value, "app.example.com")
        self.assertEqual(normalized.root_domain, "example.com")
        self.assertEqual(normalized.parent_key, "host:example.com")

    def test_normalize_url(self) -> None:
        normalized = normalize_target("https://App.Example.com/login?x=1", "url")
        self.assertEqual(normalized.hostname, "app.example.com")
        self.assertEqual(normalized.parent_key, "host:app.example.com")
        self.assertTrue(normalized.normalized_value.startswith("https://app.example.com"))

    def test_invalid_private_ip_url(self) -> None:
        with self.assertRaises(ValidationError):
            normalize_target("http://127.0.0.1/admin", "url")

    def test_root_domain_heuristic(self) -> None:
        self.assertEqual(infer_root_domain("a.b.example.co.uk"), "example.co.uk")

    def test_normalize_asn(self) -> None:
        normalized = normalize_target("13335", "asn")
        self.assertEqual(normalized.normalized_value, "AS13335")
        self.assertEqual(normalized.canonical_key, "asn:AS13335")

    def test_normalize_repository(self) -> None:
        normalized = normalize_target("https://github.com/OpenAI/codex.git", "repository")
        self.assertEqual(normalized.normalized_value, "github.com/openai/codex")
        self.assertEqual(normalized.parent_key, "host:github.com")

    def test_normalize_container_image(self) -> None:
        normalized = normalize_target("ghcr.io/acme/platform-api:1.4.2", "image")
        self.assertEqual(normalized.normalized_value, "ghcr.io/acme/platform-api:1.4.2")
        self.assertEqual(normalized.canonical_key, "image:ghcr.io/acme/platform-api:1.4.2")
        self.assertEqual(normalized.parent_key, "registry:ghcr.io")

    def test_normalize_mcp_endpoint(self) -> None:
        normalized = normalize_target("https://gateway.example.com/api/mcp", "mcp")
        self.assertEqual(normalized.canonical_key, "mcp:https://gateway.example.com/api/mcp")
        self.assertEqual(normalized.parent_key, "host:gateway.example.com")

    def test_seed_metadata_uses_canonical_identity(self) -> None:
        seed = build_seed_metadata("https://gateway.example.com/mcp", "mcp", source="csv", stage="candidate")
        self.assertEqual(seed["seed_type"], "mcp")
        self.assertEqual(seed["source"], "csv")
        self.assertEqual(seed["stage"], "candidate")

    def test_file_targets_are_supported_for_seed_metadata(self) -> None:
        normalized = normalize_target("bulk-import.csv", "file")
        self.assertEqual(normalized.canonical_key, "file:bulk-import.csv")
        seed = build_seed_metadata("bulk-import.csv", "file", source="assessment", stage="confirmed")
        self.assertEqual(seed["seed_type"], "file")
        self.assertEqual(seed["canonical_key"], "file:bulk-import.csv")


class ScanPlanningTests(unittest.TestCase):
    def test_nuclei_scan_plan_enables_scan(self) -> None:
        plan = build_scan_plan(
            scan_mode="light",
            target_type="domain",
            phases=None,
            flags=None,
            requested_scans=["nuclei"],
            requested_utilities=[],
            nuclei_tags=["custom"],
        )
        self.assertTrue(plan["phases"]["scan"])
        self.assertIn("nuclei", plan["utilities"])
        self.assertIn("custom", plan["nuclei_tags"])

    def test_url_plan_disables_cloud_and_enum(self) -> None:
        plan = build_scan_plan(
            scan_mode="medium",
            target_type="url",
            phases=None,
            flags=None,
            requested_scans=["web"],
            requested_utilities=[],
            nuclei_tags=[],
        )
        self.assertFalse(plan["phases"]["enum"])
        self.assertFalse(plan["phases"]["cloud"])
        self.assertTrue(plan["flags"]["crawl"])

    def test_mcp_plan_tracks_pipeline_and_strategy(self) -> None:
        plan = build_scan_plan(
            scan_mode="medium",
            target_type="mcp",
            phases=None,
            flags=None,
            requested_scans=[],
            requested_utilities=[],
            nuclei_tags=[],
        )
        self.assertEqual(plan["scan_strategy"], "active")
        self.assertIn("discover", plan["pipeline"])
        self.assertIn("mcp-audit", plan["utilities"])

    def test_execution_policy_rejects_exploitation_and_preserves_safe_validation(self) -> None:
        plan = build_scan_plan(
            scan_mode="aggressive",
            target_type="url",
            phases={"exploit": True},
            flags={"agent": True, "allow_active_validation": True},
            requested_scans=["web"],
            requested_utilities=["sqlmap", "hydra", "nuclei"],
            nuclei_tags=["default-login", "intrusive", "misconfig"],
        )
        self.assertFalse(plan["phases"]["exploit"])
        self.assertFalse(plan["flags"]["agent"])
        self.assertTrue(plan["flags"]["allow_active_validation"])
        self.assertNotIn("sqlmap", plan["utilities"])
        self.assertNotIn("hydra", plan["utilities"])
        self.assertNotIn("default-login", plan["nuclei_tags"])
        self.assertNotIn("intrusive", plan["nuclei_tags"])
        self.assertIn("nuclei", plan["utilities"])
        self.assertIn("misconfig", plan["nuclei_tags"])


class IntakeParserTests(unittest.TestCase):
    def test_parse_loose_row(self) -> None:
        parsed = parse_csv_row({
            "Website": "https://app.example.com/login",
            "Asset Name": "Portal",
            "Modules": "nuclei;web",
            "Tools": "httpx,nuclei",
            "Template Tags": "panel,exposures",
            "Run Now": "yes",
        })
        self.assertEqual(parsed["target"], "https://app.example.com/login")
        self.assertEqual(parsed["name"], "Portal")
        self.assertEqual(parsed["requested_scans"], ["nuclei", "web"])
        self.assertEqual(parsed["requested_utilities"], ["httpx", "nuclei"])
        self.assertEqual(parsed["nuclei_tags"], ["panel", "exposures"])
        self.assertTrue(parsed["auto_start"])

    def test_parse_asm_style_row(self) -> None:
        parsed = parse_csv_row({
            "Host": "api.example.com",
            "Labels": "prod,edge",
            "Comments": "customer edge service",
        })
        self.assertEqual(parsed["target"], "api.example.com")
        self.assertEqual(parsed["name"], "api.example.com")
        self.assertEqual(parsed["tags"], ["prod", "edge"])
        self.assertEqual(parsed["notes"], "customer edge service")

    def test_generic_host_column_infers_each_rows_value_type(self) -> None:
        cases = {
            "app.example.test": "domain",
            "192.0.2.10": "ip",
            "192.0.2.0/24": "cidr",
            "https://api.example.test/v1": "url",
        }
        for value, expected_type in cases.items():
            with self.subTest(value=value):
                parsed = parse_csv_row({"Public Host": value})
                self.assertEqual(parsed["target_type"], expected_type)

    def test_parse_camel_case_ip_export_row(self) -> None:
        parsed = parse_csv_row({
            "ipAddress": "52.71.113.79",
            "service": "NAT gateway (VPC)",
            "eniDescription": "Interface for NAT Gateway nat-0143471bf3924a83b",
            "securityGroupsDisplay": "public-sg (sg-123)",
            "addressRegion": "us-east-1",
        })
        self.assertEqual(parsed["target"], "52.71.113.79")
        self.assertEqual(parsed["target_type"], "ip")
        self.assertEqual(parsed["name"], "NAT gateway (VPC)")
        self.assertIn("public-sg", parsed["tags"][0])

    def test_parse_repository_seed_row(self) -> None:
        parsed = parse_csv_row({
            "Repository URL": "github.com/acme/platform",
            "Label": "Acme Platform",
            "Modules": "supply-chain",
        })
        self.assertEqual(parsed["target_type"], "repository")
        self.assertEqual(parsed["target"], "github.com/acme/platform")

    def test_parse_mcp_seed_row(self) -> None:
        parsed = parse_csv_row({
            "MCP Endpoint": "https://gateway.example.com/mcp",
            "Name": "Primary MCP",
        })
        self.assertEqual(parsed["target_type"], "mcp")
        self.assertEqual(parsed["target"], "https://gateway.example.com/mcp")

    def test_parse_container_image_row(self) -> None:
        parsed = parse_csv_row({
            "Container Image": "ghcr.io/acme/platform-api:1.4.2",
            "Name": "Platform API image",
        })
        self.assertEqual(parsed["target_type"], "image")
        self.assertEqual(parsed["target"], "ghcr.io/acme/platform-api:1.4.2")


class AssessmentImportBatchTests(unittest.TestCase):
    def test_retry_authorization_uses_declared_target_not_discoveries(self) -> None:
        assessment = SimpleNamespace(
            target="http://dvwa.localhost/",
            target_type="url",
            flags={},
            assets=[SimpleNamespace(value="172.21.0.2", asset_type="ip")],
        )
        self.assertEqual(
            _assessment_authorization_targets(assessment),
            [("http://dvwa.localhost/", "url")],
        )

    def test_batch_retry_authorization_uses_imported_seeds(self) -> None:
        assessment = SimpleNamespace(
            target="targets.csv",
            target_type="file",
            flags={"_imported_targets": [
                {"target": "one.example.com", "target_type": "domain"},
                {"target": "https://two.example.com/", "target_type": "url"},
            ]},
        )
        self.assertEqual(
            _assessment_authorization_targets(assessment),
            [("one.example.com", "domain"), ("https://two.example.com/", "url")],
        )

    def test_dedupe_imported_targets_collapses_duplicate_ips(self) -> None:
        imported_targets, skipped = _dedupe_imported_targets([
            {"target": "52.71.113.79", "target_type": "ip", "name": "Gateway A"},
            {"target": "52.71.113.79", "target_type": "ip", "name": "Gateway B"},
            {"target": "api.example.com", "target_type": "domain", "name": "API"},
        ])
        self.assertEqual(skipped, 1)
        self.assertEqual(len(imported_targets), 2)
        self.assertEqual(imported_targets[0]["canonical_key"], "ip:52.71.113.79")
        self.assertEqual(imported_targets[1]["canonical_key"], "host:api.example.com")

    def test_batch_target_label_summarizes_multiple_targets(self) -> None:
        label = _build_batch_target_label([
            {"target": "52.71.113.79", "target_type": "ip"},
            {"target": "99.81.164.204", "target_type": "ip"},
            {"target": "52.212.167.231", "target_type": "ip"},
        ])
        self.assertEqual(label, "52.71.113.79 (+2 more)")


class ScanProgressTests(unittest.TestCase):
    def test_phase_progress_parses_worker_output(self) -> None:
        self.assertEqual(
            _scan_phase_from_line("[INFO] Starting Vulnerability Scanning..."),
            ("nuclei", 85),
        )

    def test_unrelated_output_does_not_change_progress(self) -> None:
        self.assertIsNone(_scan_phase_from_line("Nuclei found 4 findings"))

    def test_enumeration_substeps_report_granular_progress(self) -> None:
        self.assertEqual(
            _scan_phase_from_line("[INFO] Fetching historical URLs with waybackurls"),
            ("enumeration_history", 23),
        )


if __name__ == "__main__":
    unittest.main()
