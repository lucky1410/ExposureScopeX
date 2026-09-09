import unittest
from types import SimpleNamespace

from app.api.v1.reports import _compare_findings
from app.services.assessment_runtime import build_scan_metadata
from app.services.asset_inventory import normalize_target
from app.services.celery_app import celery_app
from app.services.execution_policy import estimate_remaining_seconds, resolve_execution_policy
from app.services.open_source_catalog import build_tool_plan


class ExecutionPolicyTests(unittest.TestCase):
    def test_workloads_route_to_isolated_queues(self):
        self.assertEqual(resolve_execution_policy("medium", "domain")["queue"], "scans-web")
        self.assertEqual(resolve_execution_policy("medium", "api")["queue"], "scans-api")
        self.assertEqual(resolve_execution_policy("medium", "image")["queue"], "scans-artifact")
        self.assertEqual(resolve_execution_policy("medium", "cloud_account")["queue"], "scans-cloud")
        self.assertEqual(resolve_execution_policy("medium", "android")["queue"], "scans-mobile")

    def test_policy_rejects_oversized_target_batch(self):
        with self.assertRaises(ValueError):
            resolve_execution_policy("light", "domain", target_count=251)

    def test_scan_metadata_persists_policy_and_telemetry(self):
        metadata = build_scan_metadata(
            assessment_id="assessment",
            scan_mode="medium",
            target_type="api",
            phases={},
            flags={},
        )
        self.assertEqual(metadata["execution_policy"]["queue"], "scans-api")
        self.assertIn("eta_seconds", metadata["telemetry"])

    def test_eta_is_bounded_by_timeout(self):
        self.assertIsNone(estimate_remaining_seconds(2, 100, 1000))
        self.assertEqual(estimate_remaining_seconds(100, 100, 1000), 0)
        self.assertLessEqual(estimate_remaining_seconds(10, 900, 1000), 100)

    def test_new_artifact_targets_have_specialized_manifests(self):
        expected_stages = {
            "kubernetes": "misconfiguration_scan",
            "android": "manifest_analysis",
            "ios": "plist_analysis",
        }
        for target_type, stage_id in expected_stages.items():
            metadata = build_scan_metadata(
                assessment_id="assessment",
                scan_mode="medium",
                target_type=target_type,
                phases={},
                flags={},
            )
            self.assertIn(stage_id, [stage["id"] for stage in metadata["execution_manifest"]])

    def test_new_artifact_targets_normalize_and_plan_trivy(self):
        targets = {
            "kubernetes": "https://example.com/deployment.yaml",
            "android": "https://example.com/application.apk",
            "ios": "https://example.com/application.ipa",
        }
        for target_type, target in targets.items():
            normalized = normalize_target(target, target_type)
            self.assertEqual(normalized.normalized_value, target)
            self.assertTrue(normalized.canonical_key.startswith(f"{target_type}:"))
            tools = build_tool_plan(target_type=target_type, scan_mode="medium")
            self.assertIn("trivy", [tool["tool_id"] for tool in tools])


class ReportingComparisonTests(unittest.TestCase):
    @staticmethod
    def finding(identifier, severity="HIGH", status="new"):
        return SimpleNamespace(
            id=identifier,
            scan_id=identifier,
            asset_id="asset",
            source="nuclei",
            template_id=identifier,
            title=identifier,
            url="https://example.com",
            severity=severity,
            status=status,
            description="description",
            evidence="evidence",
            remediated_at=None,
        )

    def test_comparison_classifies_new_resolved_and_changed(self):
        baseline = [self.finding("resolved"), self.finding("changed", "MEDIUM")]
        current = [self.finding("new"), self.finding("changed", "HIGH")]
        result = _compare_findings(current, baseline)
        self.assertEqual(result["summary"], {"new": 1, "resolved": 1, "unchanged": 0, "changed": 1})


class MaintenanceScheduleTests(unittest.TestCase):
    def test_retention_runs_daily_on_default_queue(self):
        schedule = celery_app.conf.beat_schedule["artifact-retention-daily"]
        self.assertEqual(schedule["task"], "app.services.celery_app.retention_maintenance_task")
        self.assertEqual(schedule["schedule"], 86400)
        self.assertEqual(schedule["options"]["queue"], "default")
