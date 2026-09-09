import unittest

from pydantic import ValidationError

from app.schemas.report import ReportRequest
from app.services.assessment_runtime import calculate_work_progress
from app.services.scan_provenance import _redact, build_tool_execution_manifest
from app.services.scan_result_ingestion import finding_resolution_eligible, finding_scope_signature


class WeightedProgressTests(unittest.TestCase):
    def test_progress_uses_target_weighted_manifest_units(self):
        metadata = {
            "execution_policy": {"target_count": 10},
            "execution_manifest": [
                {"planned": True, "status": "completed"},
                {"planned": True, "status": "running"},
                {"planned": True, "status": "pending"},
            ],
        }
        progress, units = calculate_work_progress(metadata, 80, "running")
        self.assertEqual(units, {"total": 30, "completed": 11, "target_count": 10, "planned_stages": 3})
        self.assertEqual(progress, 36)

    def test_terminal_completion_reaches_all_units(self):
        progress, units = calculate_work_progress(
            {"execution_policy": {"target_count": 4}, "execution_manifest": [{"planned": True, "status": "running"}]},
            90,
            "completed",
        )
        self.assertEqual((progress, units["completed"], units["total"]), (100, 4, 4))


class FindingLifecycleScopeTests(unittest.TestCase):
    def test_scope_signature_ignores_key_order_but_not_scan_coverage(self):
        first = {"target_type": "domain", "utilities": ["nuclei", "nmap"], "flags_requested": {"scan": True}}
        same = {"flags_requested": {"scan": True}, "utilities": ["nmap", "nuclei"], "target_type": "domain"}
        narrower = {**same, "flags_requested": {"scan": False}}
        self.assertEqual(finding_scope_signature(first), finding_scope_signature(same))
        self.assertNotEqual(finding_scope_signature(first), finding_scope_signature(narrower))

    def test_resolution_requires_successful_finding_stage(self):
        self.assertTrue(finding_resolution_eligible({
            "scan_strategy": "active",
            "execution_manifest": [{"id": "nuclei", "planned": True, "status": "completed"}],
        }))
        self.assertFalse(finding_resolution_eligible({
            "scan_strategy": "active",
            "execution_manifest": [
                {"id": "nuclei", "planned": True, "status": "completed"},
                {"id": "reporting", "planned": True, "status": "failed"},
            ],
        }))
        self.assertFalse(finding_resolution_eligible({"scan_strategy": "import", "execution_manifest": []}))


class ProvenanceRedactionTests(unittest.TestCase):
    def test_redacts_headers_flags_assignments_and_url_credentials(self):
        value = "curl https://alice:secret@example.test -H 'Authorization: Bearer abc' --api-key xyz token=qwerty"
        redacted = _redact(value, 1000)
        self.assertNotIn("secret", redacted)
        self.assertNotIn("abc", redacted)
        self.assertNotIn("xyz", redacted)
        self.assertNotIn("qwerty", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_execution_manifest_is_stable_and_does_not_hash_raw_secrets(self):
        command = "nuclei -t cves/ --api-key super-secret -o nuclei_results.txt"
        metadata = {
            "profile": {"mode": "quick", "nuclei_tags": ["cve"]},
            "execution_policy": {"timeout_seconds": 300},
        }
        manifest = build_tool_execution_manifest(
            command, tool="nuclei", output_file="/tmp/run/nuclei_results.txt", scan_metadata=metadata
        )
        serialized = str(manifest)
        self.assertNotIn("super-secret", serialized)
        self.assertEqual(manifest["output_name"], "nuclei_results.txt")
        self.assertEqual(manifest["inputs"][0]["kind"], "template")
        self.assertEqual(len(manifest["manifest_sha256"]), 64)
        self.assertEqual(
            manifest,
            build_tool_execution_manifest(
                command, tool="nuclei", output_file="/tmp/run/nuclei_results.txt", scan_metadata=metadata
            ),
        )


class ReportScopeValidationTests(unittest.TestCase):
    def test_normalizes_report_scope(self):
        request = ReportRequest(
            assessment_id="00000000-0000-0000-0000-000000000001",
            severities=[" high "],
            statuses=[" RESOLVED "],
        )
        self.assertEqual(request.severities, ["HIGH"])
        self.assertEqual(request.statuses, ["resolved"])

    def test_rejects_unknown_finding_status(self):
        with self.assertRaises(ValidationError):
            ReportRequest(
                assessment_id="00000000-0000-0000-0000-000000000001",
                statuses=["not-a-real-state"],
            )


if __name__ == "__main__":
    unittest.main()
