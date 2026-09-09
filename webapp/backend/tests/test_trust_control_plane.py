import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services.scan_result_ingestion import _artifact_type, _file_sha256
from app.services.worker_capabilities import _normalize_worker_name, capability_snapshot


class ArtifactManifestTests(unittest.TestCase):
    def test_classifies_and_hashes_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "assessment-report.json"
            report.write_text('{"ok":true}', encoding="utf-8")
            self.assertEqual(_artifact_type(report), "report")
            self.assertEqual(
                _file_sha256(report),
                "4062edaf750fb8074e7e83e0c9028c94e32468a8b6f1614774328ef045150f93",
            )


class WorkerCapabilityTests(unittest.TestCase):
    def test_normalizes_celery_worker_prefix(self):
        self.assertEqual(_normalize_worker_name("celery@worker-1"), "worker-1")

    @patch("app.services.worker_capabilities._template_commit", return_value=None)
    @patch("app.services.worker_capabilities._tool_version", return_value="1.2.3")
    @patch("app.services.worker_capabilities.shutil.which")
    def test_snapshot_advertises_only_installed_catalog_tools(self, which, _version, _commit):
        which.side_effect = lambda binary: f"/usr/bin/{binary}" if binary in {"nuclei", "python"} else None
        snapshot = capability_snapshot("worker@test")
        self.assertEqual(snapshot["worker_name"], "worker@test")
        self.assertIn("nuclei", snapshot["capabilities"])
        self.assertIn("mcp_audit", snapshot["capabilities"])
        self.assertNotIn("subfinder", snapshot["capabilities"])
        self.assertEqual(snapshot["versions"]["nuclei"], "1.2.3")


if __name__ == "__main__":
    unittest.main()
