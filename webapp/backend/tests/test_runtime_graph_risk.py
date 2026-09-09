import unittest
import json
import tempfile
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from app.services.asset_graph import asset_state_fingerprint, diff_asset_states
from app.database import _database_engine_options
from app.services.assessment_runtime import (
    advance_execution_manifest,
    build_execution_manifest,
    finalize_execution_manifest,
)
from app.services.capability_catalog import get_capability_catalog
from app.services.risk_engine import confidence_score, contextual_risk_score
from app.services.scan_result_ingestion import _collect_specialized_findings


class RuntimeManifestTests(unittest.TestCase):
    def test_worker_database_options_disable_cross_loop_pooling(self):
        from sqlalchemy.pool import NullPool

        worker_options = _database_engine_options(True)
        api_options = _database_engine_options(False)
        self.assertIs(worker_options["poolclass"], NullPool)
        self.assertNotIn("pool_size", worker_options)
        self.assertEqual(api_options["pool_size"], 20)

    def test_manifest_respects_inventory_strategy(self):
        manifest = build_execution_manifest({
            "phases": {"enum": True, "scan": False, "cloud": False, "exploit": False, "report": True},
            "flags": {"crawl": False, "screenshots": False, "cve": False},
            "scan_strategy": "inventory",
        })
        statuses = {item["id"]: item["status"] for item in manifest}
        self.assertEqual(statuses["enumeration"], "pending")
        self.assertEqual(statuses["port_scan"], "skipped")
        self.assertEqual(statuses["reporting"], "pending")

    def test_advancing_stage_completes_preceding_planned_work(self):
        metadata = {"execution_manifest": build_execution_manifest({
            "phases": {"enum": True, "scan": True, "cloud": False, "exploit": False, "report": True},
            "flags": {"crawl": True, "screenshots": False, "cve": True},
            "scan_strategy": "active",
        })}
        now = datetime(2026, 8, 30, tzinfo=timezone.utc)
        updated = advance_execution_manifest(metadata, "port_scan", now=now)
        stages = {item["id"]: item for item in updated["execution_manifest"]}
        self.assertEqual(stages["enumeration"]["status"], "completed")
        self.assertEqual(stages["port_scan"]["status"], "running")
        self.assertEqual(stages["port_scan"]["attempts"], 1)

    def test_cancel_finalization_does_not_mark_pending_stages_complete(self):
        metadata = {"execution_manifest": build_execution_manifest({
            "phases": {"enum": True, "scan": True, "cloud": False, "exploit": False, "report": True},
            "flags": {"crawl": True, "screenshots": False, "cve": True},
            "scan_strategy": "active",
        })}
        metadata = advance_execution_manifest(metadata, "enumeration")
        final = finalize_execution_manifest(metadata, "cancelled")
        statuses = {item["id"]: item["status"] for item in final["execution_manifest"]}
        self.assertEqual(statuses["enumeration"], "cancelled")
        self.assertEqual(statuses["port_scan"], "cancelled")


class CapabilityCatalogTests(unittest.TestCase):
    def test_blueprint_surfaces_are_registered_truthfully(self):
        catalog = get_capability_catalog()
        capabilities = catalog["capabilities"]
        ids = {item["id"] for item in capabilities}
        self.assertGreaterEqual(len(capabilities), 31)
        self.assertIn("mcp", ids)
        self.assertIn("attack_graph", ids)
        self.assertIn("autonomous_red_team", ids)
        self.assertEqual(len(ids), len(capabilities))
        self.assertTrue(all(item["status"] in catalog["status_definitions"] for item in capabilities))
        self.assertEqual(catalog["document_coverage"]["unmapped_sections"], [])
        self.assertEqual(
            catalog["document_coverage"]["mapped_sections"],
            catalog["document_coverage"]["actionable_sections"],
        )


class GraphAndRiskTests(unittest.TestCase):
    def test_asset_fingerprint_is_order_stable(self):
        self.assertEqual(asset_state_fingerprint({"b": 2, "a": 1}), asset_state_fingerprint({"a": 1, "b": 2}))

    def test_asset_state_diff(self):
        delta = diff_asset_states({"ports": [80], "live": True}, {"ports": [80, 443], "live": True})
        self.assertEqual(delta["change_type"], "changed")
        self.assertEqual(delta["changed"]["ports"]["after"], [80, 443])

    def test_contextual_risk_uses_evidence_confidence(self):
        confidence = confidence_score("nuclei", "matched request and response evidence")
        score = contextual_risk_score("HIGH", confidence, reachable=True, exploitable=True)
        self.assertIsInstance(score, Decimal)
        self.assertGreater(score, Decimal("70"))

    def test_repository_findings_are_normalized_without_secret_content(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "gitleaks.json").write_text(json.dumps([{
                "RuleID": "generic-api-key",
                "Description": "API key",
                "File": "settings.py",
                "StartLine": 4,
                "Secret": "must-not-be-ingested",
                "Fingerprint": "abc123",
            }]), encoding="utf-8")
            findings = _collect_specialized_findings(root, "github.com/acme/repo")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["source"], "gitleaks")
            self.assertNotIn("must-not-be-ingested", json.dumps(findings))


if __name__ == "__main__":
    unittest.main()
