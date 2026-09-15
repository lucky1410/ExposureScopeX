import unittest
import uuid
import zipfile
import hashlib
import json
import tempfile
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pydantic import ValidationError

from app.schemas.report import ReportRequest
from app.services.assessment_runtime import calculate_work_progress, execution_coverage_summary
from app.services.celery_app import (
    _ingest_scan_results,
    _preserve_terminal_scan_outputs,
    _scan_stage_outcome_from_line,
    _seal_worker_evidence,
)
from app.services.scan_provenance import _redact, build_tool_execution_manifest
from app.services.scan_result_ingestion import (
    _screenshot_evidence_by_url,
    _terminal_evidence_by_finding_key,
    finding_resolution_eligible,
    finding_scope_signature,
)
from app.services.report_jobs import (
    _automatic_report_needs_queue,
    automatic_report_id,
    _terminal_report_needs_refresh,
    generate_forensic_evidence_bundle,
)
from app.services.scan_document_report import (
    _finding_screenshot,
    _finding_terminal_screenshot,
    _tool_terminal_screenshots,
    _verified_runtime_screenshots,
    generate_scan_docx,
    generate_scan_pdf,
)


class WeightedProgressTests(unittest.TestCase):
    @patch("app.services.celery_app._purge_runtime_web_auth_secrets")
    @patch("app.services.celery_app._seal_worker_evidence", return_value={"status": "sealed"})
    @patch("app.services.celery_app._ingest_scan_results", return_value={"findings_added": 2})
    @patch("app.services.celery_app._capture_finding_screenshots", side_effect=RuntimeError("capture unavailable"))
    def test_terminal_ingestion_survives_screenshot_failure(
        self, capture, ingest, seal, purge,
    ):
        result = _preserve_terminal_scan_outputs(
            org_id="org", assessment_id="assessment", scan_id="scan",
            session_dir="/tmp/scan", task_id="task", command=["scanner"],
            log_lines=["partial output"], status="failed", exit_code=1,
        )

        ingest.assert_called_once()
        seal.assert_called_once()
        purge.assert_called_once()
        self.assertEqual(result["ingestion_result"]["findings_added"], 2)
        self.assertIn("screenshot capture failed", result["errors"][0].lower())

    def test_parses_recoverable_stage_timeout_marker(self):
        self.assertEqual(
            _scan_stage_outcome_from_line(
                "[!] [stage-timeout] api_security: exceeded the 180s budget; remaining work was skipped"
            ),
            ("api_security", "timed_out", "exceeded the 180s budget; remaining work was skipped"),
        )

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
        self.assertEqual(units, {"total": 30, "completed": 11, "successful": 10, "exceptions": 0, "target_count": 10, "planned_stages": 3})
        self.assertEqual(progress, 36)

    def test_terminal_label_does_not_invent_completed_units(self):
        progress, units = calculate_work_progress(
            {"execution_policy": {"target_count": 4}, "execution_manifest": [{"planned": True, "status": "running"}]},
            90,
            "completed",
        )
        self.assertEqual((progress, units["completed"], units["total"]), (25, 1, 4))

    def test_coverage_requires_every_planned_stage_to_succeed(self):
        coverage = execution_coverage_summary({"execution_manifest": [
            {"planned": True, "status": "completed"},
            {"planned": True, "status": "timed_out"},
            {"planned": False, "status": "skipped"},
        ]})
        self.assertEqual((coverage["successful"], coverage["planned"], coverage["exceptions"]), (1, 2, 1))
        self.assertFalse(coverage["complete"])


class TerminalIngestionTests(unittest.TestCase):
    def test_terminal_ingestion_normalizes_dispatches_and_archives_partial_results(self):
        async def ingest(**kwargs):
            return {"findings_added": 2, "session_dir": kwargs["session_dir"]}

        async def dispatch(org_id, scan_id):
            return {"org_id": org_id, "scan_id": scan_id}

        with (
            patch("app.services.scan_result_ingestion.ingest_assessment_scan", side_effect=ingest),
            patch("app.services.eventing.dispatch_scan_exposure_events", side_effect=dispatch),
            patch("app.services.artifact_storage.archive_scan_directory", return_value="archive/key"),
        ):
            result = _ingest_scan_results(
                org_id="org", assessment_id="assessment", scan_id="scan", session_dir="/tmp/results",
            )

        self.assertEqual(result["findings_added"], 2)
        self.assertEqual(result["events_dispatched"]["scan_id"], "scan")
        self.assertEqual(result["artifact_object_key"], "archive/key")


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

    def test_accepts_scan_scoped_docx_report(self):
        request = ReportRequest(
            assessment_id="00000000-0000-0000-0000-000000000001",
            scan_id="00000000-0000-0000-0000-000000000002",
            format="docx",
        )
        self.assertEqual(request.format, "docx")

    def test_rejects_unscoped_client_deliverables(self):
        for report_format in ("pdf", "docx", "evidence"):
            with self.subTest(report_format=report_format), self.assertRaises(ValidationError):
                ReportRequest(
                    assessment_id="00000000-0000-0000-0000-000000000001",
                    format=report_format,
                )


class AutomaticDocumentReportTests(unittest.TestCase):
    def test_tool_terminal_capture_requires_registered_output_hash(self):
        png = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDAT\x08\xd7c\xf8\xcf\xc0\x00\x00"
            b"\x03\x01\x01\x00\x18\xdd\x8d\xb1\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "tool_logs" / "nmap-run.log"
            source.parent.mkdir()
            source.write_text("80/tcp open http\n", encoding="utf-8")
            screenshot = root / "forensic" / "tool-run-screenshots-task" / "tool-terminal-001-nmap.png"
            screenshot.parent.mkdir(parents=True)
            screenshot.write_bytes(png)
            metadata = {
                "capture_type": "xvfb_xterm_tool_output",
                "evidence_id": "3b653a1a-cafa-4f4d-af3e-8ddf886b9174",
                "tool_run_id": "nmap-1",
                "tool": "nmap",
                "tool_status": "completed",
                "source_artifact": "tool_logs/nmap-run.log",
                "source_artifact_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "screenshot_sha256": hashlib.sha256(png).hexdigest(),
            }
            sidecar = screenshot.with_suffix(".png.json")
            sidecar.write_text(json.dumps(metadata), encoding="utf-8")
            artifacts = [
                SimpleNamespace(path=str(screenshot.relative_to(root)), sha256=hashlib.sha256(png).hexdigest()),
                SimpleNamespace(path=str(sidecar.relative_to(root)), sha256=hashlib.sha256(sidecar.read_bytes()).hexdigest()),
                SimpleNamespace(path="tool_logs/nmap-run.log", sha256=metadata["source_artifact_sha256"]),
            ]
            verified = _verified_runtime_screenshots(SimpleNamespace(session_dir=directory, artifacts=artifacts))
            accepted = _tool_terminal_screenshots(verified, artifacts)
            artifacts[-1].sha256 = "0" * 64
            rejected = _tool_terminal_screenshots(verified, artifacts)

        self.assertEqual(accepted[0]["metadata"]["tool_run_id"], "nmap-1")
        self.assertEqual(rejected, [])

    def test_finding_terminal_capture_requires_matching_image_and_source_hashes(self):
        png = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDAT\x08\xd7c\xf8\xcf\xc0\x00\x00"
            b"\x03\x01\x01\x00\x18\xdd\x8d\xb1\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "nuclei_results.txt"
            source.write_text("[medium] cookies-without-secure http://example.test/\n", encoding="utf-8")
            screenshot = root / "forensic" / "finding-screenshots-task" / "finding-terminal-001-test.png"
            screenshot.parent.mkdir(parents=True)
            screenshot.write_bytes(png)
            evidence_id = "5b7abfe8-173c-43e8-923e-4d3a00ec3a48"
            metadata = {
                "capture_type": "xvfb_xterm_finding_source",
                "evidence_id": evidence_id,
                "finding_key": "nuclei|cookies-without-secure|http://example.test/|Cookie missing Secure",
                "source_artifact": "nuclei_results.txt",
                "source_artifact_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "screenshot_sha256": hashlib.sha256(png).hexdigest(),
            }
            sidecar = screenshot.with_suffix(".png.json")
            sidecar.write_text(json.dumps(metadata), encoding="utf-8")
            artifacts = [
                SimpleNamespace(path=str(screenshot.relative_to(root)), sha256=hashlib.sha256(png).hexdigest()),
                SimpleNamespace(path=str(sidecar.relative_to(root)), sha256=hashlib.sha256(sidecar.read_bytes()).hexdigest()),
            ]
            verified = _verified_runtime_screenshots(SimpleNamespace(session_dir=directory, artifacts=artifacts))
            indexed = _terminal_evidence_by_finding_key(root)
            finding = SimpleNamespace(evidence_metadata={
                "terminal_evidence_id": evidence_id,
                "terminal_screenshot_sha256": hashlib.sha256(png).hexdigest(),
                "source_artifact": "nuclei_results.txt",
                "source_artifact_sha256": metadata["source_artifact_sha256"],
            })
            matched = _finding_terminal_screenshot(finding, verified)
            source.write_text("tampered\n", encoding="utf-8")
            rejected = _terminal_evidence_by_finding_key(root)

        self.assertEqual(indexed[metadata["finding_key"]]["evidence_id"], evidence_id)
        self.assertEqual(matched["sha256"], hashlib.sha256(png).hexdigest())
        self.assertEqual(rejected, {})

    def test_runtime_screenshot_requires_matching_ingestion_hash(self):
        png = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDAT\x08\xd7c\xf8\xcf\xc0\x00\x00"
            b"\x03\x01\x01\x00\x18\xdd\x8d\xb1\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "forensic", "finding-screenshots-task", "playwright-001-admin.png")
            path.parent.mkdir(parents=True)
            path.write_bytes(png)
            sidecar_path = Path(f"{path}.json")
            evidence_id = "2a9996c7-b074-41e2-b38f-dff91b53906e"
            sidecar = json.dumps({
                "evidence_id": evidence_id,
                "requested_url": "https://example.test/admin",
                "final_url": "https://example.test/admin",
                "screenshot_sha256": hashlib.sha256(png).hexdigest(),
            }).encode()
            sidecar_path.write_bytes(sidecar)
            artifact = SimpleNamespace(path="forensic/finding-screenshots-task/playwright-001-admin.png", sha256=hashlib.sha256(png).hexdigest())
            sidecar_artifact = SimpleNamespace(
                path="forensic/finding-screenshots-task/playwright-001-admin.png.json", sha256=hashlib.sha256(sidecar).hexdigest()
            )
            scan = SimpleNamespace(session_dir=directory, artifacts=[artifact, sidecar_artifact])
            verified = _verified_runtime_screenshots(scan)
            matched = _finding_screenshot(SimpleNamespace(
                url="https://different.example.test/admin",
                evidence_metadata={"screenshot_evidence_id": evidence_id},
            ), verified)
            indexed = _screenshot_evidence_by_url(Path(directory))
            artifact.sha256 = "0" * 64
            rejected = _verified_runtime_screenshots(scan)

        self.assertEqual(verified[0]["content"], png)
        self.assertEqual(matched["sha256"], hashlib.sha256(png).hexdigest())
        self.assertEqual(indexed["https://example.test/admin"]["evidence_id"], evidence_id)
        self.assertEqual(rejected, [])

    def test_worker_evidence_is_sealed_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            first = _seal_worker_evidence(
                directory, scan_id="scan-1", task_id="task-1", command=["scanner", "target"],
                log_lines=["original output"], status="completed", exit_code=0,
            )
            second = _seal_worker_evidence(
                directory, scan_id="scan-1", task_id="task-1", command=["scanner", "target"],
                log_lines=["changed output"], status="completed", exit_code=0,
            )
            transcript = Path(directory, "forensic", "worker-transcript-task-1.log").read_text()

        self.assertEqual(first["status"], "sealed")
        self.assertEqual(second["status"], "already_sealed")
        self.assertEqual(transcript, "original output\n")

    def test_automatic_report_id_is_stable_per_scan(self):
        scan_id = uuid.uuid4()
        self.assertEqual(automatic_report_id(scan_id), automatic_report_id(str(scan_id)))
        self.assertNotEqual(automatic_report_id(scan_id), automatic_report_id(uuid.uuid4()))
        self.assertNotEqual(automatic_report_id(scan_id, "docx"), automatic_report_id(scan_id, "pdf"))
        self.assertNotEqual(automatic_report_id(scan_id, "pdf"), automatic_report_id(scan_id, "evidence"))

    def test_recovered_scan_refreshes_prior_terminal_report(self):
        report = SimpleNamespace(status="ready", scope={"terminal_status": "failed"})

        self.assertTrue(_terminal_report_needs_refresh(report, "recovered"))
        self.assertFalse(_terminal_report_needs_refresh(report, "historical"))

    def test_stale_automatic_report_is_requeued_but_active_one_is_not(self):
        now = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
        report = SimpleNamespace(
            status="generating",
            scope={"queued_at": (now - timedelta(minutes=16)).isoformat(), "generation_attempt": 1},
            created_at=now - timedelta(minutes=16),
            updated_at=now - timedelta(minutes=16),
        )
        self.assertTrue(_automatic_report_needs_queue(report, now))
        report.scope["queued_at"] = (now - timedelta(minutes=2)).isoformat()
        self.assertFalse(_automatic_report_needs_queue(report, now))

    def test_automatic_report_retry_is_bounded(self):
        report = SimpleNamespace(
            status="failed",
            scope={"generation_attempt": 3},
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        self.assertFalse(_automatic_report_needs_queue(report))

    def test_generates_valid_scan_docx_with_findings_and_remediation(self):
        started = datetime(2026, 9, 9, 10, 0, tzinfo=timezone.utc)
        assessment = SimpleNamespace(
            name="Authorized perimeter review", target="example.test", target_type="domain", scan_mode="light",
        )
        scan = SimpleNamespace(
            id=uuid.uuid4(), status="completed", started_at=started,
            completed_at=started + timedelta(minutes=4), current_phase="completed",
            scan_metadata={
                "telemetry": {"output_silence_seconds": 2},
                "execution_manifest": [
                    {"id": "enumeration", "label": "Enumeration", "planned": True, "status": "completed", "attempts": 1},
                    {"id": "crawler", "label": "Web crawling", "planned": True, "status": "skipped", "attempts": 0,
                     "message": "Crawler prerequisites were unavailable."},
                    {"id": "cloud", "label": "Cloud exposure", "planned": False, "status": "skipped", "attempts": 0},
                ],
            },
            artifacts=[SimpleNamespace(
                path="forensic/worker-transcript.log", size_bytes=42,
                sha256="a" * 64, provenance={"scanner_image": "test-image"},
            )], error_message=None,
            raw_log=(
                "\x1b[32m[+] Scan session started for example.test\x1b[0m\n"
                "Authorization: Bearer proof-of-concept-secret\n"
                "[+] waybackurls completed and evidence was retained\n"
                "[+] worker completed the authorized stage\n"
            ),
        )
        finding = SimpleNamespace(
            severity="HIGH", title="Exposed administrative interface", url="https://admin.example.test",
            asset_id=None, source="waybackurls", template_id="admin-interface",
            evidence="HTTP 200 response exposed the administrative interface.",
            evidence_metadata={
                "remediation": "Restrict the interface to the approved management network.",
                "source_artifact": "waybackurls.txt",
                "reproduction_steps": ["Confirm that the recorded administrative path still returns the observed response."],
            },
        )
        tool = SimpleNamespace(
            tool="waybackurls", status="timed_out", duration_ms=1200, exit_code=124,
            command="waybackurls example.test", output_excerpt="https://admin.example.test",
        )

        content = generate_scan_docx(assessment, scan, [], [finding], [tool])

        self.assertTrue(content.startswith(b"PK"))
        with zipfile.ZipFile(BytesIO(content)) as archive:
            self.assertIsNone(archive.testzip())
            document_xml = archive.read("word/document.xml").decode("utf-8")
        self.assertIn("Security Assessment Scan Report", document_xml)
        self.assertIn("Executive Summary", document_xml)
        self.assertIn("Document History", document_xml)
        self.assertIn("Point Of Contact", document_xml)
        self.assertIn("Project Scope", document_xml)
        self.assertIn("Profiling", document_xml)
        self.assertIn("Detailed Findings", document_xml)
        self.assertIn("Medium Risk Findings", document_xml)
        self.assertIn("Low Risk Findings", document_xml)
        self.assertIn("Appendix A Engagement Methodology", document_xml)
        self.assertIn("Appendix B Risk Methodology", document_xml)
        self.assertIn("Appendix C Testing Methodologies", document_xml)
        self.assertIn("Observed Attack Surface", document_xml)
        self.assertIn("Exposed administrative interface", document_xml)
        self.assertIn("Restrict the interface", document_xml)
        self.assertIn("Coverage Limitations", document_xml)
        self.assertIn("Web crawling", document_xml)
        self.assertIn("Crawler prerequisites were unavailable", document_xml)
        self.assertIn("Cloud exposure", document_xml)
        self.assertIn("Not planned", document_xml)
        self.assertIn("waybackurls", document_xml)
        self.assertIn("Timed Out", document_xml)
        self.assertIn("Evidence Integrity", document_xml)
        self.assertIn("Original Screenshot Evidence", document_xml)
        self.assertIn("EVIDENCE FAILURE", document_xml)
        self.assertIn("Proof of Concept and Reproduction", document_xml)
        self.assertIn("forensic/worker-transcript.log", document_xml)
        self.assertIn("aaaaaaaaaaaaaaaa", document_xml)
        self.assertIn("Reproducible from captured command", document_xml)
        self.assertIn("waybackurls example.test", document_xml)
        self.assertIn("waybackurls.txt", document_xml)
        self.assertNotIn("proof-of-concept-secret", document_xml)

        pdf = generate_scan_pdf(assessment, scan, [], [finding], [tool])
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertGreater(len(pdf), 2000)

        scan.scan_metadata["finding_screenshot_capture"] = {"status": "incomplete", "requested": 1, "captured": 0}
        scan.status = "failed"
        failed_content = generate_scan_docx(assessment, scan, [], [finding], [tool])
        with zipfile.ZipFile(BytesIO(failed_content)) as archive:
            failed_xml = archive.read("word/document.xml").decode("utf-8")
        self.assertIn("Partial", failed_xml)
        self.assertIn("Screenshot Evidence Coverage", failed_xml)
        self.assertIn("Original screenshot unavailable", failed_xml)

    def test_forensic_bundle_includes_only_hash_verified_original_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "tool-output.txt"
            original = b"unaltered scanner output\n"
            source.write_bytes(original)
            digest = hashlib.sha256(original).hexdigest()
            started = datetime(2026, 9, 9, 10, 0, tzinfo=timezone.utc)
            assessment = SimpleNamespace(id=uuid.uuid4(), name="Evidence test", target="example.test")
            scan = SimpleNamespace(
                id=uuid.uuid4(), status="completed", started_at=started,
                completed_at=started + timedelta(minutes=1), session_dir=directory,
                scan_metadata={"scanner_image": "sha256:image"}, raw_log="exact database worker record\n",
            )
            artifact = SimpleNamespace(
                id=uuid.uuid4(), path="tool-output.txt", artifact_type="scanner_output",
                mime_type="text/plain", size_bytes=len(original), sha256=digest, retained=True,
                created_at=started, provenance={"scanner_image": "sha256:image"},
            )
            secret_path = root / "web-auth-cookie.txt"
            secret_path.write_text("session=must-not-be-archived", encoding="utf-8")
            secret_artifact = SimpleNamespace(
                id=uuid.uuid4(), path="web-auth-cookie.txt", artifact_type="evidence",
                mime_type="text/plain", size_bytes=secret_path.stat().st_size,
                sha256=hashlib.sha256(secret_path.read_bytes()).hexdigest(), retained=True,
                created_at=started, provenance={},
            )
            tool = SimpleNamespace(
                id=uuid.uuid4(), external_id="run-1", tool="nmap", tool_version="7.95",
                status="completed", exit_code=0, command="nmap example.test", output_file="tool-output.txt",
                output_excerpt="scan complete", started_at=started,
                completed_at=started + timedelta(seconds=2), duration_ms=2000,
                provenance={"worker": "scanner-1"},
            )

            content = generate_forensic_evidence_bundle(assessment, scan, [tool], [artifact, secret_artifact])

        with zipfile.ZipFile(BytesIO(content)) as archive:
            self.assertEqual(archive.read("artifacts/tool-output.txt"), original)
            index = json.loads(archive.read("records/artifact-index.json"))
            self.assertEqual(index[0]["bundle_status"], "included_and_hash_verified")
            sums = archive.read("SHA256SUMS").decode("ascii")
            self.assertIn(digest, sums)
            self.assertNotIn(".png", "\n".join(archive.namelist()))
            self.assertNotIn("artifacts/web-auth-cookie.txt", archive.namelist())
            self.assertEqual(index[1]["bundle_status"], "excluded_sensitive_runtime_material")


if __name__ == "__main__":
    unittest.main()
