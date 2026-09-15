import io
import json
import unittest
import zipfile
from datetime import datetime, timezone
from unittest.mock import patch

from PIL import Image

from app.reporting import (
    REPORT_SECTIONS,
    _coverage_family_rows,
    _curated_findings,
    _display_url,
    _execution_exception_rows,
    _execution_exception_summary,
    _finding_business_impact,
    _finding_reproduction,
    _finding_traceability_rows,
    _assessment_perspective,
    _finding_coverage_statement,
    _http_evidence_sections,
    _protocol_breakdown,
    _protocol_text,
    _profile_evidence_sections,
    _screenshot_scope_error,
    _screenshot_segments,
    _overall_risk,
    report_status_for_scan,
    render_docx,
    render_pdf,
)


class ReportingTests(unittest.TestCase):
    def context(self) -> dict:
        now = datetime.now(timezone.utc)
        return {
            "assessment": {"id": "assessment-1", "name": "Authorized DVWA Review", "target": "http://dvwa.lab.internal", "mode": "light"},
            "scan": {"id": "scan-1", "status": "partial"},
            "stages": [
                {"position": 0, "adapter": "scope_preflight", "required": True, "status": "succeeded", "error_detail": None},
                {"position": 1, "adapter": "nuclei_baseline", "required": True, "status": "timed_out", "error_detail": "bounded timeout"},
            ],
            "findings": [{
                "id": "finding-1", "title": "Missing security header", "severity": "medium",
                "confidence": 95, "target": "http://dvwa.lab.internal", "description": "A required header was absent.",
                "business_impact": "Browser-side defenses may be weakened.",
                "remediation": "Configure the required response header.",
                "evidence": {
                    "source_sha256": "a" * 64,
                    "requires_screenshot": False,
                    "template_id": "missing-header",
                    "request": "GET / HTTP/1.1\r\nHost: dvwa.lab.internal\r\n\r\n",
                    "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>fixture</html>",
                },
            }],
            "artifacts": [{"id": "artifact-1", "storage_key": "scan/source.json", "kind": "raw_tool_output", "sha256": "a" * 64, "size_bytes": 128, "captured_at": now}],
            "artifacts_by_id": {}, "report_status": "partial", "generated_at": now.isoformat(),
            "coverage": [
                {"family": "attack_surface", "required": True, "status": "completed"},
                {"family": "service_tls_http_configuration", "required": True, "status": "timed_out"},
            ],
        }

    def test_incomplete_coverage_never_returns_a_clean_result(self) -> None:
        self.assertEqual(
            _overall_risk([], "partial", [{"required": True, "status": "timed_out"}]),
            "INCONCLUSIVE - COVERAGE INCOMPLETE",
        )

    def test_candidate_is_not_reported_as_confirmed_risk(self) -> None:
        finding = {"severity": "critical", "validation_status": "candidate"}
        self.assertEqual(
            _overall_risk([finding], "complete", [{"required": True, "status": "completed"}]),
            "POTENTIAL RISK - REVIEW REQUIRED",
        )

    def test_partial_candidate_discloses_its_coverage_limit(self) -> None:
        finding = {"severity": "critical", "validation_status": "candidate"}
        self.assertEqual(
            _overall_risk([finding], "partial", [{"required": True, "status": "timed_out"}]),
            "POTENTIAL RISK - REVIEW REQUIRED - COVERAGE INCOMPLETE",
        )

    def test_docx_contains_required_client_sections(self) -> None:
        content = render_docx(self.context())
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            document_xml = archive.read("word/document.xml").decode("utf-8")
        for section in REPORT_SECTIONS:
            self.assertIn(section, document_xml)
        self.assertIn("Project Scope", document_xml)
        self.assertIn("Profiling", document_xml)
        self.assertIn("Informational Findings", document_xml)
        self.assertIn("bounded timeout", document_xml)
        self.assertIn("Business Impact", document_xml)
        self.assertIn("Evidence Traceability", document_xml)
        self.assertIn("HTTP Request Summary", document_xml)
        self.assertIn("HTTP Response Summary", document_xml)
        self.assertIn("HTTP Request Evidence", document_xml)
        self.assertIn("HTTP Response Evidence", document_xml)
        self.assertIn("GET / HTTP/1.1", document_xml)

    def test_http_evidence_is_separated_and_summarized(self) -> None:
        evidence = self.context()["findings"][0]["evidence"]
        view = _http_evidence_sections(evidence)
        self.assertEqual(view["request_line"], "GET / HTTP/1.1")
        self.assertEqual(view["response_line"], "HTTP/1.1 200 OK")
        self.assertEqual(view["request_breakdown"]["header_count"], 1)
        self.assertEqual(view["response_breakdown"]["header_count"], 1)
        self.assertNotIn("request", {label.lower() for label, _ in view["metadata"]})

    def test_protocol_breakdown_extracts_start_line_headers_and_body_preview(self) -> None:
        breakdown = _protocol_breakdown("POST /login HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{\"user\":\"demo\"}")
        self.assertEqual(breakdown["start_line"], "POST /login HTTP/1.1")
        self.assertEqual(breakdown["header_count"], 2)
        self.assertTrue(breakdown["body_present"])
        self.assertIn("application/json", dict(breakdown["headers"])["Content-Type"])
        self.assertIn("\"user\":\"demo\"", breakdown["body_preview"])

    def test_structured_source_exchange_is_presented_without_reconstruction(self) -> None:
        payload = {
            "request": {"method": "GET", "url": "http://dvwa.lab.internal/", "headers": {"user-agent": "ExposureScopeX/3.0"}},
            "final_url": "http://dvwa.lab.internal/", "status": 200,
            "headers": {"content-type": "text/html"}, "body_sha256": "b" * 64,
        }
        view = _http_evidence_sections(self.context()["findings"][0]["evidence"], payload)
        captured = dict(view["captured_exchange"])
        self.assertEqual(captured["Request Method"], "GET")
        self.assertEqual(captured["Response Status"], "200")
        self.assertIn("content-type", captured["Response Headers"])

    def test_report_exchange_redacts_credential_bearing_headers(self) -> None:
        payload = {
            "request": {"method": "GET", "url": "http://dvwa.lab.internal", "headers": {"Cookie": "PHPSESSID=request-secret"}},
            "status": 200,
            "headers": {"set-cookie": "PHPSESSID=response-secret", "content-type": "text/html"},
        }
        captured = dict(_http_evidence_sections({}, payload)["captured_exchange"])
        self.assertNotIn("request-secret", captured["Request Headers"])
        self.assertNotIn("response-secret", captured["Response Headers"])
        self.assertIn("[REDACTED]", captured["Response Headers"])

    def test_known_finding_has_specific_impact_and_reproduction(self) -> None:
        finding = self.context()["findings"][0]
        finding["canonical_observation_key"] = "http.header.absent:content-security-policy"
        finding["evidence"] = {
            "evidence_type": "http_response_header_absence",
            "header_name": "content-security-policy",
            "requested_url": finding["target"],
            "source_sha256": "a" * 64,
        }
        self.assertIn("does not create cross-site scripting by itself", _finding_business_impact(finding))
        reproduction = " ".join(_finding_reproduction(finding))
        self.assertIn("case-insensitively", reproduction)
        self.assertIn("curl -sS", reproduction)
        self.assertIn("chain-of-custody", reproduction)

    def test_report_perspective_is_not_authenticated_without_a_test_session(self) -> None:
        self.assertEqual(_assessment_perspective(self.context()), "Unauthenticated external web")
        context = self.context()
        context["authentication_configured"] = True
        self.assertEqual(_assessment_perspective(context), "Authorized authenticated web")

    def test_out_of_scope_screenshot_is_explicitly_excluded(self) -> None:
        finding = self.context()["findings"][0]
        finding["evidence"]["screenshot_artifact_id"] = "browser-1"
        artifacts = {"browser-1": {"metadata": {"final_url": "https://forsale.example.test/"}}}
        message = _screenshot_scope_error(finding, artifacts)
        self.assertIsNotNone(message)
        self.assertIn("outside the authorized origin", message)

    def test_single_response_finding_states_its_coverage_boundary(self) -> None:
        finding = self.context()["findings"][0]
        finding["evidence"].update({"coverage_scope": "single_response", "coverage_target": finding["target"]})
        statement = _finding_coverage_statement(finding)
        self.assertIn("recorded response", statement)
        self.assertIn("other routes", statement)

    def test_traceability_rows_include_source_and_screenshot_admissibility(self) -> None:
        finding = self.context()["findings"][0]
        finding["validation_status"] = "confirmed"
        finding["evidence_integrity"] = "passed"
        finding["evidence"].update({
            "evidence_type": "http_response_header_absence",
            "source_artifact_id": "artifact-1",
            "source_sha256": "a" * 64,
            "screenshot_artifact_id": "browser-1",
            "screenshot_sha256": "b" * 64,
        })
        artifacts = {
            "artifact-1": {"kind": "raw_tool_output"},
            "browser-1": {"metadata": {"final_url": "http://dvwa.lab.internal"}},
        }
        rows = dict(_finding_traceability_rows(finding, artifacts))
        self.assertEqual(rows["Finding assurance"], "CONFIRMED")
        self.assertEqual(rows["Evidence integrity"], "PASSED")
        self.assertEqual(rows["Source artifact kind"], "raw_tool_output")
        self.assertEqual(rows["Screenshot admissibility"], "ADMISSIBLE")

    def test_protocol_evidence_is_bounded_without_false_truncation(self) -> None:
        self.assertEqual(_protocol_text("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"), "GET / HTTP/1.1\nHost: example.test")
        excerpt = _protocol_text("HTTP/1.1 200 OK\r\n\r\n<title>proof</title>" + "x" * 8000)
        self.assertIn("<title>proof</title>", excerpt)
        self.assertIn("complete", excerpt)

    def test_generic_header_observation_is_suppressed(self) -> None:
        specific = dict(self.context()["findings"][0])
        specific["evidence"] = {"evidence_type": "http_response_header_absence"}
        duplicate = dict(specific, id="finding-2", severity="info", title="HTTP Missing Security Headers")
        risks, observations, suppressed = _curated_findings([specific, duplicate])
        self.assertEqual(len(risks), 1)
        self.assertEqual(observations, [])
        self.assertEqual(len(suppressed), 1)

    def test_pdf_is_valid_and_discloses_partial_status(self) -> None:
        content = render_pdf(self.context())
        self.assertTrue(content.startswith(b"%PDF-"))
        self.assertGreater(len(content), 2000)

    def test_report_status_mapping_preserves_terminal_truth(self) -> None:
        self.assertEqual(report_status_for_scan("complete"), "final")
        self.assertEqual(report_status_for_scan("partial"), "partial")
        self.assertEqual(report_status_for_scan("failed"), "failed")
        self.assertEqual(report_status_for_scan("cancelled"), "cancelled")
        self.assertEqual(report_status_for_scan("blocked"), "blocked")
        with self.assertRaises(ValueError):
            report_status_for_scan("running")

    def test_document_history_records_both_report_and_plan_status(self) -> None:
        context = self.context()
        context["scan"]["status"] = "failed"
        context["report_status"] = report_status_for_scan("failed")
        content = render_docx(context)
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            document_xml = archive.read("word/document.xml").decode("utf-8")
        self.assertIn("Report Status", document_xml)
        self.assertIn("Plan Status", document_xml)
        self.assertIn("FAILED", document_xml)

    def test_reports_do_not_claim_independently_validated_scope_without_a_scope_file(self) -> None:
        content = render_docx(self.context())
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            document_xml = archive.read("word/document.xml").decode("utf-8")
        self.assertIn("Scope-Bounded Security Assessment Report", document_xml)
        self.assertIn("OPERATOR-ATTESTED SCOPE", document_xml)
        self.assertNotIn("Authorized Security Assessment Report", document_xml)

    def test_terminal_captures_remain_in_the_technical_bundle_not_the_decision_report(self) -> None:
        context = self.context()
        context["artifacts"].append({
            "id": "terminal-1", "storage_key": "scan/nuclei-terminal.png", "kind": "terminal_capture",
            "media_type": "image/png", "sha256": "b" * 64, "size_bytes": 128, "captured_at": datetime.now(timezone.utc),
        })
        content = render_docx(context)
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            document_xml = archive.read("word/document.xml").decode("utf-8")
        self.assertIn("Full terminal transcripts and captures are retained in the Technical Evidence ZIP", document_xml)
        self.assertNotIn("Terminal Evidence Exhibits", document_xml)

    def test_coverage_family_rows_summarize_completed_and_exceptional_cases(self) -> None:
        rows = _coverage_family_rows(self.context()["coverage"])
        self.assertIn(["Attack Surface", 1, 1, 0, 0], rows)
        self.assertIn(["Service TLS HTTP Configuration", 1, 0, 1, 0], rows)

    def test_coverage_family_rows_accept_stage_fallback_records(self) -> None:
        rows = _coverage_family_rows([
            {"adapter": "scope_preflight", "required": True, "status": "succeeded"},
            {"adapter": "nuclei_baseline", "required": True, "status": "succeeded"},
        ])
        self.assertIn(["Scope Authorization", 1, 1, 0, 0], rows)
        self.assertIn(["Attack Surface", 1, 1, 0, 0], rows)
        self.assertFalse(any(row[0] == "Unclassified" for row in rows))

    def test_report_display_normalizes_duplicate_url_slashes(self) -> None:
        self.assertEqual(_display_url("http://dvwa.lab.internal//phpinfo.php"), "http://dvwa.lab.internal/phpinfo.php")

    def test_shared_source_exchange_is_rendered_once_and_referenced(self) -> None:
        context = self.context()
        first = context["findings"][0]
        first["evidence"] = {
            "evidence_type": "http_response_header_absence",
            "header_name": "content-security-policy",
            "source_artifact_id": "artifact-1",
            "source_sha256": "a" * 64,
            "requested_url": first["target"],
        }
        second = {**first, "id": "finding-2", "title": "MIME protection missing", "evidence": {**first["evidence"], "header_name": "x-content-type-options"}}
        context["findings"] = [first, second]
        source = {
            "request": {"method": "GET", "url": first["target"], "headers": {"Cookie": "PHPSESSID=secret"}},
            "status": 200,
            "headers": {"set-cookie": "PHPSESSID=response-secret", "content-type": "text/html"},
        }
        with patch("app.reporting._source_payload", return_value=source):
            content = render_docx(context)
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            document_xml = archive.read("word/document.xml").decode("utf-8")
        self.assertEqual(document_xml.count("Protocol Evidence Exhibit P-001"), 1)
        self.assertIn("Shared Protocol Evidence", document_xml)
        self.assertNotIn("PHPSESSID=secret", document_xml)
        self.assertNotIn("response-secret", document_xml)

    def test_execution_exception_summary_and_rows_disclose_degraded_stages(self) -> None:
        context = self.context()
        context["stages"].append({
            "position": 2,
            "adapter": "authenticated_crawl",
            "required": True,
            "status": "blocked",
            "error_detail": "Blocked because scope preflight did not succeed",
        })
        summary = _execution_exception_summary(context["stages"])
        rows = _execution_exception_rows(context["stages"])
        self.assertIn("timed_out=1", summary)
        self.assertIn("blocked=1", summary)
        self.assertIn([3, "authenticated_crawl", "blocked", "Blocked because scope preflight did not succeed"], rows)

    def test_medium_profile_evidence_sections_are_exposed(self) -> None:
        now = datetime.now(timezone.utc)
        context = self.context()
        context["assessment"]["mode"] = "medium"
        context["artifacts"] = [
            {"id": "a1", "kind": "application_surface_inventory", "storage_key": "surface.json", "sha256": "1" * 64, "size_bytes": 1, "captured_at": now},
            {"id": "a2", "kind": "session_review", "storage_key": "session.json", "sha256": "2" * 64, "size_bytes": 1, "captured_at": now},
            {"id": "a3", "kind": "api_contract_review", "storage_key": "api.json", "sha256": "3" * 64, "size_bytes": 1, "captured_at": now},
        ]

        payloads = {
            "application_surface_inventory": {
                "pages": [{"status": 200, "forms": [{"fields": [{"name": "username"}, {"name": "password"}]}], "scripts": ["app.js"]}],
            },
            "session_review": {
                "authentication": {"configured": True, "verified": True},
                "cookies": [{"name": "PHPSESSID", "httpOnly": False, "secure": False}],
            },
            "api_contract_review": {
                "tested_paths": ["/openapi.json", "/swagger.json"],
                "contracts": [{"path_count": 5, "security_schemes": ["cookieAuth", "bearerAuth"]}],
            },
        }

        def fake_load(item):
            payload = payloads.get(item["kind"])
            return json.dumps(payload).encode("utf-8") if payload else None

        with patch("app.reporting._load_artifact_bytes", side_effect=fake_load):
            sections = _profile_evidence_sections(context)
        titles = [section["title"] for section in sections]
        self.assertIn("Application Surface Inventory", titles)
        self.assertIn("Authenticated Session Review", titles)
        self.assertIn("Published API Contract Review", titles)

    def test_tall_screenshot_is_split_without_losing_pixels(self) -> None:
        source = Image.new("RGB", (100, 400), "white")
        payload = io.BytesIO()
        source.save(payload, format="PNG")
        segments = _screenshot_segments(payload.getvalue())
        dimensions = []
        for segment in segments:
            with Image.open(io.BytesIO(segment)) as image:
                dimensions.append(image.size)
        self.assertGreater(len(dimensions), 1)
        self.assertTrue(all(width == 100 for width, _ in dimensions))
        self.assertEqual(sum(height for _, height in dimensions), 400)


if __name__ == "__main__":
    unittest.main()
