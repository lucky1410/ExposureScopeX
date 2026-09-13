from __future__ import annotations

import ast
import hashlib
import io
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.evaluation import EvaluationRequest, evaluate
from app.evaluator_reporting import (
    evaluation_source_sha256,
    render_evaluation_docx,
    render_evaluation_pdf,
    report_context,
)


class EvaluatorReportingTests(unittest.TestCase):
    def evaluation(self) -> dict:
        payload = EvaluationRequest.model_validate_json(
            (self.fixture_root() / "smoke-1.0.json").read_text(encoding="utf-8")
        )
        return {
            "id": uuid4(),
            "name": payload.name,
            "evaluated_agent_id": payload.agent_id,
            "evaluated_agent_version": payload.subject_version,
            "evaluator_agent_id": "ai_quality_evaluator",
            "evaluator_version": "1.2.0",
            "dataset_version": payload.dataset_version,
            "input_manifest": payload.model_dump(mode="json"),
            "metrics": evaluate(payload),
            "release_decision": "pass",
            "created_at": datetime(2026, 9, 12, tzinfo=timezone.utc),
        }

    @staticmethod
    def fixture_root():
        from pathlib import Path

        return Path(__file__).resolve().parents[2] / "benchmarks" / "evaluator"

    def test_source_digest_is_stable_for_same_evaluation(self) -> None:
        evaluation = self.evaluation()
        self.assertEqual(evaluation_source_sha256(evaluation), evaluation_source_sha256(evaluation))

    def test_docx_and_pdf_include_the_release_decision(self) -> None:
        context = report_context(self.evaluation())
        docx = render_evaluation_docx(context)
        pdf = render_evaluation_pdf(context)

        self.assertTrue(docx.startswith(b"PK"))
        self.assertTrue(pdf.startswith(b"%PDF"))
        with zipfile.ZipFile(io.BytesIO(docx)) as archive:
            document_xml = archive.read("word/document.xml")
        self.assertIn(b"AI Assurance Pre-release Report", document_xml)
        self.assertIn(b"Evaluation Process and Decision Trace", document_xml)
        self.assertIn(b"Release Gate Results", document_xml)
        self.assertIn(b"Robustness Coverage", document_xml)
        self.assertIn(b"Cost and Efficiency", document_xml)
        self.assertIn(b"PASS", document_xml)
        self.assertEqual(hashlib.sha256(docx).hexdigest(), hashlib.sha256(docx).hexdigest())

    def test_download_route_imports_and_uses_report_lookup(self) -> None:
        """Keep the API's report lookup wired to the reporting module."""
        source = (Path(__file__).resolve().parents[1] / "app" / "main.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        imported_names = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module == "evaluator_reporting"
            and node.level == 1
            for alias in node.names
        }
        lookup_calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertIn("get_evaluation_report", imported_names)
        self.assertIn("get_evaluation_report", lookup_calls)
