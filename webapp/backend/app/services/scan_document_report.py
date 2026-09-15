"""Concise Word report generation for terminal scan executions."""

from __future__ import annotations

from collections.abc import Iterable
from html import escape
from io import BytesIO
import hashlib
import re
from pathlib import Path

from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    Image as ReportImage, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)


NAVY = "16324F"
BLUE = "1E5F8A"
PALE_BLUE = "EAF2F7"
PALE_GRAY = "F3F5F7"
TEXT = RGBColor(31, 43, 55)
MUTED = RGBColor(91, 107, 121)
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "8B1E2D", "HIGH": "C2413B", "MEDIUM": "C97A16",
    "LOW": "2F6F8F", "INFO": "607481",
}


def _font(run, *, size: float = 9, bold: bool = False, color: RGBColor = TEXT) -> None:
    run.font.name = "Aptos"
    run._element.get_or_add_rPr().rFonts.set(qn("w:ascii"), "Aptos")
    run._element.get_or_add_rPr().rFonts.set(qn("w:hAnsi"), "Aptos")
    run.font.size = Pt(size)
    run.bold = bold
    run.font.color.rgb = color


def _shade(cell, fill: str) -> None:
    properties = cell._tc.get_or_add_tcPr()
    shading = properties.find(qn("w:shd"))
    if shading is None:
        shading = OxmlElement("w:shd")
        properties.append(shading)
    shading.set(qn("w:fill"), fill)


def _margins(cell, value: int = 85) -> None:
    properties = cell._tc.get_or_add_tcPr()
    margins = properties.first_child_found_in("w:tcMar")
    if margins is None:
        margins = OxmlElement("w:tcMar")
        properties.append(margins)
    for edge in ("top", "start", "bottom", "end"):
        node = margins.find(qn(f"w:{edge}"))
        if node is None:
            node = OxmlElement(f"w:{edge}")
            margins.append(node)
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")


def _heading(document: Document, text: str, level: int = 1) -> None:
    paragraph = document.add_paragraph()
    paragraph.paragraph_format.space_before = Pt(10 if level == 1 else 6)
    paragraph.paragraph_format.space_after = Pt(4)
    paragraph.paragraph_format.keep_with_next = True
    run = paragraph.add_run(text)
    _font(run, size=15 if level == 1 else 11, bold=True,
          color=RGBColor.from_string(NAVY if level == 1 else BLUE))


def _body(document: Document, text: str) -> None:
    paragraph = document.add_paragraph()
    paragraph.paragraph_format.space_after = Pt(5)
    paragraph.paragraph_format.line_spacing = 1.05
    _font(paragraph.add_run(text), size=9)


def _table(document: Document, headers: list[str], rows: Iterable[Iterable[object]], widths: list[float]) -> None:
    table = document.add_table(rows=1, cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    table.style = "Table Grid"
    for index, header in enumerate(headers):
        cell = table.rows[0].cells[index]
        cell.width = Inches(widths[index])
        cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
        _shade(cell, NAVY)
        _margins(cell)
        _font(cell.paragraphs[0].add_run(header), size=8, bold=True, color=RGBColor(255, 255, 255))
    for row_index, values in enumerate(rows):
        cells = table.add_row().cells
        for index, value in enumerate(values):
            cells[index].width = Inches(widths[index])
            cells[index].vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.TOP
            _margins(cells[index])
            if row_index % 2:
                _shade(cells[index], PALE_GRAY)
            _font(cells[index].paragraphs[0].add_run(str(value or "-")), size=7.7)
    document.add_paragraph().paragraph_format.space_after = Pt(1)


def _short(value: object, limit: int = 180) -> str:
    raw = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", str(value or ""))
    raw = re.sub(
        r"(?i)(authorization\s*:\s*(?:bearer|token|basic)\s+)[^\s\"']+",
        r"\1[REDACTED]",
        raw,
    )
    raw = re.sub(r"(?i)(cookie\s*:\s*)[^\r\n]+", r"\1[REDACTED]", raw)
    raw = re.sub(
        r"(?i)(password|secret|api[_-]?key)(\s*[=:]\s*)[^\s,;\"']+",
        r"\1\2[REDACTED]",
        raw,
    )
    safe = "".join(character for character in raw if ord(character) >= 32 or character in "\t\n\r")
    normalized = " ".join(safe.split())
    return normalized if len(normalized) <= limit else f"{normalized[:limit - 1].rstrip()}..."


def _verified_runtime_screenshots(scan) -> list[dict]:
    """Load only original PNG artifacts whose bytes match ingestion-time hashes."""
    session_dir = getattr(scan, "session_dir", None)
    if not session_dir:
        return []
    root = Path(session_dir).resolve()
    if not root.is_dir():
        return []
    artifacts = list(getattr(scan, "artifacts", None) or [])
    artifact_hashes = {str(getattr(item, "path", "")): getattr(item, "sha256", None) for item in artifacts}
    screenshots = []
    for artifact in artifacts:
        artifact_path = str(getattr(artifact, "path", ""))
        if not artifact_path.lower().endswith(".png"):
            continue
        try:
            source = (root / artifact_path).resolve()
            if not source.is_relative_to(root) or not source.is_file():
                continue
            content = source.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            if digest != artifact.sha256:
                continue
            metadata = {}
            metadata_path = f"{artifact_path}.json"
            sidecar = (root / metadata_path).resolve()
            if metadata_path in artifact_hashes and sidecar.is_relative_to(root) and sidecar.is_file():
                sidecar_bytes = sidecar.read_bytes()
                if hashlib.sha256(sidecar_bytes).hexdigest() == artifact_hashes[metadata_path]:
                    import json

                    metadata = json.loads(sidecar_bytes.decode("utf-8"))
            if str(metadata.get("capture_type") or "").lower() == "playwright_browser_error_state":
                continue
            screenshots.append({"path": artifact_path, "sha256": digest, "content": content, "metadata": metadata})
        except (OSError, ValueError):
            continue
    return screenshots


def _finding_screenshot(finding, screenshots: list[dict]) -> dict | None:
    evidence_id = str((getattr(finding, "evidence_metadata", None) or {}).get("screenshot_evidence_id") or "")
    if evidence_id:
        matched = next(
            (item for item in screenshots if str((item.get("metadata") or {}).get("evidence_id") or "") == evidence_id),
            None,
        )
        if matched:
            return matched
    finding_url = str(getattr(finding, "url", None) or "").rstrip("/")
    if finding_url:
        for screenshot in screenshots:
            metadata = screenshot.get("metadata") or {}
            if finding_url in {
                str(metadata.get("requested_url") or "").rstrip("/"),
                str(metadata.get("final_url") or "").rstrip("/"),
            }:
                return screenshot
    return None


def _terminal_screenshot(screenshots: list[dict]) -> dict | None:
    """Return terminal evidence only for the execution-evidence section."""
    return next((item for item in screenshots if "terminal-snapshot-" in item["path"]), None)


def _tool_terminal_screenshots(screenshots: list[dict], artifacts: list) -> list[dict]:
    artifact_hashes = {
        str(getattr(item, "path", "")): str(getattr(item, "sha256", "") or "")
        for item in artifacts
    }
    return sorted(
        [
            item for item in screenshots
            if str((item.get("metadata") or {}).get("capture_type") or "") == "xvfb_xterm_tool_output"
            and artifact_hashes.get(str((item.get("metadata") or {}).get("source_artifact") or ""))
            == str((item.get("metadata") or {}).get("source_artifact_sha256") or "")
        ],
        key=lambda item: (
            str((item.get("metadata") or {}).get("tool") or ""),
            str((item.get("metadata") or {}).get("tool_run_id") or ""),
        ),
    )


def _missing_tool_terminal_runs(tool_runs: list, screenshots: list[dict]) -> list:
    captured_ids = {
        str((item.get("metadata") or {}).get("tool_run_id") or "")
        for item in screenshots
    }
    terminal_states = {"completed", "failed", "timed_out", "cancelled", "warning"}
    return [
        run for run in tool_runs
        if str(getattr(run, "status", "") or "").lower() in terminal_states
        and str(getattr(run, "external_id", "") or "") not in captured_ids
    ]


def _finding_terminal_screenshot(finding, screenshots: list[dict]) -> dict | None:
    finding_metadata = getattr(finding, "evidence_metadata", None) or {}
    evidence_id = str(finding_metadata.get("terminal_evidence_id") or "")
    if not evidence_id:
        return None
    return next(
        (
            item for item in screenshots
            if str((item.get("metadata") or {}).get("evidence_id") or "") == evidence_id
            and str((item.get("metadata") or {}).get("capture_type") or "") == "xvfb_xterm_finding_source"
            and item.get("sha256") == finding_metadata.get("terminal_screenshot_sha256")
            and (item.get("metadata") or {}).get("source_artifact") == finding_metadata.get("source_artifact")
            and (item.get("metadata") or {}).get("source_artifact_sha256") == finding_metadata.get("source_artifact_sha256")
        ),
        None,
    )


def _finding_has_traceable_artifact(finding, artifacts: list) -> bool:
    """Require a retained, hashed source artifact for every reported finding."""
    metadata = getattr(finding, "evidence_metadata", None) or {}
    source_artifact = str(metadata.get("source_artifact") or "")
    if not source_artifact:
        return False
    return any(
        str(getattr(artifact, "path", "")) == source_artifact
        and bool(getattr(artifact, "sha256", None))
        for artifact in artifacts
    )


def _duration(started_at, completed_at) -> str:
    if not started_at or not completed_at:
        return "Not available"
    seconds = max(0, int((completed_at - started_at).total_seconds()))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}h {minutes}m {seconds}s" if hours else f"{minutes}m {seconds}s"


def _remediation(finding) -> str:
    metadata = finding.evidence_metadata or {}
    explicit = metadata.get("remediation") or metadata.get("recommendation") or metadata.get("solution")
    if explicit:
        return _short(explicit, 220)
    severity = str(finding.severity or "INFO").upper()
    if severity in {"CRITICAL", "HIGH"}:
        return "Validate immediately, remove or restrict the exposure, apply the vendor/configuration fix, and perform a targeted retest."
    if severity == "MEDIUM":
        return "Correct the affected configuration or component, verify access controls, and confirm closure in the next scan."
    return "Review for hardening value, document disposition, and suppress only with an approved rationale and expiry."


def _coverage_reason(item: dict) -> str:
    message = item.get("message")
    if message:
        return _short(message, 220)
    if not item.get("planned"):
        return "Excluded by the selected scan profile, strategy, or target type."
    status = str(item.get("status") or "unknown").lower()
    reasons = {
        "skipped": "Planned stage was skipped during execution; review the scan profile and tool evidence.",
        "not_run": "Stage did not run before the scan ended.",
        "failed": "Stage failed; review execution evidence before accepting coverage.",
        "cancelled": "Stage was cancelled before completion.",
        "warning": "Stage completed with a warning that may limit coverage.",
    }
    return reasons.get(status, "Review the execution record to confirm coverage.")


def _manifest_summary(manifest: list[dict]) -> tuple[int, int, int]:
    planned = [item for item in manifest if item.get("planned")]
    completed = [item for item in planned if str(item.get("status") or "").lower() == "completed"]
    limited = [item for item in planned if str(item.get("status") or "").lower() != "completed"]
    return len(completed), len(planned), len(limited)


def _assurance_conclusion(scan, completed: int, planned: int, findings: list) -> str:
    if str(scan.status).lower() != "completed":
        return (
            "Incomplete assessment. No assurance conclusion can be issued because the scan ended "
            f"before all planned checks completed ({completed} of {planned or 0} stages completed)."
        )
    if findings:
        return "Action required. Confirmed or candidate security findings require analyst validation and remediation."
    return "No normalized findings were recorded, subject to the documented scope and coverage limitations."


def _tool_evidence(run) -> str:
    excerpt = _short(getattr(run, "output_excerpt", None), 240)
    if excerpt and excerpt != "-":
        return excerpt
    output_file = getattr(run, "output_file", None)
    return f"Execution evidence retained in {output_file}." if output_file else "Execution metadata retained by the platform."


def _finding_poc(finding, tool_runs: list) -> dict:
    """Build a reproduction record without inventing commands or observations."""
    metadata = getattr(finding, "evidence_metadata", None) or {}
    evidence = str(getattr(finding, "evidence", None) or "")
    source = str(getattr(finding, "source", None) or "").lower()
    matching_run = next((
        run for run in tool_runs
        if source and (source in str(run.tool or "").lower() or str(run.tool or "").lower() in source)
    ), None)
    captured_steps = metadata.get("reproduction_steps") or metadata.get("steps_to_reproduce")
    if isinstance(captured_steps, str):
        captured_steps = [line.strip() for line in captured_steps.splitlines() if line.strip()]
    if not isinstance(captured_steps, list):
        captured_steps = []

    steps = ["Confirm written authorization and use the same target and scan profile recorded in Project Scope."]
    command = getattr(matching_run, "command", None) if matching_run else None
    if command:
        steps.append(f"Execute the captured invocation in an isolated assessment environment: {_short(command, 900)}")
    else:
        steps.append("Exact invocation was not captured for this finding; do not claim independent reproduction until an analyst records it.")
    steps.extend(_short(step, 900) for step in captured_steps)
    if evidence:
        steps.append("Compare the observed response with the evidence record and verify its SHA-256 before confirming the result.")
    else:
        steps.append("Capture direct response evidence before confirming this finding; metadata alone is insufficient.")
    return {
        "status": "Reproducible from captured command" if command and evidence else "Analyst validation required",
        "command": command,
        "artifact": metadata.get("source_artifact") or "Not recorded",
        "evidence_sha256": hashlib.sha256(evidence.encode("utf-8")).hexdigest() if evidence else "Not available",
        "steps": steps,
    }


def _report_context(assessment) -> dict:
    flags = getattr(assessment, "flags", None) or {}
    supplied = flags.get("report_context") or {}
    context = dict(supplied) if isinstance(supplied, dict) else {}
    organization = getattr(assessment, "organization", None)
    author = getattr(assessment, "created_by_user", None)
    context.setdefault("organization", getattr(organization, "name", None) or "Not recorded")
    context.setdefault("contact_name", getattr(author, "full_name", None) or "Not recorded")
    context.setdefault("contact_role", getattr(author, "role", None) or "Assessment owner")
    context.setdefault("contact_email", getattr(author, "email", None) or "Not recorded")
    context.setdefault("classification", "Confidential")
    return context


def _overall_risk(scan, findings: list) -> str:
    if str(getattr(scan, "status", "")).lower() != "completed":
        return "UNRATED - INCOMPLETE COVERAGE"
    severities = {str(getattr(item, "severity", "INFO")).upper() for item in findings}
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if severity in severities:
            return severity
    return "NO CONFIRMED FINDINGS"


def _mode_assurance_statement(mode: str) -> str:
    normalized = str(mode or "").lower()
    if normalized == "light":
        return (
            "Light mode is a bounded, non-destructive baseline. It does not provide the depth of Medium or "
            "Aggressive mode and must not be interpreted as a full penetration-test attestation."
        )
    if normalized == "medium":
        return "Medium mode provides broader enumeration and validation while preserving non-destructive testing boundaries."
    return "Aggressive mode provides the broadest non-exploitative coverage and longest evidence-collection budgets."


def _contact_value(context: dict, key: str) -> str:
    return _short(context.get(key) or "Not recorded", 180)


def generate_scan_docx(assessment, scan, assets: list, findings: list, tool_runs: list) -> bytes:
    """Return a decision-ready, self-contained DOCX for one scan execution."""
    document = Document()
    section = document.sections[0]
    section.top_margin = Inches(0.6)
    section.bottom_margin = Inches(0.6)
    section.left_margin = Inches(0.65)
    section.right_margin = Inches(0.65)
    document.styles["Normal"].font.name = "Aptos"
    document.styles["Normal"].font.size = Pt(9)

    header = section.header.paragraphs[0]
    header.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    title = document.add_paragraph(style="Title")
    title.paragraph_format.space_after = Pt(4)
    _font(title.add_run("Security Assessment Scan Report"), size=24, bold=True, color=RGBColor(0, 0, 0))
    subtitle = document.add_paragraph()
    subtitle.paragraph_format.space_after = Pt(14)
    _font(subtitle.add_run(f"{_short(assessment.name, 100)}  |  Scan {str(scan.id)[:8]}"), size=10, color=MUTED)

    severity_counts = {key: 0 for key in SEVERITY_ORDER}
    for finding in findings:
        key = str(finding.severity or "INFO").upper()
        severity_counts[key] = severity_counts.get(key, 0) + 1
    unsuccessful_tools = sum(run.status in {"failed", "timed_out"} for run in tool_runs)
    metadata = scan.scan_metadata or {}
    failure_reason = getattr(scan, "error_message", None) or metadata.get("failure_reason") or "None"
    preservation_errors = metadata.get("terminal_preservation_errors") or []
    telemetry = metadata.get("telemetry") or {}
    manifest = list(metadata.get("execution_manifest") or [])
    completed_stages, planned_stages, limited_stages = _manifest_summary(manifest)
    conclusion = _assurance_conclusion(scan, completed_stages, planned_stages, findings)
    report_context = _report_context(assessment)
    classification = _contact_value(report_context, "classification").upper()
    _font(header.add_run(f"EXPOSURESCOPEX  /  {classification}  /  AUTOMATIC SCAN REPORT"), size=7.5,
          bold=True, color=RGBColor.from_string(BLUE))
    verified_artifacts = list(getattr(scan, "artifacts", None) or [])
    runtime_screenshots = _verified_runtime_screenshots(scan)
    terminal_screenshot = _terminal_screenshot(runtime_screenshots)
    tool_terminal_screenshots = _tool_terminal_screenshots(runtime_screenshots, verified_artifacts)
    missing_tool_terminal_runs = _missing_tool_terminal_runs(tool_runs, tool_terminal_screenshots)
    missing_screenshots = [item for item in findings if _finding_screenshot(item, runtime_screenshots) is None]
    missing_terminal_evidence = [
        item for item in findings if _finding_terminal_screenshot(item, runtime_screenshots) is None
    ]
    missing_artifacts = [item for item in findings if not _finding_has_traceable_artifact(item, verified_artifacts)]
    evidence_gate_passed = (
        bool(verified_artifacts) and terminal_screenshot is not None
        and not missing_screenshots and not missing_terminal_evidence
        and not missing_tool_terminal_runs and not missing_artifacts
    )
    document_status = "Final" if str(scan.status).lower() == "completed" and evidence_gate_passed else "Partial"

    _heading(document, "Index")
    _table(document, ["Section", "Purpose"], [
        ("Document History", "Version, ownership, status, and issue date"),
        ("Point Of Contact", "Engagement and escalation contacts"),
        ("Executive Summary", "Outcome, confidence, and management interpretation"),
        ("Project Scope", "Targets, profile, execution boundaries, and coverage"),
        ("Profiling", "Observed assets and completed discovery evidence"),
        ("Evidence Integrity", "Original artifact identifiers and SHA-256 hashes"),
        ("Proof of Concept", "Evidence-linked reproduction procedure for each finding"),
        ("Detailed Findings", "Risk-grouped observations and remediation"),
        ("Appendix A", "Engagement methodology"),
        ("Appendix B", "Risk methodology"),
        ("Appendix C", "Testing methodologies"),
    ], [2.0, 4.8])

    _heading(document, "Document History")
    _table(document, ["Version", "Issue date", "Status", "Prepared by", "Change"], [[
        "1.0", scan.completed_at or scan.started_at or "Not recorded",
        document_status,
        "ExposureScopeX", "Initial automated scan report",
    ]], [0.65, 1.55, 0.8, 1.25, 2.55])

    _heading(document, "Point Of Contact")
    _table(document, ["Contact", "Role", "Email", "Organization"], [[
        _contact_value(report_context, "contact_name"),
        _contact_value(report_context, "contact_role"),
        _contact_value(report_context, "contact_email"),
        _contact_value(report_context, "organization"),
    ]], [1.7, 1.6, 2.0, 1.5])

    _heading(document, "Executive Summary")
    _body(document, conclusion)
    _body(document, _mode_assurance_statement(assessment.scan_mode))
    _body(document, (
        f"Evidence release gate: {'PASS' if evidence_gate_passed else 'FAIL'}. "
        f"Retained artifact register: {'present' if verified_artifacts else 'missing'}. "
        f"Terminal snapshot: {'verified' if terminal_screenshot else 'missing'}. "
        f"Missing finding page snapshots: {len(missing_screenshots)}. "
        f"Missing finding terminal captures: {len(missing_terminal_evidence)}. "
        f"Missing tool-run terminal captures: {len(missing_tool_terminal_runs)}. "
        f"Missing traceable source artifacts: {len(missing_artifacts)}. "
        "A failed gate prevents this document from being represented as a final forensic report."
    ))
    _body(document, (
        f"ExposureScopeX ran the {assessment.scan_mode} profile against {assessment.target}. "
        f"The execution evaluated {len(assets)} normalized asset(s), recorded {len(findings)} finding(s), "
        f"and tracked {len(tool_runs)} tool run(s)."
    ))
    _table(document, ["Overall risk", "Status", "Duration", "Progress", "Coverage", "Findings", "Exceptions"], [[
        _overall_risk(scan, findings), str(scan.status).upper(), _duration(scan.started_at, scan.completed_at),
        f"{getattr(scan, 'progress', 100)}%", f"{completed_stages}/{planned_stages}", len(findings), unsuccessful_tools,
    ]], [1.45, 0.7, 0.8, 0.7, 0.7, 0.65, 0.7])

    if str(scan.status).lower() != "completed":
        _body(document, (
            "Interpretation: successful reconnaissance output remains useful for attack-surface review, "
            "but zero findings must not be interpreted as evidence that the target is secure."
        ))

    _heading(document, "Project Scope")
    _table(document, ["Field", "Value"], [
        ("Assessment", assessment.name),
        ("Classification", classification),
        ("Target", assessment.target),
        ("Target type / mode", f"{assessment.target_type} / {assessment.scan_mode}"),
        ("Scan ID", scan.id),
        ("Started / completed", f"{scan.started_at or '-'} / {scan.completed_at or '-'}"),
        ("Final phase", scan.current_phase or scan.status),
        ("Failure reason", _short(failure_reason, 1200)),
        ("Partial-result preservation", "Complete" if not preservation_errors else "; ".join(map(str, preservation_errors))),
        ("Artifacts", len(scan.artifacts or [])),
        ("Output silence at close", f"{telemetry.get('output_silence_seconds', 0)} seconds"),
    ], [1.8, 5.0])

    if manifest:
        _heading(document, "Execution Coverage", level=2)
        _body(document, (
            f"{completed_stages} of {planned_stages} planned stages completed. "
            f"{limited_stages} planned stage(s) were incomplete, cancelled, failed, or completed with warnings."
        ))
        _table(document, ["Stage", "Included", "Status", "Attempts"], [
            (
                _short(item.get("label") or item.get("id"), 80),
                "Yes" if item.get("planned") else "No",
                item.get("status", "pending"),
                item.get("attempts", 0),
            )
            for item in manifest
        ], [3.8, 0.8, 1.4, 0.8])

        exceptional_stages = [
            item for item in manifest
            if not item.get("planned") or str(item.get("status") or "").lower()
            in {"skipped", "not_run", "failed", "cancelled", "warning"}
        ]
        exceptional_tools = [
            run for run in tool_runs
            if str(run.status or "").lower() in {"skipped", "timed_out", "failed", "cancelled", "warning"}
        ]
        if exceptional_stages or exceptional_tools:
            _heading(document, "Coverage Limitations", level=2)
            exception_rows = [
                (
                    "Stage",
                    _short(item.get("label") or item.get("id"), 70),
                    "Not planned" if not item.get("planned") else str(item.get("status") or "unknown").replace("_", " ").title(),
                    _coverage_reason(item),
                )
                for item in exceptional_stages
            ]
            exception_rows.extend(
                (
                    "Tool",
                    _short(run.tool, 70),
                    str(run.status or "unknown").replace("_", " ").title(),
                    "Tool timed out before completion; resulting coverage may be incomplete."
                    if str(run.status or "").lower() == "timed_out"
                    else "Tool did not complete successfully; review its execution evidence.",
                )
                for run in exceptional_tools
            )
            _table(document, ["Type", "Stage / tool", "Outcome", "Reason / impact"], exception_rows,
                   [0.65, 2.0, 1.05, 3.1])

    _heading(document, "Profiling")
    _body(document, (
        "Profiling consolidates normalized assets and retained discovery evidence. It identifies observed "
        "surface area but does not by itself establish exploitability or business impact."
    ))
    _heading(document, "Observed Attack Surface", level=2)
    if assets:
        _table(document, ["Asset", "Type", "Reachable", "Source context"], [
            (
                _short(getattr(asset, "value", "-"), 100),
                getattr(asset, "asset_type", "unknown"),
                "Yes" if getattr(asset, "is_live", False) else "Not confirmed",
                _short((getattr(asset, "metadata_", None) or {}).get("source") or "scan evidence", 80),
            )
            for asset in assets[:40]
        ], [3.15, 1.05, 1.05, 1.55])
        if len(assets) > 40:
            _body(document, f"The report lists 40 of {len(assets)} normalized assets. The full inventory remains available in the platform.")
    else:
        _body(document, "No assets were normalized before the scan ended. Review completed discovery-tool evidence below.")

    if tool_runs:
        _heading(document, "Completed Tool Evidence", level=2)
        completed_tools = [run for run in tool_runs if str(run.status or "").lower() == "completed"]
        if completed_tools:
            _table(document, ["Tool", "Duration", "Evidence summary"], [
                (run.tool, f"{int(run.duration_ms or 0) / 1000:.1f}s", _tool_evidence(run))
                for run in completed_tools[:30]
            ], [1.25, 0.9, 4.75])
        else:
            _body(document, "No individual tool run reached a completed state.")

        _heading(document, "Tool Execution Register", level=2)
        _table(document, ["Tool", "Status", "Duration", "Exit"], [
            (run.tool, run.status, f"{int(run.duration_ms or 0) / 1000:.1f}s", run.exit_code if run.exit_code is not None else "-")
            for run in tool_runs[:50]
        ], [3.0, 1.4, 1.5, 0.9])

    _heading(document, "Evidence Integrity", level=2)
    _body(document, (
        "The companion forensic evidence bundle preserves original available worker artifacts, screenshots, and exact "
        "execution records. No synthetic evidence is generated. Use the SHA-256 values below and the bundle manifest "
        "to verify integrity."
    ))
    if verified_artifacts:
        _table(document, ["Artifact", "Bytes", "SHA-256"], [
            (_short(item.path, 90), item.size_bytes, item.sha256)
            for item in verified_artifacts[:50]
        ], [2.8, 0.8, 3.3])
    else:
        _body(document, "No source artifact hash records were available for this scan; the report must not be treated as forensic evidence.")

    _heading(document, "Terminal Execution Evidence", level=2)
    if terminal_screenshot:
        terminal_metadata = terminal_screenshot.get("metadata") or {}
        paragraph = document.add_paragraph()
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        paragraph.add_run().add_picture(BytesIO(terminal_screenshot["content"]), width=Inches(6.5))
        _body(document, (
            f"Execution evidence only, not finding-specific proof. Evidence ID: "
            f"{terminal_metadata.get('evidence_id') or 'legacy-unassigned'} | Source: {terminal_screenshot['path']} | "
            f"SHA-256: {terminal_screenshot['sha256']} | hash verified."
        ))
    else:
        _body(document, "No hash-verified terminal execution screenshot was retained for this scan.")

    _heading(document, "Per-Tool Terminal Evidence", level=2)
    if tool_terminal_screenshots:
        for capture in tool_terminal_screenshots:
            capture_metadata = capture.get("metadata") or {}
            _heading(
                document,
                f"{capture_metadata.get('tool') or 'Unknown tool'} - {capture_metadata.get('tool_status') or 'unknown'}",
                level=3,
            )
            paragraph = document.add_paragraph()
            paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
            paragraph.add_run().add_picture(BytesIO(capture["content"]), width=Inches(6.5))
            _body(document, (
                f"Run ID: {capture_metadata.get('tool_run_id') or 'not recorded'} | "
                f"Evidence ID: {capture_metadata.get('evidence_id') or 'unassigned'} | "
                f"Output: {capture_metadata.get('source_artifact') or 'not recorded'} | "
                f"Output SHA-256: {capture_metadata.get('source_artifact_sha256') or 'not recorded'} | "
                f"Screenshot SHA-256: {capture['sha256']} | hash verified."
            ))
    else:
        _body(document, "No hash-verified per-tool terminal screenshots were retained for this scan.")
    if missing_tool_terminal_runs:
        _table(document, ["Tool", "Status", "Evidence status"], [
            (run.tool, run.status, "Terminal screenshot unavailable") for run in missing_tool_terminal_runs
        ], [2.4, 1.4, 3.0])

    _heading(document, "Screenshot Evidence Coverage", level=2)
    if missing_screenshots:
        _body(document, (
            f"Evidence gap: {len(missing_screenshots)} finding(s) lack a hash-verified original screenshot. The report "
            "remains available as a partial execution record; these findings require evidence recapture before they "
            "can be represented as screenshot-verified."
        ))
        _table(document, ["Finding", "Evidence status"], [
            (_short(item.title, 120), "Original screenshot unavailable") for item in missing_screenshots[:50]
        ], [5.5, 1.8])
    elif findings:
        _body(document, "Every reported finding has a hash-verified original screenshot artifact.")
    else:
        _body(document, "No normalized findings required finding-level screenshot evidence.")

    _heading(document, "Proof of Concept and Reproduction", level=2)
    if findings:
        _table(document, ["Finding", "PoC status", "Source artifact", "Evidence SHA-256"], [
            (
                _short(item.title, 100), _finding_poc(item, tool_runs)["status"],
                _finding_poc(item, tool_runs)["artifact"], _finding_poc(item, tool_runs)["evidence_sha256"],
            )
            for item in findings[:50]
        ], [2.0, 1.5, 1.4, 1.9])
    else:
        _body(document, (
            "No vulnerability finding reached normalization, so no vulnerability PoC can be presented. The evidence bundle "
            "proves scan execution and retained outputs only; it does not prove that the target is secure."
        ))

    document.add_page_break()
    _heading(document, "Detailed Findings")
    _table(document, ["Critical", "High", "Medium", "Low", "Info"], [[
        severity_counts.get("CRITICAL", 0), severity_counts.get("HIGH", 0),
        severity_counts.get("MEDIUM", 0), severity_counts.get("LOW", 0), severity_counts.get("INFO", 0),
    ]], [1.35] * 5)

    prioritized = sorted(findings, key=lambda item: (SEVERITY_ORDER.get(str(item.severity).upper(), 5), str(item.title)))
    if not prioritized:
        _body(document, (
            "No normalized security findings were recorded. This is not a clean bill of health when coverage "
            "is incomplete; vulnerability validation and result ingestion must complete before absence can be assessed."
        ))

    finding_number = 0
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        severity_findings = [item for item in prioritized if str(item.severity).upper() == severity]
        _heading(document, f"{severity.title()} Risk Findings", level=2)
        if not severity_findings:
            _body(document, f"No normalized {severity.lower()} risk findings were recorded for this scan.")
            continue
        for item in severity_findings[:20]:
            finding_number += 1
            _heading(document, f"{finding_number}  {_short(item.title, 150)}", level=2)
            _table(document, ["Severity", "Status", "Source", "Affected target"], [[
                item.severity, getattr(item, "status", "new"), getattr(item, "source", "unknown"),
                _short(item.url or item.asset_id, 120),
            ]], [0.9, 1.0, 1.35, 3.55])
            if getattr(item, "description", None):
                _body(document, f"Description: {_short(item.description, 900)}")
            if getattr(item, "evidence", None):
                _body(document, f"Evidence: {_short(item.evidence, 900)}")
            finding_screenshot = _finding_screenshot(item, runtime_screenshots)
            _heading(document, "Original Screenshot Evidence", level=2)
            if finding_screenshot:
                screenshot_metadata = finding_screenshot.get("metadata") or {}
                paragraph = document.add_paragraph()
                paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
                paragraph.add_run().add_picture(BytesIO(finding_screenshot["content"]), width=Inches(6.5))
                _body(document, (
                    f"Evidence ID: {screenshot_metadata.get('evidence_id') or 'legacy-unassigned'} | "
                    f"Source: {finding_screenshot['path']} | SHA-256: {finding_screenshot['sha256']} | hash verified. "
                    f"Scan: {screenshot_metadata.get('scan_id') or scan.id} | "
                    f"Task: {screenshot_metadata.get('task_id') or 'not recorded'} | "
                    f"Captured: {screenshot_metadata.get('captured_at') or 'not recorded'}."
                ))
            else:
                _body(document, "EVIDENCE FAILURE: no hash-verified original screenshot is available for this finding.")
            finding_terminal = _finding_terminal_screenshot(item, runtime_screenshots)
            _heading(document, "Original Scanner Terminal Evidence", level=2)
            if finding_terminal:
                terminal_metadata = finding_terminal.get("metadata") or {}
                paragraph = document.add_paragraph()
                paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
                paragraph.add_run().add_picture(BytesIO(finding_terminal["content"]), width=Inches(6.5))
                _body(document, (
                    f"Evidence ID: {terminal_metadata.get('evidence_id') or 'unassigned'} | "
                    f"Source artifact: {terminal_metadata.get('source_artifact') or 'not recorded'} | "
                    f"Source SHA-256: {terminal_metadata.get('source_artifact_sha256') or 'not recorded'} | "
                    f"Screenshot SHA-256: {finding_terminal['sha256']} | hash verified."
                ))
            else:
                _body(document, (
                    "EVIDENCE FAILURE: no hash-verified terminal capture of the original scanner artifact is available."
                ))
            poc = _finding_poc(item, tool_runs)
            _body(document, f"Evidence SHA-256: {poc['evidence_sha256']}")
            _body(document, f"Source artifact: {poc['artifact']}")
            _body(document, f"Reproduction status: {poc['status']}")
            for step_number, step in enumerate(poc["steps"], start=1):
                _body(document, f"Reproduction step {step_number}: {step}")
            _body(document, f"Recommended remediation: {_remediation(item)}")

    _heading(document, "Prioritized Next Actions")
    if scan.error_message:
        _body(document, f"Execution note: {_short(scan.error_message, 500)}")
    if str(scan.status).lower() != "completed":
        _body(document, "1. Resolve the documented timeout or cancellation condition and rerun the same authorized scope to completion.")
        _body(document, "2. Confirm that vulnerability validation and result ingestion finish before drawing a security conclusion.")
        _body(document, "3. Review retained reconnaissance evidence and validate whether discovered assets belong in the approved scope.")
    if prioritized:
        _body(document, "4. Validate critical and high findings first, assign owners and due dates, remediate the root cause, and run a targeted verification scan.")

    _heading(document, "Appendix A Engagement Methodology")
    _body(document, (
        "The engagement follows an evidence-first workflow: scope validation, passive discovery, active "
        "enumeration where authorized, service and application testing, finding normalization, analyst review, "
        "remediation planning, and verification. Testing stops or degrades safely when authorization, prerequisites, "
        "or time budgets are not satisfied."
    ))

    _heading(document, "Appendix B Risk Methodology")
    _body(document, (
        "Risk ratings combine technical severity, exploitability, reachability, confidence, affected-asset context, "
        "and available evidence. Critical and High findings require urgent validation; Medium findings require planned "
        "remediation; Low and Informational findings support hardening. Incomplete testing reduces assurance but does not "
        "reduce the severity of evidence already observed."
    ))

    _heading(document, "Appendix C Testing Methodologies")
    _body(document, (
        "Testing may include certificate-transparency review, passive DNS and archive collection, subdomain enumeration, "
        "HTTP reachability checks, port and service identification, TLS and header analysis, crawling, API discovery, "
        "template-based vulnerability validation, CVE correlation, and authorized safe validation. The Execution Coverage "
        "and Coverage Limitations sections identify which methods actually ran for this scan."
    ))

    _heading(document, "Report Limitations", level=2)
    _body(document, (
        "The report reflects normalized platform records and retained execution evidence for this scan ID. "
        "Results depend on the selected profile, reachable services, external data sources, tool availability, "
        "authorization boundaries, and whether each planned stage completed."
    ))
    _body(document, "This automatically generated report supports analyst review; it does not replace manual validation or an engagement-specific penetration-test attestation.")

    output = BytesIO()
    document.save(output)
    return output.getvalue()


def generate_scan_pdf(assessment, scan, assets: list, findings: list, tool_runs: list) -> bytes:
    """Return a professional PDF containing the same decision evidence as the DOCX."""
    output = BytesIO()
    doc = SimpleDocTemplate(
        output, pagesize=A4, rightMargin=42, leftMargin=42, topMargin=52, bottomMargin=48,
        title=f"{assessment.name} security assessment scan report",
        author="ExposureScopeX",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=22,
        leading=26, textColor=colors.black, alignment=TA_LEFT, spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle", parent=styles["Normal"], fontName="Helvetica", fontSize=9,
        leading=12, textColor=colors.HexColor("#5B6B79"), spaceAfter=16,
    )
    heading_style = ParagraphStyle(
        "ReportHeading", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=14,
        leading=17, textColor=colors.black, spaceBefore=12, spaceAfter=7, keepWithNext=True,
    )
    subheading_style = ParagraphStyle(
        "ReportSubheading", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=10,
        leading=13, textColor=colors.black, spaceBefore=9, spaceAfter=5, keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "ReportBody", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.5,
        leading=12, textColor=colors.HexColor("#1F2B37"), spaceAfter=6,
    )
    small_style = ParagraphStyle(
        "ReportSmall", parent=body_style, fontSize=7.2, leading=9, spaceAfter=0,
    )
    table_header_style = ParagraphStyle(
        "ReportTableHeader", parent=small_style, fontName="Helvetica-Bold", textColor=colors.white,
    )

    def p(value: object, style=body_style) -> Paragraph:
        display_value = "-" if value is None or value == "" else value
        return Paragraph(escape(str(display_value)), style)

    def table(headers: list[str], rows: list[Iterable[object]], widths: list[float]) -> Table:
        data = [[Paragraph(escape(header), table_header_style) for header in headers]]
        data.extend([[p(value, small_style) for value in row] for row in rows])
        result = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        result.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(f"#{NAVY}")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D9D9D9")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        for row_index in range(2, len(data), 2):
            result.setStyle(TableStyle([("BACKGROUND", (0, row_index), (-1, row_index), colors.HexColor("#F3F5F7"))]))
        return result

    def page_frame(canvas, document) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica-Bold", 7)
        canvas.setFillColor(colors.HexColor(f"#{BLUE}"))
        canvas.drawString(42, A4[1] - 28, f"EXPOSURESCOPEX  /  {classification}  /  AUTOMATIC SCAN REPORT")
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#5B6B79"))
        canvas.drawRightString(A4[0] - 42, 24, f"Page {document.page}")
        canvas.restoreState()

    metadata = scan.scan_metadata or {}
    failure_reason = getattr(scan, "error_message", None) or metadata.get("failure_reason") or "None"
    preservation_errors = metadata.get("terminal_preservation_errors") or []
    manifest = list(metadata.get("execution_manifest") or [])
    telemetry = metadata.get("telemetry") or {}
    completed_stages, planned_stages, limited_stages = _manifest_summary(manifest)
    prioritized = sorted(findings, key=lambda item: (SEVERITY_ORDER.get(str(item.severity).upper(), 5), str(item.title)))
    report_context = _report_context(assessment)
    classification = _contact_value(report_context, "classification").upper()
    severity_counts = {key: 0 for key in SEVERITY_ORDER}
    for finding in findings:
        severity = str(finding.severity or "INFO").upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    unsuccessful_tools = sum(str(run.status or "").lower() in {"failed", "timed_out", "warning"} for run in tool_runs)
    verified_artifacts = list(getattr(scan, "artifacts", None) or [])
    runtime_screenshots = _verified_runtime_screenshots(scan)
    terminal_screenshot = _terminal_screenshot(runtime_screenshots)
    tool_terminal_screenshots = _tool_terminal_screenshots(runtime_screenshots, verified_artifacts)
    missing_tool_terminal_runs = _missing_tool_terminal_runs(tool_runs, tool_terminal_screenshots)
    missing_screenshots = [item for item in findings if _finding_screenshot(item, runtime_screenshots) is None]
    missing_terminal_evidence = [
        item for item in findings if _finding_terminal_screenshot(item, runtime_screenshots) is None
    ]
    missing_artifacts = [item for item in findings if not _finding_has_traceable_artifact(item, verified_artifacts)]
    evidence_gate_passed = (
        bool(verified_artifacts) and terminal_screenshot is not None
        and not missing_screenshots and not missing_terminal_evidence
        and not missing_tool_terminal_runs and not missing_artifacts
    )
    document_status = "Final" if str(scan.status).lower() == "completed" and evidence_gate_passed else "Partial"

    story = [
        Paragraph("Security Assessment Scan Report", title_style),
        Paragraph(escape(f"{assessment.name}  |  Scan {str(scan.id)[:8]}"), subtitle_style),
        Paragraph("Index", heading_style),
        table(["Section", "Purpose"], [
            ("Document History", "Version, ownership, status, and issue date"),
            ("Point Of Contact", "Engagement and escalation contacts"),
            ("Executive Summary", "Outcome, confidence, and management interpretation"),
            ("Project Scope", "Targets, profile, execution boundaries, and coverage"),
            ("Profiling", "Observed assets and completed discovery evidence"),
            ("Evidence Integrity", "Original artifact identifiers and SHA-256 hashes"),
            ("Proof of Concept", "Evidence-linked reproduction procedure for each finding"),
            ("Detailed Findings", "Risk-grouped observations and remediation"),
            ("Appendix A", "Engagement methodology"),
            ("Appendix B", "Risk methodology"),
            ("Appendix C", "Testing methodologies"),
        ], [1.8 * inch, 4.55 * inch]),
        Paragraph("Document History", heading_style),
        table(["Version", "Issue date", "Status", "Prepared by", "Change"], [[
            "1.0", scan.completed_at or scan.started_at or "Not recorded",
            document_status,
            "ExposureScopeX", "Initial automated scan report",
        ]], [0.55 * inch, 1.35 * inch, 0.75 * inch, 1.15 * inch, 2.55 * inch]),
        Paragraph("Point Of Contact", heading_style),
        table(["Contact", "Role", "Email", "Organization"], [[
            _contact_value(report_context, "contact_name"), _contact_value(report_context, "contact_role"),
            _contact_value(report_context, "contact_email"), _contact_value(report_context, "organization"),
        ]], [1.5 * inch, 1.35 * inch, 2.0 * inch, 1.5 * inch]),
        Paragraph("Executive Summary", heading_style),
        p(_assurance_conclusion(scan, completed_stages, planned_stages, findings)),
        p(_mode_assurance_statement(assessment.scan_mode)),
        p(
            f"Evidence release gate: {'PASS' if evidence_gate_passed else 'FAIL'}. "
            f"Retained artifact register: {'present' if verified_artifacts else 'missing'}. "
            f"Terminal snapshot: {'verified' if terminal_screenshot else 'missing'}. "
            f"Missing finding page snapshots: {len(missing_screenshots)}. "
            f"Missing finding terminal captures: {len(missing_terminal_evidence)}. "
            f"Missing tool-run terminal captures: {len(missing_tool_terminal_runs)}. "
            f"Missing traceable source artifacts: {len(missing_artifacts)}. "
            "A failed gate prevents this document from being represented as a final forensic report."
        ),
        p(
            f"ExposureScopeX ran the {assessment.scan_mode} profile against {assessment.target}. "
            f"The execution evaluated {len(assets)} normalized asset(s), recorded {len(findings)} finding(s), "
            f"and tracked {len(tool_runs)} tool run(s)."
        ),
        table(
            ["Overall risk", "Status", "Duration", "Progress", "Coverage", "Findings", "Exceptions"],
            [[_overall_risk(scan, findings), str(scan.status).upper(), _duration(scan.started_at, scan.completed_at),
              f"{getattr(scan, 'progress', 100)}%", f"{completed_stages}/{planned_stages}", len(findings), unsuccessful_tools]],
            [1.35 * inch, 0.65 * inch, 0.75 * inch, 0.7 * inch, 0.7 * inch, 0.6 * inch, 0.75 * inch],
        ),
        Spacer(1, 8),
    ]
    if str(scan.status).lower() != "completed":
        story.append(p(
            "Interpretation: successful reconnaissance output remains useful for attack-surface review, "
            "but zero findings must not be interpreted as evidence that the target is secure."
        ))

    story.extend([
        Paragraph("Project Scope", heading_style),
        table(["Field", "Value"], [
            ("Assessment", assessment.name), ("Classification", classification), ("Target", assessment.target),
            ("Target type and mode", f"{assessment.target_type} / {assessment.scan_mode}"),
            ("Scan ID", scan.id),
            ("Started and completed", f"{scan.started_at or '-'} / {scan.completed_at or '-'}"),
            ("Final phase", scan.current_phase or scan.status),
            ("Failure reason", _short(failure_reason, 1200)),
            ("Partial-result preservation", "Complete" if not preservation_errors else "; ".join(map(str, preservation_errors))),
            ("Retained artifacts", len(scan.artifacts or [])),
            ("Output silence at close", f"{telemetry.get('output_silence_seconds', 0)} seconds"),
        ], [1.55 * inch, 5.1 * inch]),
    ])

    if manifest:
        story.extend([
            Paragraph("Execution Coverage", heading_style),
            p(f"{completed_stages} of {planned_stages} planned stages completed; {limited_stages} planned stage(s) had limited coverage."),
            table(["Stage", "Included", "Status", "Attempts"], [
                (_short(item.get("label") or item.get("id"), 80), "Yes" if item.get("planned") else "No",
                 item.get("status", "pending"), item.get("attempts", 0)) for item in manifest
            ], [3.8 * inch, 0.7 * inch, 1.1 * inch, 0.75 * inch]),
        ])
        exceptions = [item for item in manifest if not item.get("planned") or str(item.get("status") or "").lower() != "completed"]
        if exceptions:
            story.extend([
                Paragraph("Coverage Limitations", subheading_style),
                table(["Stage", "Outcome", "Reason and impact"], [
                    (_short(item.get("label") or item.get("id"), 70),
                     "Not planned" if not item.get("planned") else str(item.get("status") or "unknown").replace("_", " ").title(),
                     _coverage_reason(item)) for item in exceptions
                ], [2.2 * inch, 1.0 * inch, 3.15 * inch]),
            ])

    story.extend([
        Paragraph("Profiling", heading_style),
        p(
            "Profiling consolidates normalized assets and retained discovery evidence. It identifies observed "
            "surface area but does not by itself establish exploitability or business impact."
        ),
        Paragraph("Observed Attack Surface", subheading_style),
    ])
    if assets:
        story.append(table(["Asset", "Type", "Reachable", "Source context"], [
            (_short(getattr(asset, "value", "-"), 100), getattr(asset, "asset_type", "unknown"),
             "Yes" if getattr(asset, "is_live", False) else "Not confirmed",
             _short((getattr(asset, "metadata_", None) or {}).get("source") or "scan evidence", 80))
            for asset in assets[:40]
        ], [3.0 * inch, 1.0 * inch, 1.0 * inch, 1.35 * inch]))
    else:
        story.append(p("No assets were normalized before the scan ended. Review completed discovery-tool evidence below."))

    completed_tools = [run for run in tool_runs if str(run.status or "").lower() == "completed"]
    story.append(Paragraph("Completed Tool Evidence", heading_style))
    if completed_tools:
        story.append(table(["Tool", "Duration", "Evidence summary"], [
            (run.tool, f"{int(run.duration_ms or 0) / 1000:.1f}s", _tool_evidence(run))
            for run in completed_tools[:30]
        ], [1.15 * inch, 0.8 * inch, 4.4 * inch]))
    else:
        story.append(p("No individual tool run reached a completed state."))

    story.extend([
        Paragraph("Evidence Integrity", heading_style),
        p(
            "The companion forensic evidence bundle preserves original available worker artifacts, screenshots, and exact "
            "execution records. No synthetic evidence is generated. Use the SHA-256 values below and the bundle manifest "
            "to verify integrity."
        ),
    ])
    if verified_artifacts:
        story.append(table(["Artifact", "Bytes", "SHA-256"], [
            (_short(item.path, 90), item.size_bytes, item.sha256)
            for item in verified_artifacts[:50]
        ], [2.45 * inch, 0.7 * inch, 3.2 * inch]))
    else:
        story.append(p("No source artifact hash records were available for this scan; the report must not be treated as forensic evidence."))

    story.append(Paragraph("Terminal Execution Evidence", heading_style))
    if terminal_screenshot:
        terminal_metadata = terminal_screenshot.get("metadata") or {}
        image_width, image_height = ImageReader(BytesIO(terminal_screenshot["content"])).getSize()
        display_width = 6.35 * inch
        display_height = min(4.4 * inch, display_width * image_height / max(image_width, 1))
        story.extend([
            ReportImage(BytesIO(terminal_screenshot["content"]), width=display_width, height=display_height),
            p(
                f"Execution evidence only, not finding-specific proof. Evidence ID: "
                f"{terminal_metadata.get('evidence_id') or 'legacy-unassigned'} | Source: {terminal_screenshot['path']} | "
                f"SHA-256: {terminal_screenshot['sha256']} | hash verified.",
                small_style,
            ),
        ])
    else:
        story.append(p("No hash-verified terminal execution screenshot was retained for this scan."))

    story.append(Paragraph("Per-Tool Terminal Evidence", heading_style))
    if tool_terminal_screenshots:
        for capture in tool_terminal_screenshots:
            capture_metadata = capture.get("metadata") or {}
            image_width, image_height = ImageReader(BytesIO(capture["content"])).getSize()
            display_width = 6.35 * inch
            display_height = min(4.4 * inch, display_width * image_height / max(image_width, 1))
            story.extend([
                Paragraph(
                    escape(f"{capture_metadata.get('tool') or 'Unknown tool'} - {capture_metadata.get('tool_status') or 'unknown'}"),
                    subheading_style,
                ),
                ReportImage(BytesIO(capture["content"]), width=display_width, height=display_height),
                p(
                    f"Run ID: {capture_metadata.get('tool_run_id') or 'not recorded'} | "
                    f"Evidence ID: {capture_metadata.get('evidence_id') or 'unassigned'} | "
                    f"Output: {capture_metadata.get('source_artifact') or 'not recorded'} | "
                    f"Output SHA-256: {capture_metadata.get('source_artifact_sha256') or 'not recorded'} | "
                    f"Screenshot SHA-256: {capture['sha256']} | hash verified.",
                    small_style,
                ),
            ])
    else:
        story.append(p("No hash-verified per-tool terminal screenshots were retained for this scan."))
    if missing_tool_terminal_runs:
        story.append(table(["Tool", "Status", "Evidence status"], [
            (run.tool, run.status, "Terminal screenshot unavailable") for run in missing_tool_terminal_runs
        ], [2.2 * inch, 1.2 * inch, 3.0 * inch]))

    story.append(Paragraph("Screenshot Evidence Coverage", heading_style))
    if missing_screenshots:
        story.extend([
            p(
                f"Evidence gap: {len(missing_screenshots)} finding(s) lack a hash-verified original screenshot. The report "
                "remains available as a partial execution record; these findings require evidence recapture before they "
                "can be represented as screenshot-verified."
            ),
            table(["Finding", "Evidence status"], [
                (_short(item.title, 120), "Original screenshot unavailable") for item in missing_screenshots[:50]
            ], [4.7 * inch, 1.7 * inch]),
        ])
    elif findings:
        story.append(p("Every reported finding has a hash-verified original screenshot artifact."))
    else:
        story.append(p("No normalized findings required finding-level screenshot evidence."))

    story.append(Paragraph("Proof of Concept and Reproduction", heading_style))
    if findings:
        story.append(table(["Finding", "PoC status", "Source artifact", "Evidence SHA-256"], [
            (
                _short(item.title, 100), _finding_poc(item, tool_runs)["status"],
                _finding_poc(item, tool_runs)["artifact"], _finding_poc(item, tool_runs)["evidence_sha256"],
            )
            for item in findings[:50]
        ], [1.8 * inch, 1.4 * inch, 1.3 * inch, 1.85 * inch]))
    else:
        story.append(p(
            "No vulnerability finding reached normalization, so no vulnerability PoC can be presented. The evidence bundle "
            "proves scan execution and retained outputs only; it does not prove that the target is secure."
        ))

    story.extend([
        Paragraph("Detailed Findings", heading_style),
        table(["Critical", "High", "Medium", "Low", "Info"], [[
            severity_counts.get("CRITICAL", 0), severity_counts.get("HIGH", 0),
            severity_counts.get("MEDIUM", 0), severity_counts.get("LOW", 0), severity_counts.get("INFO", 0),
        ]], [1.25 * inch] * 5),
        Spacer(1, 7),
    ])
    if not prioritized:
        story.append(p(
            "No normalized security findings were recorded. This is not a clean bill of health when coverage "
            "is incomplete; vulnerability validation and result ingestion must complete before absence can be assessed."
        ))
    finding_number = 0
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        severity_findings = [item for item in prioritized if str(item.severity).upper() == severity]
        story.append(Paragraph(f"{severity.title()} Risk Findings", subheading_style))
        if not severity_findings:
            story.append(p(f"No normalized {severity.lower()} risk findings were recorded for this scan."))
            continue
        for item in severity_findings[:20]:
            finding_number += 1
            story.extend([
                Paragraph(escape(f"{finding_number}  {_short(item.title, 150)}"), subheading_style),
                p(f"Severity: {item.severity} | Status: {getattr(item, 'status', 'new')} | Source: {getattr(item, 'source', 'unknown')}"),
            ])
            if getattr(item, "description", None):
                story.append(p(f"Description: {_short(item.description, 900)}"))
            if getattr(item, "evidence", None):
                story.append(p(f"Evidence: {_short(item.evidence, 900)}"))
            finding_screenshot = _finding_screenshot(item, runtime_screenshots)
            story.append(Paragraph("Original Screenshot Evidence", subheading_style))
            if finding_screenshot:
                screenshot_metadata = finding_screenshot.get("metadata") or {}
                image_width, image_height = ImageReader(BytesIO(finding_screenshot["content"])).getSize()
                ratio = image_height / image_width
                display_width = 6.1 * inch
                display_height = display_width * ratio
                if display_height > 6.0 * inch:
                    display_height = 6.0 * inch
                    display_width = display_height / ratio
                story.extend([
                    ReportImage(BytesIO(finding_screenshot["content"]), width=display_width, height=display_height),
                    p(
                        f"Evidence ID: {screenshot_metadata.get('evidence_id') or 'legacy-unassigned'} | "
                        f"Source: {finding_screenshot['path']} | SHA-256: {finding_screenshot['sha256']} | hash verified. "
                        f"Scan: {screenshot_metadata.get('scan_id') or scan.id} | "
                        f"Task: {screenshot_metadata.get('task_id') or 'not recorded'} | "
                        f"Captured: {screenshot_metadata.get('captured_at') or 'not recorded'}.",
                        small_style,
                    ),
                ])
            else:
                story.append(p("EVIDENCE FAILURE: no hash-verified original screenshot is available for this finding."))
            finding_terminal = _finding_terminal_screenshot(item, runtime_screenshots)
            story.append(Paragraph("Original Scanner Terminal Evidence", subheading_style))
            if finding_terminal:
                terminal_metadata = finding_terminal.get("metadata") or {}
                image_width, image_height = ImageReader(BytesIO(finding_terminal["content"])).getSize()
                display_width = 6.1 * inch
                display_height = min(5.2 * inch, display_width * image_height / max(image_width, 1))
                story.extend([
                    ReportImage(BytesIO(finding_terminal["content"]), width=display_width, height=display_height),
                    p(
                        f"Evidence ID: {terminal_metadata.get('evidence_id') or 'unassigned'} | "
                        f"Source artifact: {terminal_metadata.get('source_artifact') or 'not recorded'} | "
                        f"Source SHA-256: {terminal_metadata.get('source_artifact_sha256') or 'not recorded'} | "
                        f"Screenshot SHA-256: {finding_terminal['sha256']} | hash verified.",
                        small_style,
                    ),
                ])
            else:
                story.append(p(
                    "EVIDENCE FAILURE: no hash-verified terminal capture of the original scanner artifact is available."
                ))
            poc = _finding_poc(item, tool_runs)
            story.extend([
                p(f"Evidence SHA-256: {poc['evidence_sha256']}"),
                p(f"Source artifact: {poc['artifact']}"),
                p(f"Reproduction status: {poc['status']}"),
            ])
            for step_number, step in enumerate(poc["steps"], start=1):
                story.append(p(f"Reproduction step {step_number}: {step}"))
            story.append(p(f"Recommended remediation: {_remediation(item)}"))

    story.append(Paragraph("Prioritized Next Actions", heading_style))
    if str(scan.status).lower() != "completed":
        story.extend([
            p("1. Resolve the documented timeout or cancellation condition and rerun the same authorized scope to completion."),
            p("2. Confirm that vulnerability validation and result ingestion finish before drawing a security conclusion."),
            p("3. Review retained reconnaissance evidence and validate whether discovered assets belong in the approved scope."),
        ])
    if prioritized:
        story.append(p("4. Validate critical and high findings, assign owners and due dates, remediate root causes, and run a targeted verification scan."))
    story.extend([
        Paragraph("Appendix A Engagement Methodology", heading_style),
        p(
            "The engagement follows an evidence-first workflow: scope validation, passive discovery, active "
            "enumeration where authorized, service and application testing, finding normalization, analyst review, "
            "remediation planning, and verification. Testing stops or degrades safely when authorization, prerequisites, "
            "or time budgets are not satisfied."
        ),
        Paragraph("Appendix B Risk Methodology", heading_style),
        p(
            "Risk ratings combine technical severity, exploitability, reachability, confidence, affected-asset context, "
            "and available evidence. Critical and High findings require urgent validation; Medium findings require planned "
            "remediation; Low and Informational findings support hardening. Incomplete testing reduces assurance but does not "
            "reduce the severity of evidence already observed."
        ),
        Paragraph("Appendix C Testing Methodologies", heading_style),
        p(
            "Testing may include certificate-transparency review, passive DNS and archive collection, subdomain enumeration, "
            "HTTP reachability checks, port and service identification, TLS and header analysis, crawling, API discovery, "
            "template-based vulnerability validation, CVE correlation, and authorized safe validation. The Execution Coverage "
            "and Coverage Limitations sections identify which methods actually ran for this scan."
        ),
        Paragraph("Report Limitations", subheading_style),
        p(
            "The report reflects normalized platform records and retained execution evidence for this scan ID. "
            "Results depend on the selected profile, reachable services, external data sources, tool availability, "
            "authorization boundaries, and whether each planned stage completed."
        ),
        p("This automatically generated report supports analyst review; it does not replace manual validation or an engagement-specific penetration-test attestation."),
    ])
    doc.build(story, onFirstPage=page_frame, onLaterPages=page_frame)
    return output.getvalue()
