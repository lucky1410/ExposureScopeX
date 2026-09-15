"""Executable checks for the accepted platform architecture contract."""

from __future__ import annotations

import re
from pathlib import Path

from app.services.scan_planning import (
    FORBIDDEN_EXECUTION_UTILITIES,
    FORBIDDEN_NUCLEI_TAGS,
)


WEBAPP_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = WEBAPP_ROOT.parent
SCHEMA_DOCUMENTS = (
    WEBAPP_ROOT / "README.md",
    WEBAPP_ROOT / "BACKLOG.md",
    WEBAPP_ROOT / "docs" / "README.md",
    WEBAPP_ROOT / "docs" / "ARCHITECTURE.md",
    WEBAPP_ROOT / "docs" / "DATA_MODEL.md",
    WEBAPP_ROOT / "docs" / "OPERATIONS.md",
    WEBAPP_ROOT / "docs" / "SECURE_SDLC.md",
)


def _latest_migration_name() -> str:
    versions = WEBAPP_ROOT / "backend" / "alembic" / "versions"
    migrations = sorted(
        path.stem for path in versions.glob("[0-9][0-9][0-9]_*.py")
    )
    assert migrations, "No Alembic migrations were found"
    return migrations[-1]


def test_canonical_documents_use_current_schema_head() -> None:
    schema_head = _latest_migration_name()
    for document in SCHEMA_DOCUMENTS:
        assert schema_head in document.read_text(encoding="utf-8"), (
            f"{document.relative_to(REPOSITORY_ROOT)} must reference {schema_head}"
        )


def test_accepted_scanning_invariants_are_documented() -> None:
    architecture = (WEBAPP_ROOT / "docs" / "ARCHITECTURE.md").read_text(
        encoding="utf-8"
    )
    adr = (
        WEBAPP_ROOT
        / "docs"
        / "adr"
        / "0005-deterministic-non-exploitative-evidence-gated-scanning.md"
    ).read_text(encoding="utf-8")

    assert "**Status:** Accepted" in adr
    for invariant in (
        "Deterministic scanning",
        "No exploitation",
        "Fail-closed scope",
        "Evidence before assurance",
        "Completion is not finality",
        "AI is post-scan only",
    ):
        assert invariant in architecture


def test_forbidden_execution_policy_matches_architecture_boundary() -> None:
    assert {"hydra", "metasploit", "msfconsole", "sqlmap"}.issubset(
        FORBIDDEN_EXECUTION_UTILITIES
    )
    assert {"default-login", "dos", "fuzz", "intrusive"}.issubset(
        FORBIDDEN_NUCLEI_TAGS
    )

    scanner = (REPOSITORY_ROOT / "exposurescopex.sh").read_text(encoding="utf-8")
    assert "source \"${SCRIPT_DIR}/modules/agent.sh\"" not in scanner
    assert "run_agent" not in scanner
    assert re.search(r"--agent\|--agent-model\|--agent-max-steps", scanner)
    assert "AI-directed scanning is not supported" in scanner


def test_canonical_product_direction_has_no_legacy_scan_claims() -> None:
    canonical = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            WEBAPP_ROOT / "docs" / "PRD.md",
            WEBAPP_ROOT / "docs" / "ROADMAP.md",
            WEBAPP_ROOT / "docs" / "SUPPORT_MATRIX.md",
        )
    )
    for forbidden_claim in (
        "AI-augmented attack surface management",
        "enum, scan, cloud, exploit",
        "Guard-railed active exploitation adapters",
        "Extend `exploitation.sh`",
    ):
        assert forbidden_claim not in canonical


def test_reference_architecture_defines_planes_and_product_boundary() -> None:
    reference = (WEBAPP_ROOT / "docs" / "REFERENCE_ARCHITECTURE.md").read_text(
        encoding="utf-8"
    )
    for plane in (
        "Experience Plane",
        "Control Plane",
        "Isolated Execution Plane",
        "Evidence and Assurance Plane",
        "Post-scan Intelligence Plane",
        "Authoritative Data Plane",
        "Integration Plane",
        "Operations and Security Plane",
    ):
        assert plane in reference

    assert "AI cannot alter" in reference
    assert re.search(
        r"no\s+adversarial simulation or exploitation engine", reference, re.IGNORECASE
    )
    assert "Partial or Final" in reference
    assert "Versioned SOC connector" in reference
