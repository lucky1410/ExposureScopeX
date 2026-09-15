from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


PROFILE_CONTRACT_VERSION = "1.0.0"
PINNED_TEMPLATE_RELEASE = "v10.4.8"
LIGHT_TEMPLATE_RELEASE = "esx-light-observations-v1"

PROHIBITED_TAGS = (
    "bruteforce",
    "default-login",
    "dos",
    "fuzz",
    "intrusive",
    "oast",
)
PROHIBITED_TYPES = ("code", "file", "headless", "javascript")


@dataclass(frozen=True)
class NucleiProfile:
    name: str
    template_paths: tuple[str, ...]
    rationale: str


PROFILES = {
    "light": NucleiProfile(
        name="light",
        template_paths=(
            "vendored-get-only-observations",
        ),
        rationale="Small, reviewed GET-only observation set against the exact declared origin.",
    ),
    "medium": NucleiProfile(
        name="medium",
        template_paths=(
            "http/exposures",
            "http/misconfiguration",
            "http/technologies",
            "http/vulnerabilities",
            "ssl",
        ),
        rationale="Light coverage plus non-prohibited web vulnerability checks.",
    ),
    "aggressive": NucleiProfile(
        name="aggressive",
        template_paths=(
            "http/cves",
            "http/exposures",
            "http/misconfiguration",
            "http/technologies",
            "http/vulnerabilities",
            "network",
            "ssl",
            "workflows",
        ),
        rationale="Medium coverage plus CVE, network and workflow checks under the same safety exclusions.",
    ),
}


def profile_for(mode: str) -> NucleiProfile:
    try:
        return PROFILES[mode]
    except KeyError as exc:
        raise ValueError(f"Unsupported Nuclei profile: {mode}") from exc


def selection_arguments(mode: str, template_root: str) -> list[str]:
    profile = profile_for(mode)
    if mode == "light":
        template_paths = [str(Path(__file__).with_name("nuclei_templates") / "light")]
    else:
        root = PurePosixPath(template_root)
        template_paths = [str(root / relative) for relative in profile.template_paths]
    arguments: list[str] = []
    for template_path in template_paths:
        arguments.extend(["-templates", template_path])
    arguments.extend(["-exclude-tags", ",".join(PROHIBITED_TAGS)])
    arguments.extend(["-exclude-type", ",".join(PROHIBITED_TYPES)])
    # Prevent all out-of-band template execution and external callback setup.
    arguments.append("-no-interactsh")
    return arguments


def maximum_template_count(mode: str) -> int | None:
    """Keep Light's request budget coupled to its reviewed template allowlist."""
    return 3 if mode == "light" else None


def _template_set_sha256(template_paths: list[str]) -> str:
    digest = hashlib.sha256()
    for raw_path in sorted(template_paths):
        path = Path(raw_path)
        digest.update(raw_path.encode("utf-8"))
        digest.update(b"\0")
        if path.is_file():
            digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def inventory_manifest(mode: str, template_paths: list[str]) -> dict:
    profile = profile_for(mode)
    normalized = sorted({path.strip() for path in template_paths if path.strip()})
    return {
        "schema_version": "1.0",
        "profile_contract_version": PROFILE_CONTRACT_VERSION,
        "template_release": LIGHT_TEMPLATE_RELEASE if mode == "light" else PINNED_TEMPLATE_RELEASE,
        "profile": mode,
        "rationale": profile.rationale,
        "template_categories": list(profile.template_paths),
        "prohibited_tags": list(PROHIBITED_TAGS),
        "prohibited_types": list(PROHIBITED_TYPES),
        "selected_template_count": len(normalized),
        "selected_templates": normalized,
        "template_set_sha256": _template_set_sha256(normalized),
        "execution_boundary": (
            "Exact declared origin only; one root target; GET-only templates; redirects disabled."
            if mode == "light" else "Profile-bounded target paths with prohibited template classes excluded."
        ),
    }
