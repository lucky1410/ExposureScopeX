from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath


PROFILE_CONTRACT_VERSION = "1.0.0"
PINNED_TEMPLATE_RELEASE = "v10.4.8"

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
            "http/exposures",
            "http/misconfiguration",
            "http/technologies",
            "ssl",
        ),
        rationale="Exposure, configuration, technology and TLS baseline.",
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
    root = PurePosixPath(template_root)
    arguments: list[str] = []
    for relative in profile.template_paths:
        arguments.extend(["-templates", str(root / relative)])
    arguments.extend(["-exclude-tags", ",".join(PROHIBITED_TAGS)])
    arguments.extend(["-exclude-type", ",".join(PROHIBITED_TYPES)])
    # Prevent all out-of-band template execution and external callback setup.
    arguments.append("-no-interactsh")
    return arguments


def inventory_manifest(mode: str, template_paths: list[str]) -> dict:
    profile = profile_for(mode)
    normalized = sorted({path.strip() for path in template_paths if path.strip()})
    return {
        "schema_version": "1.0",
        "profile_contract_version": PROFILE_CONTRACT_VERSION,
        "template_release": PINNED_TEMPLATE_RELEASE,
        "profile": mode,
        "rationale": profile.rationale,
        "template_categories": list(profile.template_paths),
        "prohibited_tags": list(PROHIBITED_TAGS),
        "prohibited_types": list(PROHIBITED_TYPES),
        "selected_template_count": len(normalized),
        "selected_templates": normalized,
    }
