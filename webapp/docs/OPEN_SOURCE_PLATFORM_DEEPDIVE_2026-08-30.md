# ExposureScopeX Open-Source Platform Deep Dive

Research baseline: 30 August 2026

This document translates the 2026 ASM red-team blueprint into an additive, production-minded architecture for ExposureScopeX. It is intentionally platform-centric: the goal is not to clone every scanner, but to orchestrate the best open-source engines behind one normalized inventory, findings, and evidence model.

## Goals

- Keep ExposureScopeX as the system of record.
- Reuse proven open-source engines where they are already stronger than a custom rewrite.
- Normalize every scan into the same asset, finding, evidence, and attack-path model.
- Preserve operator flexibility: bundled where safe, optional where licensing or packaging risk is higher.

## Recommended module layers

1. Intake and normalization
   - Accept domain, URL, IP, CIDR, ASN, repository, container image, MCP endpoint, cloud account, and organization seeds.
   - Normalize to canonical identities before dispatch.
2. Discovery and enumeration
   - Domain/IP surface via Subfinder, Assetfinder, Amass, dnsx, httpx, Naabu, Nmap, Katana, Hakrawler.
   - MCP surface via the built-in MCP audit engine.
   - Repository and image surface via Git, Gitleaks, Trivy, Syft, and Grype.
3. CSPM and cloud posture
   - Primary engine: Prowler.
   - Secondary comparator: ScoutSuite as an optional adapter.
   - Provider-specific auth stays externalized to environment or delegated identities.
4. Correlation and lifecycle
   - All raw outputs become normalized findings, assets, evidence, and graph relationships.
   - Findings stay scan-scoped today, but the architecture should evolve toward stable finding instances plus scan observations.
5. Operator workflow
   - Scans should expose tool plans, execution stages, tool-level logs, artifact manifests, progress, cancellation, and drift.
6. Artifact and image security
   - Container image assessments should be first-class inputs rather than pretending every package risk starts from a Git repository.
   - Trivy provides the primary image scan.
   - Syft provides secondary SBOM generation.
   - Grype provides secondary SBOM-driven vulnerability correlation.

## Open-source tool posture

### Bundled now

- Subfinder
- Assetfinder
- OWASP Amass
- dnsx
- httpx
- Naabu
- Nmap
- Katana
- Hakrawler
- Nuclei plus runtime template volumes
- Gitleaks
- Trivy
- Syft
- Grype
- ExposureScopeX MCP audit
- Prowler

### Adapter-ready or optional

- ScoutSuite

## Why this split

- Prowler is a strong fit for direct worker bundling because it is Apache-2.0 and produces machine-ingestible JSON-OCSF, CSV, and HTML artifacts.
- ScoutSuite is valuable as an independent comparator, but it is better treated as an optional adapter until its packaging and GPL handling are formalized for this platform.
- Nuclei remains the broad validation plane for web, API, network, and cloud-adjacent checks, but should always be mediated through curated plans and artifact manifests.

## Cloud-account execution flow

```text
cloud_account seed
    -> provider detection
    -> execution manifest
    -> seed inventory
    -> Prowler primary CSPM
    -> ScoutSuite secondary validation (optional)
    -> IAM/compliance correlation
    -> normalized findings/resources
    -> graph + risk
```

The worker should never pretend a cloud scan happened when credentials or adapters are missing. Instead it should emit a truthful summary describing:

- detected provider
- planned adapters
- command-level execution state
- artifacts produced
- which adapters were unavailable

## Image execution flow

```text
container image seed
    -> reference validation
    -> registry attribution
    -> Trivy vulnerability and misconfiguration scan
    -> Trivy CycloneDX SBOM
    -> Syft CycloneDX SBOM
    -> Grype package-vulnerability correlation
    -> normalized findings/resources
    -> graph + risk
```

## Proposed next production passes

1. Persist append-only tool run events in the database instead of reading only the latest TSV tail.
2. Add explicit cloud connection records with auth validation, least-privilege guidance, and provider-specific checks.
3. Move from scan-scoped findings toward stable finding instances plus re-observation history.
4. Move beyond basic image/repository support into policy packs, VEX handling, and provenance attestations.
5. Add policy packs for business-specific checks, not just vendor/community templates.
6. Add a proper template/source lifecycle for Nuclei community content with trust controls and rollback.

## Current implementation status in this pass

- Added a first-class open-source scanner catalog in the backend.
- Added scan metadata tool plans for operator-visible execution planning.
- Added cloud-account specialized execution stages.
- Replaced the cloud-account worker stub with adapter-driven Prowler and optional ScoutSuite execution.
- Added container-image specialized execution stages.
- Bundled Syft and Grype into the worker path for repository and image workflows.
- Added parsers for Prowler JSON-OCSF and ScoutSuite report formats.
- Added CSPM ingestion so cloud resources and findings feed back into assessments.
- Added specialized scan summaries and artifact manifests to the scan detail API/UI path.

## Non-goals of this pass

- Rebuilding Prowler or ScoutSuite logic natively.
- Claiming every industry feature is already implemented.
- Changing IRIS or importing code wholesale from other sibling projects.
