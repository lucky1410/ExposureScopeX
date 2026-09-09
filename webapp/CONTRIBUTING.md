# Contributing to ExposureScopeX

## Principles

- Preserve organization isolation and scan-specific evidence.
- Reuse platform planning, authorization, execution, ingestion and reporting.
- Prefer a maintained scanner adapter over a partial native reimplementation.
- Never convert user input into an arbitrary shell command.
- Never present unavailable, blocked or skipped checks as successful.
- Do not commit secrets, target data, reports or scanner artifacts.

## Change workflow

1. Link the change to `BACKLOG.md` or document the reason for an urgent fix.
2. Review architecture and threat-model impact before implementation.
3. Add migration for model changes and preserve forward/backward deployment compatibility.
4. Add success, failure, authorization, tenant and cancellation coverage as applicable.
5. Run the relevant Make targets and security checks.
6. Update OpenAPI-facing schemas, support matrix, module docs, operations and changelog.
7. Include deployment, migration and rollback notes in the pull request.

## Definition of done

Connected UI/API behavior, authorization, safe defaults, graceful errors,
cancellation, normalized evidence, provenance, observability, documentation and
automated checks are required. A page, adapter stub or catalog item alone is not
done.

## Scanner additions

Document license, pinned source/version, supported target types, required
privileges, network behavior, credentials, time/disk limits, parser contract,
redaction, evidence format, failure semantics and update owner. Add the tool to
the fixed catalog and capability registry. Scanner downloads or Git clones must
occur at image build/runtime cache refresh, not once per target.

## Documentation governance

Use `docs/README.md` to find canonical sources. Do not add another current
backlog or duplicate route-by-route API table. Dated review files are immutable
snapshots; create a new review when needed. Validate relative links before merge.
