# Reporting

## Formats

ExposureScopeX generates HTML, PDF, Markdown, SARIF, CSV, JSON and ZIP evidence
bundles. HTML/PDF/Markdown serve human review, SARIF supports compatible code/
security ingestion, CSV/JSON support analysis, and evidence bundles contain
normalized evidence plus `SHA256SUMS`.

## Scope

Every report is generated from explicit organization-owned assessment scope and
may further filter scan, assets, severity, status and modules. A report opened
from a scan must retain that scan identifier; it must not silently include older
findings from the same asset or assessment.

The report record stores immutable scope and content digest. S3-backed reports
store object metadata in PostgreSQL and verify integrity during download.
Database-backed reports retain content in PostgreSQL.

## Content expectations

- Executive context, target and assessment profile
- Applied filters and exclusions
- Asset inventory and severity summary
- Findings with asset, scan, source and evidence attribution
- Tool/profile coverage, including failed/skipped/blocked work
- Limitations, prerequisites and authorization statement
- Digest and generation timestamp

Secrets, raw authorization tokens and unredacted credentials are excluded.
Target-controlled strings must be escaped in rendered formats. CSV exports must
neutralize spreadsheet formulas.

## Lifecycle

Reports can be listed, compared, downloaded, cancelled and deleted according to
tenant capability and retention. Report deletion does not delete the underlying
scan or finding. Generation runs asynchronously on a dedicated queue through a
durable `generating -> ready|failed|cancelled` state machine. Output limits,
tenant quota, SHA-256 verification and generation/export audit events are
enforced. Branding, watermarking and scheduled delivery remain backlog work.
