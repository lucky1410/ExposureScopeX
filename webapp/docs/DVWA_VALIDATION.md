# DVWA Validation Protocol

DVWA is an authorized local quality fixture, not proof that a profile is universally accurate. Use it to verify authenticated discovery, bounded validation, finding ingestion, original screenshot evidence, and report generation. Release precision and recall still require the full benchmark program in `webapp/benchmarks/README.md`.

## Assessment setup

1. Reset DVWA to a known database state and choose the intended DVWA security level before scanning.
2. Create a URL assessment for `http://dvwa.localhost/` and enable **Safe Active Validation**.
3. Enable **Authenticated Web Coverage** with `http://dvwa.localhost/login.php` and an approved DVWA test account.
4. Keep Screenshots, Deep Crawl, CVE Correlation, and Reporting enabled.
5. Run each mode from the same reset fixture. Do not compare modes against different DVWA states.

## Mode acceptance criteria

| Mode | Required behavior | Active input checks | Expected interpretation |
|---|---|---:|---|
| Light | Authenticated crawl, headers, configuration checks, five-minute actionable-severity Nuclei baseline, evidence and report | 0 | Rapid exposure baseline; low recall is intentional |
| Medium | Light controls plus deeper crawl and capped safe validation | Up to 25 same-origin GET forms | Balanced assessment; database-error indicators may be detected on DVWA Low |
| Aggressive | Broader discovery, all-port service coverage, extended Nuclei budget, repeated evidence coverage | Up to 100 same-origin GET forms | Maximum non-destructive breadth, not exploitation |

The validator submits only one malformed apostrophe to eligible GET forms. A finding is created only when a database-specific error is newly present compared with the baseline response. It is reported as an injection indicator and never as confirmed SQL injection. XSS, command execution, credential attacks, destructive requests, data extraction, persistence, and attack simulation remain outside platform policy.

## Evidence and completion gates

A result is acceptable only when the execution manifest records every planned stage, every normalized finding has a retained source-artifact hash and original Playwright screenshot, and DOCX/PDF/evidence reports are generated. Authentication failures, missing screenshots, tool failures, and timeouts must produce a Partial report rather than a clean or conclusive result.

Routes containing logout, reset, setup, install, delete, remove, or signout semantics are excluded from authenticated discovery and validation to avoid invalidating the session or mutating the fixture.
