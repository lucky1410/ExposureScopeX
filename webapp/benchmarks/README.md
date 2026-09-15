# Assessment Benchmark Program

ExposureScopeX scan profiles are release-tested against immutable, versioned ground truth. The benchmark path is deterministic and does not use an LLM to generate findings, label truth, or decide whether a release passes.

## Required suites

| Suite | Primary purpose | Expected adapter |
|---|---|---|
| OWASP Benchmark | Large labeled true/false web weakness corpus | Finding-to-test-case mapping |
| OWASP crAPI | API discovery, authorization, and API weakness coverage | Endpoint and finding mapping |
| OWASP Juice Shop | Modern web weakness coverage and crawl reach | Challenge-to-finding mapping |
| OWASP WebGoat | Repeatable web weakness scenarios | Lesson-to-finding mapping |
| DVWA | Local smoke and evidence-pipeline validation | Module-to-finding mapping |
| ExposureScopeX protocol lab | Negative controls, timeouts, scope escapes, redirects, and evidence failures | Native fixture mapping |

Pin every suite by container digest or source commit. Never compare a result against a moving `latest` image. Ground-truth changes require a fixture-version change and review.

## Release protocol

1. Run each profile at least three times against the same reset fixture and tool/template lockfile.
2. Score precision, recall, F1, false-positive rate, evidence completeness, scope violations, execution coverage, and unreported stage outcomes.
3. Apply the profile's quality gates from `app.services.scan_profiles`.
4. Fail the release on any hard-gate violation. A timed-out tool may yield a truthful partial scan, but it cannot be represented as complete benchmark coverage.
5. Store the input fixture, scorecard, execution manifest, tool provenance, evidence hashes, and environment fingerprint together.

The profile thresholds are ExposureScopeX release targets, not values mandated by OWASP or NIST. OWASP WSTG and ASVS provide test/control taxonomies; NIST SP 800-115 structures planning, execution, analysis, and reporting.

## Local smoke score

```powershell
python webapp/scripts/score-assessment-benchmark.py webapp/benchmarks/fixtures/smoke-pass.json --mode light
```

Exit code `0` passes, `1` means a quality gate failed, and `2` means the fixture is invalid.

The authenticated DVWA mode protocol and acceptance boundaries are defined in `../docs/DVWA_VALIDATION.md`.
