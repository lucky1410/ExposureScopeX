# Light Sign-Off and Medium Handoff

Status: final Light wrap-up contract  
Date: 2026-09-11  
Intent: close Light today, move to Medium next

## 1. Decision

We are stopping the Light profile from becoming an endless polish loop.

Today’s goal is not "perfect forever." Today’s goal is:

- freeze a trustworthy Light baseline,
- perform one final acceptance run,
- record what is accepted,
- record what is explicitly deferred,
- and move to Medium tomorrow.

## 2. What Light Must Mean at Close

Light is accepted as a release-ready baseline only if the final run proves all
of the following:

- exact-origin scope enforcement works,
- all required Light stages reach truthful terminal states,
- findings are backed by real retained evidence,
- evidence validation succeeds,
- a report is generated in PDF/DOCX/evidence-bundle form,
- partial or failed states are explained honestly when they occur,
- and the report clearly states that Light is a bounded exposure and
  configuration assessment, not a full penetration test.

Light does **not** need to become Medium before we close it.

## 3. Final Acceptance Criteria for Today

The Light profile is considered signed off today if the final validation run
meets these concrete conditions:

### Required

- Assessment status: `complete`
- Required stages:
  - `scope_preflight` succeeded
  - `http_profile` succeeded
  - `tls_service_discovery` succeeded
  - `authenticated_crawl` succeeded
  - `security_headers` succeeded
  - `nuclei_baseline` succeeded
  - `evidence_validation` succeeded
- Findings, if present, have:
  - stable source artifact references,
  - valid hashes,
  - no out-of-scope screenshot dependency,
  - and reproducible safe retest steps
- Report outputs exist:
  - PDF
  - DOCX
  - evidence bundle

### Acceptable residual limitations

These do **not** block Light sign-off:

- The report is credible but not yet premium consulting-grade.
- Shared evidence presentation is still somewhat repetitive.
- Security observations still need stronger analyst-language normalization.
- Light does not yet claim benchmark-backed enterprise superiority.

### Blocking defects

Any one of these keeps Light open:

- required stage fails, times out, or silently stalls,
- evidence validation fails,
- findings are released with broken provenance,
- report generation fails,
- or the report claims deeper coverage than the actual run performed.

## 4. One Final Run Rule

We will not keep rerunning the same Light cycle repeatedly.

From this point:

1. Rebuild the currently changed backend and runner once.
2. Run one final Light acceptance scan.
3. Review the result against the criteria above.
4. If it passes, freeze Light and move to Medium.
5. If it fails, only fix the specific blocking defect; do not reopen general
   Light redesign.

## 5. What Is Frozen After Sign-Off

If the final run passes, the following are frozen as the accepted Light
contract:

- stage order and required Light workflow,
- deterministic non-AI scanner boundary,
- exact-origin scope and safe-route enforcement,
- evidence validation behavior,
- Light report methodology and coverage disclaimers,
- and the rule that every run must produce report artifacts.

Changes after sign-off must be:

- bug fixes,
- benchmark calibration,
- or shared improvements that do not alter Light’s declared meaning.

## 6. What Moves to Medium Tomorrow

Tomorrow’s work begins from this baseline and does not reopen Light unless a
true blocking defect is discovered.

Medium starts with:

- better route, form, parameter, and script inventory presentation,
- authenticated session review as a first-class assessed output,
- API contract review as a first-class assessed output,
- deterministic auth, authz, input, and API validation adapters,
- and benchmark-backed Medium acceptance gates.

## 7. Honest Final Position Today

Current honest status:

- Light backend: close to acceptable sign-off
- Light report: credible, but not yet 10/10 premium
- Medium: architecture and contract defined, implementation still in progress

That is enough to stop looping.

## 8. Final Checklist for Today

- rebuild `api` and `runner`
- execute one final Light acceptance run
- confirm required stages succeeded
- confirm evidence validation succeeded
- confirm PDF, DOCX, and evidence bundle exist
- review for any blocking defect only
- sign off Light
- start Medium tomorrow
