# Six-Stage Local Acceptance

This checklist tests PRE-D's evaluator, not a customer's production system.
The reference application is disposable, loopback-only, has synthetic data,
and deliberately contains switchable defects. No Docker, account, remote
model, live integration, or continuously running service is needed.

## Run and Retain Evidence

Install this source version into an evaluator environment, then from
`v3/client-runner` run:

```text
python -m unittest discover -s tests -q
python tests/run_system_acceptance.py --out ./acceptance-evidence --real-schedule
```

Use a new output directory each time. The second command includes actual
60-second intervals between three monitor cycles; allow about three minutes.
Omitting `--real-schedule` skips only that timed experiment and explicitly
records `real_schedule_executed: false`. It is not the full scheduling acceptance.
The overall acceptance and stage 1 remain incomplete in that shorter run.
No OS task is installed. All owned fixture workers and HTTP listeners stop
when the tests finish.

Outputs include `acceptance-results.json`, `acceptance-review.html`, individual
system reports, underlying AI metric reports, audit logs and local trend history.
The JSON index records test outcomes, stage, duration, package import path,
runtime and artifact SHA-256 values. An installed-wheel run should identify the
installed package path, not the source checkout. Hashes detect accidental changes;
they are not independent attestation of who ran the tests.

## Verified Run: 2026-09-20

The installed local wheel passed **360 regression tests** on Windows/Python 3.12.
The dedicated pack passed **59/59 acceptance checks**: stage 0 (18), stage 1
(19), stage 2 (6), stage 3 (5), stage 4a (5), stage 4b (6). These counts overlap:
58 of the acceptance tests are in the 360-test suite; the real timed-monitor
experiment is additional.

The timed experiment lasted 120.204 seconds, with observed intervals of 60.069
and 60.052 seconds. The third observation produced the expected regression
alert against two prior baselines. All 202 retained artifact hashes verified;
all 38 installed Python modules matched the source files byte for byte.

Evidence is in the workspace output directory
`outputs/pred-six-stage-acceptance-final/`, starting with `acceptance-review.html`
or `acceptance-results.json`. A deliberately corrupted history database is part
of the negative controls; do not reuse fixture histories as operational history.
An earlier failed run was retained separately rather than overwritten. No
customer application, production target, or GitHub-hosted CI run is certified
by this local result.

## Acceptance Matrix

Each stage needs both positive controls and deliberately failing/blocked
controls. A correctly reported application failure counts as a passing harness
acceptance test, not as a passing application release.

| Stage | Required local acceptance | Evidence/control |
| --- | --- | --- |
| 0: inventory/integrity | Discover the known mixed Python/JavaScript/OpenAPI inventory without executing source; disclose limits; account for all declared components and all 14 metric dimensions | Source raises if imported; duplicate routes are correlated; limited discovery is marked truncated; one executed component out of ten leaves nine explicit gaps |
| 0: inventory/integrity | Prevent stale approval, changed bound configs, invalid flags/gates, unsafe targets and unreviewed dispatch | Mutated plans/configs fail before target calls; numeric booleans and out-of-range rate gates are rejected |
| 0: setup/report | Save reviewed drafts without dispatch; reject malformed or cross-origin setup requests; preserve honest reports and exit codes | Add component/roles/load draft; approval invalidates; HTML escaping, JSON/audit presence, 0/2 exit codes and missing-role/flag/dependency gaps |
| 1: decision regression | Execute real local adapters and independently compute accuracy, calibration and abstention; do not invent missing confidence | Six labelled endpoint cases per run: healthy, regressed, repaired; separate label-only and decision-evidence-only cases |
| 1: population/history | Preserve population denominators; stratify without replacement; compare compatible runs and reject protocol changes or corrupt history | Per-class sample counts, 6/100 fraction, two prior baselines, cross-application-version regression, changed-case exclusion, tampered database rejection |
| 1: monitoring | Run repeated cycles, produce an actual rolling alert and exit honestly | Three actual foreground cycles with two 60-second waits; third health observation regresses; local alert and exit 2; no clock mocking in this experiment |
| 2: code/integration | Execute actual tests, detect a broken contract even with HTTP 200, and clear the same failure after repair | Two real unittest cases written as JUnit; content/dependency checks; healthy, broken, repaired results |
| 2: result integrity | Never use exit code alone, stale/empty/skipped XML, entities or a timed-out test process as passing evidence | Fresh JUnit requirement, malformed/UTF-8/UTF-16/UTF-32 entity cases, timeout classification and owned child-process termination |
| 3: authorization | Exercise both allow and deny paths for every declared fixture role; detect a seeded authorization bypass | Two endpoints x four roles; three forbidden administrative accesses fail under the bypass and clear after repair |
| 3: isolation | Require owning-tenant positive controls and cross-tenant denials | Both directions of a two-tenant read matrix; two cross-tenant leaks detected and cleared |
| 3: adversarial | Execute attack and benign controls against an actual isolated tool-dispatch path | External test harness observes simulator tool events; injected private-tool execution fails; benign public-tool execution remains allowed |
| 4a: operational behavior | Observe real concurrent requests, latency budgets and health counters; distinguish missing transport evidence from failed contracts | Twelve requests at concurrency four; seeded 503 saturation, excessive latency and dead letters; repaired reruns; refused connections remain blocked, not inferred capacity defects |
| 4b: recovery | Require explicit approval and observed disruption; detect both successful recovery and a live-but-stuck worker | Kill only the fixture's worker after its durable lease; observe supervisor 503; restart; check completed job and exactly one side effect; failed lease recovery breaches the deadline |
| 4b: containment | Preserve idempotency and stop on unsuccessful cleanup | Concurrent duplicate submissions produce one effect; no-op injection is blocked; cleanup failure stops later checks and monitor cycles; unapproved injection makes zero target calls |

## Scope of the Evidence

These checks exercise real subprocesses, local HTTP requests, SQLite history,
fresh test results, executable metric adapters, a killed/restarted worker and
retained reports. They are not just mocked return values. Selected lower-level
tests also use deterministic judges and a mocked wait to validate edge cases;
the real timed-monitor experiment is recorded separately.

The application supplies predictions, not the expected decisions. Gold labels
and abstention expectations live in the test dataset. The seeded abstention
regression changes accuracy from 1 to 0, ECE from 0.01 to 0.4, and observed
abstention from 0 to 1; repairing the application clears the failed gates.
These exact results are fixtures, not estimates of another product's quality.

For each run, open the system report and follow its evidence links to the
per-case metric report. Test failures/errors in the acceptance harness make
the acceptance index incomplete. Application faults deliberately detected by
the harness remain visible as failed checks in their individual reports.

## Still Required Before Application Sign-Off

- Review the real module inventory, mounted routes, flags, dependencies and approved scope. Static discovery cannot prove that it found every business capability.
- Connect real test identities, JWT/SSO sessions, an independently reviewed permission matrix and isolated tenant fixtures. The local role tests use fixture identities, not the customer's identity provider.
- Supply independent decision cases and the relevant response/source/trace evidence. Semantic tests here validate judge contracts and arithmetic, not a real judge's accuracy or universal hallucination detection.
- Run reviewed adversarial cases against the real model/agent path. The acceptance agent is a deterministic policy simulator, not an LLM security benchmark.
- Test representative load and the actual queue/infrastructure failure modes in isolated staging. A bounded local worker experiment does not establish distributed failover or maximum production capacity.
- Perform visual and accessibility review of the report/setup UI. Content/escaping/API tests are not visual sign-off; local-file browser policy prevented that part of report QA in this environment.

PRE-D must report missing scope and evidence rather than convert these remaining
application-specific requirements into a passing release claim.
