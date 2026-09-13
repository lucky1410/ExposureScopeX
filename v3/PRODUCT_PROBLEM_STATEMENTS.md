# ExposureScopeX Product Problem Statements

This document is the canonical plain-language product boundary for ExposureScopeX
v3. It separates the two product components so that their claims, evidence, and
release criteria are not confused.

## 1. Platform Problem

Security and AI teams must decide whether a software release is safe to operate,
but their evidence is fragmented. Traditional application-security tools can
identify code, dependency, configuration, and exposed-service risks. AI
evaluation tools can measure model and agent behavior. Neither result is enough
on its own to establish an accountable release decision for an AI-enabled
application.

**ExposureScopeX is an AI-native red-team assurance platform that connects
authorized application-security assessment and AI-system evaluation to
evidence-backed, reproducible release decisions.**

It does not claim that a pass proves an application is completely secure. A pass
means the declared version met the declared policy on the declared authorized
scope and labelled evaluation dataset.

## 2. Assessment Scanner Problem

Teams need a repeatable way to assess an authorized web, API, network, or cloud
surface without relying on undocumented manual steps or treating raw scanner
output as fact. They need to know what was in scope, what was tested, what was
not tested, which observations were independently validated, and what evidence
supports every reported finding.

**The Assessment Scanner performs bounded, non-destructive assessments of
explicitly authorized targets and produces traceable findings, evidence, coverage,
and reports.**

It is not an autonomous exploitation platform. It does not perform credential
attacks, persistence, destructive checks, or unsupported business-logic claims.
Scanner observations remain candidates until evidence and the applicable
validation rules support a finding.

## 3. AI Assurance & Observability: Pre-release Evaluation Problem

Teams shipping models, RAG applications, and tool-using agents need to know
whether a version behaves correctly, safely, and consistently before deployment.
Source-code scanning cannot reliably answer whether an agent follows policy,
grounds an answer in evidence, resists an adversarial input, uses tools within
scope, or gives appropriately calibrated confidence.

**AI Assurance & Observability's Pre-release Evaluator measures an AI system
against a versioned, labelled evaluation contract and returns a reproducible
PASS, FAIL, or INCONCLUSIVE release decision.**

It measures classification quality, attack and detection outcomes, evidence
grounding, confidence calibration, RAG quality, agent trajectory and policy
behavior, robustness, judge agreement, repeatability, and cost and efficiency
when the required labelled records are supplied.

The active capability is an evaluator *of* AI systems before release. Its
authoritative metric engine is deterministic. An optional, independently
configured LLM judge may provide advisory semantic review, but it cannot replace
the deterministic release gate. Runtime observability is a future integration,
not a current product claim. The Pre-release Evaluator does not perform
assessment scanning, continuous telemetry collection, or SOC operations.

## 4. How The Components Work Together

The Assessment Scanner and AI Assurance pre-release evaluation have different inputs and
different proof standards:

| Component | Evaluates | Requires | Produces |
| --- | --- | --- | --- |
| Assessment Scanner | Authorized application and infrastructure exposure | Scope, authorization, target access, optional test credentials | Validated security findings, evidence, coverage, assessment report |
| AI Assurance pre-release evaluation | Model, RAG, or agent behavior | Versioned labelled cases, policy, and optional redacted traces | Metric scorecard, release decision, provenance, assurance report |

A future release may correlate both records for the same product release. It
must not merge them into one score or imply that an AI-evaluation pass validates
an application's external attack surface, or that an assessment pass proves AI
behavior is safe.

## 5. Integration Position

ExposureScopeX complements CI/CD and source-code security tooling. CI executes
checks. SAST inspects source code. DAST assesses a running external interface.
AI Assurance pre-release evaluation is a behavior-level quality and security
gate for AI systems, designed to run locally, in customer CI, or through a
bounded approved endpoint integration.

## 6. Meaning Of A Release Decision

- **PASS:** Every required, measurable gate passed for the declared subject,
  version, dataset, and policy.
- **FAIL:** At least one required measured gate failed.
- **INCONCLUSIVE:** No measured required gate failed, but required evidence,
  labelled truth, coverage, or an independent review is missing.

No decision is a blanket production-security guarantee, a replacement for human
review, or proof of behavior outside the supplied scope.

## 7. Platform Assurance Selection Flow

ExposureScopeX presents assurance as one platform experience, but a user first
selects the component they want to evaluate. A platform-level result is composed
from component results; it is never a blended score.

| Selected assurance target | What it proves | Current status |
| --- | --- | --- |
| AI system before release | Labelled model, RAG, agent, or multi-agent behavior meets declared release gates | Available |
| Assessment Scanner | Scanner accuracy, scope enforcement, evidence, and known-target coverage meet a lab benchmark | Benchmark-scoring foundation exists; persisted suite pending |
| Assessment Report | A report agrees with its immutable assessment record and exports correctly | Report generation exists; validation suite pending |
| Full ExposureScopeX release | Every required component suite passed for one named platform release | Blocked until scanner and report suites are available |

The selection step makes the user-facing boundary explicit. Selecting a suite
does not allow one component's score to stand in for another component's proof.
