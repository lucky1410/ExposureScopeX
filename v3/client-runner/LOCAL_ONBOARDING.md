# Reusable Local Setup and Change Review

Available in PRE-D Local 0.15.0. Install the published wheel or this checkout
to test protected reusable profiles, bounded local planning and change review.

PRE-D keeps a local application profile containing discovered components,
reviewed checks, role references and behavior objectives. On the next build,
refresh that profile and review its changes instead of creating it again.
Existing metric engines remain the scoring implementation.

## Start Once

Run from a separate evaluator directory, outside the application's repository:

~~~text
esx-eval system bootstrap --project sample-app --version candidate-1 --repo ../application --openapi ./openapi.json --base-url http://127.0.0.1:8000 --role admin --role reader --out ./application-profile.json
esx-eval system setup --plan ./application-profile.json
~~~

Either a repository or a local OpenAPI 3.x JSON file is sufficient. Source
discovery reads files; it does not import or execute them. OpenAPI references
are not fetched. Unknown routes, feature flags, business rules and hidden
modules remain review items. Discovery never counts as executed coverage.

The setup page provides:

- A profile summary with component, reviewed-check and unbound-behavior counts.
- Source protection status and discovery refresh.
- Template suggestions, or an optional local planning model.
- Individual suggestion selection and acceptance as draft behavior objectives.
- Existing role, check, evidence-binding and whole-system review controls.

The application team still supplies test identities, approved expectations,
safe fixture data and ground truth. PRE-D can automate drafting, but it cannot
infer the correct business answer or permission policy from observed output.
Credentials are referenced by environment-variable name.

## Optional Local Planning Agent

Templates work without a model:

~~~text
esx-eval system assist --plan ./application-profile.json --out ./proposal.json
~~~

For model-assisted planning, use an already installed local Ollama model:

~~~text
esx-eval system assist --plan ./application-profile.json --model YOUR_INSTALLED_MODEL --max-turns 4 --out ./model-proposal.json
~~~

To draft objectives from intended business rules, supply a local context file:

~~~text
esx-eval system assist --plan ./application-profile.json --business-context ./business-context.json --out ./business-proposal.json
~~~

Minimum shape:

~~~json
{
  "schema_version": "pre-d-business-context-1.0",
  "rules": [
    {
      "id": "BR-001",
      "title": "High-risk approval requires reviewer sign-off",
      "expected_behavior": "A high-risk action cannot complete until an approved reviewer sign-off exists.",
      "component_ids": ["component-id-from-profile"],
      "layers": ["functional", "authorization"],
      "actors": ["operator", "reviewer"],
      "entities": ["request", "approval"],
      "states": ["pending", "approved", "rejected"],
      "permissions": ["approve_high_risk_action"],
      "dependencies": ["identity provider", "audit log"],
      "expected_outcomes": ["unapproved request remains pending", "approved request records reviewer"],
      "negative_outcomes": ["ordinary operator cannot bypass approval"],
      "source": "approved-policy-document",
      "risk": "high",
      "reviewed": true
    }
  ]
}
~~~

The rule file is an input to planning, not a test result. Accepted suggestions
become unreviewed behavior objectives carrying `business_rule_id`, intended
behavior and evidence-needed metadata. Bind executable checks and review the
expected behavior before claiming coverage.

The connector uses Ollama's [JSON chat API](https://docs.ollama.com/api/chat)
at loopback port 11434 by default. It does not download models. Run a locally
hosted model with remote forwarding disabled; a loopback address by itself is
not proof of the model server's internal network behavior.

The bounded loop lets the model request metadata for existing component IDs
and then propose behavior objectives and module grouping. It receives inventory
metadata, never file bodies, environment values, credentials or application
response bodies. Paths and module names can still be sensitive metadata.
Responses are untrusted, schema-checked drafts. Unknown actions, invented
component IDs, extra fields and stale proposals are rejected.

A proposal contains at most 100 suggestions. It reports how many components it
addresses and lists every unaddressed component. All discovered components stay
in the system scope even when a proposal does not cover them.

The agent has no shell, application HTTP client, arbitrary file reader, code
editor, execution approval or scoring tool. A proposal cannot enable tests,
invent labelled cases or declare a metric verified. Agent step hashes, producer,
model name and accepted suggestion IDs are retained locally.

Use the setup page to accept individual suggestions, or:

~~~text
esx-eval system accept --plan ./application-profile.json --proposal ./proposal.json --suggestion suggestion-ID_FROM_PROPOSAL
~~~

Acceptance adds unbound, unreviewed behavior objectives. Confirm the expected
behavior and attach executable evidence before enabling the check.

## Application Code Protection

Bootstrap profiles use a read-only source policy. PRE-D rejects profile,
report, history, session and diagnostic output paths inside the protected
repository, including paths resolved through symlinks or junctions. Keep the
evaluator directory and browser session storage outside the application.

Source fingerprints contain relative paths and content hashes, not source
contents. They cover at most 10,000 regular files and 128 MB, excluding the
cache/build directories listed in the snapshot. Unreadable files, links,
concurrent edits and limits are disclosed; incomplete fingerprints block a
protected run. No repository means source integrity is explicitly unobserved.

Before execution, the fingerprint must match the reviewed profile. After each
check and at completion, PRE-D rechecks it. An observed change stops further
checks, records changed paths/hashes and prevents a clean readiness verdict or
use as a regression baseline. PRE-D does not revert changes or attribute them
to a process without evidence.

**Execution boundary:** source fingerprints detect changes; they are not an
operating-system sandbox. Protected profiles therefore refuse arbitrary
command adapters, command judges, JUnit commands and recovery commands. Those
need a separately isolated execution environment before they can be admitted
under the same guarantee. Built-in HTTP and browser connectors remain
available; approved interactions can affect application data. Code protection
does not imply that an endpoint is free of runtime side effects.

Earlier system plans remain compatible, including their command execution
paths. They do not acquire source protection automatically and must not be
represented as sandboxed. Bootstrap a protected profile when adopting this
contract. Do not remove protection fields to work around a blocked check.

## Review, Run, Reuse

~~~text
esx-eval system approve --plan ./application-profile.json
esx-eval system preflight --plan ./application-profile.json --require-whole-system
esx-eval system run --plan ./application-profile.json --require-whole-system --out ./runs/candidate-1 --history ./pred-history.sqlite
~~~

Whole-system preflight still requires reviewed inventory totals, behavior
objectives, exact evidence bindings and running-candidate identity checks.
The planning agent does not satisfy those requirements on its own.

When the application changes:

~~~text
esx-eval system refresh --plan ./application-profile.json --version candidate-2
esx-eval system setup --plan ./application-profile.json
~~~

Refresh preserves custom assertions, module grouping and attached configuration
paths. New components get draft checks/objectives. Removed components remain
explicit gaps; their checks are disabled. Changed contracts require review.
A candidate-version change disables attached evaluations until rebound to
matching configurations. Every refresh invalidates approval.

After review and approval, compare with an explicitly selected accepted run:

~~~text
esx-eval system run --plan ./application-profile.json --out ./runs/candidate-2 --history ./pred-history.sqlite --baseline ./runs/candidate-1/system-report.json
esx-eval system compare --before ./runs/candidate-1/system-report.json --after ./runs/candidate-2/system-report.json --out ./comparison.json
~~~

HTML and JSON show source changes, scope changes, role changes, check outcomes,
evidence-provenance changes and compatible verified metric deltas. Changed
protocols or invalid candidate evidence are labelled incomparable. Declared
metrics do not become verified through comparison. The selected baseline is
never advanced silently.

This comparison is distinct from rolling-history detection. Use system monitor
and system trend for bounded scheduled runs and configured median-delta alerts.
No daemon or OS scheduler is installed.

## Traceability and Storage

The profile's adjacent .audit.jsonl records bootstrap, suggestions, acceptance,
refresh and approval with before/after hashes. Each execution has its own
check audit. Comparisons reference run IDs, report hashes, check IDs and result
hashes. Changed source paths include before/after content hashes.

Profiles, reports, audits and optional SQLite history stay local. Hash chains
detect editing; they do not prove authenticity against someone who can rewrite
the entire chain. Preserve a separately trusted digest if that threat matters.
Existing explicit history pruning remains available; report artifacts are not
silently removed.

## Verification

~~~text
python -m unittest discover -s tests -p test_system_onboarding.py -v
python tests/run_onboarding_acceptance.py --out ../onboarding-acceptance
~~~

Acceptance uses an isolated local reference application and a scripted planning
endpoint. It demonstrates integration and guards, not the semantic quality of
an installed model or coverage of a customer application. Test the chosen local
model and reviewed application scope before relying on a release decision.
