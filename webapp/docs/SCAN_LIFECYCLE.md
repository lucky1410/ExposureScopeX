# Scan Lifecycle

## Planning

Targets are normalized before persistence. A plan combines target type, built-in
mode (`light`, `medium`, `aggressive`), requested scan intents, optional saved
profile, selected utilities, Nuclei tags, phases and flags. Preview resolves the
queue, required tools, worker compatibility, policy bounds and estimates without
dispatching work.

Target queues are web by default, API/MCP on `scans-api`, repositories/images/
Kubernetes on `scans-artifact`, cloud accounts on `scans-cloud`, and Android/iOS
on `scans-mobile`.

## State model

```text
draft/pending -> queued -> running -> completed
                    |         |----> failed
                    |         |----> cancelling -> cancelled
                    |----------------------------> cancelled
```

Assessment status is a summary; scan rows and durable events are authoritative
for individual runs. Retrying creates a new execution identity and preserves
the failed run. Cloning creates an editable assessment draft. Results must be
filtered by scan when the operator asks for one execution.

## Work units and progress

Each planned tool/stage has pending, running, completed, failed, skipped,
blocked or cancelled state. Overall progress derives from persisted work units,
not elapsed time alone. ETA is suppressed before enough progress exists.
Commands, bounded output, exit state, version, artifacts and provenance are
available in scan detail where captured.

## Cancellation

Cancellation sets durable intent, asks Celery to revoke work and relies on
cooperative subprocess termination. Workers must stop child processes, flush
available evidence and commit cancelled state. API cancellation is idempotent.
Terminal scans cannot be silently rewritten as successful.

## Recovery

Distributed leases prevent duplicate concurrent ownership. Worker heartbeats
and stale-run recovery identify scans whose task disappeared. Recovery must
prefer an explicit failed/cancelled outcome over indefinite `running`. Automatic
resume is allowed only for stages known to be idempotent; otherwise retry creates
a new scan.

## Evidence ingestion

Parsers convert tool output into normalized assets, findings, observations,
relationships and artifacts. Parse failure does not erase raw tool failure
evidence. Stable finding identity groups recurrence; scan observations preserve
when and where a result was seen. Report generation binds explicit assessment,
scan, asset, severity, status and module scope.

## Safety gates

Active execution requires tenant capability, target authorization, accepted
scope, policy limits, available worker capability and valid adapter prerequisites.
Exploit-like or destructive behavior is never inferred from an `aggressive`
label alone; it requires explicit approved configuration.
