# MCP Security Assessment

## Requirements

- A reachable MCP HTTP endpoint. A service on the Docker host commonly uses
  `http://host.docker.internal/...`, not container-local `localhost`.
- Authentication header/token when the server requires it.
- Authorization to enumerate tools, resources, prompts and protocol behavior.
- Disposable task/resource identifiers and canary data for stateful tests.
- Explicit consent and an isolated lab for any destructive/state-changing probe.

Validate connectivity with a normal JSON-RPC `tools/list` request before a full
assessment. Secrets are stored/configured as sensitive values and redacted from
displayed exchanges.

## Non-destructive coverage

The built-in assessment covers protocol/version handling, JSON-RPC validation,
initialization and capability discovery; tools/resources/prompts inventory;
unknown object and method behavior; authentication and authorization boundaries;
origin, CORS and content-type behavior; malformed/duplicate/confusable input;
path/traversal-shaped resource identifiers; task list/get/cancel behavior where
supported; cache/session isolation indicators; bounded amplification and error
disclosure; and drift/evidence normalization.

Expanded checks adapt to advertised capabilities. An HTTP `200` is not a pass:
JSON-RPC error objects, authorization decisions and semantic response content are
evaluated separately.

## Safety tiers

- **Baseline:** inventory and protocol behavior with minimal side effects.
- **Expanded:** additional malformed, isolation and bounded-state probes.
- **Destructive lab:** tool execution, task mutation, canaries and cross-agent
  scenarios only with disposable data and explicit approval.

Blocked, unsupported, downgraded and inconclusive checks remain visible in
coverage. The platform must not invoke arbitrary discovered tools merely because
the server advertised them.

## Reporting

MCP reports should include endpoint/scope, profile, advertised capabilities,
checks performed/skipped, finding evidence, redacted request/response exchanges,
authorization assumptions and manual follow-up. Full connected-agent simulation,
configuration linting, reusable replay profiles and specialized report packs
remain in the canonical backlog.
