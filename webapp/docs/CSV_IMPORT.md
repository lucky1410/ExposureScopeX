# CSV Import and Normalization

Assessment import creates one assessment containing all valid normalized rows;
it must not create one assessment per column or target type. ASM import adds
normalized target inventory records.

## Accepted input behavior

The parser examines headers and values rather than requiring one vendor schema.
Recognizable values include domains, hostnames, URLs, IPv4/IPv6 addresses,
CIDRs, ASNs, repositories, container images, cloud/account identifiers, MCP
endpoints and supported artifact references. Common descriptive columns may
provide name, owner, source, environment, tags or notes.

Unknown columns are retained only when safe metadata handling supports them;
they are never treated as shell arguments. Empty rows, duplicates and invalid
values produce row outcomes.

## Import result

The response reports added, skipped and errored counts plus bounded row-level
messages. `0 added, 0 skipped, N errors` is a failed import. The UI must keep or
reopen review context instead of displaying a generic success toast.

## Normalization rules

- Trim whitespace and safe wrappers; normalize case where identifiers permit it.
- Preserve URL scheme/path when the target is a URL.
- Canonicalize IP/CIDR syntax without expanding unsafe ranges in the control plane.
- Deduplicate by canonical type/value within the organization and intended scope.
- Preserve source row number and inferred field/type in import evidence.
- Do not require a second primary target when valid CSV rows already establish scope.
- Ambiguous or low-confidence values require review rather than unsafe guessing.

## Limits and safety

Upload/request and target-count limits apply before dispatch. CSV import does not
authorize targets. Private/local destinations remain subject to explicit policy,
including the narrow MCP localhost alias. Spreadsheet formulas are data and must
be neutralized in exported CSV to prevent formula injection.
