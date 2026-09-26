---
decision_id: decision-define-the-supported-mcp-resources-read-boundary
status: accepted
scope: workspace
title: Define the supported MCP `resources/read` boundary
decided_at: 2026-09-25
spec: distribution
---
# Define the supported MCP `resources/read` boundary

## Decision

An official MCP integration that claims `resources/read` implements
[`docs/reference/mcp-resources-read.md`](../reference/mcp-resources-read.md)
(#843), the boundary that
[`decision-rule-on-the-mcp-boundary-open-questions`](2026-09-25-rule-on-the-mcp-boundary-open-questions.md)
made next. It is a thin specialization of the MCP boundary
([`decision-define-the-supported-mcp-redaction-boundary`](2026-09-25-define-the-supported-mcp-redaction-boundary.md))
and, through it, of the AI-context boundary and its key-aware
`sanitizeValue`
([`decision-define-key-aware-sanitize-value`](2026-09-25-define-key-aware-sanitize-value.md)).
It adds two operations (`sanitizeResourceResult`, `sanitizeResourceRead`)
and no scan, walk, or policy of its own. Its behavior is pinned by
[`conformance/fixtures/mcp-resources-read.json`](../../conformance/fixtures/mcp-resources-read.json),
replayed against the packed JavaScript package on the Node addon lane and in
three browser engines. The installable package is
redact-secret-adapters#33.

Rules 1, 2, 3, 5, 7, and 8 of the MCP boundary record apply unchanged to a
`ReadResourceResult`: the whole result is one bounded `sanitizeValue` with
limits from the root (`contents[]` with each entry's `uri`, `mimeType`,
`text`, and `_meta`, the result's `_meta`, and any later field); `text` is
scanned as text, never parsed as JSON, whatever its `mimeType`; a `blob`
blocks as `unsupported_value` unless the host opts in with the same
`binaryContent: "pass"` that governs tool-result binary content; the
key-context backstop runs on the sanitized value-shaped parts; audit is
`onFinding` plus `{ stage, outcome, reason?, code? }`; and the supported SDK,
protocol, transport, and runtime range is the same closed range. What is new:

1. **An entry is exactly one of text or blob.** An entry with both, with
   neither, with a non-string `text`, or that is not a plain object blocks as
   `unsupported_value`, as does a result without a `contents` array.
2. **Failures are fixed JSON-RPC errors, not results.** Every `blocked`
   outcome maps to `{ "code": -32603, "message": <fixed blocked text> }`, and
   a read that throws or rejects is `read_error`, mapped to the same code
   with a second fixed message. Neither has a `data` member. `aborted`
   delivers nothing. An integration catches every read-callback failure and
   throws only the fixed error; a client-side `readResource` rejection is
   `read_error` and its message is never read.
3. **Resource findings get their own label.** The AI-context label set gains
   `resource`, and the audit record's `stage` is `resource`. Labels stay
   telemetry-only.

### Exclusions stated, not solved

- `resources/list`, `resources/templates/list`, and their free-text names,
  titles, and descriptions (server-authored listing metadata). Reading a
  resource whose URI a template produced is covered.
- `resources/subscribe`, `notifications/resources/updated`, and
  `notifications/resources/list_changed`. An update notification carries only
  the subscribed `uri` and optional `_meta`, never contents; the new contents
  arrive through a `resources/read`, which is covered.
- `prompts/get`, sampling, elicitation, completion, and the logging and
  progress notifications; a secret split across entries or reads;
  authentication, authorization, resource permissions, prompt injection,
  model output, secret restoration, binary decoding; the Python `mcp` SDK.

## Rationale

- **The same mapping, because a resource is a tool result without the
  wrapper.** Resource contents reach context, logs, and storage the same way
  a tool result does, and an embedded `resource` block inside a
  `CallToolResult` is already scanned this way. Reusing the one-value rule,
  the binary rule, the backstop, and the range keeps one behavior for one
  shape, and keeps the adapter a mapping (#609).
- **Text stays text for resources too.** Configuration files and JSON
  documents are the likeliest secret-bearing resources, and their key
  context is visible only in the text. The key-aware walker covers the
  structured part a resource has, its `_meta`.
- **A JSON-RPC error, because the protocol has nowhere else to put a
  failure.** `ReadResourceResult` has no `isError`, and the MCP
  specification tells servers to answer a failed read with a JSON-RPC error
  (-32002 not found, -32603 internal). Rule 6 of the MCP boundary record
  rejected JSON-RPC errors for `tools/call` because their `message` and
  `data` are free text that SDKs and hosts log verbatim. That concern is
  about content, not the channel: with a fixed, input-free message and no
  `data`, a verbatim log line carries nothing derived from input. Both
  supported SDK lines send a thrown error's integer `code` and exact
  `message` and add `data` only when the error carries one, so a server-side
  wrapper can produce exactly the fixed error.
- **-32603, because a blocked resource is not missing.** -32002 would tell
  the host the resource does not exist, which a host may cache, drop from an
  index, or report to a user. A server-defined code risks colliding with a
  code a later protocol revision assigns.
- **Separate `read_error`, because the host must know which side failed.**
  `tool_error` names a tool; reusing it would mislabel a resource read in
  every audit record.
- **A `resource` label, for the reason `tool-arguments` exists.** An audit
  should tell a secret in a resource from one in a tool result.
- **Subscriptions carry no contents.** Scanning update notifications would
  scan only a URI the client chose, and would add a claim for no content the
  model sees.

## Alternatives considered

- **Map a failure to an empty `contents` array.** Rejected. It is
  indistinguishable from an empty resource, so a host would cache, index, or
  show nothing as the resource's real contents, and nothing tells it that a
  secret was withheld.
- **Map a failure to one placeholder text entry carrying the fixed
  sentence.** Rejected. An entry needs a `uri`, which is input (or a
  fabricated one), and it presents invented contents as the resource, which
  a host would persist as if it were real.
- **Use -32002 "Resource not found".** Rejected for the index and caching
  reason above.
- **Parse JSON text (`application/json`) and walk it.** Rejected on the
  measurement the MCP boundary record cites: it loses key-context detection.
- **Reuse the `tool-result` label.** Rejected: an audit could not tell the
  two paths apart.
- **Include `notifications/resources/updated` or `resources/list`.**
  Rejected by default, as #843 asked; revisit if a host shows that listing
  metadata carries credentials in practice.
- **A new SDK range for resources.** Rejected. Both lines have supported
  `resources/read` with this result shape across the whole claimed range, and
  the adapter tests both endpoints of each line for it.

## Consequences

- `docs/specs/distribution.md` gains the rule; widening the range stays an
  edit of the MCP row backed by the adapter's compatibility evidence.
- The AI-context contract gains the `resource` label, and the MCP audit
  record gains the `resource` stage. `@redact-secret/adapter-ai-context` and
  `@redact-secret/adapter-mcp` must add both.
- `scripts/consumer-harness.mjs` replays the fixture on every installed
  JavaScript lane, and `scripts/record-artifact-inventory.py` requires
  `mcpResourcesRead: passed` from each one.
- Nothing in `@redact-secret/core` changes.
- Still open: whether listing metadata (`resources/list`, templates) needs a
  boundary, and `prompts/get`, both excluded until someone shows a need.
