---
decision_id: decision-define-the-supported-mcp-redaction-boundary
status: accepted
scope: workspace
title: Define the supported MCP redaction boundary
decided_at: 2026-09-25
spec: distribution
---
# Define the supported MCP redaction boundary

## Decision

An official MCP integration implements
[`docs/reference/mcp-boundary.md`](../reference/mcp-boundary.md), a thin
specialization of the AI-context boundary
([`decision-define-the-framework-neutral-ai-context-boundary-contract`](2026-09-25-define-the-framework-neutral-ai-context-boundary-contract.md)).
It adds four operations over an AI-context boundary (`sanitizeToolResult`,
opt-in `sanitizeToolArguments`, `sanitizeToolCall`,
`sanitizeStreamedToolResult`) and no scan, walk, policy, or error mapping of
its own. Its behavior is pinned by
[`conformance/fixtures/mcp-boundary.json`](../../conformance/fixtures/mcp-boundary.json),
replayed against the packed JavaScript package on the Node addon lane and in
three browser engines. The installable package is
redact-secret-adapters#13.

The authoritative boundary is in the MCP host, after the SDK parses a
`CallToolResult` and before the result is logged, persisted, or placed into
model context. A server-side boundary is preventive from the host's view.

### Rules that are new policy

1. **A result is one value.** The whole `CallToolResult` goes through one
   `sanitizeValue`, so every field is scanned, including `_meta`,
   `resource_link` fields, and fields a later revision adds, and traversal
   limits count from the result root. Text blocks are scanned as text, never
   parsed as JSON.
2. **Unscannable content fails closed.** `image`/`audio` `data` and
   `resource.blob` block the result as `unsupported_value` by default; a
   host may opt in to pass them unscanned. A content block type outside
   protocol revisions 2025-06-18 and 2025-11-25 blocks.
3. **Key-context check.** Each value-shaped part of the sanitized result
   (and sanitized arguments) is serialized and scanned again as text. A
   `redact` or `block` finding there blocks the whole operation as `policy`.
4. **Tool arguments get their own label.** The AI-context label set gains
   `tool-arguments`. Labels stay telemetry-only.
5. **Streams signal early failure.** The AI-context stream gains an
   input-free `accepting` boolean. An MCP integration stops pulling and
   closes the producer as soon as it is `false`.
6. **Failures are fixed tool errors.** Every `blocked` outcome maps to one
   fixed `CallToolResult` with `isError: true`. A tool or producer failure
   maps to a second fixed result as `tool_error`, with its error never read.
   `aborted` delivers nothing. A boundary outcome is never a JSON-RPC error.
7. **Audit is findings plus one record.** The safe finding metadata goes
   through `onFinding`, and each crossing gets `{ stage, outcome, reason?,
   code? }`.
8. **The support claim is a closed range.** `@modelcontextprotocol/sdk`
   `>=1.13.0 <=1.30.1`; `@modelcontextprotocol/client` and `/server`
   `>=2.0.0 <=2.1.0`; protocol revisions 2025-06-18 and 2025-11-25; stdio
   and Streamable HTTP; Node.js 20, 22, 24. The adapter tests both endpoints
   of each line. The Python `mcp` SDK is not supported.

### Exclusions stated, not solved

- A secret split across content blocks, fields, or tool calls. Joining them
  would scan text the model never sees as one string and would make offsets
  meaningless.
- MCP messages other than `tools/call`: resources, prompts, sampling,
  elicitation, completion, and logging and progress notifications.
- Authentication, authorization, prompt injection, tool permissions, model
  output, and secret restoration.

## Rationale

- **Thin, so the adapter cannot drift.** #609 rules out detection or policy
  logic in adapters. Every MCP rule here is a choice of which AI-context
  operation runs on which part of a tool call, so the adapter stays a
  mapping, and the AI-context fixture keeps qualifying the scanning itself.
- **One value, because MCP results grow fields.** Scanning named fields and
  copying the rest (the golden path's approach) passed `_meta` and
  `resource_link` through unscanned. Scanning everything fails closed on
  fields nobody listed. Counting limits from the root keeps one bound per
  result instead of one per part.
- **Text stays text.** Measured on the real core, the text
  `{"password":"synthetic-not-a-secret"}` is redacted as a contextual
  secret, while the leaf `synthetic-not-a-secret` alone is not detected.
  Parsing JSON-in-text would give up exactly the detection that key context
  provides.
- **The key-context check closes the structured copy.** MCP tells a tool
  that returns `structuredContent` to return its serialization as text too.
  Without the check, the text copy would be redacted and the structured copy
  would reach context unchanged. Rescanning the sanitized serialization uses
  only `sanitizeText`, does not re-detect placeholders, and blocks rather
  than guessing which leaf to rewrite.
- **Binary blocks by default, because it cannot be scanned.** A base64
  payload can carry anything, and decoding is deferred
  ([`decision-defer-encoded-input-decoding`](2026-09-20-defer-encoded-input-decoding.md)).
  A host that must pass images makes that choice explicitly, and the
  documentation names it as a false negative.
- **Early failure is a resource bound.** After a failed stream the core
  session is gone, so later chunks are discarded without any limit applying
  to them. A host that cannot see the failure keeps reading a producer of
  unbounded length. `accepting` reveals only that the stream stopped, which
  telemetry of a `block` finding already reveals, not why.
- **`isError`, because JSON-RPC errors get logged.** MCP defines
  `CallToolResult.isError` for failures the model should see, and a
  JSON-RPC error's `message` and `data` are free text that SDKs and hosts log.
  The SDKs' own conversion of a thrown handler error puts the error message
  into `isError` text, so the integration must catch first.
- **A closed range, because only tested endpoints are claims.** The adapter
  duck-types a `CallToolResult`, so both TypeScript SDK lines carry the same
  shape. A closed upper bound keeps a new SDK release from becoming a claim
  before it is tested.

## Alternatives considered

- **Label arguments `context`.** Rejected. It is what the golden path does,
  and it leaves an audit unable to tell a secret the model put into a tool
  call from one in constructed context.
- **Pass binary content through by default.** Rejected. It is the golden
  path's behavior and a silent false negative for anything a tool encodes.
- **Drop `_meta` instead of scanning it.** Rejected. `_meta` carries
  protocol state (related tasks, progress) that hosts rely on.
- **Parse JSON-in-text and scan leaf by leaf.** Rejected on measurement: it
  loses key-context detection. The placeholder-inside-JSON corruption it
  prevented is an availability issue, not a leak.
- **Redact, rather than block, on a key-context finding.** Rejected for now.
  The finding's offsets point into a serialization, not a leaf. Making
  `sanitizeValue` key-aware is a change to the AI-context contract, already
  an open question there.
- **Document the drained stream as availability-only.** Rejected. No
  plaintext leaks, but a failed stream reading an unbounded producer with no
  limit in force is a denial-of-service risk the host cannot see.
- **Map a blocked outcome to a JSON-RPC error.** Rejected: it invites
  verbatim logging and hides the failure from the model.
- **Claim every 1.x and 2.x release.** Rejected. Only tested endpoints are
  evidence.
- **Include the Python `mcp` SDK.** Rejected for beta.9. No Python MCP
  adapter is planned, and a claim needs an adapter that tests it.

## Consequences

- `docs/specs/distribution.md` states the rule and the supported range.
  Widening the range is an edit of that row backed by the adapter's
  compatibility evidence, not a new decision.
- The AI-context contract gains the `tool-arguments` label and the stream's
  `accepting` property (`conformance/ai-context-boundary.mjs`).
  `@redact-secret/adapter-ai-context` must add both before
  `@redact-secret/adapter-mcp` can conform.
- `scripts/consumer-harness.mjs` replays the MCP fixture on every installed
  JavaScript lane, and `scripts/record-artifact-inventory.py` requires
  `mcpBoundary: passed` from each one.
- `examples/mcp-redact` keeps its listed differences until it moves onto
  `@redact-secret/adapter-mcp`. `examples/ai-context/smoke.mjs` checks the
  reference flow on an MCP-shaped result.
- Open maintainer questions, not decided here: whether key-context findings
  should redact the matching leaf once `sanitizeValue` can carry key
  context; whether resources and prompts need their own MCP boundary; and
  whether a Python MCP adapter is wanted.
