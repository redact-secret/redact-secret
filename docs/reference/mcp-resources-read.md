# MCP `resources/read` boundary contract

[Documentation home](../README.md)

This contract says what an official Model Context Protocol (MCP) integration
of Redact Secret may claim for `resources/read`: the contents a client reads
from an MCP server and then logs, stores, or places into model context. It
is a thin specialization of the [MCP redaction boundary](mcp-boundary.md)
(#612), which is itself a thin specialization of the
[AI-context boundary](ai-context-boundary.md) (#610). Every scan, every
nested-value walk (key-aware since beta.10,
[#842](https://github.com/redact-secret/redact-secret/issues/842)), every
policy decision, every limit, the binary-content rule, and the key-context
backstop are the ones those contracts already define. This contract adds
only which part of a `ReadResourceResult` goes where, and which fixed
JSON-RPC error a failure becomes.

The installable implementation is `@redact-secret/adapter-mcp`
([redact-secret-adapters#33](https://github.com/redact-secret/redact-secret-adapters/issues/33)).
Independent black-box evidence for it is
[redact-secret-benchmarks#321](https://github.com/redact-secret/redact-secret-benchmarks/issues/321).
This repository owns the contract, its conformance fixture, and the core
behavior underneath it.

Decided by
[`decision-define-the-supported-mcp-resources-read-boundary`](../decisions/2026-09-25-define-the-supported-mcp-resources-read-boundary.md)
(#843), following
[`decision-rule-on-the-mcp-boundary-open-questions`](../decisions/2026-09-25-rule-on-the-mcp-boundary-open-questions.md);
the current rule is in [distribution](../specs/distribution.md).

```text
resource read (client readResource or server read callback)
  -> AI-context sanitizeValue (resource, key-aware) -> key-context backstop
  -> ReadResourceResult to context, log, store, or response
  -> or a fixed JSON-RPC error (-32603), or nothing when cancelled
```

## What this protects, in plain language

- A secret inside a resource the host reads is redacted or blocked before
  the contents are written to a log, stored, or placed into the text a model
  sees. That covers the text of every entry, each entry's `uri`, `mimeType`,
  and `_meta`, the result's own `_meta`, and fields a later protocol
  revision adds.
- A JSON or configuration file delivered as a text resource stays text: it
  is scanned exactly as the model will see it, so `"password": "..."` in it
  is caught by its key context.
- A secret in structured metadata (`_meta`) that only its own key
  identifies, such as `{"password": "<value>"}`, is replaced by a
  placeholder at that value, and the rest of the result is delivered.
- If anything goes wrong (a policy says block, a limit is hit, the scanner
  fails, the read itself fails), the host, its logs, and the MCP peer get one
  fixed JSON-RPC error. They never get the contents, a piece of them, the
  resource URI, or an error message.
- If the read is cancelled, nothing is delivered at all.

## What it does not do

These are non-goals. An integration must not claim them:

- **Resource permissions, MCP authentication, or authorization.** Which
  resources a client may read, and with which credentials, is the server's,
  the transport's, and the host's job.
- **Prompt-injection prevention.** A resource can still carry instructions
  aimed at the model. Redaction removes secrets, not intent.
- **Decoding binary resources.** A `blob` is base64 and is never decoded. By
  default it blocks the result (see [Traversal](#traversal)).
- **Model-output moderation and secret restoration**, as for `tools/call`.
- **Every MCP SDK or transport.** Only the [supported range](#supported-range)
  is claimed.

It also does not cover:

- **`resources/list`, `resources/templates/list`, and their metadata.**
  Resource names, titles, and descriptions are server-authored listing
  metadata, like tool descriptions, and are not scanned by this contract.
  Reading a resource whose URI came from a template *is* `resources/read`
  and is covered; the template listing is not.
- **`resources/subscribe` and `notifications/resources/updated`.** An update
  notification carries only the `uri` the client subscribed to (and
  optional `_meta`), never contents. The new contents arrive through a
  following `resources/read`, which this contract covers. A host that logs
  update notifications, or `notifications/resources/list_changed`, does so
  outside this claim.
- **`prompts/get`, sampling, elicitation, completion, and the logging and
  progress notifications**, which stay excluded
  ([ruling](../decisions/2026-09-25-rule-on-the-mcp-boundary-open-questions.md)).
- **A secret split across two `contents` entries or two reads.** Each entry
  is scanned on its own; they are not joined.
- **The Python `mcp` SDK**, and anything the
  [MCP](mcp-boundary.md#what-it-does-not-do) and
  [AI-context](ai-context-boundary.md#trust-boundaries) contracts exclude.

## Where the authoritative boundary sits

The authoritative boundary is in the MCP host: the process that receives a
`ReadResourceResult` from an MCP client. It runs after the SDK has parsed
the result and before any of these:

1. writing the result, or anything derived from it, to a log or a trace;
2. persisting it (conversation history, caches, a resource index);
3. placing it into model context.

The host wraps its `readResource` call in `sanitizeResourceRead`, so the raw
result exists only inside that call and a rejected read is never inspected.
An MCP server may run the same boundary inside its resource read callbacks
before it responds. That is preventive from the host's point of view: the
host cannot verify it, so it applies the boundary again on every result it
receives.

## Operations

Two operations, added to the MCP boundary's four under whatever names suit
the integration's API, on the same AI-context boundary and the same
`binaryContent` setting:

| Operation | Input | AI-context path |
| --- | --- | --- |
| `sanitizeResourceResult` | one `ReadResourceResult` | one `sanitizeValue` of the whole result, label `resource`, then the key-context backstop |
| `sanitizeResourceRead` | the host's resource read (a client `readResource`, or a server read callback) | run it; a throw or rejection is `read_error`; otherwise `sanitizeResourceResult` |

### Traversal

A `ReadResourceResult` is scanned as one bounded value. Traversal limits
(`maxDepth`, `maxNodes`) count from the result itself, so an entry's `_meta`
is three levels from the root, and every entry counts toward one `maxNodes`.
Every field is scanned, including fields this contract does not name, so a
future field fails closed rather than passing through.

| Part | Treatment |
| --- | --- |
| `contents[]` entry with a string `text` (`TextResourceContents`) | `text` scanned as text, exactly as it will reach the model, whatever its `mimeType`. It is never parsed as JSON: parsing would drop the key context that catches `"password":"..."` in text. |
| `contents[]` entry with `blob` (`BlobResourceContents`) | base64, never decoded. **Default: the whole result is `blocked` / `unsupported_value`.** A host that opts in (`binaryContent: "pass"`, the same setting as tool-result binary content) passes the `blob` through unchanged and unscanned, at its original position; every other field of the entry is still scanned. A non-string `blob` always blocks. |
| an entry with both `text` and `blob`, with neither, or with a non-string `text`; an entry that is not a plain object | `blocked` / `unsupported_value`: a later revision's content kind may carry content this contract cannot scan |
| `contents` missing or not an array; a result that is not a plain object | `blocked` / `unsupported_value` |
| `uri`, `mimeType`, and `_meta` (on an entry or on the result), and any other field | scanned as values; a token in a URI query or in `_meta` is caught, and a `_meta` leaf its own key identifies is redacted in place |
| non-string scalars | passed unchanged |

An empty `contents` array is `ok`. Object keys are scanned, and a key with a
`redact` or `block` finding blocks the whole result, as the AI-context
contract requires.

### Key-context backstop

The same backstop as for a tool result
([MCP boundary](mcp-boundary.md#key-context-backstop)): after the key-aware
leaf-by-leaf pass, the sanitized result without `contents`, and each entry
without its already-scanned `text`, is serialized and scanned once more as
text. A `redact` or `block` finding there, which only a sibling or parent
key can produce, blocks the result as `policy`; a `warn` finding passes.

### Size limits

The host configures the limits, as for every AI-context boundary. A text
over `maxInputBytes` blocks the whole result as `limit_exceeded` with the
code `INPUT_LIMIT_EXCEEDED`; a result with more nodes or deeper nesting
than the traversal limits blocks as `limit_exceeded`. A resource is never
truncated, sampled, or delivered in part. A host that reads large files sets
the limits for them and accepts the scan cost, or does not read them into
context.

### Cancellation

Each operation takes an optional `AbortSignal`: the SDK's `extra.signal` in a
server read callback, or the host's own signal for a client read. It is
checked as the AI-context contract requires. An aborted read delivers
nothing: the SDK sends no response for a cancelled request, and a host
discards a cancelled client read, even when the read itself had already
returned. A signal that fires while the read rejects is `aborted`, not
`read_error`.

## Outcomes and fixed errors

| Outcome | Means | Delivered |
| --- | --- | --- |
| `ok` | sanitized; `value` is the `ReadResourceResult` | `value` as the result, and nothing else |
| `blocked` (every reason: `policy`, `limit_exceeded`, `unsupported_value`, `lifecycle`, `core_error`) | the boundary refused it | the fixed blocked error |
| `read_error` | the read threw or rejected; its error was never read | the fixed read error |
| `aborted` | the signal fired | nothing |

The fixed errors are exact JSON-RPC error objects, with no `data` member, a
new object on every call:

```json
{ "code": -32603, "message": "This MCP resource read was blocked by secret-redaction policy. No content, URI, or error detail is included." }
{ "code": -32603, "message": "This MCP resource read failed. No content, URI, or error detail is included." }
```

- **A JSON-RPC error, because `ReadResourceResult` has no `isError`.** The
  MCP specification tells a server to answer a failed `resources/read` with a
  JSON-RPC error (-32002 for a missing resource, -32603 for an internal
  error). The `tools/call` contract avoids JSON-RPC errors because their
  `message` and `data` are free text that SDKs and hosts log verbatim; here
  the message is fixed and input-free and there is no `data`, so logging it
  verbatim logs nothing derived from input.
- **Not an empty or placeholder result.** An empty `contents` array would be
  indistinguishable from an empty resource, and a host could cache or index
  it as the resource's real contents. A placeholder text entry would need a
  `uri`, which is input, and would present fabricated contents as the
  resource.
- **-32603, never -32002.** A blocked resource exists. Reporting it as not
  found invites a host to drop it from an index or retry elsewhere.
- **The SDK's own error text never runs.** A server SDK turns an exception
  thrown by a read callback into a JSON-RPC error whose `message` is the
  exception's message. An integration catches every callback failure itself
  and throws only the fixed error, so the thrown message is never sent. On
  the client side, a `readResource` rejection (an `McpError` carrying the
  server's free-text message, or a transport error) is `read_error`, and its
  message is never read.

## Audit metadata

As for `tools/call`, two things are safe to audit:

- **Findings**, through the AI-context `onFinding(finding, { boundary })`
  callback: exactly the eight allowlisted fields, with `boundary` set to
  `resource`. This label is the one addition this contract makes to the
  AI-context label set; like every label, it never changes an outcome, and it
  lets an audit tell a resource finding from a tool-result finding.
- **One record per read**: `{ stage, outcome, reason?, code? }`, with
  `stage` set to `resource`, `reason` only for `blocked`, and `code` only
  when the core raised a registered error. No count, size, offset, URI, or
  text derived from input.

The resource URI, the server identity, and timing are the host's own
metadata and outside this contract; a host that audits the URI should know
it can carry a credential (a signed URL, a token in a query).

## Supported range

The MCP boundary's [supported range](mcp-boundary.md#supported-range),
unchanged: `@modelcontextprotocol/sdk` `>=1.13.0 <=1.30.1`,
`@modelcontextprotocol/client` and `/server` `>=2.0.0 <=2.1.0`, protocol
revisions 2025-06-18 and 2025-11-25 (both define `ReadResourceResult` with
`TextResourceContents` and `BlobResourceContents`), stdio and Streamable
HTTP, Node.js 20, 22, and 24. The adapter tests `resources/read` at both
endpoints of each line, on both transports. The Python `mcp` SDK is not
supported.

## Conformance

- [`conformance/fixtures/mcp-resources-read.json`](../../conformance/fixtures/mcp-resources-read.json)
  holds the cases: text, JSON and configuration text that stays text,
  key-identified `_meta` leaves redacted in place (top-level and nested in an
  array), the sibling-key backstop and its `warn`, `uri`, `mimeType`, and
  `_meta` scanned, several entries with mixed siblings, unknown fields,
  empty contents, `blob` under both settings and a non-string `blob`,
  malformed entries and results, block findings in text and in keys,
  traversal and input limits counted from the root, a large benign text, a
  split across entries that is not joined, policy blocks and failures,
  cancellation before and during a read, a failing read, and the
  uninitialized core. It pins the limits, the label, the safe field set, and
  both fixed errors. Every value is synthetic.
- [`conformance/mcp-resources-read.mjs`](../../conformance/mcp-resources-read.mjs)
  holds the fixed errors and the runner. The two operations are methods of
  the MCP reference model in
  [`conformance/mcp-boundary.mjs`](../../conformance/mcp-boundary.mjs), which
  composes the AI-context reference model and adds no scan of its own. The
  runner takes any implementation through `createBoundary`, so the adapter
  replays the fixture through its own public API. For each case it checks
  the outcome, the delivered response, the audit record, the telemetry
  label and fields, how many reads ran, and that no synthetic secret reached
  metadata, audit, telemetry, or a delivered response.
- [`scripts/consumer-harness.mjs`](../../scripts/consumer-harness.mjs)
  replays it against the packed, clean-installed `@redact-secret/core` on the
  Node addon lane and in Chromium, Firefox, and WebKit, before and after
  `initialize()`. The artifact inventory requires `mcpResourcesRead: passed`
  from every lane.
- [`conformance/mcp-resources-read.test.mjs`](../../conformance/mcp-resources-read.test.mjs)
  tests the model and runner against a fake core in `npm run ci`.

An adapter qualifies by replaying the fixture at a pinned commit of this
repository through its own public API, at both endpoints of every supported
SDK line, and reaching the same outcomes. A change to a case, a traversal
rule, a fixed error, or the label changes the contract.
