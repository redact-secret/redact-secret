# MCP redaction boundary contract

[Documentation home](../README.md)

This contract says what an official Model Context Protocol (MCP) integration
of Redact Secret may claim, and which points of an MCP tool call it must
protect. It is a thin specialization of the
[AI-context boundary contract](ai-context-boundary.md) (#610): every scan,
every nested-value walk, every policy decision, every limit, and every
failure mapping is the AI-context boundary's. This contract adds only the MCP
shape: which parts of a tool call are scanned, what happens to content that
cannot be scanned, how streamed tool output stops, and which fixed MCP result
a failure becomes.

The installable implementation is `@redact-secret/adapter-mcp`, owned by
[`redact-secret-adapters`](https://github.com/redact-secret/redact-secret-adapters)
([redact-secret-adapters#13](https://github.com/redact-secret/redact-secret-adapters/issues/13)).
Independent black-box evidence for it is
[redact-secret-benchmarks#281](https://github.com/redact-secret/redact-secret-benchmarks/issues/281).
This repository owns the contract, its conformance fixture, and the core
behavior underneath it.

Decided by
[`decision-define-the-supported-mcp-redaction-boundary`](../decisions/2026-09-25-define-the-supported-mcp-redaction-boundary.md);
the current rule is in [distribution](../specs/distribution.md).

```text
tool arguments (opt-in) -> AI-context sanitizeValue (tool-arguments) -> key-context check -> dispatch or fixed error
tool result             -> AI-context sanitizeValue (tool-result)    -> key-context check -> context, log, store, or fixed error
streamed tool output    -> AI-context openStream (tool-result)       -> stop pulling on failure -> one text block or fixed error
```

## What this protects, in plain language

- A secret inside a tool's result is redacted or blocked before the result
  is written to a log, stored, or placed into the text a model sees. That
  covers the result's text, its structured content at any depth, its
  metadata (`_meta`), embedded text resources, and resource links.
- When the application opts in, a secret inside the arguments of a tool
  call is redacted or blocked before the tool runs.
- If anything goes wrong (a policy says block, a limit is hit, the scanner
  fails, the tool itself fails), the model and the logs get one fixed
  sentence that says the call was blocked or failed. They never get the
  original content, a piece of it, or an error message.
- If the call is cancelled, nothing is delivered at all.
- A tool whose output arrives in pieces is scanned as one text, so a secret
  split across two pieces is still caught. Nothing is released until the
  whole output has been scanned, and once the result is known to fail, the
  integration stops reading the rest.

## What it does not do

These are non-goals. An integration must not claim them:

- **MCP authentication or authorization.** Who may connect, and with which
  credentials, is the transport's and the host's job.
- **Prompt-injection prevention.** A tool result can still carry
  instructions aimed at the model. Redaction removes secrets, not intent.
- **Tool permission decisions.** Whether a tool may run, and with which
  arguments, is the host's policy.
- **Model-output moderation.** What the model writes back is a different
  boundary.
- **Arbitrary secret restoration.** A placeholder is never turned back into
  the secret by this contract.
- **Every MCP SDK or transport.** Only the SDKs, versions, protocol
  revisions, and transports listed under [Supported range](#supported-range)
  are claimed.

It also does not cover:

- **MCP messages other than `tools/call`.** `resources/read`, `prompts/get`,
  `sampling/createMessage`, elicitation, completion, and the logging and
  progress notifications (whose `message` fields are free text) are not
  scanned by this contract.
- **A secret split across two content blocks, two fields, or two tool
  calls.** Each is scanned on its own; they are not joined. Only a split
  across the chunks of one streamed output is handled.
- **Content that cannot be scanned.** Images, audio, and binary (`blob`)
  resources are base64 and are never decoded. By default they block the
  result (see [Traversal](#traversal)).
- **Anything the AI-context contract excludes**: encoded values, detection
  that is incomplete, plaintext in process memory, and the host's own
  callbacks ([trust boundaries](ai-context-boundary.md#trust-boundaries)).

## Where the authoritative boundary sits

The authoritative boundary is in the MCP host: the process that receives a
`CallToolResult` from an MCP client and builds model context from it. It
runs after the SDK has parsed the result and before any of these:

1. writing the result, or anything derived from it, to a log or a trace;
2. persisting it (conversation history, caches, databases);
3. placing it into model context.

Nothing downstream of the host (the model provider, its logs, its retention)
is under the host's control, so no check there substitutes for this one.

An MCP server may run the same boundary inside its tool handlers before it
returns a result. That is useful, and it uses the same operations and the
same fixed results, but from the host's point of view it is preventive: the
host cannot verify it, so the host applies the boundary again on every
result it receives, including results marked `isError: true`.

The reference flow shows the ordering:
[`examples/ai-context`](../../examples/ai-context/README.md) runs
`buildSafeContext` from the
[`examples/mcp-redact`](../../examples/mcp-redact/README.md) golden path on
the released core. The raw tool result exists only inside `buildSafeContext`
until the boundary has sanitized it; the host receives only the sanitized
turn or an outcome with nothing derived from input.
[`examples/ai-context/smoke.mjs`](../../examples/ai-context/smoke.mjs)
checks, on the released core, that an MCP-shaped result with secrets in a
text block, an embedded text resource, and nested `structuredContent`
reaches the host's model call, log, and store only in sanitized form, as
fresh objects that share no reference with the raw result. The golden path
predates this contract; its differences are listed under
[The golden path today](#the-golden-path-today).

## Operations

An MCP integration exposes these four operations under whatever names suit
its API. Each is built on an AI-context boundary the host configures with
explicit limits, a policy, and optional telemetry.

| Operation | Input | AI-context path |
| --- | --- | --- |
| `sanitizeToolResult` | one `CallToolResult` | one `sanitizeValue` of the whole result, label `tool-result`, then the key-context check |
| `sanitizeToolArguments` | `CallToolRequest.params.arguments` (opt-in) | one `sanitizeValue`, label `tool-arguments`, then the key-context check |
| `sanitizeToolCall` | the host's tool invocation (a client `callTool`, or a server handler) | run it; a throw or rejection is `tool_error`; otherwise `sanitizeToolResult` |
| `sanitizeStreamedToolResult` | chunks of one logical text | one staged `openStream`, label `tool-result`, released as a one-block `CallToolResult` |

### Tool arguments

Argument sanitation is opt-in: arguments are written by the model from
context that was already sanitized, so an application decides whether the
extra scan is worth it. When it is enabled:

- `arguments` is scanned as one value (every string leaf and every key).
  Absent arguments are `ok` with no value. Anything other than a plain object
  is `blocked` / `unsupported_value`.
- The tool name and the request's `_meta` are not scanned. The name is
  matched against the host's tool list; `_meta` is protocol metadata the host
  generated.
- On any non-`ok` outcome the tool is not dispatched and the original
  arguments are not forwarded. The model receives the fixed blocked result.
- Findings reach telemetry with the label `tool-arguments`, so an audit can
  tell an argument finding from a result finding. This label is the one
  addition this contract makes to the AI-context label set; like every
  label, it never changes an outcome.

### Traversal

A `CallToolResult` is scanned as one bounded value. Traversal limits
(`maxDepth`, `maxNodes`) count from the result itself, so `structuredContent`
nested five levels deep is seven levels from the root. Every field is
scanned, including fields this contract does not name, so a future field
fails closed rather than passing through.

| Part | Treatment |
| --- | --- |
| `content[]` `text` block | `text` scanned as text, exactly as it will reach the model. It is not parsed as JSON: parsing would drop the key context that catches `"password":"..."` in text. |
| `resource` block with `resource.text` | `text` scanned as text; `uri`, `mimeType`, and the other fields scanned as values |
| `resource_link` block | every field (`uri`, `name`, `title`, `description`, `mimeType`, ...) scanned; a token in a URL query is caught |
| `image` / `audio` `data`, `resource.blob` | base64, never decoded. **Default: the whole result is `blocked` / `unsupported_value`.** A host may opt in (`binaryContent: "pass"`) to pass the payload through unchanged and unscanned, at its original position; every other field of the block is still scanned. A non-string payload always blocks. |
| any other block `type` | `blocked` / `unsupported_value`: a type from a later protocol revision may carry content this contract cannot scan |
| a block that is not a plain object; `content` that is not an array; a result that is not a plain object | `blocked` / `unsupported_value` |
| `structuredContent` | scanned as a nested value (every leaf and key), then the key-context check |
| `_meta` (on the result or on a block), `annotations` | scanned as values like any other field |
| `isError` and other non-string scalars | passed unchanged |

Object keys are scanned, and a key with a `redact` or `block` finding blocks
the whole result, as the AI-context contract requires.

### Key-context check

A string leaf is scanned without the key it sits under. So `{"password":
"<value>"}` in `structuredContent` would pass when `<value>` does not
identify itself, even though the same pair inside a text block is caught.
MCP makes this sharp: a tool that returns `structuredContent` is expected to
return its JSON serialization as text too, and a leaf-only scan would redact
the text copy and deliver the structured copy as it was.

So after the leaf-by-leaf pass, the integration serializes each value-shaped
part of the **sanitized** result with `JSON.stringify` and scans it once more
as text: the result without its `content` array (which covers
`structuredContent`, `_meta`, and any other field), and each content block
without its already-scanned `text`. Sanitized arguments get the same check.
A `redact` or `block` finding there cannot be mapped back to one leaf, so it
blocks the whole operation as `policy`. Placeholders written by the first
pass are not detected again, and a `warn` finding passes, as `warn` always
does. The check's findings reach telemetry (their offsets are into the
serialization); `ok.findings` lists the leaf findings only. The serialization
is bounded by the same whole-input limits, so a serialized part over
`maxInputBytes` blocks as `limit_exceeded`.

The trade is availability for a structured result that names a secret only
by its key: it is blocked, not redacted. A host that needs such results
through can drop `structuredContent` and keep the (redacted) text copy.

### Streamed tool output

The base MCP protocol returns one `CallToolResult` per call; this contract
does not claim the SDK's experimental task or partial-result delivery. A
streamed tool result here is a tool whose output is produced in pieces (a
subprocess, a file, an HTTP body) and assembled before it is returned:

- All pieces go through one staged AI-context stream, so a secret split
  across pieces is detected as one secret. Chunks must be strings from a
  streaming decoder; a non-string chunk blocks the result.
- Nothing is released before a successful finalize. The released value is a
  one-block `CallToolResult`: `{ content: [{ type: "text", text }] }`.
- **Early failure.** The stream exposes `accepting`, an input-free boolean
  that turns `false` the moment the stream fails (a `block` finding, a
  limit, a lifecycle or core failure) or is aborted. After every append the
  integration reads it, and when it is `false` it pulls no further chunk and
  closes the producer (`return()` on its iterator), so an upstream process
  or request can be cancelled. Without this, a failed stream would keep
  reading a producer whose output is discarded unscanned: no plaintext is
  released, but the host keeps paying for input no limit bounds any more.
  `accepting` says only that later appends would be discarded, never why;
  the reason still arrives at finalize.
- A producer that throws or rejects is `tool_error`, and its error is never
  read. A signal that fired meanwhile is reported as `aborted`.

### Cancellation

Each operation takes an optional `AbortSignal`: the SDK's `extra.signal` in a
server handler, or the host's own signal for a client call. It is checked as
the AI-context contract requires (before and after every scan, and on every
chunk). An aborted operation delivers nothing: the SDK sends no response for
a cancelled request, and a host discards a cancelled client call. Text that
was already sanitized is discarded with it.

## Outcomes and fixed MCP results

The outcomes are the AI-context three plus one the host owns:

| Outcome | Means | Delivered to the model, the log, and the store |
| --- | --- | --- |
| `ok` | sanitized; `value` is the result or arguments | `value`, and nothing else |
| `blocked` (every reason: `policy`, `limit_exceeded`, `unsupported_value`, `lifecycle`, `core_error`) | the boundary refused it | the fixed blocked result |
| `tool_error` | the tool, or a streamed tool's producer, threw or rejected; its error was never read | the fixed tool-error result |
| `aborted` | the signal fired | nothing |

The fixed results are exact. They carry no `structuredContent` and no
`_meta`, and they are a new object on every call:

```json
{ "content": [{ "type": "text", "text": "This MCP tool call was blocked by secret-redaction policy. No content, arguments, or error detail is included." }], "isError": true }
{ "content": [{ "type": "text", "text": "This MCP tool call failed. No content, arguments, or error detail is included." }], "isError": true }
```

- **A tool error, never a JSON-RPC error.** A JSON-RPC error's `message` and
  `data` are free text that SDKs and hosts log verbatim, and MCP defines
  `CallToolResult.isError` for failures the model should see. The block
  reason is not in the text: the model learns only that the call was
  blocked. The supported client SDKs accept an `isError` result without
  `structuredContent` even when the tool declares an `outputSchema`, so such
  a tool can still return the fixed result.
- **The SDK's own error text never runs.** An MCP server SDK turns an
  exception thrown by a tool handler into an `isError` result whose text is
  the exception's message. An integration catches every handler failure
  itself and returns the fixed tool-error result, so that conversion is
  never reached. On the client side, a `callTool` rejection (an `McpError`
  or a transport error) is `tool_error`, and its message is never read.

## Audit metadata

Two things are safe to audit, and nothing else crosses the boundary:

- **Findings**, through the AI-context `onFinding(finding, { boundary })`
  callback: exactly the eight allowlisted fields, with `boundary` set to
  `tool-result` or `tool-arguments`.
- **One record per crossing**: `{ stage, outcome, reason?, code? }`, where
  `stage` is `arguments` or `result`, `reason` is present only for
  `blocked`, and `code` only when the core raised a registered error. It
  holds no count, size, offset, or text derived from input.

The tool name, the server identity, and timing are the host's own metadata
and outside this contract.

## Supported range

An integration may claim only this range, and within it only what its
compatibility matrix has tested. The adapter tests both endpoints of every
line. Widening a range is a new endpoint in the adapter's compatibility
matrix plus an edit of the distribution spec row; it is not a new decision.

| Surface | Supported |
| --- | --- |
| TypeScript SDK, v1 line | `@modelcontextprotocol/sdk` `>=1.13.0 <=1.30.1` (1.13.0 is the first release with protocol revision 2025-06-18: `structuredContent`, `resource_link`, output schemas; 1.30.1 is the latest 1.x on 2026-09-25) |
| TypeScript SDK, v2 line | `@modelcontextprotocol/client` and `@modelcontextprotocol/server` `>=2.0.0 <=2.1.0` |
| Protocol revisions | `2025-06-18` and `2025-11-25`. Earlier revisions lack `structuredContent` and `resource_link`; draft revisions are not claimed. |
| Transports | stdio and Streamable HTTP. The boundary acts on the parsed result, so the transport does not change what is scanned, but only these are exercised. The deprecated HTTP+SSE transport is not claimed. |
| Runtime | Node.js 20, 22, and 24, the core's declared engines |
| Not supported | the Python `mcp` SDK (1.x and 2.x): no Python MCP adapter exists, although the Python binding qualifies the AI-context contract, so a host can build one without a support claim; every other language SDK; `experimental.tasks` and partial-result delivery |

## The golden path today

`examples/mcp-redact` predates this contract and still differs from it. It
stays an example until it moves onto `@redact-secret/adapter-mcp` (the
follow-up to redact-secret-adapters#13), as #610's example did:

| Golden path | This contract |
| --- | --- |
| `image`, `audio`, `resource_link`, and `blob` resources pass through unscanned | binary payloads block by default; `resource_link` fields are scanned |
| `_meta` on the result is copied unchanged | `_meta` is scanned |
| A text block that parses as a JSON object or array is scanned leaf by leaf and re-serialized | text is scanned as text |
| `content` and `structuredContent` are scanned separately, each with its own traversal limits, and `maxContentBlocks` bounds blocks | one value, limits counted from the result root |
| no key-context check | key-context check |
| arguments use the `context` label | `tool-arguments` |
| a failed stream keeps pulling (and discarding) chunks until the producer ends | the stream stops pulling when `accepting` is `false` |

## Conformance

- [`conformance/fixtures/mcp-boundary.json`](../../conformance/fixtures/mcp-boundary.json)
  holds the cases: text, JSON in text, nested `structuredContent`, `_meta`,
  embedded and linked resources, binary content under both settings, unknown
  and malformed blocks, traversal limits counted from the root, the
  key-context check, a split across blocks that is not joined, opt-in
  arguments, a failing tool, streaming splits, early failure that stops
  pulling, cancellation before and during a stream, blocked and core-error
  results, and the uninitialized core. It also pins the limits, the safe
  field set, the content types, and both fixed results. Every value is
  synthetic.
- [`conformance/mcp-boundary.mjs`](../../conformance/mcp-boundary.mjs) is the
  JavaScript reference model and runner. It composes the AI-context
  reference model and adds no scan of its own. It takes any implementation
  through `createBoundary`, so the adapter replays the fixture through its
  own public API. For each case it checks the outcome, the delivered MCP
  result, the audit record, the telemetry labels and fields, how many chunks
  were pulled, whether the producer was closed, and that no synthetic secret
  reached metadata, audit, telemetry, or a delivered result.
- [`scripts/consumer-harness.mjs`](../../scripts/consumer-harness.mjs)
  replays it against the packed, clean-installed `@redact-secret/core` on the
  Node addon lane and in Chromium, Firefox, and WebKit, before and after
  `initialize()`. The artifact inventory requires `mcpBoundary: passed` from
  every lane.
- [`conformance/mcp-boundary.test.mjs`](../../conformance/mcp-boundary.test.mjs)
  tests the model and runner against a fake core in `npm run ci`.

An adapter qualifies by replaying the fixture at a pinned commit of this
repository through its own public API, at both endpoints of every supported
SDK line, and reaching the same outcomes. A change to a case, a traversal
rule, a fixed result, or a label changes the contract.
