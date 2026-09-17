# Redact secrets in MCP tool calls

Middleware, in JavaScript and Python, that **redacts** secrets in MCP tool
call arguments and results instead of rejecting the whole call (issue #327).
Existing MCP protections block outright — Docker MCP Gateway's default
`--block-secrets` rejects the whole tool call when any of its 88 regexes
match (`pkg/interceptors/block_secrets.go`), and the ggshield AI hook blocks
prompts and tool calls the same way. A tool result that includes a leaked
`.env` line then becomes a failed call rather than a usable, sanitized one.

Both languages are examples, not package exports: no new dependency is
added to `@redact-secret/core` or `redact-secret`, and no MCP SDK is
installed in this workspace — see [SDK versions](#sdk-versions).

## Files

| File | Role |
| --- | --- |
| [`redact-tool-call.mjs`](./redact-tool-call.mjs) / [`python/redact_tool_call.py`](./python/redact_tool_call.py) | The shared primitive: redact a `CallToolResult`'s content blocks / `structuredContent`, or a tool call's argument object, mapping findings onto the issue's `redact`/`warn`/`block` policy contract. No `@modelcontextprotocol/sdk`/`mcp` import — `CallToolResult` is a plain, duck-typed shape, the same choice `examples/tracing-masking/redact-span-attributes.mjs` makes for OpenTelemetry's `SpanProcessor`. |
| [`wrap-tool-call.mjs`](./wrap-tool-call.mjs) / [`python/wrap_tool_call.py`](./python/wrap_tool_call.py) | Server-side (`wrapServerToolHandler`/`wrap_server_tool_handler`) and client-side (`wrapClientCallTool`/`wrap_client_call_tool`) wrappers built on the primitive above, shaped to drop into a real `ToolCallback` / `on_call_tool` handler / `callTool`/`call_tool`. |
| [`streaming-tool-result.mjs`](./streaming-tool-result.mjs) / [`python/streaming_tool_result.py`](./python/streaming_tool_result.py) | Redaction for a tool result assembled progressively (a handler piping a subprocess/file/HTTP response in chunks), built on `createIncrementalSanitizer`/`IncrementalSanitizer`. See [Streamed results](#streamed-or-progressive-results). |
| [`demo.mjs`](./demo.mjs) / [`python/demo.py`](./python/demo.py) | Runnable, side-by-side: the same synthetic tool result through block-all vs. this middleware's redact behavior. |

## Policy mapping

- **`redact`**: the finding's span is replaced with a placeholder; the call
  continues.
- **`warn`**: the text passes through unchanged; the finding is still
  reported to `onFinding`/`on_finding`.
- **`block`**, on any finding anywhere in the call, or a `scanAndRedact`
  failure: the *whole* call becomes a fixed `CallToolResult` tool error
  (`isError: true`, `content: [{ type: "text", text: BLOCKED_MESSAGE }]`) —
  never a partial result, the matched value, or an input excerpt. This
  differs from `examples/tracing-masking`'s per-leaf `BLOCK_MARKER`
  substitution: MCP already has a first-class "tool error" outcome, so
  blocking maps onto that instead of a leaf-level placeholder. The block
  *decision* stays with the injected policy (the default policy redacts
  high-confidence/known-type findings and warns on the rest,
  `crates/secret-scan-core/src/policy.rs`); this middleware only maps
  whatever the policy decided onto the correct MCP-level outcome — it does
  not choose to block on its own.

A block anywhere aborts before any further scanning — once blocked, no
further leaves are scanned, minimizing exposure. On the server side, a
blocked *argument* finding (only checked when `redactArguments`/
`redact_arguments_before_forwarding` is enabled) means the wrapped tool
handler is never called at all: a blocked secret never reaches the tool
implementation.

**Safe finding metadata for auditing.** `onFinding`/`on_finding` is called
for every finding — including on a blocked outcome — with exactly the safe
metadata `scan`/`scan_and_redact` already return (`id`, `type`, `detector`,
`confidence`, `action`, `start`, `end`); never the input or a matched value.
A throwing callback is swallowed and never influences the redaction
outcome.

## Arguments: opt-in, not automatic

`redactArguments`/`redact_arguments_before_forwarding` defaults to `false`.
Most tools need the real argument value to function — an API key the tool
must actually send, a signed URL it must fetch — so redacting arguments
before forwarding is opt-in per tool, not a default. This is also the
per-tool opt-out the issue's false-positive section asks for: a tool whose
result *must* carry an exact value (a signed URL) can be excluded from
result redaction the same way, by not wrapping it, or with a policy that
`warn`s instead of `redact`s for the relevant finding types.

## JSON-in-text results

An MCP text block's `text` may itself be a JSON-serialized value (a
stringified API response). `redactToolResult`/`redact_tool_result` detects
this (`JSON.parse`/`json.loads` succeeds into an object or array) and
redacts every string leaf inside the parsed structure before
re-serializing, rather than scanning the raw JSON text as one opaque
string. Scanning raw JSON text directly risks placing a placeholder outside
a quoted string and corrupting the JSON; walking the parsed structure
cannot. JS's `JSON.stringify` and Python's `json.dumps(..., separators=(",",
":"))` are both configured for the same compact, no-space separators, so
the two languages produce byte-identical re-serialized text.

## Multi-block results and non-text content

A `CallToolResult.content` array may mix block types. Only `text` blocks
and embedded **text** resources (`{ type: "resource", resource: { text }
}`) are scanned. `image`, `audio`, `resource_link`, and embedded **blob**
resources (`resource.blob`, base64 binary) pass through unchanged — the
documented false-negative boundary from the issue: non-text content is not
scanned.

## Streamed or progressive results

The base MCP protocol resolves one `CallToolResult` per call; there is no
standard content-streaming primitive, and the SDK's chunked-delivery
`experimental.tasks` API is marked unstable
(`@modelcontextprotocol/sdk@1.30.0`: "may change without notice"). Instead,
`streaming-tool-result.mjs`/`streaming_tool_result.py` targets the case a
handler actually faces: assembling one result from chunks (piping a
subprocess, file, or HTTP response) without ever holding the whole
unredacted text in memory, and without a secret split across a chunk
boundary slipping through. It drives the core's own bounded
`IncrementalSanitizer` — the same session the byte-stream adapters use —
and its limits are mandatory, matching that session's "no
environment-derived or silent defaults" contract
(`packages/javascript/src/types.ts`'s `IncrementalLimits`).

**Fails closed.** Any error the session raises — a declared limit
exceeded — aborts the session and discards every chunk already
accumulated, including text that was already safe. A partial result is not
a safe result. `streaming-tool-result.test.mjs`/`test_streaming_tool_result.py`
prove both properties with a fake session: a secret split across two
`append()` calls is still redacted once the session resolves it (at
`finalize()`, in the deliberately maximal-buffering fake — see
`fixtures/fake-incremental-sanitizer.mjs`), and exceeding the declared
buffer limit blocks the call and returns no text at all.

## False positives and false negatives

- **False positives** turn a rejected call into a partially masked result
  instead — safer for availability, since most tool output is not a secret,
  but it can still break a tool that needs an exact value it returned (a
  signed URL). Use the per-tool opt-out above, or a relaxed policy, for
  those tools.
- **Non-text content is not scanned** (see above).
- **Split secrets**: a secret split across separate content blocks, or
  across argument keys, is not joined — each leaf is scanned independently.
  A secret split across a *streaming chunk boundary within one leaf* is
  handled (see above); this is a different case.
- **Encoded values** (base64, URL-encoded JSON) are not decoded before
  scanning, so an encoded secret is not detected.

## SDK versions

Verified while resolving issue #327, directly against each package's
published type declarations / source, not from memory:

- **TypeScript**: `@modelcontextprotocol/sdk@1.30.0`. `ToolCallback` —
  `server/mcp.d.ts` — is `(args, extra) => CallToolResult |
  Promise<CallToolResult>`; `Client#callTool` — `client/index.d.ts` — takes
  `CallToolRequest['params']` and resolves to the same `CallToolResult`;
  `CallToolResultSchema` — `types.d.ts` — is `{ content: ContentBlock[],
  structuredContent?, isError? }` with `ContentBlock` a union of `text`,
  `image`, `audio`, `resource_link`, and `resource` (embedded, `text` or
  `blob`).
- **Python**: the official SDK, `mcp@2.2.0` (chosen over the standalone
  `fastmcp` package for the same reason the TS side targets
  `@modelcontextprotocol/sdk` — both are the `modelcontextprotocol` org's
  own SDK, keeping the two languages' pinned dependency on the same
  publisher). `mcp.server.lowlevel.Server`'s `on_call_tool` constructor
  callback — `mcp/server/lowlevel/server.py` — is `Callable[[ctx,
  CallToolRequestParams], Awaitable[CallToolResult | InputRequiredResult]]`;
  `mcp.client.session.ClientSession.call_tool` —
  `mcp/client/session.py` — is `(name, arguments) -> CallToolResult`.
  `CallToolResult`/content block shapes — `mcp_types` (a `mcp` dependency,
  same version) — mirror the TS side field for field
  (`is_error`/`isError`, `structured_content`/`structuredContent`).

Neither package is installed in this workspace: every wrapper here is
duck-typed against these verified shapes, exactly like
`examples/tracing-masking`'s `SpanProcessor` wrapper needs no OpenTelemetry
import. A real integration installs the SDK itself; see the JSDoc/docstring
usage example at the top of `wrap-tool-call.mjs`/`wrap_tool_call.py`.

## Running the tests

```bash
node --test examples/mcp-redact/*.test.mjs
python3 -B -m unittest discover -s examples/mcp-redact/python -p "test_*.py"
```

Both suites use a fake `scanAndRedact`/`scan_and_redact` (and, for
streaming, a fake incremental session) — no built native addon or extension
is required. `redact-tool-call.test.mjs` and
`python/test_redact_tool_call.py` both read
[`fixtures/mcp-redact-cases.json`](./fixtures/mcp-redact-cases.json), so
text results, JSON-in-text results, arguments, and multi-block results
produce identical redacted output in both languages by construction, not by
inspection.

Running the demos requires a real, built package resolvable by name —
`@redact-secret/core` / `redact_secret` — which this monorepo checkout does
not provide from an `examples/` path by default (only `packages/javascript`
self-resolves its own name; there is no npm workspace linking it to
`examples/`). Link it first, exactly as a downstream consumer's install
would resolve it:

```bash
npm run js:build
(cd packages/javascript && npm link)
(cd examples/mcp-redact && npm link @redact-secret/core)
node examples/mcp-redact/demo.mjs
# afterwards: npm unlink -g @redact-secret/core; rm -rf examples/mcp-redact/node_modules examples/mcp-redact/package-lock.json

python3 examples/mcp-redact/python/demo.py   # requires a built redact_secret extension on PYTHONPATH
```

## Upstream validation

Acceptance criterion for issue #327: share this example with at least one
MCP framework or gateway maintainer (a docs PR, a discussion, or an issue)
to validate integrator demand, and link it from the issue. That is a real
action against an external repository (`modelcontextprotocol/*`,
`docker/mcp-gateway`, or another gateway's own repo) and is not performed by
this change — like issue #326's equivalent criterion, it is tracked as
follow-up.
