# Redact secrets in MCP tool calls

A tested recipe that **redacts** secrets in MCP tool call arguments and
results instead of rejecting the whole call (issue #327), and composes that
into the AI-context golden path a whole agent turn needs (issue #587):

```
user input -> scan -> application policy
tool result -> scan -> context construction
safe context -> model
```

The JavaScript side runs on the framework-neutral
[AI-context boundary contract](../../docs/reference/ai-context-boundary.md)
(#610), through the installable `@redact-secret/adapter-ai-context`
(redact-secret-adapters#12). It is consumed as a publish-shaped `npm pack`
artifact built from a pinned adapters commit (see
[Installing the pinned adapter](#installing-the-pinned-adapter)). This
directory adds only the MCP shape and the order of the turn. The boundary
does every scan, every traversal, every limit, and every failure mapping.
The Python twins under [`python/`](./python) keep their beta.7 behavior; see
[Python](#python).

[`agent-context.mjs`](./agent-context.mjs) is this flow, end to end; see
[The AI-context golden path](#the-ai-context-golden-path).
Existing MCP protections block outright. Docker MCP Gateway's default
`--block-secrets` rejects the whole tool call when any of its 88 regexes
match (`pkg/interceptors/block_secrets.go`), and the ggshield AI hook blocks
prompts and tool calls the same way. A tool result that includes a leaked
`.env` line then becomes a failed call rather than a usable, sanitized one.

## Support level

**The MCP wiring is example-only.** The AI-context boundary underneath it is
a package, `@redact-secret/adapter-ai-context`, owned by
[`redact-secret-adapters`](https://github.com/redact-secret/redact-secret-adapters).
It implements the core's contract and qualifies by replaying the core's
conformance fixture. The MCP-specific part here (which content blocks carry
text, JSON-in-text, the fixed tool-error result, the two wrappers) is not a
maintained package. The supported MCP boundary is #612, and its adapter is
redact-secret-adapters#13. Copy this code out to use it; from then on you own
the copy. The MCP SDK versions it is verified against are in
[SDK versions](#sdk-versions); nothing here claims any other version.

## Files

| File | Role |
| --- | --- |
| [`redact-tool-call.mjs`](./redact-tool-call.mjs) | The MCP shape over the boundary: `redactToolResult` sanitizes a `CallToolResult`'s text content blocks, embedded text resources, and `structuredContent`; `redactArguments` sanitizes a tool call's argument object. Both return the boundary's `ok` / `blocked` / `aborted` outcome. No `@modelcontextprotocol/sdk` import: `CallToolResult` is a duck-typed shape. |
| [`wrap-tool-call.mjs`](./wrap-tool-call.mjs) | Server-side (`wrapServerToolHandler`) and client-side (`wrapClientCallTool`) wrappers built on the above, shaped to drop into a real `ToolCallback` / `callTool`. A non-`ok` outcome becomes the fixed `buildBlockedResult()` tool error. |
| [`agent-context.mjs`](./agent-context.mjs) | The AI-context golden path (`buildSafeContext`), `EXAMPLE_LIMITS`, and the boundary factories (`createGoldenPathBoundary` over the real core, `createGoldenPathBoundaryWith` over an injected one). See [below](#the-ai-context-golden-path). |
| [`streaming-tool-result.mjs`](./streaming-tool-result.mjs) | `redactStreamedToolResult`: a tool result delivered as chunks, through the boundary's staged `openStream`, with cancellation and producer failure. `buildSafeContext`'s `streamTool` runs it. See [Streamed results](#streamed-or-progressive-results). |
| [`demo.mjs`](./demo.mjs) | Runnable, side-by-side: the same synthetic tool result through block-all and through this middleware, on the real core. It prints only the two outputs, never the unscanned input. |
| [`package.json`](./package.json) | This directory as a consumer project: its only dependencies are the pinned `file:` tarballs from `adapters/pin-source.json`. |
| [`fixtures/fake-core.mjs`](./fixtures/fake-core.mjs) | The two injected core operations, faked for the tests: `fake-scanner.mjs`'s rules plus the core's whole-input byte limit, and a core that behaves as if uninitialized. |
| [`python/`](./python) | The Python twins of every file above, at their beta.7 behavior. |

## The AI-context golden path

```
user input -> scan -> application policy
tool result -> scan -> context construction
safe context -> model
```

`buildSafeContext({ boundary, userInput, callTool? | streamTool?, buildToolRequest?, signal? })`
runs one agent turn and returns one of:

- `{ outcome: "ok", value: [{ role, content }], findings }`, the same shape
  the boundary's `buildContext` returns. `value` is the only thing that may
  go to a model, a log line, or storage.
- The boundary's `{ outcome: "blocked", reason, code? }` or
  `{ outcome: "aborted" }`, plus `stage` (`"input"` or `"tool"`). There is no
  value, no findings, and nothing derived from input.
- `{ outcome: "tool_error", stage: "tool" }` when `callTool` rejects, or
  `streamTool` throws or its chunks reject. This is the host's own outcome,
  outside the contract's set: dispatching a tool is the host's job, and the
  error, which may carry input, is never read.

The steps:

1. **User input → scan → application policy.** `userInput` goes through
   `boundary.sanitizeText` (label `user-input`) before anything else. A
   non-`ok` outcome ends the turn: no tool is dispatched, no context exists,
   and `userInput` never appears in the return value on any path.
2. **Tool result → scan → context construction.** `callTool` is dispatched
   from `buildToolRequest(safeInputText)`, the *sanitized* input, never the
   raw one. Its result goes through `redactToolResult` (label `tool-result`)
   before it joins the context. A tool that streams its output is passed as
   `streamTool` instead; its chunks go through one staged boundary stream
   and join the context in the same `CallToolResult` shape (see
   [Streamed results](#streamed-or-progressive-results)).
3. **Safe context → model.** The returned `value` is the only thing this
   function produces that is safe to forward.

Create the boundary once, with the limits and callbacks the host chooses:

```js
import { buildSafeContext, createGoldenPathBoundary } from "./agent-context.mjs";

const boundary = await createGoldenPathBoundary({ onFinding: (finding, { boundary }) => audit(boundary, finding) });
const turn = await buildSafeContext({ boundary, userInput, callTool, buildToolRequest, signal });
if (turn.outcome === "ok") await callModel(turn.value);
```

**All four policy actions**, each tested in `agent-context.test.mjs`:
`allow` (clean input, no findings), `redact` (a finding's span is replaced
and the turn continues), `warn` (the text is untouched and the finding is
reported), and `block` (the whole turn ends, at the input or the tool stage).

**Edge cases, each with its own test, none retaining plaintext:**

- **Limits.** `EXAMPLE_LIMITS` declares every limit the contract requires:
  whole-input (`maxInputBytes`, `maxFindings`), incremental, and traversal
  (`maxDepth` containers, root included; `maxNodes` values). Exceeding one
  blocks the whole operation as `limit_exceeded`. Oversized input is refused
  by the core's whole-input limit before any detection work. Nothing is
  truncated or marked and passed on.
- **Initialization failure.** Before `initialize()`, the core's own
  `NOT_INITIALIZED` becomes `core_error` / `NOT_INITIALIZED`, with no
  separate branch. `createGoldenPathBoundary` never rejects for a core that
  cannot be loaded or initialized: every operation of the boundary it
  returns fails closed.
- **Callback failure.** A throwing `onFinding` is swallowed by the boundary
  and never changes the outcome. A throwing `policy` is `core_error` /
  `POLICY_FAILURE`.
- **Cancellation.** An already-aborted `signal` ends the turn before any
  scan.
- **Abort.** The signal is checked again before the tool is dispatched,
  after it returns, by every scan, and on every streamed chunk, so a signal
  firing mid-flight discards everything, including text already sanitized
  and a stream's staged text.

**What changed from beta.7** (the contract's four fail-closed divergences):

| Beta.7 | Now |
| --- | --- |
| A subtree past a traversal limit became `[REDACTED:LIMIT_EXCEEDED]`, and array items or content blocks past a limit were dropped | The whole call is blocked with `limit_exceeded` |
| Object keys were not scanned | Keys are scanned; a key that would be redacted or blocked blocks the value |
| Non-plain objects passed through, and a cycle became a marker | Anything but JSON values, and any cycle, blocks with `unsupported_value` |
| A blocked outcome carried its findings, and `onFinding` got `{ scope }` | A non-`ok` outcome carries nothing; the boundary's `onFinding(finding, { boundary })` is the audit path |

## Policy mapping

- **`redact`**: the finding's span is replaced with a placeholder; the call
  continues.
- **`warn`** and **`allow`**: the text passes through unchanged; a `warn`
  finding is still reported to telemetry.
- **`block`**, on any finding anywhere in the call, and any other non-`ok`
  outcome (a limit, an unsupported value, a key finding, a core failure, an
  abort): the *whole* call becomes a fixed `CallToolResult` tool error
  (`isError: true`, `content: [{ type: "text", text: BLOCKED_MESSAGE }]`),
  never a partial result, the matched value, or an input excerpt. MCP has a
  first-class "tool error" outcome, so blocking maps onto that instead of a
  leaf-level placeholder. The block *decision* stays with the injected
  policy (the default policy redacts high-confidence/known-type findings and
  warns on the rest, `crates/secret-scan-core/src/policy.rs`).

The first non-`ok` block or value ends the call; nothing after it is
scanned. On the server side, a blocked *argument* (only checked when
`redactArguments` is on) means the wrapped tool handler is never called, so a
blocked secret never reaches the tool implementation. The server wrapper
passes the request's `extra.signal` to the boundary, so a cancelled request
fails closed.

**Safe finding metadata for auditing.** The boundary's
`onFinding(finding, { boundary })` is called for every finding, including in
a call that ends up blocked. It gets exactly the contract's allowlisted
fields (`id`, `type`, `detector`, `confidence`, `action`, `obfuscation`,
`start`, `end`), never the input or a matched value. Tool arguments are
labelled `context` until the MCP boundary (#612) names them. A throwing
callback is swallowed and never influences the outcome.

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
this (`JSON.parse`/`json.loads` succeeds into an object or array), sends the
parsed value through the boundary's `sanitizeValue` (every string and every
key scanned), and re-serializes it. Scanning the raw JSON text as one opaque
string risks placing a placeholder outside a quoted string and corrupting the
JSON; walking the parsed structure cannot. JS's `JSON.stringify` and
Python's `json.dumps(..., separators=(",", ":"))` use the same compact
separators, so the two languages produce byte-identical re-serialized text.

## Multi-block results and non-text content

A `CallToolResult.content` array may mix block types. Only `text` blocks
and embedded **text** resources (`{ type: "resource", resource: { text }
}`) are scanned. `image`, `audio`, `resource_link`, and embedded **blob**
resources (`resource.blob`, base64 binary) pass through unchanged. This is
the documented false-negative boundary: the contract does not decode or scan
non-text content. A content entry that is not an object, or a `content` that
is not an array, blocks the call with `unsupported_value`. More than
`maxContentBlocks` (default 200) blocks it with `limit_exceeded`.
Top-level fields other than `content` and `structuredContent` (`isError`,
`_meta`) are copied unchanged.

## Streamed or progressive results

The base MCP protocol resolves one `CallToolResult` per call; there is no
standard content-streaming primitive, and the SDK's chunked-delivery
`experimental.tasks` API is marked unstable
(`@modelcontextprotocol/sdk@1.30.0`: "may change without notice"). So
streaming here is the case a handler actually faces: one text result
produced in chunks (a subprocess's stdout, a file, an HTTP body) that must
be sanitized before it joins model context, without a secret split across
two chunks slipping through.

`streaming-tool-result.mjs`'s `redactStreamedToolResult(boundary, chunks,
{ signal })` feeds the chunks (`AsyncIterable<string>` or
`Iterable<string>`) through one `boundary.openStream({ boundary:
"tool-result", signal })`, which is one core `IncrementalSanitizer`
session under `EXAMPLE_LIMITS.incrementalLimits`. The golden path runs it
when the tool is passed as `streamTool`:

```js
const turn = await buildSafeContext({
  boundary,
  userInput,
  buildToolRequest,
  signal,
  // Decode bytes with a streaming decoder (setEncoding, TextDecoderStream).
  streamTool: (request, { signal }) => spawnTool(request, { signal }).stdout.setEncoding("utf8"),
});
```

What the stream guarantees, each tested:

- **Split secrets.** A secret split across chunks is detected as one
  secret; finding offsets are absolute in the joined text. For text inside
  both the whole-input and the incremental limits, the result equals a
  whole-input scan of the joined text at every split.
- **Staging.** Nothing is released before the stream finalizes, even text
  the core has already sanitized. The released value is a one-block
  `CallToolResult`, `{ content: [{ type: "text", text }] }`, the same shape
  a `callTool` result joins the context in.
- **Block and limits.** A `block` finding or a limit failure mid-stream
  aborts the core session at once; later chunks are discarded unscanned and
  the turn is `blocked` with no value and no findings.
- **Cancellation.** When `signal` fires, the boundary aborts the core
  session, which drops its retained plaintext, and discards the staged
  text. The loop stops pulling chunks and closes the iterator (`return()`),
  so the producer's `finally` runs and an upstream process or request can be
  cancelled. `streamTool` also gets the signal itself. The turn is
  `aborted`.
- **Producer failure.** A producer that throws or rejects mid-stream is
  aborted the same way and the turn is `tool_error`; its error, which may
  quote the output, is never read.
- **Single release.** `finalize` is called once. On the boundary's own
  stream, a second `finalize` is `blocked` / `lifecycle` and releases
  nothing, an `append` after `finalize` or `abort` is discarded unscanned,
  and `abort` after a successful `finalize` does nothing
  ([lifecycle rules](../../docs/reference/ai-context-boundary.md#lifecycle-rules)).
- **Unsupported chunks.** A non-string chunk (undecoded bytes), a bare
  string, or a value that is not iterable blocks as `unsupported_value`.

Two limits of this design. A mid-stream `block` is only visible at
`finalize`, so the producer is drained (its chunks discarded unscanned)
rather than closed early: the boundary's stream exposes no failed state
before then. And a producer that never yields again after the signal fires
is not interrupted by this loop; it must honor the `signal` it is given.
The core session is aborted the moment the signal fires either way.

`streaming-tool-result.test.mjs` covers all of this over the fake core.
`streaming-tool-result.real-core.test.mjs` covers it over the real core's
`IncrementalSanitizer`, with a synthetic AWS key split mid-token, and checks
that every cancelled, failed, or blocked session was aborted and refuses
further input (`INVALID_STATE`).

## False positives and false negatives

- **False positives** turn a rejected call into a partially masked result
  instead — safer for availability, since most tool output is not a secret,
  but it can still break a tool that needs an exact value it returned (a
  signed URL). Use the per-tool opt-out above, or a relaxed policy, for
  those tools.
- **Non-text content is not scanned** (see above).
- **Split secrets**: a secret split across separate content blocks,
  values, or keys is not joined; each is scanned on its own. A secret split
  across *chunks of one streamed result* is handled (see above); this is a
  different case.
- **Encoded values** (base64, URL-encoded JSON) are not decoded before
  scanning, so an encoded secret is not detected.
- **Stricter than beta.7, on purpose.** A nested value with one blocked
  leaf, one key that would be redacted, one non-JSON value, or anything past
  a traversal limit now blocks the whole call where beta.7 marked or dropped
  the part. That trades availability for never forwarding a partly scanned
  value.

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
`@redact-secret/adapter-otel`'s `SpanProcessor` wrapper needs no OpenTelemetry
import. A real integration installs the SDK itself; see the JSDoc/docstring
usage example at the top of `wrap-tool-call.mjs`/`wrap_tool_call.py`.

## Installing the pinned adapter

`@redact-secret/adapter-ai-context` is not on npm yet, so this directory
consumes it the way an outside consumer would install it: an `npm pack`
tarball built from one immutable, 40-hex `redact-secret-adapters` commit,
recorded in [`adapters/pin-source.json`](../../adapters/pin-source.json)
with each package's content digest. [`package.json`](./package.json) names
those tarballs as `file:` dependencies. From the repository root:

```bash
npm run adapter-pins:install   # builds the pinned adapters once (network), verifies digests, installs here
```

The artifacts live in the gitignored `.cache/adapters/<commit>/`. CI runs the
same command before `npm run ci`, and `npm run examples:test` refuses to run
against a missing or stale install. Re-pinning, the checks, and how to add
another consumer are in [`adapters/README.md`](../../adapters/README.md).

## Running the tests

```bash
npm run adapter-pins:install   # once
npm run examples:test          # every example suite, both languages, over fake cores
python3 -B -m unittest discover -s examples/mcp-redact/python -p "test_*.py"
```

These suites inject a fake core (`fixtures/fake-core.mjs`, built on
`fake-scanner.mjs`, and a fake incremental session for streaming), so no
built native addon or extension is required. `redact-tool-call.test.mjs`
and `python/test_redact_tool_call.py` both read
[`fixtures/mcp-redact-cases.json`](./fixtures/mcp-redact-cases.json), so
text results, JSON-in-text results, arguments, and multi-block results
produce identical redacted output in both languages by construction. The
cases that differ by design (limits, keys, non-JSON values, findings on a
blocked outcome) are tested in the JavaScript suite only.

`streaming-tool-result.real-core.test.mjs` runs the streamed golden path on
the real core instead. It needs a built core resolvable from this directory
(linked as in [Running the demo](#running-the-demo), or an installed
candidate package) and fails, never skips, without one:

```bash
npm run examples:real-core:test
```

It is not part of `npm run ci`, whose Node job builds no core. With a core
linked, `agent-context.test.mjs`'s "core cannot be loaded" case fails by
design, since it asserts this directory has no core.

## Running the demo

`demo.mjs` needs a real core resolvable from this directory. This checkout
does not link `packages/javascript` into `examples/` (there is no npm
workspace), and the consumer install deliberately adds no core. Build it and
link it into the installed tree:

```bash
npm run js:build
npm run adapter-pins:install
ln -s ../../../../packages/javascript examples/mcp-redact/node_modules/@redact-secret/core
node examples/mcp-redact/demo.mjs
# the next `npm run adapter-pins:install` removes the link

python3 examples/mcp-redact/python/demo.py   # requires a built redact_secret extension on PYTHONPATH
```

## Running the golden path against the installed candidate

The suites above never touch the real engine. The `golden-path` job of
[`artifact-qualification.yml`](../../.github/workflows/artifact-qualification.yml)
does (issue #720): it runs `buildSafeContext` on an installed release
candidate, once in Node.js and once through the Python twin, and fails unless
the model-facing context is sanitized. It is one command, the same one CI
runs:

```bash
npm run golden-path:qualify -- --lane <node|python> --candidate-dir <dir>
```

`<dir>` holds the candidate: the npm tarballs
`scripts/pack-npm-candidate.mjs` packs for this host (core, wasm, and the host
addon) and/or the wheel. The Node lane also needs the pinned adapter
tarballs, so run `npm run adapter-pins:install` first.
[`docs/qualification.md`](../../docs/qualification.md#golden-path-qualification)
shows how to build a candidate locally.

[`scripts/qualify-golden-path.mjs`](../../scripts/qualify-golden-path.mjs)
copies `agent-context.mjs` (or `python/agent_context.py`) and every example
module it imports into an empty directory outside the checkout. The Node lane
installs `@redact-secret/core` and this directory's pinned adapters from a
local registry that serves only the candidate and pinned tarballs. The Python
lane installs the candidate wheel into a fresh virtual environment with no
index. One turn carries a synthetic credential in the user input and another
in the tool result. The lane passes only if the turn is `ok`, the tool was
called with already-sanitized input, and the model-facing value carries a
placeholder instead of either credential. The installed packages must match
the candidate files byte for byte. In CI the candidate is this run's own
qualified addon, wasm builds, and wheel, and the `inventory` job rejects a
report whose `.node`, `.wasm`, or `.whl` digests are not ones it recorded.

## Python

The Python twins (`python/agent_context.py`, `redact_tool_call.py`,
`wrap_tool_call.py`, `streaming_tool_result.py`) keep their beta.7 behavior:
a marker for a subtree past a limit, unscanned keys, findings on a blocked
outcome, and a length check for oversized input. `streaming_tool_result.py`
is also not composed into `agent_context.py` and has no cancellation: it is
the beta.7 standalone redactor over an injected session. Its JavaScript
counterpart moved onto the boundary's `openStream` (#721); the Python one
waits for a Python `open_stream`, because re-deriving the staging,
cancellation, and single-release rules here would be a second, unqualified
implementation of the contract. There is no Python
AI-context adapter package yet. The core's Python binding already passes the
contract's fixture (`bindings/python/tests/test_ai_context_boundary.py`),
so a Python adapter can be pinned the same way once
`redact-secret-adapters` ships one.

## Upstream validation

Acceptance criterion for issue #327: share this example with at least one
MCP framework or gateway maintainer (a docs PR, a discussion, or an issue)
to validate integrator demand, and link it from the issue. That is a real
action against an external repository (`modelcontextprotocol/*`,
`docker/mcp-gateway`, or another gateway's own repo) and is not performed by
this change — like issue #326's equivalent criterion, it is tracked as
follow-up.
