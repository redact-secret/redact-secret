# Redact secrets in MCP tool calls

A tested recipe that **redacts** secrets in MCP tool call arguments and
results instead of rejecting the whole call (issue #327), and composes that
into the AI-context golden path a whole agent turn needs (issue #587):

```
user input -> scan -> application policy
tool result -> scan -> context construction
safe context -> model
```

The JavaScript side runs on the supported
[MCP redaction boundary contract](../../docs/reference/mcp-boundary.md)
(#612), through the installable `@redact-secret/adapter-mcp`
(redact-secret-adapters#13), which is a thin specialization of the
framework-neutral [AI-context boundary contract](../../docs/reference/ai-context-boundary.md)
(#610) and its `@redact-secret/adapter-ai-context` (redact-secret-adapters#12).
Both are installed from the npm registry at exact versions, pinned by
[`package-lock.json`](./package-lock.json) (see
[Installing the adapters](#installing-the-adapters)). This
directory adds only the order of the turn. The adapters do every scan, every
traversal, every MCP shape rule, every limit, and every failure mapping.
This example is JavaScript only: **Python MCP is not supported** (see
[Python](#python)).

[`agent-context.mjs`](./agent-context.mjs) is this flow, end to end; see
[The AI-context golden path](#the-ai-context-golden-path).
Existing MCP protections block outright. Docker MCP Gateway's default
`--block-secrets` rejects the whole tool call when any of its 88 regexes
match (`pkg/interceptors/block_secrets.go`), and the ggshield AI hook blocks
prompts and tool calls the same way. A tool result that includes a leaked
`.env` line then becomes a failed call rather than a usable, sanitized one.

## Support level

**The recipe is example-only; the boundary under it is not.** The MCP
boundary is a package, `@redact-secret/adapter-mcp`, owned by
[`redact-secret-adapters`](https://github.com/redact-secret/redact-secret-adapters).
It implements the core's [MCP boundary contract](../../docs/reference/mcp-boundary.md),
replays the core's MCP conformance fixture, and is tested with real MCP SDK
instances at both endpoints of every supported line, over stdio and
Streamable HTTP. The JavaScript files here only compose it into an agent turn
and two thin wrappers, so they follow the contract: the whole result is
scanned (including `_meta` and resource links), text is scanned as text,
binary content blocks unless the host opts in, and a key-context check runs
after the leaf pass. Copy this code out to use it; from then on you own the
copy. There is no Python recipe: the Python `mcp` SDK is not supported (see
[Python](#python)). The supported SDK range is in [SDK versions](#sdk-versions).

The locked `adapter-mcp@0.1.0-alpha.1` and
`adapter-ai-context@0.1.0-alpha.1` include the key-aware `sanitizeValue`
(#842), which redacts a leaf that only its own key identifies, and the
[`resources/read` boundary](../../docs/reference/mcp-resources-read.md)
(#843). The AI-context reference smoke exercises both through these exact
registry packages.

## Files

| File | Role |
| --- | --- |
| [`redact-tool-call.mjs`](./redact-tool-call.mjs) | `@redact-secret/adapter-mcp` over the host's AI-context boundary: `redactToolResult` is the adapter's `sanitizeToolResult` (the whole `CallToolResult` as one value, then the key-context check); `redactArguments` is its `sanitizeToolArguments` (label `tool-arguments`). It also exposes the cached MCP boundary and `toReadResourceResponse` for the `resources/read` reference flow. No `@modelcontextprotocol/sdk` import. |
| [`wrap-tool-call.mjs`](./wrap-tool-call.mjs) | Server-side (`wrapServerToolHandler`, the adapter's `wrapToolHandler`) and client-side (`wrapClientCallTool`, its `sanitizeToolCall`) wrappers, shaped to drop into a real `ToolCallback` / `callTool`. A non-`ok` outcome becomes the contract's fixed `isError` result; a thrown handler or a rejected `callTool` becomes the fixed tool-error result; a cancelled call delivers nothing. |
| [`agent-context.mjs`](./agent-context.mjs) | The AI-context golden path (`buildSafeContext`), `EXAMPLE_LIMITS`, and the boundary factories (`createGoldenPathBoundary` over the real core, `createGoldenPathBoundaryWith` over an injected one). See [below](#the-ai-context-golden-path). |
| [`streaming-tool-result.mjs`](./streaming-tool-result.mjs) | `redactStreamedToolResult`: a tool result delivered as chunks, through the adapter's `sanitizeStreamedToolResult` (one staged `openStream` that stops pulling once it fails), with cancellation and producer failure. `buildSafeContext`'s `streamTool` runs it. See [Streamed results](#streamed-or-progressive-results). |
| [`demo.mjs`](./demo.mjs) | Runnable, side-by-side: the same synthetic tool result through block-all and through this middleware, on the real core. It prints only the two outputs, never the unscanned input. |
| [`package.json`](./package.json), [`package-lock.json`](./package-lock.json), [`.npmrc`](./.npmrc) | This directory as a consumer project: its only dependencies are the published `@redact-secret/adapter-ai-context@0.1.0-alpha.1` and `@redact-secret/adapter-mcp@0.1.0-alpha.1` (dist-tag `alpha`), with `@redact-secret/adapter@0.1.2` under them, all locked exactly. `.npmrc` sets `legacy-peer-deps`, so the adapters' `@redact-secret/core` peer is not installed here: the tests inject their core. |
| [`fixtures/fake-core.mjs`](./fixtures/fake-core.mjs) | The two injected core operations, faked for the tests: `fake-scanner.mjs`'s rules plus the core's whole-input byte limit, and a core that behaves as if uninitialized. |

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
- **`block`**, on any finding anywhere in the call, and any other `blocked`
  outcome (a limit, an unsupported value, a key finding, a key-context
  finding, a core failure): the *whole* call becomes a fixed `CallToolResult` tool error
  (`isError: true`, `content: [{ type: "text", text: BLOCKED_MESSAGE }]`),
  never a partial result, the matched value, or an input excerpt. MCP has a
  first-class "tool error" outcome, so blocking maps onto that instead of a
  leaf-level placeholder. The block *decision* stays with the injected
  policy (the default policy redacts high-confidence/known-type findings and
  warns on the rest, `crates/secret-scan-core/src/policy.rs`).

An `aborted` outcome delivers nothing at all: a cancelled request gets no
response, and a cancelled client call resolves to `null`.

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
`start`, `end`), never the input or a matched value. Results are labelled
`tool-result` and arguments `tool-arguments`. A throwing callback is
swallowed and never influences the outcome.

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
stringified API response). The MCP contract scans it **as text**, exactly as
the model will see it, and never parses it: parsing would drop the key
context that catches `"password":"..."` in text, and the core's contextual
detectors read that context. A secret inside JSON-in-text is replaced inside
its quoted string. `structuredContent`, which a tool is expected to return
next to its text serialization, is scanned as a value. The key-aware
`sanitizeValue` redacts a leaf identified by its immediate key in place, and
the serialized key-context check stays as a backstop for sibling and parent
keys; see
[Key-context backstop](../../docs/reference/mcp-boundary.md#key-context-backstop).

## Multi-block results and non-text content

A `CallToolResult` is scanned as one bounded value: every block, every
field (`uri`, `name`, `title`, `description` of a `resource_link`, the
`uri` and `mimeType` of an embedded resource), `_meta` on the result and on
each block, `annotations`, and any field the contract does not name.
Traversal limits count from the result root, so there is no separate block
count. `image` and `audio` `data` and a `resource.blob` are base64 and never
decoded: by default they block the whole result as `unsupported_value`.
Passing `binaryContent: "pass"` (to `redactToolResult`, the wrappers, or
`buildSafeContext`) passes a string payload unchanged and unscanned at its
original position, while the rest of the block is still scanned. A block
type outside `text`, `image`, `audio`, `resource_link` and `resource`, a
content entry that is not an object, or a `content` that is not an array
blocks the call with `unsupported_value`.

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
  aborts the core session at once, and no further chunk is pulled (see
  **Early stop** below). The turn is `blocked` with no value and no
  findings.
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

**Early stop.** After every chunk the adapter reads the stream's input-free
`accepting` flag. Once it is `false` (a `block` finding, a limit, a core
failure, or cancellation), it pulls no further chunk and closes the
producer: `return()` on its iterator, and `destroy()` on a Node `Readable`.
It does not wait on either, and a real `AbortSignal` also ends a producer
that is still pending. So a failed stream no longer drains its producer.

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
- **Non-text content is never decoded** (see above). By default it blocks
  the result; with `binaryContent: "pass"` it passes unscanned.
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

The JavaScript side makes no SDK claim of its own. It inherits
`@redact-secret/adapter-mcp`'s, which is the contract's
[supported range](../../docs/reference/mcp-boundary.md#supported-range):
`@modelcontextprotocol/sdk` `>=1.13.0 <=1.30.1`, and
`@modelcontextprotocol/client` / `@modelcontextprotocol/server`
`>=2.0.0 <=2.1.0`. Protocol revisions 2025-06-18 and 2025-11-25, over stdio
and Streamable HTTP, on Node.js 20, 22 and 24. The adapter's CI runs real
clients and servers at both endpoints of each line
([`compatibility.json`](https://github.com/redact-secret/redact-secret-adapters/blob/main/compatibility.json)).
The wrappers here stay duck-typed: a tool handler is `(args, extra)` on 1.x
and `(args, ctx)` with `ctx.mcpReq.signal` on 2.x, and the adapter reads
either signal.

- **Python**: the Python `mcp` SDK is **not supported** by the MCP contract,
  and no Python MCP adapter exists (see [Python](#python)).

A real integration installs the SDK itself; see the JSDoc usage example at
the top of `wrap-tool-call.mjs`.

## Installing the adapters

`@redact-secret/adapter-ai-context` and `@redact-secret/adapter-mcp` are
published by the adapters train 2026.09.26 as `0.1.0-alpha.1` under the
`alpha` dist-tag. [`package.json`](./package.json) names those exact
versions, and [`package-lock.json`](./package-lock.json) locks them, and
`@redact-secret/adapter@0.1.2` under them, with their registry integrity.
From the repository root:

```bash
npm run examples:install   # npm ci here (network): exactly the locked registry packages
```

CI runs the same command before `npm run ci`. Moving to a newer adapter
release is an edit of `package.json` plus a regenerated lockfile
(`npm install` here), reviewed like any other change.

## Running the tests

```bash
npm run examples:install   # once
npm run examples:test      # every example suite, over fake cores
```

These suites inject a fake core (`fixtures/fake-core.mjs`, built on
`fake-scanner.mjs`, and a fake incremental session for streaming), so no
built native addon is required. `redact-tool-call.test.mjs` reads
[`fixtures/mcp-redact-cases.json`](./fixtures/mcp-redact-cases.json). The
two binary cases (an image, a blob resource) block by default under the MCP
contract, and pass only with `binaryContent: "pass"`, which the suite checks
both ways.

`streaming-tool-result.real-core.test.mjs` runs the streamed golden path on
the real core instead. It needs a built core resolvable from this directory
(linked as in [Running the demo](#running-the-demo), or an installed
candidate package) and fails, never skips, without one:

```bash
npm run examples:real-core:test
```

It is not part of `npm run ci`, whose Node job builds no core. The
`golden-path` qualification job runs it against the installed candidate core
(see [below](#running-the-golden-path-against-the-installed-candidate)).
`agent-context.test.mjs`'s "core cannot be loaded" case makes the core
unloadable with a module resolve hook, so it holds with or without a core
here.

## Running the demo

`demo.mjs` needs a real core resolvable from this directory. This checkout
does not link `packages/javascript` into `examples/` (there is no npm
workspace), and the consumer install deliberately adds no core. Build it and
link it into the installed tree:

```bash
npm run js:build
npm run examples:install
ln -s ../../../../packages/javascript examples/mcp-redact/node_modules/@redact-secret/core
node examples/mcp-redact/demo.mjs
# the next `npm run examples:install` removes the link
```

## Running the golden path against the installed candidate

The suites above never touch the real engine. The `golden-path` job of
[`artifact-qualification.yml`](../../.github/workflows/artifact-qualification.yml)
does (issue #720): it runs `buildSafeContext` on an installed release
candidate in Node.js, and fails unless the model-facing context is
sanitized. It is one command, the same one CI runs:

```bash
npm run golden-path:qualify -- --lane node --candidate-dir <dir>
```

`<dir>` holds the candidate: the npm tarballs
`scripts/pack-npm-candidate.mjs` packs for this host (core, wasm, and the host
addon). The driver fetches the adapter tarballs itself (network).
[`docs/qualification.md`](../../docs/qualification.md#golden-path-qualification)
shows how to build a candidate locally.

[`scripts/qualify-golden-path.mjs`](../../scripts/qualify-golden-path.mjs)
copies `agent-context.mjs` and every example module it imports into an empty
directory outside the checkout. It installs the candidate
`@redact-secret/core` and this directory's adapters from a local registry
that serves only the candidate tarballs and the adapter tarballs
[`package-lock.json`](./package-lock.json) locks. Those are the published
registry bytes, fetched from each entry's `resolved` URL and verified against
its `integrity` before they are served, so the clean project runs the same
adapter versions this directory does. One turn carries a synthetic credential in the user input and another
in the tool result. The lane passes only if the turn is `ok`, the tool was
called with already-sanitized input, and the model-facing value carries a
placeholder instead of either credential. The lane then runs the test
files `npm run examples:real-core:test` names in the same project, so the
streamed path runs on the installed candidate's `IncrementalSanitizer` too.
The installed packages must match
the candidate files byte for byte. In CI the candidate is this run's own
qualified addon and wasm builds, and the `inventory` job rejects a report
whose `.node` or `.wasm` digests are not ones it recorded, or whose adapters
are not the ones the lockfile locks.

## Python

**Python MCP is not supported.** The
[supported MCP redaction boundary decision](../../docs/decisions/2026-09-25-define-the-supported-mcp-redaction-boundary.md)
(#612) excludes the Python `mcp` SDK, and there is no Python AI-context or MCP
adapter package. This directory therefore has no Python recipe. The Python
twins that used to live under `python/` kept their beta.7 behavior (binary content and
`_meta` passed through unscanned, JSON-in-text parsed, no key-context check,
arguments labelled `context`, a streamed redactor with no early stop or
cancellation). They read as a Python MCP support claim, so they were retired
with their golden-path qualification lane (#810) instead of being aligned in
place: a second, unqualified implementation of the contract is what the
adapters exist to avoid.

The core's Python binding does pass the AI-context contract's fixture
(`bindings/python/tests/test_ai_context_boundary.py`). A Python recipe returns
only when `redact-secret-adapters` ships a Python AI-context and MCP adapter to
build it on.

## Upstream validation

Acceptance criterion for issue #327: share this example with at least one
MCP framework or gateway maintainer (a docs PR, a discussion, or an issue)
to validate integrator demand, and link it from the issue. That is a real
action against an external repository (`modelcontextprotocol/*`,
`docker/mcp-gateway`, or another gateway's own repo) and is not performed by
this change — like issue #326's equivalent criterion, it is tracked as
follow-up.
