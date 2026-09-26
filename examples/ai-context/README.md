# Reference: redact secrets while constructing AI context

The AI-context reference architecture (#611; index in
[runtime-boundary reference architectures](../../docs/guides/reference-architectures.md)).
An agent turn takes user input, calls a tool, and builds the context it
sends to a model. Every value crosses the framework-neutral
[AI-context boundary contract](../../docs/reference/ai-context-boundary.md)
(#610) before it joins that context.

```bash
npm run reference:ai-context   # from the repository root: npm ci in examples/mcp-redact and here, then the smoke test
```

This directory adds no redaction logic and no second golden path. It
composes two things that already exist:

- the [`examples/mcp-redact`](../mcp-redact/README.md) golden path
  (`buildSafeContext`, `createGoldenPathBoundaryWith`, `redactToolResult`),
  which runs on `@redact-secret/adapter-ai-context`, the contract's
  implementation, with tool results sanitized by `@redact-secret/adapter-mcp`
  (the [MCP boundary contract](../../docs/reference/mcp-boundary.md)), both
  installed there from the npm registry at `0.1.0-alpha` (dist-tag
  `alpha`, with `@redact-secret/adapter@0.1.1` under them), pinned exactly by
  [`examples/mcp-redact/package-lock.json`](../mcp-redact/package-lock.json);
- the released `@redact-secret/core@0.1.0-beta.8` from the npm registry,
  pinned exactly by [`package-lock.json`](./package-lock.json), initialized
  once and injected into the boundary.

`npm run reference:ai-context` runs `npm run examples:install` first, which
installs the locked adapters into `examples/mcp-redact` with `npm ci`.
There is no Python AI-context reference: Python MCP is not supported
([decision](../../docs/decisions/2026-09-25-define-the-supported-mcp-redaction-boundary.md)),
and the Python MCP golden-path twins were retired (#810).

| File | Role |
| --- | --- |
| [`app.mjs`](./app.mjs) | `createAppBoundary`: initializes the registry core and builds the golden path's boundary over it. |
| [`smoke.mjs`](./smoke.mjs) | The end-to-end smoke test: whole turns through `buildSafeContext`, with a single and a streamed tool result, on the real core. |
| [`package.json`](./package.json) / [`package-lock.json`](./package-lock.json) | This directory as a consumer project. Its only dependency is the registry core. |

```js
import { buildSafeContext, createAppBoundary } from "./app.mjs";

const boundary = await createAppBoundary({ onFinding: (finding, { boundary }) => audit(boundary, finding) });
const turn = await buildSafeContext({ boundary, userInput, callTool, buildToolRequest, signal });
if (turn.outcome === "ok") await callModel(turn.value);
```

## Trust zone

Plaintext exists in the host process: the raw user input, the raw tool
result, and the text the boundary is scanning. The sanitized context
(`turn.value`) is the only value that may leave that zone for a model
provider, a log line, a trace, or conversation storage. A non-`ok` outcome
carries nothing derived from input.

## Authoritative scan point

The boundary's operations, in the order `buildSafeContext` calls them:

```
user input -> sanitizeText (user-input)  -> application policy
tool result -> redactToolResult (tool-result) -> context construction
safe context -> model
```

The tool is dispatched from the *sanitized* input, so a tool argument
derived from what the user typed never carries the raw value. The scan
happens in the host, before the model call, because nothing after it (the
provider's API, its logs, its retention) is under the host's control.

## Preventive versus authoritative scanning

A scan in the client, the browser, or an IDE before the text is sent is
preventive UX: it catches mistakes early but can be bypassed. The
server-side boundary here is authoritative. A model provider's own filtering
is outside the host's control and is not a substitute.

## Failure and limit behavior

Every case below is exercised by `smoke.mjs` against the real core.

| Case | Outcome |
| --- | --- |
| A `redact` finding | `ok`; the span becomes `<SECRET_N>` and the turn continues |
| A `block` finding in the user input | `blocked` / `policy` at stage `input`; the tool is never dispatched |
| A `block` finding in the tool result | `blocked` / `policy` at stage `tool`; no context |
| Input over the whole-input limit | `blocked` / `limit_exceeded` / `INPUT_LIMIT_EXCEEDED`, refused before detection |
| A core or policy failure | `blocked` / `core_error`, with the core's registered code only |
| The tool call rejects | `tool_error`; the rejection's error, which may carry input, is never read |
| An abort while the tool runs, or mid-stream | `aborted`; text already sanitized is discarded |
| Every finding | Reported to `onFinding` as allowlisted metadata only, never the input or a matched value |
| An MCP-shaped result (text, embedded text resource, nested `structuredContent`) | The model call, a host log line, and a conversation store receive only the sanitized turn, as fresh objects sharing no reference with the raw result |

Limits are mandatory and explicit (`EXAMPLE_LIMITS` in
`examples/mcp-redact/agent-context.mjs`). Nothing is truncated and passed
on: exceeding a limit blocks the whole operation.

## Streaming behavior

A tool that produces its result in chunks is passed as `streamTool`
instead of `callTool` (#721). `buildSafeContext` feeds the chunks through
the boundary's staged `openStream`: a secret split across chunk boundaries
is redacted as one secret, nothing is released before the stream finalizes,
and an abort or a failing producer discards everything and closes the
producer. `smoke.mjs` runs both the split secret and an abort mid-stream.
The details are in [`examples/mcp-redact`](../mcp-redact/README.md).

## What it does not protect

- **Context that skips the boundary.** Retrieved documents, system prompts,
  and conversation history must also go through `buildContext`,
  `sanitizeText`, or `sanitizeValue`; the golden path covers only user input
  and one tool result, single or streamed.
- **Model output.** Scanning what the model returns is a different
  boundary and is out of the contract's scope.
- **A secret split across values or keys.** Each string leaf and key is
  scanned on its own, so JSON loses key context: `{"api_key": "<value>"}`
  scans the value without the `api_key` name next to it, and a value that is
  not self-identifying is not detected. `API_KEY=<value>` inside one string
  is.
- **Non-text content and encoded values.** Images, audio, blobs, base64,
  and percent-encoding are not decoded or scanned.
- **The MCP transport and tool authorization.** Tool results follow the
  [MCP redaction boundary contract](../../docs/reference/mcp-boundary.md)
  (#612) through `@redact-secret/adapter-mcp`: the whole result is scanned,
  `_meta` and `resource_link` fields included, and binary content blocks by
  default. Authentication, authorization, prompt injection, and tool
  permissions are its non-goals too.
- **The process itself.** Plaintext exists in memory, and callbacks the
  host passes in are trusted code.

## Evidence

- Support: the [support matrix](../../docs/support-matrix.md).
- Core cost per scan and per artifact: `redact-secret-benchmarks`'
  [operational evidence](https://github.com/redact-secret/redact-secret-benchmarks/blob/main/docs/reports/2026-09-25-beta8-141-operational-evidence.md).
- The contract's conformance fixture, replayed by the adapter on the real
  core, and the core range it is qualified against: the adapters
  repository's
  [`compatibility.json`](https://github.com/redact-secret/redact-secret-adapters/blob/ea92c2abd451b66899722170344e73d8f34ef47e/compatibility.json)
  at the `train/2026.09.25` commit that published these adapter versions.
