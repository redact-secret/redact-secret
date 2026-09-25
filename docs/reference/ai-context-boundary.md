# AI-context boundary contract

[Documentation home](../README.md)

This contract says what any integration must do when untrusted text or tool
output crosses into an AI workflow: into a prompt, a tool call, a constructed
model context, or a log or store next to them. It is framework-neutral. It
names no model vendor, agent framework, or transport, and it can be
implemented from documented core APIs alone. The installable implementation
belongs to [`redact-secret-adapters`](https://github.com/redact-secret/redact-secret-adapters)
([redact-secret-adapters#12](https://github.com/redact-secret/redact-secret-adapters/issues/12)).
This repository owns the contract, its conformance fixture, and the core
behavior underneath it.

Decided by
[`decision-define-the-framework-neutral-ai-context-boundary-contract`](../decisions/2026-09-25-define-the-framework-neutral-ai-context-boundary-contract.md);
the current rule is in [distribution](../specs/distribution.md).

```text
untrusted input or tool output
  -> bounded traversal / incremental decode
  -> core scan and policy
  -> redact | warn | block | allow
  -> safe context value or input-free failure
```

## Where it comes from

The contract takes the boundary semantics that the beta.7 golden path
(#587) already exercises in tests and turns them into rules. It adds no
speculative framework API. Sources, pinned at
[`76fc779`](https://github.com/redact-secret/redact-secret/tree/76fc779ea926d4983ec5d32b85c4726b40308bcb/examples/mcp-redact):

| Measured behavior | Beta.7 source |
| --- | --- |
| Scan user input before anything else; `block` ends the turn with no context | [`redactUserInput`, `buildSafeContext`](https://github.com/redact-secret/redact-secret/blob/76fc779ea926d4983ec5d32b85c4726b40308bcb/examples/mcp-redact/agent-context.mjs#L56-L152) |
| Scan tool output before it joins context; any `block` blocks the whole result | [`redactToolResult`](https://github.com/redact-secret/redact-secret/blob/76fc779ea926d4983ec5d32b85c4726b40308bcb/examples/mcp-redact/redact-tool-call.mjs#L52-L72) |
| A core failure, including an uninitialized runtime, fails closed | [`redactUserInput`'s catch](https://github.com/redact-secret/redact-secret/blob/76fc779ea926d4983ec5d32b85c4726b40308bcb/examples/mcp-redact/agent-context.mjs#L69-L78) |
| A throwing telemetry callback is swallowed and never changes the outcome | [`emitFindings`](https://github.com/redact-secret/redact-secret/blob/76fc779ea926d4983ec5d32b85c4726b40308bcb/examples/mcp-redact/wrap-tool-call.mjs#L50-L60) |
| Cancellation and abort discard everything, including text already sanitized | [`buildSafeContext`](https://github.com/redact-secret/redact-secret/blob/76fc779ea926d4983ec5d32b85c4726b40308bcb/examples/mcp-redact/agent-context.mjs#L109-L152) |
| A streamed result is staged; a limit failure aborts the session and returns no text | [`createStreamingToolResultRedactor`](https://github.com/redact-secret/redact-secret/blob/76fc779ea926d4983ec5d32b85c4726b40308bcb/examples/mcp-redact/streaming-tool-result.mjs#L26-L108) |

The contract diverges from beta.7 in four places. Each divergence is the
fail-closed choice; beta.7's example left the case open or was lossy:

| Beta.7 example | Contract |
| --- | --- |
| A subtree beyond a traversal limit becomes `[REDACTED:LIMIT_EXCEEDED]`, and array items past the limit are silently dropped | The whole value is blocked with `limit_exceeded`. A partially scanned value is not a safe value. |
| Object keys are not scanned | Keys are scanned. A key with a `redact` or `block` finding blocks the whole value, because a key cannot be rewritten without changing the value's shape. |
| Non-plain objects pass through unchanged, and a cycle becomes a marker | Anything other than a string, finite number, boolean, `null`, array, or plain object is blocked with `unsupported_value`. So is a cycle. |
| A blocked outcome carries its findings | A non-`ok` outcome carries no value and no findings. Findings reach auditing through the telemetry callback, which receives the same safe metadata. |

Streaming cancel/abort was not in the beta.7 golden path (#721). The
contract takes that behavior from the core's own lifecycle corpus
([`incremental-lifecycle-corpus.json`](../../conformance/fixtures/incremental-lifecycle-corpus.json))
and qualifies it in the conformance fixture below.

## Who owns what

| Concern | Owner |
| --- | --- |
| Detection, overlap resolution, policy evaluation, placeholders, whole-input and incremental limits, fixed error codes and messages, retained-plaintext discard | Core (this repository) |
| The contract text, its conformance fixture, and the reference runners | This repository |
| Bounded traversal of nested values, outcome mapping, staging, cancellation wiring, telemetry delivery, and the fixed blocked surface a host sees | Adapter (`redact-secret-adapters`) |
| Choosing a policy, choosing limits, dispatching tools, calling a model, and rejecting a blocked operation | Host application |

An adapter never detects, never decides policy, and never rescans or edits
core output. It maps what the core returned onto the outcomes below.

## Documented core APIs the contract uses

Nothing else is needed:

| Need | JavaScript (`@redact-secret/core`) | Python (`redact_secret`) |
| --- | --- | --- |
| Initialize | `initialize()` | not required |
| Whole-input scan, policy, redact | `scanAndRedact(text, { policy, limits })` | `scan_and_redact(text, policy=, limits=WholeInputLimits(...))` |
| Incremental session | `createIncrementalSanitizer({ limits, policy })` with `append`, `finalize`, `abort` | `IncrementalSanitizer(IncrementalLimits(...), policy=)` with the same three calls |
| Failure identity | `SecretScanError.code` | `SecretScanError.code` |
| Finding metadata | `id`, `type`, `detector`, `confidence`, `action`, `obfuscation`, `start`, `end` | the same attributes |

Rust exposes the same operations (`scan_and_redact_with_limits`,
`IncrementalSanitizer`), but no Rust adapter is planned, so no Rust runner is
committed.

## Operations

An adapter exposes these four operations under whatever names suit its
language:

| Operation | Input | Core path |
| --- | --- | --- |
| `sanitizeText` | one string (user input, one tool-result text, one context string) | one whole-input `scanAndRedact` |
| `sanitizeValue` | a bounded JSON-shaped value (tool arguments, structured tool output) | one whole-input scan per string leaf and per object key |
| `buildContext` | an ordered list of `{ role, text }` or `{ role, value }` parts | `sanitizeText` or `sanitizeValue` per part |
| `openStream` | chunks of one logical text (`append`, then `finalize`, or `abort`) | one incremental session, staged |

Each operation takes a boundary label (`user-input`, `tool-result`,
`tool-arguments`, or `context`) and an optional cancellation signal. The
label goes only to telemetry and never changes the outcome. `tool-arguments`
was added by the [MCP boundary](mcp-boundary.md) (#612) for opted-in tool-call
argument sanitation.

A stream also exposes `accepting`, an input-free boolean: `true` while it
still scans chunks, `false` once it has failed, been aborted, or been
finalized. It never says why; the reason arrives at `finalize`. A host reads
it after each `append` so it can stop pulling from, and cancel, a producer
whose output would be discarded anyway (#612).

## Outcomes

Every operation ends in exactly one of three frozen shapes:

```text
{ outcome: "ok",      value, findings }
{ outcome: "blocked", reason, code? }
{ outcome: "aborted" }
```

- `ok.value` is the only thing that may go to a model, a tool, a log, or
  storage. `buildContext` returns an ordered `[{ role, content }]` list.
- `blocked.reason` is one of `policy`, `limit_exceeded`,
  `unsupported_value`, `lifecycle`, or `core_error`.
- `blocked.code` is present only when the core raised an error, and only
  with a code from the fixed registry
  ([`error-codes.json`](../../conformance/fixtures/error-codes.json), plus
  the binding-level `NOT_INITIALIZED`, `INITIALIZATION_FAILED`,
  `INVALID_CHUNK`, `INVALID_UTF8`, and `UNPAIRED_SURROGATE`). A message is
  never forwarded, not even the core's fixed one, and an error that is not a
  `SecretScanError` maps to `core_error` with no code.
- A non-`ok` outcome never carries a value, findings, partial text, an
  excerpt, or a count derived from input.

| Cause | Outcome |
| --- | --- |
| Any finding whose resolved action is `block` | `blocked` / `policy` |
| `INPUT_LIMIT_EXCEEDED`, `FINDING_LIMIT_EXCEEDED`, `BUFFER_LIMIT_EXCEEDED`, `TOKEN_LIMIT_EXCEEDED`, `MULTILINE_LIMIT_EXCEEDED` | `blocked` / `limit_exceeded` + code |
| Traversal depth or node count exceeded | `blocked` / `limit_exceeded`, no code |
| Unsupported value type, or a cycle | `blocked` / `unsupported_value` |
| `INVALID_STATE`, or a second `finalize` | `blocked` / `lifecycle` |
| Any other core error: `NOT_INITIALIZED`, `POLICY_FAILURE`, `PLACEHOLDER_FAILURE`, `UNPAIRED_SURROGATE`, and so on | `blocked` / `core_error` + code |
| Signal aborted, or `abort()` called before a successful `finalize` | `aborted` |

## Safe metadata

A finding that crosses the boundary, in `ok.findings` or through
telemetry, is a copy that holds exactly `id`, `type`, `detector`,
`confidence`, `action`, `obfuscation`, `start`, and `end`. Adapters copy by
allowlist, so a field the core adds later cannot reach a host through the
boundary unless this contract is changed. No score, probability, threshold,
or feature contribution is part of this contract: #768 keeps the evidence
score internal and shadow-only in beta.9. Offsets are in the runtime's own
unit ([API concepts](api-contract.md#findings-and-coordinates)). They reveal
where a secret sat and how long it was, never what it was.

Telemetry is one optional callback, `onFinding(finding, { boundary })`,
called once per finding in scan order. It is observational. An exception
it throws is swallowed and never read, and it never changes an outcome.
Nothing else is emitted: no input, no value, no error, and no per-chunk
event.

## Lifecycle rules

- **Initialization.** Calling an operation before the runtime is ready
  gives `blocked` / `core_error` / `NOT_INITIALIZED`, from the core's own
  error, with no separate adapter branch. An initialization failure is
  surfaced the same way. An adapter never falls back to returning input.
- **Limits are mandatory and explicit.** Whole-input limits
  (`maxInputBytes`, `maxFindings`), incremental limits (all four), and
  traversal limits (`maxDepth` counts nested containers including the root;
  `maxNodes` counts every visited value) are declared by the adapter's
  caller. Input and incremental limits are enforced by the core, before
  detection work that the limit exists to prevent. Exceeding any limit fails
  the whole operation. Nothing is truncated or marked and passed on.
- **Cancellation.** A signal that is already aborted ends the operation as
  `aborted` before any scan or session is created. The signal is checked
  again after scanning, between context parts, and on every `append` and
  `finalize`.
- **Abort.** `abort()` or a fired signal discards staged text, aborts the
  core session (which drops its retained plaintext), and makes the next
  `finalize` return `aborted`. Abort after a successful `finalize` does
  nothing, because the value was already released once.
- **Staging.** A stream releases nothing before a successful `finalize`,
  even though the core may emit sanitized text from `append`. A `block`
  finding, a limit failure, or a callback failure mid-stream aborts the
  session at once, and later appends are discarded unscanned.
- **Finalization is single-use.** The first `finalize` returns the outcome.
  Every later `finalize` returns `blocked` / `lifecycle` and never releases
  the value again. An `append` after `finalize` is discarded and never
  scanned.
- **Callback failure.** A throwing policy or placeholder formatter becomes
  the core's fixed `POLICY_FAILURE` / `PLACEHOLDER_FAILURE`, so the
  operation fails closed as `core_error`. A throwing telemetry callback is
  ignored (see [Safe metadata](#safe-metadata)).
- **Context construction is all-or-nothing.** If any part of
  `buildContext` is not `ok`, the whole context is that outcome, and no
  partial context exists.

## Whole-input and incremental equivalence

For text that fits within both the whole-input and the incremental limits,
the staged `openStream` outcome must equal the `sanitizeText` outcome for
the same logical text, at every chunk partition. That covers the value,
every finding field (IDs and absolute offsets included), and the block
reason. The rule follows from the core's partition invariance
([`incremental-corpus.json`](../../conformance/fixtures/incremental-corpus.json)),
and the conformance runners check it directly. Two cases are outside it,
by design:

- An incremental session has no finding-count limit, so a whole-input
  `FINDING_LIMIT_EXCEEDED` has no incremental counterpart.
- Token and multiline limits apply only to incremental sessions. Text that
  whole-input accepts may still fail a stream with `limit_exceeded`.

## Invariants

Checked for every conformance case, on every runtime lane:

1. No synthetic secret from the case appears in outcome metadata, a
   `blocked` outcome, or any telemetry event.
2. A redacted or blocked secret never appears in the released value. Only a
   `warn` or `allow` decision may pass text through, as policy intends.
3. Telemetry findings carry exactly the safe metadata fields, and telemetry
   context carries exactly `boundary`.
4. A non-`ok` outcome carries no value and no findings.
5. Runner failures name a case ID and a field. They never print an input,
   a value, or a match. Qualification reports record counts only.

## Trust boundaries

- **Server-side is authoritative.** A client-side boundary is preventive
  UX. The server applies this contract again on its own, even when the
  client already did ([safe integration](../guides/safe-integration.md)).
- **Callbacks are trusted code.** A policy, formatter, or telemetry
  callback receives only safe metadata, but a closure can still capture raw
  input. The contract limits what the adapter hands over, not what the
  host's own code does.
- **Plaintext exists in process memory.** Discarding retained text does
  not zeroize memory, and it does not erase the caller's own copy.
- **Detection is not complete.** An `ok` outcome with no findings is not
  proof that no secret was present ([detection limits](detection.md)).

## Unsupported and out of scope

- Non-text content (images, audio, binary blobs) and encoded values
  (base64, percent-encoding). Neither is decoded or scanned
  ([`decision-defer-encoded-input-decoding`](../decisions/2026-09-20-defer-encoded-input-decoding.md)).
- A secret split across separate values, object keys, or context parts.
  Each is scanned on its own. Only a split across chunks of one stream is
  handled.
- Progressive release of stream output before `finalize`. It cannot be
  recalled after a later `block`, so it is outside this contract.
- MCP specifics. The [MCP boundary contract](mcp-boundary.md) (#612)
  specializes this one for tool calls. OpenAI, Anthropic, LangChain, or
  LangGraph wrappers are adapter follow-ups.
- Secret restoration, prompt-injection detection, and tool authorization.
- Scanning model output. That is a different boundary; this contract covers
  what goes into context.

## Conformance

- [`conformance/fixtures/ai-context-boundary.json`](../../conformance/fixtures/ai-context-boundary.json)
  holds the cases, the limits they run under, the safe field set, and the
  reason set. Every input is synthetic and already exists in the synchronous
  corpus.
- [`conformance/ai-context-boundary.mjs`](../../conformance/ai-context-boundary.mjs)
  is the JavaScript reference model and runner. It is plain ESM and takes
  the core API as an argument.
  [`scripts/consumer-harness.mjs`](../../scripts/consumer-harness.mjs) runs
  it against the packed, clean-installed `@redact-secret/core` on the Node
  addon lane and in Chromium, Firefox, and WebKit. It runs twice: before
  `initialize()` for the uninitialized cases, and after for the rest. The
  artifact inventory requires `aiContextBoundary: passed` from every lane.
- [`bindings/python/tests/test_ai_context_boundary.py`](../../bindings/python/tests/test_ai_context_boundary.py)
  is the Python twin. `qualify-python-wheel.py --conformance` runs it
  against each installed wheel.
- [`conformance/ai-context-boundary.test.mjs`](../../conformance/ai-context-boundary.test.mjs)
  tests the runner itself against a fake core in `npm run ci`. It checks
  that non-contract fields are stripped, that an error message never
  crosses the boundary, and that a pass-through core is rejected without
  its secret being printed.

An adapter qualifies by replaying the fixture at a pinned commit of this
repository through its own public API and reaching the same outcomes. Any
change to a case, a reason, or a safe field changes the contract. It needs
a spec row and, if it is new policy, a decision record.
