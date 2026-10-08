# Incremental sanitization and streams

[Documentation home](../README.md)

| Surface | Current incremental support |
| --- | --- |
| Rust | `IncrementalSanitizer` |
| Python | `IncrementalSanitizer` |
| CLI | Standard input |
| JavaScript Node artifact | `createIncrementalSanitizer` |
| JavaScript browser (WebAssembly) artifact | `createIncrementalSanitizer` |

A secret may cross any chunk boundary. Scanning each chunk independently can
leak it. A session retains unresolved plaintext until a detector window
closes, finalization supplies the end-of-input boundary, or a declared limit
fails, then emits text and findings. An append may legitimately return empty
text.

Every session requires explicit total-input, retained-plaintext, token, and
multiline limits. Host adapters own backpressure, cancellation, and
destruction; the Rust core owns scan semantics and retained-plaintext safety.

`createIncrementalSanitizer` and `IncrementalSanitizer::with_common_built_in`
support the opt-in `common` detector profile on every surface that exposes
it; the JavaScript stream factories have their own `common`-profile
subpaths — see
[streaming under the `common` profile](#streaming-under-the-common-profile).

## JavaScript incremental example

Both installed JavaScript artifacts expose the same root API. Findings count
UTF-16 code units on Node.js and in browsers. The four limits are UTF-8 byte
ceilings, enforced by the Rust core on both artifacts, so they are named
`maxInputBytes`, `maxBufferedBytes`, `maxTokenBytes` and `maxMultilineBytes`.
The older names `maxInputCodeUnits`, `maxBufferedCodeUnits`,
`maxTokenCodeUnits` and `maxMultilineCodeUnits` are deprecated aliases with the
same meaning; they keep working. Give each limit under one name. Naming both
spellings of one limit is accepted only when the values are equal; different
values throw `INVALID_LIMITS`, as does leaving a limit out. Size non-ASCII input
with `TextEncoder` when choosing those bounds.

```ts
import { createIncrementalSanitizer, initialize } from "@redact-secret/core";

await initialize();

const session = createIncrementalSanitizer({
  limits: {
    maxInputBytes: 32_768,
    maxBufferedBytes: 16_512,
    maxTokenBytes: 8_192,
    maxMultilineBytes: 16_384,
  },
});
const first = session.append("api_key=SYNTHETIC_REVOKED_");
const second = session.append("INCREMENTAL_VALUE\nordinary text");
const final = session.finalize();
const safeText = first.text + second.text + final.text;
```

### Migrating shared options from beta.14

Released beta.14 silently ignored incremental `ruleset` options. The unreleased
validation fix rejects the **presence of the key**, including own or inherited
`ruleset: undefined`, without reading its value or calling its getter. After
initialization the fixed error is `INVALID_OPTIONS`; before initialization it
is `NOT_INITIALIZED`. This applies to Node/browser and full/common sessions.
Whole-input rulesets and incremental `actionPolicy` remain supported.

Under the accepted [contract-1 compatibility classification](../decisions/2026-10-02-define-the-0-1-x-stable-public-contract-and-its-compatibility-classes.md),
rejecting this unsupported request alone does not mandate `0.2.0`. It still
changes these beta.14 runtime call shapes. The first shipped release will be
identified in CHANGELOG when a release version is approved.

TypeScript can reject an extra key in a direct object literal but accept the
same extra key on a variable through structural typing. If custom detection is
not required, construct dedicated incremental options from supported fields,
rather than spreading a whole-input options object:

```ts
import { createIncrementalSanitizer, initialize, typedPlaceholderFormatter } from "@redact-secret/core";
import type { IncrementalSanitizerOptions } from "@redact-secret/core";

await initialize();
const sharedOptions = {
  limits: {
    maxInputBytes: 32_768,
    maxBufferedBytes: 16_512,
    maxTokenBytes: 8_192,
    maxMultilineBytes: 16_384,
  },
  actionPolicy: JSON.stringify({ actionPolicyRevision: 1, base: "default", rules: [] }),
  ruleset: undefined,
};
// Passing sharedOptions directly would compile, then throw INVALID_OPTIONS.
const incrementalOptions: IncrementalSanitizerOptions = {
  limits: sharedOptions.limits,
  actionPolicy: sharedOptions.actionPolicy,
  placeholderFormatter: typedPlaceholderFormatter,
};
const session = createIncrementalSanitizer(incrementalOptions);
const safeText = session.append("ordinary text").text + session.finalize().text;
```

An incremental `policy` callback is another supported choice, but is mutually
exclusive with `actionPolicy`; select one. The formatter is independent of
that choice. Copy only options supported by the destination session, whose
policy callback context differs from whole-input policy context.

If custom detection is required, do not remove the ruleset to make the call
succeed. Collect one logical input within an application-enforced byte bound
and use whole-input processing. Bound collection before allocating or appending
another chunk; the check below also bounds processing of an already collected
string. Reject overflow without forwarding the original input. A ruleset
finding has medium confidence and warns by default, so explicitly select
redaction for its type:

```ts
import { initialize, scanAndRedact } from "@redact-secret/core";

await initialize();
const input = "TOKEN=ACME_" + "a".repeat(20); // synthetic
const maxInputBytes = 32_768;
if (new TextEncoder().encode(input).byteLength > maxInputBytes) {
  throw new Error("Input exceeds the whole-input bound");
}
const ruleset = `ruleset-revision: 1

detector: acme-internal-token
specificity: contextual
prefix: "ACME_"
alphabet: alnum-dash
run: at-least 20
validator: none
`;
const result = scanAndRedact(input, {
  ruleset,
  actionPolicy: JSON.stringify({
    actionPolicyRevision: 1,
    base: "default",
    rules: [{ id: "redact-acme", match: { type: ["acme-internal-token"] }, action: "redact" }],
  }),
});
const safeText = result.text;
```

Use the ruleset grammar in the [rulesets guide](rulesets.md). Calling
whole-input detection separately for each chunk is not an equivalent fallback:
a secret crossing a chunk boundary can be missed.

### Catch creation and execution errors

All four public factories (`node-stream`, `web-stream`,
`common/node-stream`, `common/web-stream`) can throw synchronously while creating
the session, before returning a stream or consuming input. A trailing
`pipeline(source, createNodeStreamSanitizer(options), sink).catch(...)` cannot
catch that factory error, because the call happens before `pipeline` returns.
Put creation and awaited execution in one `try`/`catch`. Limit, decoding,
callback, cancellation, and upstream errors can also occur during execution;
commit output only after success when all-or-nothing processing is required.
The Node examples stream sanitized output to stdout, where a later failure can
leave an incomplete prefix; check the exit status before accepting it.
Log fixed codes or a fixed message, never arbitrary error text that might
contain input.

For byte streams, use the runtime adapter rather than decoding each chunk.
The adapters own one fatal, stateful UTF-8 decoder, so a multibyte character
may cross byte chunks without replacement or leakage:

```ts
import { pipeline } from "node:stream/promises";
import { initialize, SecretScanError } from "@redact-secret/core";
import { createNodeStreamSanitizer } from "@redact-secret/core/node-stream";

try {
  await initialize();
  const sanitizer = createNodeStreamSanitizer({
    limits: {
      maxInputBytes: 32_768,
      maxBufferedBytes: 16_512,
      maxTokenBytes: 8_192,
      maxMultilineBytes: 16_384,
    },
  });
  await pipeline(process.stdin, sanitizer, process.stdout);
} catch (error) {
  console.error(error instanceof SecretScanError ? error.code : "Stream sanitization failed");
  process.exitCode = 1;
}
```

Browser code uses the same creation-and-execution boundary:

```ts
import { initialize, SecretScanError } from "@redact-secret/core";
import { createWebStreamSanitizer } from "@redact-secret/core/web-stream";

const source = new ReadableStream<Uint8Array>({
  start(controller) {
    controller.enqueue(new TextEncoder().encode("ordinary text"));
    controller.close();
  },
});
const chunks: string[] = [];
const sink = new WritableStream<string>({
  write(chunk) { chunks.push(chunk); },
});
try {
  await initialize();
  const sanitizer = createWebStreamSanitizer({
    limits: {
      maxInputBytes: 32_768,
      maxBufferedBytes: 16_512,
      maxTokenBytes: 8_192,
      maxMultilineBytes: 16_384,
    },
  });
  await source.pipeThrough(sanitizer).pipeTo(sink);
  // Commit chunks only after this awaited completion succeeds.
} catch (error) {
  chunks.length = 0;
  console.error(error instanceof SecretScanError ? error.code : "Stream sanitization failed");
}
```

Repository tests
type-check those Markdown examples, and artifact qualification executes the
same public incremental and stream calls from clean candidate-package installs
on Node.js 20, 22, and 24 and in Chromium, Firefox, and WebKit.

### Streaming under the `common` profile

`@redact-secret/core/common/node-stream` and
`@redact-secret/core/common/web-stream` mirror `@redact-secret/core/node-stream`
and `@redact-secret/core/web-stream`, except their `createNodeStreamSanitizer`
and `createWebStreamSanitizer` factories open a session against `common`
instead of `full`. Resolving one of these two subpaths from a browser bundle
never reaches the `full` runtime or the root `@redact-secret/wasm` artifact
specifier, so a `common` consumer's stream path pays only for the `common`
WebAssembly build:

```ts
import { pipeline } from "node:stream/promises";
import { initialize, SecretScanError } from "@redact-secret/core/common";
import { createNodeStreamSanitizer } from "@redact-secret/core/common/node-stream";

try {
  await initialize();
  const sanitizer = createNodeStreamSanitizer({
    limits: {
      maxInputBytes: 32_768,
      maxBufferedBytes: 16_512,
      maxTokenBytes: 8_192,
      maxMultilineBytes: 16_384,
    },
  });
  await pipeline(process.stdin, sanitizer, process.stdout);
} catch (error) {
  console.error(error instanceof SecretScanError ? error.code : "Stream sanitization failed");
  process.exitCode = 1;
}
```

The browser equivalent imports `createWebStreamSanitizer` from
`@redact-secret/core/common/web-stream` and pipes through it the same way the
[JavaScript incremental example](#javascript-incremental-example)'s stream
snippet does.

The `NodeStreamSanitizer`/`WebStreamSanitizer` classes themselves are
profile-agnostic — they wrap whichever session they are given, and the same
two classes back all four stream subpaths — so constructing one directly with
a session from [`@redact-secret/core/common`](javascript.md#detector-profiles)'s
own `createIncrementalSanitizer` still works, and is the only option when a
session needs profile-specific policy or placeholder options the convenience
factory does not expose:

```ts
import { pipeline } from "node:stream/promises";
import { initialize, createIncrementalSanitizer } from "@redact-secret/core/common";
import { NodeStreamSanitizer } from "@redact-secret/core/common/node-stream";

await initialize();
const session = createIncrementalSanitizer({
  limits: {
    maxInputBytes: 32_768,
    maxBufferedBytes: 16_512,
    maxTokenBytes: 8_192,
    maxMultilineBytes: 16_384,
  },
});
await pipeline(process.stdin, new NodeStreamSanitizer(session), process.stdout);
```

## Python example

```python
import redact_secret

max_token = 8_192
max_multiline = 32_768
limits = redact_secret.IncrementalLimits(
    max_input_bytes=1_000_000,
    max_buffered_bytes=redact_secret.IncrementalLimits.minimum_buffered_bytes(
        max_token, max_multiline
    ),
    max_token_bytes=max_token,
    max_multiline_bytes=max_multiline,
)
with redact_secret.IncrementalSanitizer(limits) as session:
    first = session.append("api_key=SYNTHETIC_REVOKED_")
    second = session.append("INCREMENTAL_VALUE\nordinary text")
    final = session.finalize()

safe_text = first.text + second.text + final.text
assert safe_text == "api_key=<SECRET_1>\nordinary text"
```

The four limits cover total accepted input, retained unresolved input, an open
single-line construct, and an open multiline construct. Rust and Python count
UTF-8 bytes; Python findings still count code points. Use the minimum-buffer
helper rather than copying private lookaround arithmetic. The token bound
applies to unresolved logical lines, not just credential length, so long
minified or unbroken ordinary text can exceed it.

Python also temporarily indexes Unicode continuation-byte positions for the
whole incoming chunk before pruning. The index can keep its peak allocated
capacity until session cleanup. Bound incoming chunk sizes; `max_buffered_bytes`
alone does not cap all binding memory.

## Rust example

```rust
use redact_secret::{IncrementalLimits, IncrementalSanitizer, SecretScanError};

fn main() -> Result<(), SecretScanError> {
    let max_token = 8_192;
    let max_multiline = 32_768;
    let limits = IncrementalLimits::new(
        1_000_000,
        IncrementalLimits::minimum_buffered_bytes(max_token, max_multiline),
        max_token,
        max_multiline,
    )?;
    let mut session = IncrementalSanitizer::new(limits)?;

    let mut safe_text = String::new();
    safe_text.push_str(session.append("api_key=SYNTHETIC_REVOKED_")?.text());
    safe_text.push_str(session.append("INCREMENTAL_VALUE\nordinary text")?.text());
    safe_text.push_str(session.finalize()?.text());

    assert_eq!(safe_text, "api_key=<SECRET_1>\nordinary text");
    Ok(())
}
```

`IncrementalLimits::new` takes the four limits in the order total input,
retained input, token, and multiline, all in UTF-8 bytes.

## Command line example

CLI standard input is streamed through the same incremental core, with limits
the CLI chooses (see `redact-secret --help`). A credential split across two
writes is still found:

```bash
{ printf 'api_key=SYNTHETIC_REVOKED_'; printf 'INCREMENTAL_VALUE\nordinary text\n'; } | redact-secret --redact
# api_key=<SECRET_1>
# ordinary text
```

Accept the output only after exit status `0`; a failure can leave a sanitized
but incomplete prefix on standard output ([CLI guide](cli.md)).

## Lifecycle and failure

A session starts `accepting` and becomes terminally `finalized`, `aborted`, or
`failed`. Call `finalize()` once to supply end-of-input and emit retained text.
`abort()` discards retained text. Leaving the Python context manager aborts an
unfinished session. Lifecycle misuse and limit or callback failures drop
retained plaintext and use fixed errors.

Host-side append validation also discards retained plaintext and offset state
and moves an accepting session to `failed`. Non-string chunks raise
`INVALID_INPUT`; lone high or low surrogates raise `UNPAIRED_SURROGATE` in
JavaScript and `INVALID_INPUT` in Python. These errors have fixed, input-free
messages. Every later append, finalize, or abort raises `INVALID_STATE`, even
if the later chunk is invalid, and the session stays `failed`.

Concatenate every append result and the final result in order. For accepted
input within the limits, output and findings must match whole-input operation
on the same logical string. Findings use absolute original-input positions;
placeholder numbering continues across emissions.

If reading bytes, use one strict stateful UTF-8 decoder across chunks, and flush
it at EOF. A UTF-8 code point can cross a byte boundary. Python session `append`
accepts text, not bytes; the host owns decoding, cancellation, and backpressure.

Previously emitted text cannot be recalled after a later failure. Require
successful finalization before committing output when your application needs
all-or-nothing processing. Discarding retained text is not a guarantee of secure
memory zeroization or erasure of caller-owned input; see
[plaintext memory lifetime](../reference/plaintext-lifetime.md).
