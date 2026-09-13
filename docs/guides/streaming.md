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
leak it. A session retains unresolved text until its detection window closes,
then emits text and findings. An append may legitimately return empty text.

## JavaScript incremental example

Both installed JavaScript artifacts expose the same root API. Findings count
UTF-16 code units on Node.js and in browsers. The four limit properties retain
their existing `CodeUnits` names for compatibility, but their numeric ceilings
are enforced by the Rust core as UTF-8 byte limits on both artifacts. Size
non-ASCII input with `TextEncoder` when choosing those bounds.

```ts
import { createIncrementalSanitizer, initialize } from "@redact-secret/core";

await initialize();

const session = createIncrementalSanitizer({
  limits: {
    maxInputCodeUnits: 32_768,
    maxBufferedCodeUnits: 16_512,
    maxTokenCodeUnits: 8_192,
    maxMultilineCodeUnits: 16_384,
  },
});
const first = session.append("api_key=SYNTHETIC_REVOKED_");
const second = session.append("INCREMENTAL_VALUE\nordinary text");
const final = session.finalize();
const safeText = first.text + second.text + final.text;
```

For byte streams, use the runtime adapter rather than decoding each chunk.
The adapters own one fatal, stateful UTF-8 decoder, so a multibyte character
may cross byte chunks without replacement or leakage:

```ts
import { pipeline } from "node:stream/promises";
import { initialize } from "@redact-secret/core";
import { createNodeStreamSanitizer } from "@redact-secret/core/node-stream";

await initialize();
await pipeline(
  process.stdin,
  createNodeStreamSanitizer({
    limits: {
      maxInputCodeUnits: 32_768,
      maxBufferedCodeUnits: 16_512,
      maxTokenCodeUnits: 8_192,
      maxMultilineCodeUnits: 16_384,
    },
  }),
  process.stdout,
);
```

Browser code uses `createWebStreamSanitizer` from
`@redact-secret/core/web-stream` with `source.pipeThrough(transform)`; the
package README contains the complete typed example. Repository tests
type-check those Markdown examples, and artifact qualification executes the
same public incremental and stream calls from clean candidate-package installs
on Node.js 20, 22, and 24 and in Chromium, Firefox, and WebKit.

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

## Lifecycle and failure

A session starts `accepting` and becomes terminally `finalized`, `aborted`, or
`failed`. Call `finalize()` once to supply end-of-input and emit retained text.
`abort()` discards retained text. Leaving the Python context manager aborts an
unfinished session. Lifecycle misuse and limit or callback failures drop
retained plaintext and use fixed errors.

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
memory zeroization or erasure of caller-owned input.
