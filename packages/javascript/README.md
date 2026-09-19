# @redact-secret/core

Deterministic secret detection and redaction for browser and server
JavaScript/TypeScript applications.

One typed API, two artifacts: the package's `imports` map selects the Node
N-API addon on Node.js and the browser WebAssembly build everywhere else
(`decision-define-runtime-bindings`). Every built-in detector runs in the Rust
core, so both runtimes see the same findings for the same input.

## Install

```bash
npm install @redact-secret/core
```

Node.js 20, 22, and 24 are supported, on glibc and musl Linux, macOS, and
Windows (x64 and arm64). Where no addon can load — an unsupported platform, a
failed optional-dependency install, or an unloadable addon — `initialize()`
falls back to the WebAssembly artifact, and `artifact()` reports `"addon"` or
`"wasm"`. Cloudflare Workers is supported through the `workerd` export
condition; Vercel Edge is not. Browser applications need ES2022 and
WebAssembly support. The package is ESM only.

See the [JavaScript guide](https://github.com/redact-secret/redact-secret/blob/main/docs/guides/javascript.md)
for browser asset loading and troubleshooting.

## Initialize once, then work synchronously

Every runtime requires one successful `await initialize()` before any
synchronous operation. On Node the underlying setup has nothing to await, but
the call stays part of the contract so the usage model does not vary by
runtime. It is idempotent, so any number of call sites may await it; a failed
attempt is not cached and may be retried.

```ts
import { initialize, scanAndRedact } from "@redact-secret/core";

await initialize();

const { text, findings } = scanAndRedact("API_KEY=SYNTHETIC_REVOKED_VALUE");

if (findings.some((finding) => finding.action === "block")) {
  throw new Error("Blocked sensitive input");
}

console.log(text);
```

Calling a synchronous operation first throws `SecretScanError` with code
`NOT_INITIALIZED`, without inspecting the input.

## Scan, redact, or both

```ts
import { initialize, redact, scan } from "@redact-secret/core";

await initialize();

const input = "API_KEY=SYNTHETIC_REVOKED_VALUE";
const findings = scan(input);
const redacted = redact(input, findings);
```

`scanAndRedact` does the same in one call, so the text and the findings cannot
disagree. `redact` expects the findings `scan` returned for that same input.
Each call is bounded by default to 64 MiB of input and 50,000 findings; pass
`limits: { maxInputBytes, maxFindings }` to change that. Exceeding a bound
fails with `INPUT_LIMIT_EXCEEDED` or `FINDING_LIMIT_EXCEEDED` rather than
truncating.

Every finding is frozen and carries only safe metadata — id, type, detector,
confidence, action, a range, and `obfuscation` (`"none"` or
`"invisible-characters"`). It never carries the matched value.

## Offsets are UTF-16 code units

`start` and `end` index the JavaScript string you passed in, so
`input.slice(start, end)` selects exactly the matched span. The exported
`RANGE_UNIT` states this, and the Rust core's UTF-8 byte offsets are converted
by each binding without changing the selected span.

```ts
import { initialize, RANGE_UNIT, scan } from "@redact-secret/core";

await initialize();

const input = "🔑 API_KEY=SYNTHETIC_REVOKED_VALUE";
const [finding] = scan(input);

if (finding !== undefined) {
  console.log(RANGE_UNIT, finding.start, finding.end);
  // Do not log input.slice(finding.start, finding.end): it is plaintext.
}
```

## Custom policy and placeholder formatter

The first stable extension surface is a policy and a placeholder formatter.
Both receive safe metadata only, never the input or a matched value. Custom
detector callbacks are not part of this API.

```ts
import {
  initialize,
  scanAndRedact,
  typedPlaceholderFormatter,
} from "@redact-secret/core";
import type { SecretPolicy } from "@redact-secret/core";

await initialize();

const policy: SecretPolicy = {
  evaluate: (finding) => (finding.confidence === "high" ? "block" : "warn"),
};

const result = scanAndRedact("api_key=SYNTHETIC_REVOKED_VALUE", {
  policy,
  placeholderFormatter: typedPlaceholderFormatter,
});
```

Omit `policy` to use the built-in policy, which runs in Rust. Pass
`defaultPlaceholderFormatter` to name the built-in placeholder format
(`<SECRET_1>`, `<SECRET_2>`, ...) explicitly; `typedPlaceholderFormatter`
names the finding type instead (`<JWT_1>`).

## Incremental and stream availability

The Node artifact builds a real incremental session, wrapping the same core
`IncrementalSanitizer` the Python binding does, and the browser (WebAssembly)
artifact builds the same kind of session over the compiled WebAssembly
module. `createIncrementalSanitizer` retains unresolved text until its
detection window closes, then emits sanitized text and findings;
concatenating every `append`/`finalize` result's text reconstructs the whole
sanitized output. Findings carry absolute UTF-16 offsets into the logical
whole-session input, so `input.slice(finding.start, finding.end)` selects the
matched span, on every runtime. Do not scan chunks independently — a
credential may cross a chunk boundary.

```ts
import { createIncrementalSanitizer, initialize } from "@redact-secret/core";

await initialize();

const limits = {
  maxInputCodeUnits: 32_768,
  maxBufferedCodeUnits: 16_512,
  maxTokenCodeUnits: 8_192,
  maxMultilineCodeUnits: 16_384,
};
const session = createIncrementalSanitizer({ limits });

const first = session.append("api_key=SYNTHETIC_REVOKED_");
const second = session.append("INCREMENTAL_VALUE\nordinary text");
const final = session.finalize();

const safeText = first.text + second.text + final.text;
```

The four limit fields keep their existing `CodeUnits` names for compatibility,
but both artifacts enforce their values as UTF-8 byte ceilings in the Rust
core. Findings and their `start`/`end` ranges still use UTF-16 code units.

A session starts `accepting` and moves to the terminal `finalized` (one
successful `finalize()`), `aborted` (`abort()`), or `failed` (a limit,
detector, policy, or placeholder failure) state; every operation outside
`accepting` throws `INVALID_STATE`, and every terminal transition discards
whatever plaintext the session still retained.

`@redact-secret/core/node-stream` wraps a session in a byte-to-byte Node
`Transform`, finalizing it when the stream ends normally and aborting it on
every other exit:

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

`@redact-secret/core/web-stream` wraps a session in a byte-to-string Web
`TransformStream`, finalizing it when the writable side closes normally and
aborting it on every other exit:

```ts
import { initialize } from "@redact-secret/core";
import { createWebStreamSanitizer } from "@redact-secret/core/web-stream";

await initialize();

declare const source: ReadableStream<Uint8Array>;
declare const destination: WritableStream<string>;

await source
  .pipeThrough(
    createWebStreamSanitizer({
      limits: {
        maxInputCodeUnits: 32_768,
        maxBufferedCodeUnits: 16_512,
        maxTokenCodeUnits: 8_192,
        maxMultilineCodeUnits: 16_384,
      },
    }),
  )
  .pipeTo(destination);
```

See the [streaming guide](https://github.com/redact-secret/redact-secret/blob/main/docs/guides/streaming.md).

## Errors

Every failure is a `SecretScanError` carrying nothing but a fixed `code` and
its fixed message — never the input, a matched value, a placeholder, or a
failing callback's own message.

```ts
import { initialize, scan, SecretScanError } from "@redact-secret/core";
import type { SecretScanErrorCode } from "@redact-secret/core";

try {
  await initialize();
  scan("API_KEY=SYNTHETIC_REVOKED_VALUE");
} catch (error) {
  if (error instanceof SecretScanError) {
    const code: SecretScanErrorCode = error.code;
    console.error(code);
  }
}
```

`NOT_INITIALIZED` and `INITIALIZATION_FAILED` come from the binding layer,
`INVALID_CHUNK` and `INVALID_UTF8` from the stream adapters,
`UNPAIRED_SURROGATE` from this package's own input check — a JavaScript
string may contain a lone UTF-16 surrogate, which has no UTF-8
representation, so `scan`, `redact`, `scanAndRedact`, and an incremental
sanitizer's `append` all reject one with this fixed code before it reaches
either binding, identically on Node.js and in the browser. Core failures are
mapped to the same fixed error vocabulary.

## Public API

Runtime values: `initialize`, `artifact`, `scan`, `redact`, `scanAndRedact`,
`createIncrementalSanitizer`, `defaultPlaceholderFormatter`,
`typedPlaceholderFormatter`, `SecretScanError`, `RANGE_UNIT`, `VERSION`,
`PROFILE`.

Types: `ArtifactKind`, `DetectedSecretFinding`, `SecretFinding`, `SecretAction`,
`SecretConfidence`, `SecretObfuscation`, `SecretPolicy`, `PolicyContext`, `PlaceholderFormatter`,
`PlaceholderContext`, `ScanOptions`, `RedactOptions`, `ScanAndRedactOptions`,
`ScanResult`, `WholeInputLimits`, `IncrementalSanitizer`, `IncrementalSanitizerOptions`,
`IncrementalSanitizerResult`, `IncrementalSanitizerState`,
`IncrementalLimits`, `IncrementalSecretPolicy`, `IncrementalPolicyContext`,
`RangeUnit`, `SecretScanErrorCode`.

Stream subpaths: `@redact-secret/core/node-stream` exports
`createNodeStreamSanitizer`, `NodeStreamSanitizer`, and `SecretScanError`;
`@redact-secret/core/web-stream` exports `createWebStreamSanitizer`,
`WebStreamSanitizer`, and `SecretScanError`. `@redact-secret/core/common/node-stream`
and `@redact-secret/core/common/web-stream` export the same names, bound to
the `common` runtime instead of `full` (see below).

`@redact-secret/core/common` exports the same runtime values and types as the
root, backed by the opt-in `common` detector profile: `PROFILE` is `"common"`
there and `"full"` on the root. `common` omits every provider detector, so a
bare provider token is not detected. `initialize()` rejects with
`INITIALIZATION_FAILED` when the loaded artifact reports a different profile
than the entry point that loaded it. `@redact-secret/core/node-stream` and
`@redact-secret/core/web-stream`'s `createNodeStreamSanitizer` and
`createWebStreamSanitizer` factories always open a `full` session; for a
`common` byte stream, use `createNodeStreamSanitizer`/`createWebStreamSanitizer`
from `@redact-secret/core/common/node-stream`/`@redact-secret/core/common/web-stream`
instead — a browser bundle resolving one of those two subpaths never resolves
the `full` runtime or the root `@redact-secret/wasm` artifact. The
`NodeStreamSanitizer`/`WebStreamSanitizer` classes themselves are
profile-agnostic and identical across all four subpaths, so constructing one
directly with a session from `@redact-secret/core/common`'s
`createIncrementalSanitizer` still works too.

The root export, `@redact-secret/core/common`, and the four stream subpaths
are the executable public API.
`@redact-secret/core/package.json` also exposes package metadata. Internal
modules are unreachable through the `exports` map. `VERSION` is
the shared product version; the Rust crate, this package, the Python package,
and the CLI are released in lockstep
(`decision-release-bindings-in-lockstep`), and `initialize()` refuses an
artifact that reports a different one.

## Security

Client-side scanning is preventive UX; server-side scanning is the
authoritative enforcement boundary. See
[SECURITY.md](https://github.com/redact-secret/redact-secret/blob/main/SECURITY.md)
for the security model and private vulnerability reporting.

## License

[MIT](https://github.com/redact-secret/redact-secret/blob/main/LICENSE)
