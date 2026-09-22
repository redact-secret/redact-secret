# JavaScript and TypeScript

[Documentation home](../README.md) · [Installation](../getting-started.md)

The package is ESM and exposes one typed whole-input API on Node and modern
browsers. Initialize once before synchronous operations: the explicit
initialization contract makes native or WebAssembly loading failures
observable without making every scan asynchronous. Initialization is
idempotent; a failed attempt may be retried. It also checks that the binding
version matches the wrapper version.

```ts
import { initialize, scanAndRedact } from "@redact-secret/core";

await initialize();
const result = scanAndRedact("API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE");
console.log(result.text); // API_KEY=<SECRET_1>
console.log(result.findings.length); // 1
```

`scan(input)` returns findings. `redact(input, findings)` uses findings from
that same original input. Prefer `scanAndRedact` when you need both. Findings
and result metadata are frozen and contain no matched plaintext. Their
half-open `start`/`end` offsets count UTF-16 code units in the original input.
Never log `input.slice(finding.start, finding.end)`. Offsets point into the
original input even when the sanitized output has a different length:

```ts
result.findings[0];
// {
//   id: "finding-1",
//   type: "contextual_secret",
//   detector: "generic-token",
//   confidence: "high",
//   action: "redact",
//   start: 8,
//   end: 39
// }
```

## Runtime selection

On Node.js, `@redact-secret/core` installs a prebuilt N-API addon for glibc
and musl Linux, macOS, and Windows (x64 and arm64 each: eight platform
packages, `engines.node` `20.x || 22.x || 24.x`) as an optional dependency.
On a host with no matching addon at all — an unsupported platform or
architecture, a matching optional dependency that failed to install, or a
corrupt addon — `initialize()` falls back to the same WebAssembly artifact
browsers use instead of failing outright. Call `artifact()` after
`initialize()` to see which one actually loaded: `"addon"` or `"wasm"`. Bun
and Deno get this fallback for free.

```ts
import { artifact, initialize } from "@redact-secret/core";

await initialize();
console.log(artifact()); // "addon" on a supported host, "wasm" on the fallback
```

**Cloudflare Workers is a verified, supported runtime**: it resolves its own
`workerd` package condition to a loader that instantiates the WebAssembly
artifact from a bundler-compiled `WebAssembly.Module` instead of the generated
glue's `import.meta.url`-based `fetch`, which does not work under a real
`workerd` sandbox (`decision-verify-edge-runtimes`). **Vercel Edge is not yet
supported**: it resolves the plain browser entry point, whose `fetch`-based
initialization fails there for a related but distinct reason, verified
against Vercel's own reference Edge Runtime engine. See
[qualification](../qualification.md) for the verified root cause, why the
Cloudflare Workers fix does not carry over, the full target matrix, exactly
which failures engage the Node fallback, and how CI keeps both from drifting.

## Choose a policy

```ts
import { initialize, scanAndRedact, typedPlaceholderFormatter } from "@redact-secret/core";
import type { SecretPolicy } from "@redact-secret/core";

await initialize();
const policy: SecretPolicy = { evaluate: () => "redact" };
const result = scanAndRedact("API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE", {
  policy,
  placeholderFormatter: typedPlaceholderFormatter,
});
console.log(result.text); // API_KEY=<CONTEXTUAL_SECRET_1>
```

This policy replaces every detected finding; it cannot detect additional
formats. To reject a request, choose `block` and check the returned actions
before any downstream use. [Safe integration](safe-integration.md) explains
that distinction and failure handling.

## Whole-input limits

`scan`, `redact`, and `scanAndRedact` default to a 64 MiB input bound and a
50,000 finding-count bound (`decision-bound-whole-input-operations-by-default`),
failing closed with `INPUT_LIMIT_EXCEEDED`/`FINDING_LIMIT_EXCEEDED` — never a
truncated result. Pass an explicit `limits` option to raise or lower the
bound:

```ts
import { initialize, scanAndRedact } from "@redact-secret/core";

await initialize();
const result = scanAndRedact("API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE", {
  limits: { maxInputBytes: 128 * 1024 * 1024, maxFindings: 100_000 },
});
console.log(result.text); // API_KEY=<SECRET_1>
```

## Detector profiles

`@redact-secret/core` is `full`: every built-in detector, and the default and
compatibility baseline on every surface. `@redact-secret/core/common` is a
smaller, opt-in built-in detector set for size- or latency-sensitive
**preventive** consumers — browser UX and small agent or tool processes.
Switch by changing the import; the rest of the API is identical:

```ts
import { initialize, scanAndRedact, PROFILE } from "@redact-secret/core/common";

await initialize();
console.log(PROFILE); // "common"
```

Both entry points export a `PROFILE` constant identifying which profile that
module is built from (`"full"` on the root export, `"common"` on `./common`).
`initialize()` rejects with `INITIALIZATION_FAILED` if the artifact it loaded
reports a different profile than the entry point that loaded it — the same
detail-free rejection an unusable or version-mismatched artifact already gets,
so mixing a `full` addon/Wasm build with the `./common` entry point (or vice
versa) fails closed rather than silently running the wrong detector set.

`common` only detects the structural and contextual patterns (a private key,
a JWT, an `otpauth://` URI, a credential-bearing connection URI, a `Bearer`
header, and a contextual assignment); it never detects a bare, unadorned
provider token. See [detection coverage](../reference/detection.md#detector-profiles)
for the false-negative tradeoff and the measured savings. Python and the CLI stay `full` only.

## Browser loading

The package's conditions select the browser loader and its `@redact-secret/wasm`
dependency. Use a bundler that honors browser conditions and preserves the
WebAssembly asset referenced by the generated glue. Serve that asset over HTTP
with the correct URL and `application/wasm` content type. Check asset requests
if `initialize()` fails. There is no public custom-Wasm-URL initialization option.

Loading the artifact may fetch a local/site asset; secret detection itself
performs no network lookup. Scan on the device before constructing the request
body, and scan again at the authoritative server boundary.

## Current limitations

Node support is 20, 22, and 24 on the eight published targets, glibc and
musl Linux included. Retain npm optional dependencies so the matching native
addon can be installed; without one, `initialize()` falls back to the
WebAssembly artifact and `artifact()` returns `"wasm"`. Both the
Node artifact and the browser (WebAssembly) artifact support
`createIncrementalSanitizer` and their respective stream factories
(`createNodeStreamSanitizer`, `createWebStreamSanitizer`); do not scan
independent chunks — a credential may cross a chunk boundary, which is why
this API exists instead. JavaScript strings containing an unpaired surrogate
fail with `UNPAIRED_SURROGATE` before reaching the binding.

See [API concepts](../reference/api-contract.md), [streaming](streaming.md),
[troubleshooting](../troubleshooting.md), and the
[package API inventory](../../packages/javascript/README.md#public-api).
