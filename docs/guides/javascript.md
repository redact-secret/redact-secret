# JavaScript and TypeScript

[Documentation home](../README.md) · [Installation](../getting-started.md)

Install with `npm install @redact-secret/core@beta` (the newest beta while no
stable release exists); the [quickstart](../quickstart.md) pins an exact version
for Node.js and for a browser bundler. The package is ESM and exposes one typed
whole-input API on Node and modern browsers. Initialize once before synchronous operations: the explicit
initialization contract makes native or WebAssembly loading failures
observable without making every scan asynchronous. Initialization is
idempotent; a failed attempt may be retried. It also checks that the binding
version matches the wrapper version.

## Which release has what

`@beta` selects the newest published beta. These names are newer than
`0.1.0-beta.13` and are absent from any older release; check the
[version status](../quickstart.md#which-version-you-get) for which version is
published today.

| API | Introduced in |
| --- | --- |
| `status()` (also `./common`) | `0.1.0-beta.14` |
| `actionPolicy` option, `INVALID_ACTION_POLICY` | `0.1.0-beta.14` |
| `defaultPolicy` | `0.1.0-beta.14` |
| `compareActionPolicies` | `0.1.0-beta.14` |

A named import of a missing export fails to link, so a program that must run
on an older release imports the namespace and tests each name before use. This
file runs unchanged on `0.1.0-beta.13` (it takes the callback branch) and on
`0.1.0-beta.14` (it takes the declarative branch), and prints the same
`default: redacted` and `keep-github: unchanged` lines on both:

```js
import * as core from "@redact-secret/core";

await core.initialize();

// `status`, `actionPolicy`, `defaultPolicy` and `compareActionPolicies` were
// added in 0.1.0-beta.14. A namespace import of an older release has no such
// property, where a named import of a missing export fails to link.
const hasStatus = typeof core.status === "function";
const hasActionPolicy = typeof core.compareActionPolicies === "function" && typeof core.defaultPolicy === "object";

const TEXT = "API_KEY=" + ["ghp", "_SYNTHETICREVOKED", "0".repeat(20)].join("");

console.log("status:", hasStatus ? JSON.stringify(core.status()) : "not available before 0.1.0-beta.14");

// Keep GitHub tokens and redact the rest. A release with action policies takes
// a declarative document; an older release takes a callback, which must itself
// spell out what the default would have done for every other finding.
const keepGithub = hasActionPolicy
  ? {
      actionPolicy: {
        actionPolicyRevision: 1,
        base: "default",
        rules: [{ id: "keep-github", match: { type: ["github_token"] }, action: "warn" }],
      },
    }
  : { policy: { evaluate: (finding) => (finding.type === "github_token" ? "warn" : "redact") } };

console.log("default:", core.scanAndRedact(TEXT).text === TEXT ? "unchanged" : "redacted");
console.log("keep-github:", core.scanAndRedact(TEXT, keepGithub).text === TEXT ? "unchanged" : "redacted");
```

```ts
import { initialize, scanAndRedact } from "@redact-secret/core";

await initialize();
const result = scanAndRedact("API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE");
console.log(result.text); // API_KEY=<SECRET_1>
console.log(result.findings.length); // 1
```

PII activation is explicit and defaults off. Pass `pii: ["pii"]` to activate
the global selector, then inspect the canonical identity with
`piiActivation()`. The selector closes over the available
`pii:global:email`, `pii:global:iban`, `pii:global:network-address`,
`pii:global:payment-card`, and `pii:global:phone` families; use a
`pii:family:global:*` selector for
exact selection. The `pii:us` selector closes over those global families plus
`pii:us:ssn`; `pii:family:us:ssn` selects only SSNs. They need reviewed
high-signal context. Under `pii-v1`, the five global families are `provisional` (not `stable`;
phone covers `+1` / NANP only) and US SSN is `pending`; see
[detection](../reference/detection.md#opt-in-pii-availability-is-not-support). Reordered or duplicate equivalent selectors are
idempotent; a later different selection fails with the fixed,
input-free `PII_ACTIVATION_CONFLICT` error. The `./common` entry point follows
the same contract while retaining `credentials=common` in its identity.

One thread has one runtime per entry point, so a second wrapper or a second
`initialize` selection does not create a second owner. Independent PII
selections need a `worker_threads` Worker each; the
[configuration ownership guide](configuration-ownership.md) has the recipe and
the unsupported list.

## Status query

Introduced in `0.1.0-beta.14`. `status()` reports whether this entry point is initialized, and its public
activation, without loading, initializing or reconfiguring anything. It is
synchronous, takes no input, never throws, and returns a frozen object with
four fixed fields and nothing else. `configuration` is new after `0.1.0-beta.14`
and additive: the digest of the snapshot of the configuration this runtime is
fixed to (`describeConfig().digest`), `null` before initialization.

```ts
import { status } from "@redact-secret/core";

status();
// { initialized: false, profile: "full", activation: null, configuration: null }   before initialize()
// { initialized: true, profile: "full", activation: "credentials=full;selectors=off;...", configuration: "sha256:..." }
```

`initialized` is `true` only after an `initialize()` call has succeeded, so it
is `false` while a load is pending and after a failed load. `activation` is
the `piiActivation()` string once initialized and `null` before; a failure
never appears in the result. It is a point-in-time answer about this module,
not a guarantee about detection coverage or a later call. A release that
predates `status()` does not export it: probe with `typeof status ===
"function"` (a namespace import of an older release has no such property) and
fall back to the existing calls. The `./common` entry point exports the same
function with `profile: "common"`.

In a browser, a Cloudflare Worker, or the Node WebAssembly fallback, the PII
runtime lives in a separate WebAssembly build of each profile. The
`initialize()` call that loads the binding fetches the default build, which
has no PII runtime, unless its options carry a non-empty `pii` selection;
then it fetches the profile's `pii` build instead. A page that never selects
PII therefore never downloads PII code. A bundler emits both builds as
assets, and only the selected one is fetched. Because activation is
one-shot, choose the selection in the first `initialize()` call: a later,
different selection is still `PII_ACTIVATION_CONFLICT`. The Node addon
carries the PII runtime in its single build.

```ts
import { initialize, piiActivation } from "@redact-secret/core";

await initialize({ pii: ["pii", "pii:global"] });
console.log(piiActivation());
// credentials=full;selectors=pii:global;families=pii:global:email,pii:global:iban,pii:global:network-address,pii:global:payment-card,pii:global:phone;vocabulary=pii-context/v2
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
//   obfuscation: "none",
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

To change only a few actions and keep the default for every other finding, pass
a declarative `actionPolicy` instead of a callback (introduced in
`0.1.0-beta.14`, as are `defaultPolicy` and `compareActionPolicies` below; see
[which release has what](#which-release-has-what) for a fallback on older releases). It takes a plain object,
JSON text or bytes, on `scan`, `scanAndRedact`, `createIncrementalSanitizer` and
the stream factories; the Rust core evaluates it on both runtimes, and a call or
session takes a callback or an action policy, never both (`INVALID_OPTIONS`).
A rejected document throws `INVALID_ACTION_POLICY`. For a callback that wants
"mine, else the default", `defaultPolicy.evaluate(finding)` asks the core
instead of copying the default table. See the
[action policy guide](action-policy.md#javascript).

To see why each finding got its action, or what changes when you swap one
policy for another, `compareActionPolicies(input, { policies })` evaluates one to
four policies (`{ kind: "default" }`, `{ kind: "action-policy", actionPolicy }`
or `{ kind: "callback", policy }`) over one detection pass and returns each
policy's action, the deciding rule and each document's SHA-256 as frozen data. It
is a preview, never enforcement, it takes one string (there is no stream or
incremental comparison), and a callback side that fails fails the whole
comparison with no partial result. See
[Compare in JavaScript](action-policy.md#compare-in-javascript).

## Request-wide placeholder numbering

Every call numbers its placeholders from 1, so scanning the string leaves of
one request one call at a time gives each leaf its own `<SECRET_1>`. To keep the
numbers unique across the request, give each call a `placeholderFormatter` that
adds the number of placeholders already used. The package adds no helper for
this: the formatter already receives `context.placeholderIndex`, and the only
state the host keeps is one integer.

```ts
import { initialize, scanAndRedact } from "@redact-secret/core";
import type { PlaceholderFormatter } from "@redact-secret/core";

await initialize();

/** One per request. Create a new one for the next request. */
function createRequestNumbering() {
  let replacedSoFar = 0;
  return {
    redactLeaf(leaf: string): string {
      const base = replacedSoFar;
      let used = 0;
      const placeholderFormatter: PlaceholderFormatter = (_finding, context) => {
        used = context.placeholderIndex;
        return `<SECRET_${base + context.placeholderIndex}>`;
      };
      const { text } = scanAndRedact(leaf, { placeholderFormatter });
      replacedSoFar = base + used;
      return text;
    },
  };
}
```

Call `redactLeaf` for each leaf in the order your traversal visits them. The
tests in `packages/javascript/test/request-wide-numbering.test.ts` run this code
against the real engine, through the built package, and prove the following,
and nothing more:

- A bare call restarts at `<SECRET_1>`; with the recipe, leaves holding the
  same or different values continue from the previous leaf's last number. A
  second request starts at 1 because it has its own
  `createRequestNumbering()`.
- `placeholderIndex` is one-based within one call. A leaf with several findings
  uses consecutive numbers, and a leaf with none uses none.
- Each occurrence gets its own number, including two identical values in one
  leaf or in two leaves. Numbers do not identify a value.
- The formatter runs only for findings that are replaced. `redact` and `block`
  take a number; `warn` (for example `password=hunter2xyz` under the default
  policy) keeps its text and takes none. The offset therefore equals the count
  of `redact` and `block` entries in `result.findings`, so a host that prefers
  to count findings gets the same offset.
- A formatter that throws fails the call with `PLACEHOLDER_FAILURE` and no
  partial text. The offset moves only after a call returns; treat any throw as
  a failure of the whole request and discard the redacted leaves.
- A `createIncrementalSanitizer` per streamed leaf works the same way: its
  `placeholderIndex` counts across that session's `append` calls, so read the
  offset after `finalize` and give the next leaf's formatter the new base.

The closure holds integers only, never a matched value, and the formatter still
sees no input. To keep key context, record the leaf's path and the first and
last number it used (`base + 1` through `replacedSoFar`) in a host-side list.
Keep the path out of the placeholder text: a key name is caller-controlled
input.

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

A returned value means every detector inspected the whole input; a thrown
`SecretScanError` comes with no partial result. These calls are synchronous,
cannot be cancelled and have no deadline, so a large input blocks the calling
thread until it finishes. See
[Completeness of `Ok`](../reference/api-contract.md#completeness-of-ok) and
[Cancellation and time bounds](../reference/api-contract.md#cancellation-and-time-bounds).

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
if `initialize()` fails. There is no public custom-Wasm-URL initialization option. The
[quickstart](../quickstart.md#browser-with-a-bundler) walks through a complete
[Vite](https://vite.dev) project, which is the bundler the documented path and
CI exercise; another bundler needs the same two things, the `browser`
condition and the emitted `.wasm` asset.

The package ships two `.wasm` assets per profile. The default one
(`redact_secret_wasm_bg.wasm`, or `redact_secret_wasm_common_bg.wasm` for
`/common`) links no PII runtime and is the only one fetched when `initialize()`
has no `pii` option. A second, lazily loaded asset (`redact_secret_wasm_pii_bg.wasm`,
or `redact_secret_wasm_common_pii_bg.wasm`) is fetched only when the first
`initialize()` call passes a non-empty `pii` selection. Make sure your bundler
emits both and that your server serves both with `application/wasm`; a page
that never enables PII never requests the PII asset. Transfer sizes of the
default builds are in [detector profiles](../reference/detection.md#detector-profiles);
raw, gzip and brotli sizes of all four assets, including the PII split, are in
the [#1127 measurement](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1127/README.md).

A PII selection fails with one of three fixed, input-free errors:

| Code | Meaning |
| --- | --- |
| `PII_SELECTOR_INVALID` | A selector is malformed, for example uppercase `"PII"`. Use lowercase `pii`, `pii:global`, `pii:us`, or `pii:family:<jurisdiction>:<family>`. |
| `PII_SELECTOR_UNSUPPORTED` | The selector is well formed but names a jurisdiction or family this release does not support (for example `pii:kr`). |
| `PII_SELECTOR_UNAVAILABLE` | The selector is valid but the loaded artifact has no PII runtime, or the family is not available. `@redact-secret/core` loads the PII-capable build for you; you see this only when importing `@redact-secret/wasm` directly, which must use `@redact-secret/wasm/pii` or `@redact-secret/wasm/common/pii` to select PII. |

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
