# Evidence: verifying `@redact-secret/core` on Cloudflare Workers and Vercel Edge

Issue #462. Split out of #443
(`decision-add-node-wasm-fallback`), which established that both
Cloudflare Workers and Vercel Edge resolve the package's `browser` condition
(never `runtime/node.ts`) but left whether that existing browser path
actually works under either platform's real runtime unverified. This
document records what was actually run, against real engines, to settle that.

Every artifact below was built from this revision (`npm run wasm:build`,
`npm run js:build`). No credential, matched secret value, or fixture other
than the repository's own synthetic corpus appears anywhere in this
evidence.

## Cloudflare Workers: verified pass, root cause found and fixed

**Tooling**: `wrangler dev` (a real local `workerd` server — the same engine
that runs Cloudflare Workers in production), `wrangler` 4.135.0.

### Step 1 — reproduce the unverified path's real failure

A worker script that imports the *unmodified* browser artifact and calls the
generated glue's own no-argument `default()` (`runtime/browser.ts`'s exact
call, before this issue's change) was run against a real `wrangler dev`
sandbox:

```js
let metaUrl;
try { metaUrl = import.meta.url; } catch (e) { metaUrl = "THROW: " + e.message; }
// ...
const u = new URL("./foo.wasm", metaUrl);
const resp = await fetch(u);
```

Response from the real sandbox:

```json
{"fetchResult":"THROW: TypeError: Invalid URL string."}
```

`metaUrl` is missing from the JSON entirely because `import.meta.url` is
`undefined` inside a real `workerd` module worker (`JSON.stringify` drops an
`undefined` value silently) — confirmed, not assumed. `new URL("./foo.wasm",
undefined)` then throws `Invalid URL string`. This is the same failure shape
issue #443's prior iife-format `@edge-runtime/vm` smoke test found, now
reproduced against the actual production engine rather than a synthetic
harness, closing that open question: the existing browser path does not work
on Cloudflare Workers, for a real and specific reason, not a bundler
artifact of one iife-format configuration.

### Step 2 — verify the fix against the real artifact

Cloudflare's own documented pattern for `wasm-bindgen` output is to import
the `.wasm` binary as its own module specifier, which `wrangler`'s bundler
resolves to an already-compiled `WebAssembly.Module` via its default
`CompiledWasm` rule (`[[rules]] type = "CompiledWasm" globs = ["**/*.wasm"]`)
instead of fetching it. Passing that module into the generated glue's
`default({ module_or_path: <module> })` — a documented alternate calling
convention already used by `runtime/node.ts`'s WebAssembly fallback for
bytes — was verified end to end against the real, unmodified
`redact_secret_wasm_bg.wasm` artifact:

```js
import init, { initialize, version, profile, scan } from "@redact-secret/wasm";
import wasmModule from "@redact-secret/wasm/redact_secret_wasm_bg.wasm";
await init({ module_or_path: wasmModule });
initialize();
scan("AKIAABCDEFGHIJKLMNOP");
```

Response from the real sandbox:

```json
{"version":"0.1.0-beta.4","profile":"full","findings":1}
```

Verified both with the `.wasm` resolved relative to the worker's own source
directory and resolved through `node_modules` at the exact
`@redact-secret/wasm/redact_secret_wasm_bg.wasm` subpath the shipped fix
uses (added to `bindings/wasm/npm/package.json`'s `exports`).

### Step 3 — verify the shipped fix, in the package, end to end

`scripts/qualify-workerd-artifact.mjs` drives the real, built
`@redact-secret/core` package (not a reduced probe) through a real
`wrangler dev` sandbox, for both detector profiles:

```
$ npm run workerd:qualify -- --wasm-dir bindings/wasm/pkg
ok - workerd (full) · artifact() reports wasm
ok - workerd (full) · VERSION/PROFILE match the built package
ok - workerd (full) · scan matches the canonical fixture's finding count
ok - workerd (full) · scanAndRedact agrees with scan then redact
ok - workerd (full) · an incremental session matches the whole-input result
qualified the Cloudflare Workers runtime path (full profile) against a real workerd sandbox.

$ npm run workerd:qualify -- --wasm-dir bindings/wasm/pkg-common --detector-profile common
ok - workerd (common) · artifact() reports wasm
ok - workerd (common) · VERSION/PROFILE match the built package
ok - workerd (common) · scan matches the canonical fixture's finding count
ok - workerd (common) · scanAndRedact agrees with scan then redact
ok - workerd (common) · an incremental session matches the whole-input result
qualified the Cloudflare Workers runtime path (common profile) against a real workerd sandbox.
```

**Conclusion**: Cloudflare Workers is now a verified, supported runtime.

## Vercel Edge: verified failure, root cause found, no fix shipped

**Tooling**: `@edge-runtime/vm`'s `EdgeVM`, the reference implementation
Vercel publishes and that `next dev`/`vercel dev` use to run Edge Functions
and Edge Middleware locally. `@edge-runtime/vm` 5.0.0.

### What was verified

`EdgeVM`'s `evaluate(code: string)` runs `code` as a plain classic script
(`vm.Script`, confirmed by reading `@edge-runtime/vm`'s own `dist/vm.js`: no
`vm.SourceTextModule` or other ESM entry point exists in the package). Two
real bundling shapes were tried, matching the two ways a real edge-runtime
build could plausibly hand code to this engine:

```
--- format: iife ---
ERROR: TypeError: Invalid URL

--- format: esm ---
EVAL/RUN THREW: Cannot use 'import.meta' outside a module
```

The `iife` result reproduces issue #443's prior finding, now against the
same production-adjacent reference engine (not the iife output format
itself) as the actual constraint: `import.meta.url` is unusable there for
the same reason it is in `workerd`. The `esm` result establishes something
`workerd` does not share: this reference engine has no live ES module
loader at all — `import`/`export`/`import.meta` syntax is a `SyntaxError` in
whatever `evaluate()` is handed, so no import-graph condition
(`package.json` `imports`/`exports`) can direct a bundler to a
workerd-style fix, because there is no bundler-visible module graph left by
the time code reaches this engine. Whatever hands this engine its code must
already have resolved every import, including any `.wasm` import, into a
single script with no import statements left.

A synchronous `WebAssembly.Module` *can* be constructed and instantiated
inside this engine once one already exists (verified: an esbuild plugin
built for this investigation, standing in for whatever produces Vercel's own
documented `?module`-suffixed `.wasm` import contract, inlined the compiled
module's bytes into an `iife` bundle and the real generated glue, real
artifact, and real detector all worked identically to the `workerd` case).
This narrows the actual gap precisely: the WebAssembly runtime and generated
glue are not the problem on either platform; only reaching an already-compiled
module without a live import statement is.

### Why the Cloudflare fix does not transfer

The Cloudflare fix works because `wrangler`'s bundler still resolves a real,
literal `.wasm` import at build time and workerd still executes a real ES
module graph at runtime — the package's own `imports` map condition
(`workerd`) is enough to redirect to a loader that does this. Vercel's
documented wasm-import convention (a `?module`-suffixed specifier) implies
their build tooling performs the equivalent transform, but confirming that
requires observing Vercel's own production build step, which is not
reachable from this environment — no Vercel account or deployment was
created to investigate this issue, matching this repository's release and
external-service policy. Shipping a `package.json` `imports` condition on
the strength of the documented convention alone, without observing it work
end to end, would be exactly the unverified claim `AGENTS.md`'s change rules
and security boundary forbid.

**Conclusion**: Vercel Edge remains unsupported. The failure and its root
cause are verified, not assumed; the fix path is scoped (see
`decision-verify-edge-runtimes`) but not implemented, pending verified
access to Vercel's actual build output for a real Edge Function or Next.js
Edge Runtime route importing this package.
