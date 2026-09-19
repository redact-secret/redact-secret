---
decision_id: decision-add-node-wasm-fallback
status: accepted
scope: workspace
title: Add a Node WebAssembly fallback when the native addon is unusable
decided_at: 2026-09-19
---

# Add a Node WebAssembly fallback when the native addon is unusable

## Decision

`packages/javascript/src/runtime/node.ts` (and its `common`-profile sibling
`node-common.ts`) fall back to the already-published `@redact-secret/wasm`
WebAssembly artifact (`/common` for the `common` profile) when the native
addon path cannot produce a usable binding: an unsupported platform or
architecture, a matching optional dependency that failed to install, or a
corrupt/unloadable addon. Today all three reach a fixed
`INITIALIZATION_FAILED`; after this decision, `initialize()` instead tries
the WebAssembly artifact before giving up.

This is shape 2 of the three the originating issue named: the fallback
ships, and the loaded artifact's identity becomes observable. `NativeBinding`
gains an `artifact(): "addon" | "wasm"` operation, and the public API of
`@redact-secret/core` and `@redact-secret/core/common` gains a new export,
`artifact`, mirroring `version`/`profile`, so an application can log or
assert what actually ran.

No second `wasm-bindgen` target is introduced. The Node loader reuses the
exact `--target web` artifact and glue already published for browsers,
instantiating it from bytes read via `node:fs` instead of the generated
glue's own `fetch`-based default path:

```ts
const module = await import(WASM_SPECIFIERS[profile]); // non-literal
const wasmPath = join(
  dirname(require.resolve(`${packageName}/package.json`)),
  WASM_BINARY_NAMES[profile],
);
await module.default({ module_or_path: readFileSync(wasmPath) });
```

Verified directly against the real artifact while implementing this decision
(not merely at the source level): built the `full`-profile artifact with
`scripts/build-browser-artifact.mjs`, then from a plain Node script read its
`_bg.wasm` binary with `readFileSync` and called the generated `default()`
export with `{ module_or_path: <bytes> }` — initialization, `version()`,
`profile()`, and `scan()` all behaved identically to the browser path.
Separately confirmed that `createRequire(import.meta.url).resolve("<pkg>/package.json")`
resolves even though the package's main entry point declares only `types`/
`import` conditions (no `require`/`default`), because a bare-string
`"./package.json"` export target is condition-agnostic — so no change to
`@redact-secret/wasm`'s `exports` map is needed to locate its sibling
`.wasm` binary from Node.

The dynamic `import()` specifier is a lookup into a small map
(`WASM_SPECIFIERS[profile]`), not a string literal at the call site. A
bundler that only follows literal specifiers (the same behavior
`runtime/browser.ts`'s module comment already relies on to keep the `full`
and `common` WebAssembly artifacts from bundling into each other) does not
statically discover or inline this glue into a Node build. This is what
keeps the export-boundary constraint holding: `@redact-secret/wasm` is
already an ordinary (non-optional) `dependencies` entry of
`@redact-secret/core`, so it is always present in `node_modules` at runtime
regardless of whether a consumer's bundler chose to inline it, and nothing
about `runtime/browser.ts`/`browser-common.ts` or what a browser bundle
resolves changes — this code exists only behind the package's `imports`
map's `node` condition, exactly like the rest of `node.ts`.

## Rationale

`decision-define-runtime-bindings` chose N-API over WebAssembly for Node
specifically to avoid imposing browser-oriented WebAssembly loading and glue
on Node *by default*. This decision does not reopen that choice: the native
addon remains the only thing a supported host ever loads. It adds a fallback
that engages only once the primary path has already failed, for hosts the
addon matrix does not (yet, or ever) cover — the general safety net that
`decision-publish-musl-node-addons` deliberately does not need for musl,
because that decision gives musl its own qualified, faster native path
instead. This fallback's value is for what remains after that: unsupported
architectures, a failed optional-dependency install, or a corrupted addon on
an otherwise-supported host. It also reaches Bun and Deno for free, verified
by resolving this package's `node`/`browser` export conditions under each
runtime's own condition set during the originating issue's research: both
select the `node` branch and have every capability the loader needs
(`node:fs`, `createRequire`, instantiate-from-bytes).

Edge runtimes (Cloudflare Workers, Vercel Edge) are explicitly out of scope:
resolving each platform's own condition set during research showed neither
ever reaches `runtime/node.ts` — both select the `browser` branch, which
already has its own WebAssembly path today, unaffected by this decision.
Whether that existing browser path actually works under `workerd` was not
verified and is not claimed here; that question belongs to a follow-up
issue, not this one (issue #462).

## Alternatives considered

- **Shape 1 (silent fallback), no reported identity.** Rejected for the
  reason the issue gives: performance and artifact identity would change
  without the application being told, and a qualification result would stop
  describing what actually ran.
- **Shape 3 (opt-in only), default behavior unchanged.** The issue's own
  escape hatch to this shape is conditional: "If that cannot be done
  cleanly, option 3 is the answer," referring to the export-boundary
  constraint. That constraint is measurably satisfiable (verified above), so
  the condition does not fire. An opt-in-only fallback would also leave
  every host it could help exactly where it is today by default, for no
  compensating benefit.
- **A second `wasm-bindgen --target nodejs` artifact**, instead of reusing
  the `web`-target build. Rejected: the existing artifact already
  initializes correctly from `fs` bytes (verified above), so a second build
  target would duplicate a qualified artifact and double the WebAssembly
  build/publish surface for no behavioral gain.
- **Probe multiple candidate addons in sequence** instead of loading the one
  fallback artifact. Not applicable here (there is only one WebAssembly
  artifact to fall back to), but rejected as a general pattern for the
  reason `decision-publish-musl-node-addons` gives: an addon linked against
  the wrong libc fails process-fatally, not catchably, so any host-selection
  logic in this area must detect, never probe.

## Consequences

- `packages/javascript/src/native.ts`'s `NativeBinding` contract gains
  `artifact()`; both native-side constructors
  (`createBindingFromAddon`/`createBindingFromCommonAddon` in `node.ts`) and
  the shared WebAssembly normalization (`createBindingFromWasmModule` in
  `wasm-binding.ts`) implement it, and every test double
  (`fake-binding.ts`, `wasm-shaped-binding.ts`) must too.
- `packages/javascript/src/runtime.ts`'s `RedactSecretRuntime` and the public
  `index.ts`/`common.ts` entry points gain an `artifact` export. This is
  additive to the package's public surface; `exact-exports.test.ts`'s pinned
  export list is updated accordingly, and this is a non-breaking change.
- `packages/javascript/src/runtime/wasm-binding.ts`'s `WasmModule.default`
  signature gains an optional init-source parameter (only the Node fallback
  passes one; `runtime/browser.ts`'s and `browser-common.ts`'s existing
  no-argument calls are unaffected).
- Incremental sessions and the Node `Transform` adapter
  (`packages/javascript/src/adapters/node-stream-core.ts`) work over the
  fallback binding unmodified, because both are already built purely against
  the internal `NativeBinding`/`IncrementalSanitizer` contract with no
  addon-specific code; this is asserted by a new test driving
  `NodeStreamSanitizer` over a forced-fallback binding, not merely inferred
  from the types lining up.
- No CI qualification job exercises the fallback branch the way `node-addon`
  and `browser` qualify their own artifacts per platform, because no host in
  the current matrix is missing a native addon by design. The fallback path
  is covered by unit/integration tests against the real artifact's
  instantiation mechanics (verified above) and a forced-fallback double, not
  by a dedicated per-platform qualification job; `README.md` and
  `docs/qualification.md` state this precisely rather than claiming
  full-matrix qualification the fallback does not have.
- `README.md` and `docs/qualification.md` describe the fallback's real
  scope: which failures trigger it, what `artifact()` reports, and that Bun
  and Deno are covered while edge runtimes are unclaimed pending a follow-up
  issue.
- This decision does not select a version or authorize any release. Existing
  release authority (`AGENTS.md`, "Release authority") remains in force.
