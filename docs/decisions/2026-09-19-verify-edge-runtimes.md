---
decision_id: decision-verify-edge-runtimes
status: accepted
scope: workspace
title: Verify @redact-secret/core on Cloudflare Workers and Vercel Edge
decided_at: 2026-09-19
---

# Verify @redact-secret/core on Cloudflare Workers and Vercel Edge

## Decision

`decision-add-node-wasm-fallback` established that both Cloudflare Workers
and Vercel Edge resolve `@redact-secret/core`'s `browser` condition, and left
whether that path actually works under either platform's real runtime as an
open, explicitly unclaimed question (issue #462). It is now settled for both,
by running the real artifact against each platform's real engine rather than
a synthetic harness (full transcripts: `docs/audits/evidence/462/README.md`).

**Cloudflare Workers is now supported.** A real `wrangler dev` sandbox (a
real local `workerd` server, the same engine Cloudflare Workers runs in
production) shows `import.meta.url` is `undefined` inside a `workerd` module
worker, so `runtime/browser.ts`'s generated-glue no-argument `default()` —
`new URL('...', import.meta.url)` then `fetch()` — throws `Invalid URL`
before it ever reaches the network. `packages/javascript/package.json`'s
`#native`/`#native-common` import maps gain a `workerd` condition, ahead of
`browser`, resolving to two new loaders:
`packages/javascript/src/runtime/workerd.ts` and `workerd-common.ts`. Each
imports its profile's `.wasm` binary by its own literal specifier —
`@redact-secret/wasm/redact_secret_wasm_bg.wasm` /
`.../redact_secret_wasm_common_bg.wasm`, new bare-string subpath exports
added to `bindings/wasm/npm/package.json` — instead of relying on
`import.meta.url`. `wrangler`'s bundler applies its `CompiledWasm` module
rule to any `.wasm`-extension import by default, resolving it to an
already-compiled `WebAssembly.Module` rather than fetching bytes; the loader
passes that module straight to the generated glue's documented alternate
calling convention, `default({ module_or_path: <module> })` — the same
convention `runtime/node.ts`'s WebAssembly fallback already uses for bytes
read from disk. `WasmModule.default`'s shared type
(`runtime/wasm-binding.ts`) widens from `Uint8Array` to `Uint8Array |
object` to admit this third caller; `object` stands in for the real
`WebAssembly.Module` type because this package's `lib.ES2022`-only
`tsconfig.json` deliberately excludes `dom`, so no runtime file's
type-checking depends on browser-only globals.

`scripts/qualify-workerd-artifact.mjs` (`npm run workerd:qualify`) qualifies
this path against the real, built package in a real `wrangler dev` sandbox,
for both detector profiles: `initialize()`, `artifact()` (asserted `"wasm"`),
a synchronous scan against the canonical fixture, `redact`, `scanAndRedact`,
and one incremental session. Like `node-wasm-fallback:qualify`, this is not
(yet) wired into `npm run ci` or the artifact-qualification workflow's own
matrix — no host in the current CI matrix runs `workerd`, so there is no
natural fan-out slot for it the way the addon and browser jobs have; a
dedicated CI lane is left to a follow-up, the same scope `node-wasm-fallback`
already carries.

**Vercel Edge remains unsupported**, verified as a real, specific failure
rather than left an assumption. `@edge-runtime/vm` — the reference engine
Vercel publishes and that `next dev`/`vercel dev` use locally to run Edge
Functions and Middleware — runs code via a plain classic-script `vm.Script`
with no ES module loader at all: `import`/`export`/`import.meta` syntax is a
`SyntaxError` in whatever is handed to `evaluate()`. This is a stronger
constraint than `workerd`'s: `workerd` still executes a real ES module graph
and a bundler can still redirect within it via a `package.json` condition,
which is exactly what the Cloudflare fix above does. On this reference
engine, whatever hands it code must already have resolved every import,
`.wasm` included, into one import-free script before `evaluate()` ever runs
it — a transform this package's own `imports`/`exports` conditions cannot
reach or verify, because it happens entirely inside the consumer's build
tool, not inside a module graph this package participates in. Vercel
documents a `?module`-suffixed `.wasm` import convention that implies their
build tooling performs exactly this transform, but confirming that requires
observing Vercel's own production build output for a real Edge Function or
Next.js Edge Runtime route, which was not done: no Vercel account or
deployment was created to investigate this issue. Shipping a `package.json`
condition on the strength of the documented convention alone, without
observing it resolve correctly end to end, would be exactly the unverified
edge-runtime claim `AGENTS.md`'s change rules forbid. `README.md` and
`docs/qualification.md` state this precisely: Vercel Edge's failure and root
cause are verified, its fix path is scoped here, and it remains
unimplemented pending that verification.

## Rationale

The originating research (`decision-add-node-wasm-fallback`) verified only
package-resolution conditions — which file each platform's bundler selects —
and explicitly left whether the selected file works as a separate, open
question. Answering it required running the real, unmodified artifact
against each platform's own real engine, because the two failures that
research anticipated (a synthetic iife-format smoke test's `Invalid URL`, and
the theoretical possibility that real deployments differ) turned out to have
the same underlying cause on Cloudflare Workers but a materially different
one on Vercel Edge — `import.meta.url` unavailability is shared, but only
`workerd` retains a live module graph a package-level condition can redirect
within. Treating both platforms identically because their condition
resolution research looked identical would have produced either a false "not
supported" for Cloudflare Workers (an easy, real, low-risk fix) or a false
"supported" for Vercel Edge (an unverifiable claim resting on inference about
a third party's private build pipeline).

## Alternatives considered

- **Ship the same `.wasm`-import technique for Vercel Edge under an
  `edge-light` condition**, matching Vercel's own documented `?module`
  convention. Rejected for now: a bare (non-`?module`) `.wasm` specifier
  under an `edge-light` condition is not guaranteed to resolve the way a
  bare `.wasm` specifier resolves under `wrangler`'s bundler by default, and
  a `?module`-suffixed specifier is meaningless to any bundler that is not
  specifically Vercel's. Shipping either without observing it work against
  Vercel's actual build output would let a probably-broken code path
  silently ship as if verified, which is worse than the current honest
  `INITIALIZATION_FAILED`. Revisit once Vercel's build behavior for this
  exact package shape has actually been observed.
- **Add a Node-style fallback that avoids WebAssembly loading conditions
  entirely** (for example, embedding the compiled bytes in the published
  package and instantiating them without any bundler-specific import) for
  both platforms. Rejected: `workerd` already has a documented,
  bundler-native mechanism that this decision uses and verifies; inventing a
  parallel mechanism would duplicate a working path for no benefit on
  Cloudflare Workers, and would not resolve Vercel Edge's actual constraint
  (no live module graph at evaluation time) since the compiled bytes still
  have to reach the evaluated script through *some* import that a
  Vercel-specific transform resolves, or be embedded by that same build step
  another way — either way requiring the observation this decision does not
  yet have.
- **Leave Cloudflare Workers unimplemented alongside Vercel Edge**, on the
  premise that both were equally unverified before this investigation.
  Rejected once the two platforms' actual constraints diverged under real
  testing: withholding a verified, low-risk fix for Cloudflare Workers to
  keep documentation symmetric with an unverifiable one for Vercel Edge
  would not serve either platform's users.

## Consequences

- `packages/javascript/package.json`'s `#native`/`#native-common` import
  maps gain a `workerd` condition; `check-artifact-matrix.py` and existing
  export-boundary tests are unaffected, since this is an additive condition
  key, not a change to the package's public `exports` map.
- Two new runtime files ship:
  `packages/javascript/src/runtime/workerd.ts` and `workerd-common.ts`.
- `bindings/wasm/npm/package.json` gains two new bare-string subpath
  exports, `./redact_secret_wasm_bg.wasm` and
  `./redact_secret_wasm_common_bg.wasm`, resolvable under any condition the
  same way `./package.json` already is.
- `runtime/wasm-binding.ts`'s `WasmModule.default` parameter type widens from
  `{ module_or_path: Uint8Array }` to `{ module_or_path: Uint8Array | object
  }`; every existing caller (`runtime/browser.ts`, `browser-common.ts`,
  `runtime/node.ts`'s fallback) is unaffected, since `Uint8Array` still
  satisfies the widened type.
- `scripts/qualify-workerd-artifact.mjs` and `npm run workerd:qualify` ship,
  requiring `wrangler` (a new root `devDependency`). Not wired into `npm run
  ci` or the artifact-qualification workflow, matching
  `node-wasm-fallback:qualify`'s own scope; a dedicated CI lane is a
  follow-up.
- `README.md` and `docs/qualification.md` state Cloudflare Workers as a
  verified, supported runtime and Vercel Edge as a verified, documented gap
  with its root cause and the specific missing observation blocking a fix —
  not an assumption in either direction.
- This decision does not select a version or authorize any release. Existing
  release authority (`AGENTS.md`, "Release authority") remains in force.
