# Issue #382 — qualify modular detector profiles across conformance and release surfaces

[Audit archive](../../README.md) · [Epic #377](https://github.com/redact-secret/redact-secret/issues/377) · [Issue #382](https://github.com/redact-secret/redact-secret/issues/382) · [#378 baseline](../378/README.md) · [#381 artifact experiment](../381/README.md) · [Profile contract](../../../decisions/2026-09-18-define-detector-profile-and-pack-contract.md)

Measured 2026-09-18 on `workbench/382-qualify-detector-profiles`, branched
from `main` at commit `922d4dada304a7b550fc13be5779fa8e4104ee2a`. This is the
epic's closing qualification task. It does not authorize a release
(`AGENTS.md`'s release authority) and introduces no aggregate accuracy score,
online credential verification, or automatic version/tag/publish action.

`#381` recommended keeping `common` as a candidate supported surface and
handing qualification and the package exports to this issue. Both are done
here: every surface the accepted contract names now exposes `common`, is
qualified against real artifacts, and CI/release enforce the contract's
guarantees rather than only documenting them.

## Result

| Question | Answer |
| --- | --- |
| Is detector membership and canonical order pinned for both profiles? | Yes. `crates/secret-scan-core/src/detectors/mod.rs`'s `BUILT_IN_PACKS` table is asserted, in tests, to equal `built_in_detectors()`'s order exactly, and `common_built_in_detectors()`'s ids are asserted to be exactly the table's `Pack::Common` rows, in order, and an order-preserving subsequence of `full`. |
| Do the full/default qualification suites still pass unmodified? | Yes. `cargo test --workspace`, `cargo test -p redact-secret-wasm --no-default-features`, `cargo clippy --workspace --all-targets -- -D warnings`, and `npm run ci` (decisions, legacy-identifier, Python package, artifact-matrix, coverage, precision-contract, assessment, release-manifest/gate/refs, reconcile-guard, SAST, examples, JS typecheck and test) all pass at this revision with no expectation relaxed. |
| Are there profile-specific fixtures proving inclusion/omission? | Yes, carried forward from #381 and exercised here on every surface: `conformance/fixtures/common-profile-expectations.json` (1,212 fixtures) plus `crates/secret-scan-core/tests/common_profile_corpus.rs`, and a bare-provider-token negative case on every runtime (`bindings/wasm`, `bindings/node`, the browser artifact page, the Node addon). |
| Are ranges, metadata, overlap ownership, policy action, and surrounding text verified per profile? | Yes, via the full corpus run under `common` (below) plus the browser and Node package-facade checks, which compare exact `(detector, type, confidence, start, end)` tuples and reconstruct the exact expected redacted output from each fixture's own findings. |
| Is whole-input/incremental parity verified per profile? | Yes, on the Rust core, the WASM artifact (browser and native), and now the Node addon and its stream adapter — see "Runtime qualification" below. |
| Is every profile-exposing runtime surface verified? | Yes: Rust core, `bindings/wasm` (native and real browser artifact, both entries: `@redact-secret/core` and the new `@redact-secret/core/common`), `bindings/node` (native and the real addon through both `@redact-secret/core` entries). Python and the CLI are confirmed `full`-only by the contract and untouched by this issue. |
| Can release accidentally publish `common` under the `full` identity? | No — a new release-time guard loads the packed root `@redact-secret/wasm` artifact and fails the job unless `profile() === "full"`. |
| Is there an artifact/toolchain evidence record? | Yes — this document, `artifact-sizes.json`, `build-evidence.json`, `performance.json`, and the qualification logs below. |
| Is user-facing documentation updated? | Yes — `README.md` gains an opt-in `common` section stating the false-negative tradeoff; `ARCHITECTURE.md`'s "Detector profiles" section, `docs/qualification.md`, and `bindings/wasm/README.md` are updated to the shipped state. |
| Are remaining limitations and the named-pack question recorded? | Yes — see "Known limitations" and "Named packs beyond `common`" below. |

## What this issue built

The contract's delivery order (`decision-define-detector-profile-and-pack-contract`,
"Migration strategy") assigned this issue two things beyond qualification:
finishing the Rust-side surfaces the contract requires but #380/#381 did not
reach, and adding the package exports "[n]othing public ships a `common`
entry before #382 qualification passes."

- **`bindings/node`** had zero profile awareness before this issue — not even
  a `profile()` export for `full`. It now exports `profile()`/`profileCommon()`
  and a `common` counterpart to every registry-backed export
  (`initializeCommon`, `scanCommon`, `scanAndRedactCommon`,
  `createIncrementalSanitizerCommon`). `redact()` stays shared: it never
  touches the registry, so it needed no `common` variant. One compiled addon
  serves both profiles, unlike WASM, which compiles a second binary.
- **`@redact-secret/core`** gains a `./common` export
  (`packages/javascript/src/common.ts`) with the same public API as the root
  export, and both export a `PROFILE` constant. `runtime.ts`'s `initialize()`
  now rejects with `INITIALIZATION_FAILED` when the loaded artifact's
  `profile()` disagrees with the entry point that loaded it — the general
  form of the contract's WASM-specific mismatch requirement, applied
  uniformly so a Node consumer gets the same protection.
- **`@redact-secret/wasm`** gains a `common` subpath export
  (`bindings/wasm/npm/package.json`), shipping the `common` artifact's own
  glue and `.wasm` beside the unchanged root (`full`) files.
- **CI and release** now build, qualify, and package both artifacts. See
  "CI and release wiring" below.

## Files

| File | Contents | Produced by |
| --- | --- | --- |
| [`artifact-sizes.json`](artifact-sizes.json) | Per profile: `.wasm` and glue sizes (raw, gzip -9, brotli -11), SHA-256, toolchain, savings | `scripts/measure-wasm-profiles.mjs` |
| [`build-evidence.json`](build-evidence.json) | Per profile: linked `detectors::<module>` names classified as common, shared engine, or provider; export list; guard verdict | same |
| [`performance.json`](performance.json) | Median init/processing/throughput per workload × profile on Chromium, through each profile's own facade (`@redact-secret/core` / `@redact-secret/core/common`) | same |
| [`raw/<profile>/chromium-<workload>.json`](raw/common/chromium-scale-logs-small-whole.json) | The full 10-run assessment result with samples, stddev, and provenance | `scripts/assessment-browser-performance.mjs` |
| [`browser-qualification-full.txt`](browser-qualification-full.txt), [`browser-qualification-common.txt`](browser-qualification-common.txt) | Every browser check, both artifact and package pages | `scripts/qualify-browser-artifact.mjs` |
| [`node-addon-qualification-full.txt`](node-addon-qualification-full.txt), [`node-addon-qualification-common.txt`](node-addon-qualification-common.txt) | Every Node addon check, all five passes | `scripts/qualify-node-addon.mjs` |

Reproduce:

```bash
npm run js:build
node scripts/measure-wasm-profiles.mjs --out-dir docs/audits/evidence/382 --engine chromium
node scripts/qualify-browser-artifact.mjs --artifact-dir target/wasm-profiles/full
node scripts/qualify-browser-artifact.mjs --detector-profile common --artifact-dir target/wasm-profiles/common

cd bindings/node && npm run build:debug && cd ../..
node scripts/qualify-node-addon.mjs
node scripts/qualify-node-addon.mjs --detector-profile common
```

Two runs at this revision produced byte-identical `.wasm` files to #381's
record (`full` `137934a8…54d6`, `common` `d40ba652…14f9`): this issue changed
no detector, membership, or canonical order, so the compiled artifacts are
unchanged from #381's measurement.

## Artifact size and toolchain

| | `full` | `common` | Saved | Saved % |
| --- | --- | --- | --- | --- |
| `.wasm` raw | 281,549 B | 225,195 B | 56,354 B | 20.02% |
| `.wasm` gzip -9 | 96,415 B | 79,832 B | 16,583 B | 17.22% |
| `.wasm` brotli -11 | 77,485 B | 65,263 B | 12,222 B | 15.77% |
| glue `.js` raw / brotli | 29,548 / 5,571 B | 29,569 / 5,574 B | — | — |
| `.wasm` SHA-256 | `137934a8…54d6` | `d40ba652…14f9` | | |

| Item | Value |
| --- | --- |
| rustc / cargo | 1.98.1 (`48a229cea` 2026-09-01) / 1.98.1 (`797e8a9bc` 2026-08-05) |
| `wasm-bindgen` CLI and crate | 0.2.128 |
| `[profile.release]` | `codegen-units = 1`, `lto = "fat"` |
| `wasm-opt` | not invoked |
| Node.js | v22.16.0 |
| Host | macOS (`darwin-25.5.0`), `arm64` |

`build-evidence.json`'s guard passed with zero failures: `common` is smaller
than `full`, links no `provider` detector module, holds every `common`-pack
module, and exports the same 41-symbol surface (`build-evidence.json`
enumerates the linked `detectors::<module>` names and the exported symbol
list per profile).

## Behavior evidence

Unchanged from #381, restated because this issue's runtime qualification
depends on it: `crates/secret-scan-core/tests/common_profile_corpus.rs` runs
`common` over all 1,212 evaluated canonical fixtures and pins the result in
`conformance/fixtures/common-profile-expectations.json` (detector, type,
confidence, action, UTF-8 byte range — never a value). It also asserts every
`common` finding comes from a `common` detector, and that each `common`
detector emits identical candidates in `common` and `full` over the whole
corpus (per-detector invariance, contract obligation 2). 805 of 1,212
outcomes are identical between profiles; 348 lose a provider-only positive;
59 provider findings fall back to `generic-token` (44 stay `redact`, 15
become `warn`); zero findings appear in `common` that are absent from `full`.

## Runtime qualification

### Rust core and `bindings/wasm` (native)

`cargo test --workspace` (26 workspace tests plus 10 core doctests) and
`cargo test -p redact-secret-wasm --no-default-features` (26 tests, the
`common`-feature build) both pass, including
`a_bare_provider_token_is_detected_only_by_the_full_profile`,
`profile_reports_the_compiled_profile`, and
`full_and_common_sessions_report_the_profile_they_were_built_from`.
`cargo clippy --workspace --all-targets --locked -- -D warnings` is clean.

### `bindings/node` (new this issue)

`cargo test -p redact-secret-node` passes 25 tests, including
`a_bare_provider_token_is_detected_only_by_the_full_profile`,
`profile_and_profile_common_report_their_fixed_names`,
`initialize_common_is_idempotent`,
`scan_and_redact_common_matches_separate_scan_then_redact`, and
`a_common_incremental_session_never_emits_a_provider_only_finding`.
`cargo clippy -p redact-secret-node --all-targets -- -D warnings` is clean.

The real compiled addon (`bindings/node`, built locally with
`napi build --platform`) passes all five qualification passes for **both**
profiles — [`node-addon-qualification-full.txt`](node-addon-qualification-full.txt),
[`node-addon-qualification-common.txt`](node-addon-qualification-common.txt):
inspect, smoke test, whole-corpus conform (against `full`'s own expectations
or `common-profile-expectations.json`, with a foreign-detector check), a
`profile()`/`profileCommon()` identity check, the published package's public
API (`@redact-secret/core` or `@redact-secret/core/common`, including a
`PROFILE` assertion), and the Node `Transform` stream adapter — byte-boundary
partitioning, BOM handling, malformed/truncated UTF-8, backpressure,
`destroy()`, and downstream-failure propagation. `common`'s stream check uses
`jwt-positive-structured` rather than the shared `host-dotenv-github` fixture:
the latter is a `provider`-pack (`github-token`) finding under `full` that
`common` reports as `generic-token`/`warn` — unredacted — which would make
the "a known secret is not left unredacted" sanity check vacuous.
`jwt-positive-structured` is a `common`-pack (`jwt`) finding that is `redact`
and identical between profiles by the per-detector invariance guarantee, so
the same stream-adapter assertions apply unmodified. Node's package/stream
passes are symmetric across profiles because one compiled addon serves both
— there is no second binary a bundler could resolve incorrectly.

### `bindings/wasm` (real browser artifact)

[`browser-qualification-full.txt`](browser-qualification-full.txt): 33 checks
pass on Chromium — the artifact page (initialization gate, corpus match,
profile-membership check, incremental/whole-input parity, callback
contracts) and the package page (the published `@redact-secret/core` facade,
including the Web `TransformStream` adapter's byte-partition, Unicode,
malformed-input, backpressure, cancellation, and error-propagation behavior).

[`browser-qualification-common.txt`](browser-qualification-common.txt): 23
checks pass — the same artifact page (14 checks) plus the package page now
driving `@redact-secret/core/common` (9 checks: initialization, identity,
corpus match against `common-profile-expectations.json`, frozen findings,
`scanAndRedact` consistency, a policy callback, and incremental session
lifecycle). This issue is what makes the package page runnable for `common`
at all: before it, `@redact-secret/core` had no `common` entry, so
`scripts/qualify-browser-artifact.mjs` skipped that page entirely for
`common` (#381's record). The 10-check gap versus `full`'s package page is
the Web stream adapter's checks, skipped for a structural reason recorded
below, not a coverage shortfall in this issue's own work.

**A bundling bug the refactor caught.** `browser-common.ts`'s first draft
imported `createBindingFromWasmModule`/`WasmModule` from `runtime/browser.ts`
directly, reusing that file's shared normalization logic. That pulled
`browser.ts`'s own literal `import("@redact-secret/wasm")` — the `full`
artifact loader — into any bundle that resolved `browser-common.ts`, because
a bundler resolves every literal dynamic import it finds while walking a
module graph, even one behind a function the entry point never calls. A real
consumer bundling `@redact-secret/core/common` would have silently pulled in
the `full` `.wasm` too, defeating `common`'s bundle-size purpose. The fix
factors the profile-agnostic normalization into
`packages/javascript/src/runtime/wasm-binding.ts`, imported by both
`browser.ts` and `browser-common.ts`, neither of which imports the other.
`scripts/qualify-browser-artifact.mjs`'s own package-harness bundling (which
builds a real esbuild bundle per profile, the same way a consumer would)
caught this immediately as an unresolvable-specifier build failure — it did
not surface as a runtime behavior difference, so a check that only exercises
already-loaded modules would have missed it.

**A back-compat break a manual audit caught.** `runtime.ts`'s
`createRedactSecretRuntime` gained a required second `expectedProfile`
parameter so `initialize()` can reject a profile mismatch. None of the CI
suites this issue's own qualification runs (`npm run ci`, `cargo test
--workspace`, the real node-addon and browser qualification passes) exercise
`docs/audits/evidence/beta2-final-review/reproduce.mjs`, a revision-bound
audit probe from an earlier issue that also imports `createRedactSecretRuntime`
directly from `packages/javascript/dist/runtime.js` and calls it with only
one argument — its own header states it reports defects rather than gating
CI, which is exactly why nothing caught the break automatically. Fixed by
passing `"full"`, matching the `full`-profile addon the script loads;
re-run against a locally built debug addon (`napi build --platform`) to
confirm it completes without throwing `INITIALIZATION_FAILED`. This is a
reminder that a signature change to a shared, currently two-caller function
can still miss a caller outside the qualified surface area; the fixed script
is not itself part of this issue's qualification suite and is not re-run by
CI, so a future signature change to `createRedactSecretRuntime` should grep
`docs/audits/evidence/**/*.mjs` for other direct imports before assuming the
qualification suites above are the complete caller set.

## Known limitations

- **`@redact-secret/core/web-stream` and `@redact-secret/core/node-stream`
  are not profile-aware.** `packages/javascript/src/adapters/web-stream.ts`
  and `node-stream.ts` both import `runtime` from `../session.js` at module
  scope, unconditionally — the `full` runtime — for their
  `createWebStreamSanitizer`/`createNodeStreamSanitizer` convenience
  exports. A consumer combining `@redact-secret/core/common` with
  `@redact-secret/core/web-stream`'s convenience function would get `full`'s
  bundle and registry for their streaming path, silently contradicting their
  `common` choice, and in the browser would bundle both WebAssembly
  artifacts. The `WebStreamSanitizer`/`NodeStreamSanitizer` **classes**
  themselves are profile-agnostic — each just wraps whatever
  `IncrementalSanitizer` session it is constructed with — so a `common`
  consumer can already work around this by calling
  `createIncrementalSanitizer` from `@redact-secret/core/common` directly and
  passing that session into `new WebStreamSanitizer(session)` /
  `new NodeStreamSanitizer(session)`, bypassing the convenience function.
  `scripts/browser-package-harness-common.mjs` and
  `scripts/qualify-node-addon.mjs`'s Node-side stream check route around this
  the same way: Node's check passes fully because it constructs the class
  directly with a `common`-sourced session; the browser's package page
  qualifies everything except the stream adapter, and skips those checks
  rather than silently passing them against the wrong profile. The accepted
  contract's runtime-surfaces table does not name the stream adapters, so
  giving them their own profile-aware entry (`@redact-secret/core/common/web-stream`,
  or a profile-parametric convenience function) is deferred as follow-up
  work, not part of this issue.
- **Performance was measured on Chromium only in this record.** #381 already
  measured Chromium, Firefox, and WebKit and found consistent 2.9–6.1×
  processing speed-ups; this issue did not re-measure Firefox/WebKit because
  neither the Rust core, the WASM artifact, nor the detector set changed —
  only the JavaScript/Node package surface around them did, which the
  correctness qualification above covers per engine (CI runs the full
  Chromium/Firefox/WebKit browser-qualification matrix, including `common`,
  on every run — see "CI and release wiring").
- **Python and the CLI remain `full`-only**, unchanged by this issue, per the
  accepted contract's explicit non-goal.

## CI and release wiring

- `.github/workflows/ci.yml` already ran clippy, native tests, and wasm32
  tests for `bindings/wasm --no-default-features` before this issue (#381).
  Unchanged.
- `.github/workflows/artifact-qualification.yml`'s `browser` job now also
  builds the `common` artifact (`npm run wasm:build:common`), qualifies it
  per engine (`--detector-profile common`), and uploads it as `wasm-web-common`
  on the same chromium leg the `full` `wasm-web` artifact already uses. Its
  `node-addon` job now runs `scripts/qualify-node-addon.mjs --detector-profile
  common` once per target (one compiled addon serves both profiles, so this
  is not duplicated per Node major).
- `.github/workflows/release.yml`'s `publish-wasm-dependency` job downloads
  both `wasm-web` and `wasm-web-common` into `bindings/wasm/npm` before
  packing, and a new verification step loads the packed root artifact
  (`redact_secret_wasm.js`/`.wasm`, from bytes, no fetch) and fails the job
  unless `profile() === "full"` — the concrete guard against publishing a
  `common`/tiny build under the `full`/default package identity (this
  issue's acceptance criterion on release builds).
- `.github/workflows/reconcile-release.yml` and
  `.github/workflows/package-release-rehearsal.yml` needed the same
  two-artifact staging: `bindings/wasm/npm/package.json`'s `files` now lists
  both profiles' glue and `.wasm`, and `publish-dependency-package.mjs`'s
  packed-contents check fails a pack that is missing any declared `files`
  entry, so reconciliation and the rehearsal dry run were genuinely broken by
  the package.json change, not just "not yet applicable."
- `scripts/record-artifact-inventory.py` recognizes `wasm-web-common` as its
  own artifact family so the inventory job does not fail with "unrecognized
  artifact(s)" once the new upload exists. It is deliberately not on the
  required-family list: the upload step's own `if-no-files-found: error`
  already guards a missing artifact, matching how `wasm-web` is guarded
  today.

## Named packs beyond `common`

No named vendor pack (AI, cloud, source-control, package-registry, SaaS)
ships now. None of the contract's three re-measurement triggers fired at
this revision: the built-in count is still 42 (trigger at 63), `full`'s
brotli WebAssembly size is unchanged from the #381/#378 baseline at 77,485 B
(trigger at 96,759 B or more, a 25% growth), and no issue has named a
consumer, its runtime, and a byte or latency budget that `common` misses on
coverage and `full` misses on cost (trigger 3). This issue's own work adds no
new evidence toward a named pack — it qualifies and ships the two profiles
the contract already decided on. **Recommendation: unchanged from the
contract — no named pack now; re-measure with
`scripts/measure-detector-cost.mjs` and revisit if a trigger fires.**

## What this evidence does not claim

It does not measure over a network, on a cold HTTP cache, or on a slower
device. It does not repeat performance runs across hosts or days, and it did
not re-run the Firefox/WebKit performance measurement (see "Known
limitations"). It does not make `@redact-secret/core/web-stream` or
`@redact-secret/core/node-stream` profile-aware. It does not change Python or
the CLI. It publishes or exports nothing to a registry: the `./common`
exports exist in this working tree and are covered by CI, but shipping them
in a released version is a separate, explicitly authorized release decision
(`AGENTS.md`).
