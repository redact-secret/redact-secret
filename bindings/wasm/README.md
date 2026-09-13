# bindings/wasm

`wasm-bindgen` build for browsers. Crate: `redact-secret-wasm`. Target:
`wasm32-unknown-unknown`.

- Exports `initialize`, `version`, `scan`, `redact`, `scanAndRedact`, and
  `createIncrementalSanitizer`, plus the `Finding`, `Range`,
  `ScanAndRedactResult`, `IncrementalSanitizer`, and `IncrementalResult`
  classes those return. `scan`/`redact`/`scanAndRedact` accept an optional
  custom `policy`/`formatter` JavaScript function; see the doc comments in
  `src/lib.rs`.
- `createIncrementalSanitizer(maxInputCodeUnits, maxBufferedCodeUnits,
  maxTokenCodeUnits, maxMultilineCodeUnits, policy?, formatter?)` builds a
  real, bounded `IncrementalSanitizer` session — the same core
  `redact_secret::IncrementalSanitizer` `bindings/node` and `bindings/python`
  wrap — with an explicit `accepting`/`finalized`/`aborted`/`failed`
  lifecycle (`src/incremental.rs`). Every range it reports is an absolute
  UTF-16 code-unit offset into the logical whole-session input, converted
  chunk by chunk without ever holding the whole input as one string.
  The four legacy `CodeUnits` limit parameter names are retained for API
  compatibility, while their values are enforced as UTF-8 byte ceilings by
  the Rust core.
- `initialize` is this crate's own synchronous, idempotent setup step (it
  builds and caches the built-in detector registry) — distinct from, and in
  addition to, wasm-bindgen's own generated `init()`/default export, which a
  consumer must still `await` first to fetch and instantiate the `.wasm`
  binary itself. A higher-level JavaScript API that wraps both into one
  `await initialize()` (`decision-define-runtime-bindings`) belongs to
  whatever consumes this crate (`packages/javascript`), not to this crate.
- Every range this crate returns (`Range.start`/`Range.end`) is in UTF-16
  code units, converted from the core's UTF-8 byte offsets in `src/range.rs`
  without changing the selected span.
- A custom `policy`/`formatter` callback receives only safe, JSON-shaped
  metadata (`src/metadata.rs`); it never sees the scanned input or a matched
  value, and any failure (a thrown exception or an unexpected return value)
  becomes a fixed, input-free error, never the exception's own message.
- Consumed by `packages/javascript` as the ordinary dependency
  `@redact-secret/wasm` (`npm/package.json` in this directory); never
  imported directly by an application.
- CI checks this crate and the core on the wasm32 target so the core cannot
  grow a dependency that does not compile for browsers, and runs this
  crate's own test suite for that target under Node (no browser needed) via
  `wasm-bindgen-test`.
