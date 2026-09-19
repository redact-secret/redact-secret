# bindings/node

N-API native addon (`napi-rs`) for Node.js. Crate: `redact-secret-node`.

- Owns Node-specific loading, buffer handling, and UTF-16 range conversion.
- Exports `version`, `profile`, `initialize`, `scan`, `redact`,
  `scanAndRedact`, and `createIncrementalSanitizer` for the default `full`
  detector profile, and `profileCommon`, `initializeCommon`, `scanCommon`,
  `scanAndRedactCommon`, and `createIncrementalSanitizerCommon` for `common`.
  `redact` is shared; one compiled addon serves both profiles.
- This directory's own `package.json` is `private` and only carries the
  `napi` build configuration; it is never published itself. `npm/` holds one
  tiny publication package per `node-publish-targets` platform triple
  (`@redact-secret/node-<platform>`), each carrying only that platform's
  built `.node` file. The eight packages support Node.js 20, 22, and 24 on
  glibc and musl Linux, macOS, and Windows, x64 and arm64
  (`decision-publish-musl-node-addons`); on Linux the loader picks `gnu` or
  `musl` by detected libc. `packages/javascript` depends on the eight
  publication packages through
  `optionalDependencies`, and npm's `os`/`cpu`/`libc` fields skip the ones
  that do not match a given install.
- `createIncrementalSanitizer` wraps the core's `IncrementalSanitizer` the
  same way `bindings/python` does: mandatory limits, an explicit
  `accepting`/`finalized`/`aborted`/`failed` lifecycle, and absolute UTF-16
  offsets converted from the core's UTF-8 byte offsets without retaining the
  input (`src/incremental.rs`). `bindings/wasm` exposes the same real core
  session for browser consumers.
