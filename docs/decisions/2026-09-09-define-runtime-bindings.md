---
decision_id: decision-define-runtime-bindings
status: accepted
scope: workspace
title: Define runtime bindings
decided_at: 2026-09-09
spec: engine
---

# Define runtime bindings

## Decision

Expose the Rust core through runtime-specific bindings:

- Node.js uses an N-API native addon.
- Browsers use a `wasm-bindgen` WebAssembly build.
- Python uses PyO3 and maturin, with CPython 3.10+ abi3 wheels for supported
  Linux, macOS, and Windows targets plus a source distribution that requires a
  Rust toolchain when no wheel applies.
- Rust consumers use the public library crate directly.

The npm package presents one JavaScript API across Node and browser targets.
Consumers call `await initialize()` once before using synchronous `scan`,
`redact`, `scanAndRedact`, incremental, or adapter operations. Node
initialization may be a fast no-op, but it remains part of the contract so the
usage model does not vary by runtime.

Each binding exposes ranges in its native string-index unit: JavaScript uses
UTF-16 code units, Python uses Unicode code points, and Rust uses UTF-8 byte
offsets. The unit must be explicit in each public contract.

The first stable extension surface supports custom policy and placeholder
formatter callbacks, which receive normalized safe metadata. Custom detector
callbacks are excluded from the first stable API; all built-in detectors run in
Rust.

## Rationale

N-API avoids imposing browser-oriented WebAssembly loading and glue on Node,
while WebAssembly is the portable browser target. Requiring initialization
explicitly makes loading failures observable without turning every scan into an
asynchronous operation. Native offsets keep slicing and integration idiomatic
within each language.

## Alternatives considered

- One WebAssembly build for Node and browsers was rejected because their
  loaders and generated glue differ and Node can use a native addon directly.
- Making every scan asynchronous was rejected because it complicates streaming
  and policy composition after initialization is complete.
- A pure-Python fallback was rejected because it would restore a second
  detector implementation and its drift risk.
- A common UTF-8 public offset was rejected because it makes JavaScript and
  Python text handling unnecessarily error-prone.

## Consequences

- npm release qualification covers both N-API platform artifacts and browser
  WebAssembly loading.
- Binding layers must translate ranges without changing the selected span.
- Policy and formatter callback errors must retain fixed, input-free public
  error behavior across FFI boundaries.
