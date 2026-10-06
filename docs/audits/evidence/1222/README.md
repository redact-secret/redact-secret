# Evidence: #1222, configuration ownership recipes run against built artifacts

Frozen record for [#1222](https://github.com/redact-secret/redact-secret/issues/1222)
(epic [#1216](https://github.com/redact-secret/redact-secret/issues/1216)).
It records what was executed for the documentation-only outcome in
[`decision-keep-the-configuration-bound-scanner-handle-out-of-0-1-x-for-node-webassembly-and-python`](../../../decisions/2026-10-06-keep-the-configuration-bound-scanner-handle-out-of-0-1-x-for-node-webassembly-and-python.md)
and shown in [`docs/guides/configuration-ownership.md`](../../../guides/configuration-ownership.md).
The research it builds on is [#1221](../1221/README.md). All inputs are
synthetic and the credential-shaped value is assembled at run time. Nothing here
claims installed-package parity or performance.

## Identity of what was run

| Item | Value |
| --- | --- |
| Source | branch `workbench/1216-user-owned-config` at `574e0543` plus this change, `0.1.0-beta.13` |
| Host | macOS (Darwin 25.5.0), arm64 |
| Toolchain | `rustc`/`cargo` from `rust-toolchain.toml`; Node v22.16.0; Python 3 with maturin; `wasm-bindgen` |
| Node | `cargo build -p redact-secret-node --release`; the `.node` file wrapped as `@redact-secret/node-darwin-arm64` and linked under `packages/javascript/node_modules`; `npm run js:build`; examples run from a clean directory whose only dependency is a link to the built `packages/javascript` |
| WebAssembly | `node scripts/build-browser-artifact.mjs --out-dir <dir>` (release); the example reads `redact_secret_wasm.js` and `redact_secret_wasm_pii.js` from it |
| Python | `maturin build --release --locked`; the abi3 wheel installed into a fresh venv; `python -I` |
| CLI | `cargo build -p redact-secret-cli --release --locked` |

## What each example printed

Every example prints one line per tenant for the same two synthetic lines (an
email and a private-range network address). The expected result is PII off with
no finding, `pii:global` with both, and the network-address family with one.

| Example (`examples/configuration-ownership/`) | Surface | Result |
| --- | --- | --- |
| `node-worker-tenants.mjs` | `@redact-secret/core` facade on the native addon, one Worker per tenant | `pii-off []`, `pii-global ["pii_global_email","pii_global_network_address"]`, `network-address-only ["pii_global_network_address"]`: **pass** |
| `node-policy-per-call.mjs` | facade, `actionPolicy` and `compareActionPolicies` in one thread | `default: redacted`, `keep-github: unchanged`, `redact -> warn changed: 1`: **pass** |
| `node-singleton-conflict.mjs` | facade, one thread | equivalent selection idempotent, differing one `PII_ACTIVATION_CONFLICT`, active selection still `pii:global`: **pass** |
| `wasm-instance-tenants.mjs` | generated WebAssembly glue, one module instance per tenant | same three lines as the Worker example: **pass** |
| `python_process_tenants.py` | wheel, one single-process pool per tenant, `spawn` | same three lines, then `PII_ACTIVATION_CONFLICT` for a second selection in one process: **pass** |
| `python_policy_per_call.py` | wheel, `action_policy=` and `compare_action_policies` | `default: redacted`, `keep-github: unchanged`, `redact -> warn changed: 1`: **pass** |
| CLI, three runs over a file with the same two lines | `redact-secret`, `--pii` | 0 findings (exit 0); 2 findings (exit 1); 1 finding, network address (exit 1): **pass** |
| `cargo test -p redact-secret --test configuration_ownership_1222` | Rust `BuiltInRegistry` shared across threads, per-call policy and comparison | 3 passed: **pass** |

What this adds to #1221: the Worker recipe was there executed on the raw addon
and only source-inspected on the facade. Here the built `@redact-secret/core`
package ran it, and a Worker that imports the package got its own runtime, so
the facade claim is now executed, on this one host.

## Commands

From the repository root; `$S` is a scratch directory outside the repository.

```bash
# Rust: the recipes and their drift guard against the guide
cargo test -p redact-secret --locked --test configuration_ownership_1222

# Node: build the addon and the package, link the addon the way an install would
cargo build -p redact-secret-node --release --locked
cp target/release/libredact_secret_node.dylib $S/addon/redact-secret.node   # with a package.json and index.js that require it
ln -s $S/addon packages/javascript/node_modules/@redact-secret/node-darwin-arm64
npm run js:build
# $S/consumer/node_modules/@redact-secret/core is a link to packages/javascript
cp examples/configuration-ownership/node-*.mjs $S/consumer/
node $S/consumer/node-worker-tenants.mjs
node $S/consumer/node-policy-per-call.mjs
node $S/consumer/node-singleton-conflict.mjs

# WebAssembly
node scripts/build-browser-artifact.mjs --out-dir $S/wasm-full
node examples/configuration-ownership/wasm-instance-tenants.mjs $S/wasm-full

# Python
python3 -m venv $S/venv
(cd bindings/python && maturin build --release --locked -o $S/wheels)
$S/venv/bin/pip install $S/wheels/redact_secret-*.whl
$S/venv/bin/python -I examples/configuration-ownership/python_process_tenants.py
$S/venv/bin/python -I examples/configuration-ownership/python_policy_per_call.py

# CLI
cargo build -p redact-secret-cli --release --locked
target/release/redact-secret tenant.txt
target/release/redact-secret --pii pii:global tenant.txt
target/release/redact-secret --pii pii:family:global:network-address tenant.txt
```

## What is checked in CI and what is manual

- The Rust recipes run in `cargo test`, and the test fails when the guide stops
  containing the tested code verbatim.
- The Node, WebAssembly and Python examples need a built addon, artifact or wheel
  that the documentation checks do not have. They are manual evidence here, and
  `examples/configuration-ownership/guide-sync.test.mjs` (part of `npm run
  examples:test`) fails when the guide stops containing each file verbatim, so a
  later edit cannot change what the guide shows without changing what was run.
- The CLI block in the guide is a manual run; its output is copied from the run
  recorded above.

## Limits

- One host and one build, arm64 macOS; no Linux, Windows or browser run, and no
  bundler was tried for the WebAssembly instance recipe, which relies on distinct
  module URLs giving distinct instances.
- No timing, throughput or memory was measured here. The roughly 1.7 MiB per
  initialized `pii` instance is #1221's single indicative figure.
- The Python 3.14 sub-interpreter failure and the `status()` repr defect are
  #1221's observations and were not re-run.
