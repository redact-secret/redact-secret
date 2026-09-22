# Developer onboarding and local validation

[Documentation home](README.md) · [Contribution guide](../CONTRIBUTION.md)

Read [architecture](../ARCHITECTURE.md), [conventions](../CONVENTIONS.md),
[decisions](decisions/DECISIONS.md), and [workspace policy](rust-workspace.md)
before changing behavior. Use unmistakably synthetic or revoked examples only.
Findings, errors, snapshots, and diagnostics must not copy matched values.

## Run the repository checks

From the root, with a supported Node version and Rust 1.88 or newer:

```bash
npm ci
npm run ci
npm run rust:check
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo package -p redact-secret --locked
```

`npm run ci` checks declarations, release guards, conformance schema, JavaScript
types, and wrapper tests. It does not run the full native platform matrix or
substitute for the real artifact qualifiers. [Qualification](qualification.md)
and [Python packaging](python-packaging.md) give those commands and inputs.

Build and qualify the CPython artifacts (see
[Python packaging](python-packaging.md)):

```bash
npm run python:check
uvx maturin build --release -m bindings/python/Cargo.toml -o dist
uvx maturin sdist -m bindings/python/Cargo.toml -o dist
python3 scripts/qualify-python-wheel.py --conformance dist/*.whl
python3 scripts/qualify-python-wheel.py --build-sdist dist/*.tar.gz
```

Build and qualify the Node addon, the browser artifact, and the CLI for this
host (see [qualification](qualification.md)):

```bash
npm run artifacts:check
npm --prefix bindings/node ci && npm --prefix bindings/node run build
npm run js:build && npm run addon:qualify -- --target <triple>
npm run wasm:build && npm run browser:qualify
cargo build --release --locked -p redact-secret-cli
npm run cli:qualify -- --binary target/release/redact-secret
```

Release qualification builds, tests, and smoke-tests the Rust crate, npm
package, Python package, and CLI from the same commit without publishing,
across every declared target and browser engine, and records an artifact
inventory tied to the source commit. See
[Versioning, qualification, and release](../ARCHITECTURE.md#versioning-qualification-and-release)
for the design and [qualification](qualification.md) for how to run it locally.

## Repository layout

```text
conformance/             shared cross-language contract
assessment/              cross-language evaluation protocol (corpus, profiles, result contract)
crates/secret-scan-core canonical Rust implementation
crates/secret-scan-cli  CLI host adapter
bindings/node           Node N-API binding
bindings/wasm           browser WebAssembly binding
bindings/python         Python PyO3 binding and package
packages/javascript     unified JavaScript package, published as @redact-secret/core
```

## Behavior changes

Detector, redaction, overlap, or policy changes need deterministic regressions.
Prefer the shared [conformance corpus](../conformance/README.md) for behavior
that all runtimes must preserve. Explain false-positive and false-negative
tradeoffs. Keep host I/O in adapters and the Rust core side-effect free.

## Documentation

User-facing guides live under `docs/` and start at [the documentation home](README.md).
Use ordinary Markdown, descriptive headings, relative links, and synthetic
examples. Keep current behavior distinguishable from historical audits and
future work. Describe only capabilities that the shipping runtime can execute.

Existing audit and decision URLs are preserved for traceability.

## Release boundary

Review changes to the public API and [changelog](../CHANGELOG.md).
Local green tests are not cross-platform qualification or registry verification.
Releases follow the [release authority](../AGENTS.md#release-authority) and the
[release runbook](releasing.md).
