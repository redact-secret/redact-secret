# Developer onboarding and local validation

[Documentation home](README.md) · [Contribution guide](../CONTRIBUTION.md)

Read [architecture](../ARCHITECTURE.md), [conventions](../CONVENTIONS.md),
[decisions](decisions/DECISIONS.md), and [workspace policy](rust-workspace.md)
before changing behavior. Use unmistakably synthetic or revoked examples only.
Findings, errors, snapshots, and diagnostics must not copy matched values.

## Run the repository checks

From the root, with a supported Node version and Rust 1.88 or newer, run
`npm ci` once. While iterating, run only the scope your change touches.
`npm run check:changed` reads your branch's changes against `origin/main` and
prints the scoped commands to run (`-- --run` runs them); a path no scope
covers makes it print `npm run ci` instead.

| Change | Read first | Run |
| --- | --- | --- |
| Documentation or Markdown only | [conventions](../CONVENTIONS.md) | `npm run check:docs` |
| ADR or spec file (`docs/decisions/`, `docs/specs/`) | [decision router](decisions/DECISIONS.md), the spec file it changes | `npm run check:docs` |
| Detector, PII context, or policy in the core | [architecture](../ARCHITECTURE.md), [detector families](specs/detector-families.md), [contextual detection](specs/contextual-detection.md) | `npm run check:rust && npm run check:detector` |
| Conformance fixture | [conformance corpus](../conformance/README.md) | `npm run check:detector && npm run check:js && npm run check:rust` |
| Other Rust: engine, CLI, bindings | [engine](specs/engine.md), [workspace policy](rust-workspace.md) | `npm run check:rust` (plus `check:js` for the Node or wasm binding) |
| JavaScript wrapper or examples | [architecture](../ARCHITECTURE.md) | `npm run check:js` |
| Release, CI workflow, packaging, or `scripts/` | [release runbook](releasing.md), [distribution](specs/distribution.md), [evidence and gates](specs/evidence-and-gates.md) | `npm run check:release` |

Each `check:<scope>` script in `package.json` chains existing gates from
`npm run ci`; `check:rust` also runs `cargo fmt`, `cargo clippy` and
`cargo test`, and `check:js` needs `npm run examples:install` once. Every
gate in `npm run ci` belongs to at least one scope, and
`npm run check-scopes:test` fails if one does not. Scopes are a local
convenience: CI runs the full suite below on every pull request, so you are
not expected to reproduce the platform matrix, the wheel build, or the
artifact qualifiers locally to open one.

### Measure statement coverage

CI fails any layer under 80% statement coverage (OpenSSF Silver
`test_statement_coverage80`). Run the same commands locally:

```bash
# Rust lines: the `rust-coverage` job (needs cargo-llvm-cov)
eval "$(cargo llvm-cov show-env --sh)"
cargo build --workspace --locked --examples   # integration tests run these
cargo test --workspace --locked
cargo llvm-cov report --summary-only --fail-under-lines 80

# JavaScript wrapper: packages/javascript/src, from the js:test suite
npm run js:coverage

# Python wrapper: the pure-Python redact_secret package, against a local build
python -m venv .venv && . .venv/bin/activate
python -m pip install --require-hashes --only-binary :all: -r .github/requirements/python-coverage.txt
maturin develop --locked --manifest-path bindings/python/Cargo.toml
python -m pytest bindings/python/tests --cov=redact_secret --cov-report=term-missing --cov-fail-under=80
```

The JavaScript tests import `src/*.ts` directly, so coverage is already
source-level; only `.d.ts` files are excluded. The Python number covers the
wrapper module, not the Rust extension, which `rust-coverage` measures.

### Formatting and lint

CI's `lint` job enforces the coding standard for the languages `cargo fmt` and
`cargo clippy` do not cover. Run the same checks before you push:

```bash
npm ci --ignore-scripts
npm run lint      # Biome: packages/javascript, scripts/**/*.mjs, examples/
npm run format    # apply Biome's fixes and formatting

python -m pip install --require-hashes -r .github/requirements/python-lint.txt
ruff check bindings/python scripts
ruff format --check bindings/python scripts   # drop --check to apply
```

Biome's rules are in `biome.json` and Ruff's in `ruff.toml`; Ruff's version is
pinned by hash in `.github/requirements/python-lint.txt` and Biome's exactly in
`package.json`.

### Full suite

The complete local sequence, and what CI enforces before merge:

```bash
npm ci
npm run examples:install
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
