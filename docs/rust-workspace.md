# Rust workspace

This page records the ownership boundaries and the explicit policies of the
Rust and binding workspace introduced by
`decision-adopt-rust-core-monorepo` and `decision-define-runtime-bindings`.
The repository-root TypeScript implementation that formerly served as the
behavioral oracle has been removed (`RB-2`, issue #72); the canonical
behavioral contract is now the fixture corpus under `conformance/fixtures/`
(`decision-govern-cross-language-conformance`).

## Layout and ownership

| Path | Cargo package | Role | May depend on | Publishes as |
| --- | --- | --- | --- | --- |
| `crates/secret-scan-core` | `redact-secret` (lib `redact_secret`) | Canonical detection, overlap resolution, policy, redaction, incremental sanitization. UTF-8 byte offsets. | `std` and the allowlist in `[workspace.metadata.redact-secret]` (currently empty) | crates.io `redact-secret` |
| `crates/secret-scan-cli` | `redact-secret-cli` (bin `redact-secret`) | Host adapter for process arguments, standard streams, exit codes, and files. | core, host crates | CLI artifact of the same version |
| `bindings/node` | `redact-secret-node` (cdylib) | N-API addon; UTF-16 code unit ranges. | core, `napi`, `napi-derive`, `napi-build` | Consumed by `packages/javascript`; never on its own |
| `bindings/wasm` | `redact-secret-wasm` (cdylib) | `wasm-bindgen` browser build; UTF-16 code unit ranges. | core, `wasm-bindgen` | Consumed by `packages/javascript`; never on its own |
| `bindings/python` | `redact-secret-python` (cdylib, module `redact_secret._native`) | PyO3 extension built by maturin; Unicode code point ranges. | core, `pyo3` | PyPI `redact-secret` (imported as `redact_secret`) |
| `packages/javascript` | none | The `@redact-secret/core` npm package: one typed API whose `exports` map selects the Node addon or the wasm build, with the shared `await initialize()` contract. | Node and wasm bindings | npm `@redact-secret/core` |

Bindings and the CLI translate host APIs to the core. They never reimplement
detector behavior, and they convert ranges without changing the selected span.

`bindings/python` is the Python binding `decision-release-bindings-in-lockstep`
requires before the separately created `secret-scan-python` GitHub repository
(empty today) is archived with a redirect. The redirect text is prepared, not
yet applied, in
[`docs/python-repository-redirect.md`](./python-repository-redirect.md).

### One manifest named `@redact-secret/core`

`packages/javascript` is the only tracked manifest that declares the package
name `@redact-secret/core`; it is what `npm publish` publishes. The
repository root `package.json` is private tooling for this monorepo and
is named `redact-secret-workspace` and is not a published product. This was not
always true: until
`RB-2` (issue #72) cut the published artifact over, the repository-root
TypeScript implementation (`src/`, `test/`) was a second manifest under the
same name and the released package.

`packages/javascript` owns the public JavaScript API, the runtime loaders, and
the initialization contract. It may depend on the Node and WebAssembly
bindings, and it must not reimplement detector behavior. Build it with
`npm run js:build`, type-check it with `npm run js:typecheck`, and test it with
`npm run js:test`; `npm run ci` runs all three.

It depends on those bindings the N-API way
(`decision-ship-first-release-artifact-set`): an `optionalDependencies` entry
per publishable `bindings/node/package.json` `napi.targets`
(`@redact-secret/node-<platform>`, `os`/`cpu`/`libc`-scoped so npm skips
the ones that do not match a given install), resolved at runtime by
`process.platform`/`process.arch` — and, on Linux, detected libc — in
`src/runtime/node.ts`, plus an ordinary `dependencies` entry on
`@redact-secret/wasm`, which that same runtime module falls back to when no
addon can be loaded at all (`decision-add-node-wasm-fallback`). The
`0.1.0-beta.1` release record confirms publication of the facade, all six
then-publishable native packages, and the wasm package; the two musl N-API
addons were qualified but not published to npm at that release.
`decision-publish-musl-node-addons` extended publication to both of them in
a later release; see `docs/qualification.md` for the current matrix.

Publishing the dependency packages is not a separate one-time action gated
apart from `packages/javascript` itself (issue #141):
`.github/workflows/release.yml`'s `publish-native-dependencies` and
`publish-wasm-dependency` jobs pack, content-check, publish, and verify every
dependency package from the exact artifact `artifact-qualification` already
qualified for that commit, and the wrapper's own `publish` job declares both
in `needs:` (`scripts/check-release-gate.py` enforces the edge), so it cannot
become eligible ahead of them. `scripts/publish-dependency-package.mjs` is
idempotent by registry state rather than by a cutover-vs-routine switch: when
a package for the requested version is absent it publishes the qualified
artifact; when the same version is already published it verifies matching
registry content and skips republishing it (npm versions are immutable). One
dispatch of `Release`, gated on the release approval `AGENTS.md` mandates,
handles both initial publication and routine releases -- there is no separate
"publish only the wrapper" path.

## Policies

### Format

`rustfmt.toml` uses only stable options so `cargo fmt --all --check` gives
the same answer on the MSRV and on current stable. CI fails on any diff.

### Lint

`[workspace.lints]` in the root `Cargo.toml` is inherited by every member
through `[lints] workspace = true`. Clippy pedantic is a warning, and
`unwrap_used`, `expect_used`, `panic`, `dbg_macro`, `todo`, `unimplemented`,
and `undocumented_unsafe_blocks` are errors. `clippy.toml` relaxes `unwrap`
and `expect` in tests. CI runs `cargo clippy --workspace --all-targets` with
`-D warnings` and builds with `RUSTFLAGS=-D warnings`, so `missing_docs` and
other warning-level lints also fail the build there.

### Test

`cargo test --workspace --locked` runs on Linux, macOS, and Windows. Tests
must be deterministic and must not embed real credentials; the same fixture
rules as the TypeScript suite apply. Cross-language behavior is exercised by
the canonical conformance corpus, not by per-binding copies.

### Dependency

Two layers apply:

- `deny.toml` (`cargo deny check`) allows only crates.io as a source,
  restricts licenses to the listed permissive set, denies yanked crates and
  known advisories, and denies wildcard requirements.
- `[workspace.metadata.redact-secret]` in the root `Cargo.toml` declares the
  core boundary. `npm run rust:check` walks the core's transitive normal and
  build dependency graph from `cargo metadata` and fails when a package is
  missing from `allowed-dependencies` or present in
  `forbidden-dependencies`. The forbidden list names crates that provide
  runtime network, filesystem, environment, telemetry, secret-storage, or UI
  behavior and cannot be allowlisted. Dev-dependencies are outside the
  boundary because they never ship.

To add a core dependency, add it and each of its transitive dependencies to
`allowed-dependencies` in the same change, and state in the pull request why
the dependency keeps the core deterministic and side-effect free.

### Public API

The core crate is the published library, so its surface is pinned in three
places that must agree:

- `crates/secret-scan-core/src/lib.rs` declares it. Every module below the
  crate root is private; the crate root re-exports the names that are public,
  and its documentation opens with a "Public surface" table that names them
  all.
- `[workspace.metadata.redact-secret] core-public-api` in the root `Cargo.toml`
  lists those names. `npm run rust:check` fails when the crate root exports a
  name the list does not carry, when the list names an export that is gone,
  and when the documented table and the list disagree in either direction —
  so a change to the published surface is always a reviewed manifest change,
  and the documentation cannot quietly fall behind it.
- `crates/secret-scan-core/tests/public_api.rs` uses every one of them
  through a `redact_secret::` path, the way a dependent crate does, and pins
  the range contract, the `scan_and_redact` ≡ `scan` + `redact` equivalence
  over the canonical corpus, and the sanitized-error shape.

Two things are deliberately outside the surface and must stay there:

- **The built-in detector registry.** `detectors` is a private module.
  Callers reach the built-in set only through
  `DetectorRegistry::with_built_in`, so which detectors exist and how they
  are constructed can change without breaking a dependent. What is public is
  the observable consequence of their order: it is the fourth overlap tie
  breaker, fixed by the conformance corpus.
- **Retention tuning.** The lookaround reserve the incremental session needs
  is a private constant that tracks the built-in detector set. Callers derive
  the requirement with `IncrementalLimits::minimum_buffered_bytes` instead of
  reproducing the arithmetic.

Ranges in every public value are UTF-8 byte offsets into the *original*
input, including the findings returned alongside redacted text by
`scan_and_redact` and by an incremental session — redaction changes lengths,
so a range read against the sanitized text would select the wrong span.

### No runtime I/O

Two checks in `npm run rust:check` back the claim that the core is
side-effect free, on top of the dependency boundary above:

- **Source boundary.** No file under `crates/secret-scan-core/src` may name
  `std::fs`, `std::net`, `std::env`, `std::process`, `std::io`,
  `std::thread`, `std::time`, `std::os`, `option_env!`, `include_str!`,
  `include_bytes!`, `println!`, or `eprintln!`, or reach for a crate listed
  in `binding-dependencies`. The `env!` macro is allowed: the compiler
  resolves it, and it reads nothing at runtime.
- **Manifest shape.** The core declares no Cargo features, no optional
  dependency, no target-specific dependency, and nothing from
  `binding-dependencies`. There is one shape of this crate, and it is the one
  the test suite exercises. `binding-dependencies` is separate from
  `forbidden-dependencies` because the bindings depend on those crates
  legitimately; only the core may not.

  `bindings/wasm` is a binding, not the core, so this constraint does not
  reach it: it declares one default-on Cargo feature, `full`. The default
  build (`npm run wasm:build`) links the `full` registry constructors;
  `npm run wasm:build:common` builds `--no-default-features`, linking only
  the `common` ones instead. Each built artifact reports which one it linked
  through a `profile()` export. See
  [detector profiles](../ARCHITECTURE.md#detector-profiles).

### Package contents

`crates/secret-scan-core/Cargo.toml` declares `include`, so the published
package is the library, its README, and the manifest metadata cargo
generates — nothing else. `npm run rust:check` runs `cargo package --list`
for the core and fails when a file matches no `core-package-globs` entry or
when a `core-package-required` file is missing.

The integration tests stay out of the package on purpose: they `include_str!`
the canonical fixtures under `conformance/fixtures/`, which live above the
package root and cannot travel with it. `cargo package` therefore verifies
the published crate by building the library alone, and reports the excluded
test targets as warnings.

### Unsafe code

`[workspace.lints.rust] unsafe_code = "deny"` applies to every member, and
`crates/secret-scan-core/src/lib.rs` and `crates/secret-scan-cli/src/main.rs`
carry `#![forbid(unsafe_code)]`; `npm run rust:check` fails if either is
removed. A binding may add an item-scoped `#[allow(unsafe_code)]` only at a
real FFI boundary, with a `// SAFETY:` comment that
`clippy::undocumented_unsafe_blocks` requires, and the review must record why
the binding macros were insufficient.

### Generated invisible-code-point table

`crates/secret-scan-core/src/invisible_table.rs` is generated data, not a
dependency: the removed set of
`decision-normalize-invisible-characters-before-detection`
(`Default_Ignorable_Code_Point ∪ Cf`) derived from a pinned UCD version, so
`allowed-dependencies` stays empty. `scripts/generate-invisible-table.py`
derives it in two offline steps. `--refresh-ucd DIR` verifies the full
`DerivedCoreProperties.txt` and `UnicodeData.txt` against the SHA-256 values
pinned in the script and writes verbatim line extracts to
`crates/secret-scan-core/ucd/`; with no flag the script regenerates the table
from those extracts. `npm run rust:check` runs it with `--check` and fails on
a stale or hand-edited table, and `crates/secret-scan-core/tests/invisible_table.rs`
re-derives the set from the same extracts with its own parser, so
`cargo test` asserts it too. A UCD bump changes the pinned version and hashes,
the extracts, the table, and the ADR together, each as a reviewable diff. The
extracts sit outside `include`, so they never enter the published package.

### Version lockstep

Every workspace member's Cargo version and every JSON manifest carrying the
product version share `[workspace.package] version` in the root `Cargo.toml`.
`scripts/check-rust-workspace.py` enforces:

- `LOCKSTEP_MANIFESTS`: the private root `package.json`,
  `bindings/node/package.json`, and `packages/javascript/package.json`;
- `bindings/wasm/npm/package.json` and every native platform manifest discovered
  under `bindings/node/npm/*/package.json`; and
- every Cargo workspace member, including the three private binding crates.

The root remains private tooling, but its version-bearing manifest is checked
as of #144; private status does not exempt a declared product version.
`bindings/python/pyproject.toml` uses a dynamic version inherited through its
Cargo manifest (SemVer prereleases become the corresponding PEP 440 spelling
in Python distribution metadata). Lockfiles record these same package versions
and must be refreshed when an approved version changes. Policy tests reject
version drift, including drift in the private root and native/Wasm packages.

`npm run rust:check` runs the enforcement. First and subsequent publications
use the same approved release graph, including all seven npm dependencies
before the wrapper; there is no separate first-cutover dispatch. A manifest
value alone neither selects nor authorizes a release.

### MSRV

The supported minimum Rust version is the highest `rust-version` required by
the binding dependencies selected in the root `Cargo.toml`:

| Dependency | Version | `rust-version` |
| --- | --- | --- |
| `napi` (with `napi-sys`, `libloading`) | 3.12.2 | 1.88 |
| `napi-derive`, `napi-build` | 3.6.3, 2.4.1 | 1.88 |
| `pyo3` | 0.29.2 | 1.83 |
| `wasm-bindgen` | 0.2.128 | 1.77 |

Derived and pinned MSRV: **1.88** (Rust 2024 edition), recorded on
2026-09-09. It is pinned once in `[workspace.package] rust-version` and
inherited by every member, mirrored by the `MSRV` value in
`.github/workflows/ci.yml`, and exercised by the `Rust MSRV` job with
`cargo check --workspace --all-targets --locked` on that toolchain.
`npm run rust:check` fails when a member drifts, when the workflow value
differs, or when any resolved dependency requires a newer compiler than the
pin.

To raise the MSRV, update `rust-version`, the workflow `MSRV` value, and this
table together, and note the change in the changelog.

## Registry names

The product name is `Redact Secret` for every artifact
(`decision-adopt-redact-secret-naming-contract`). Registry names may differ
from the product name in principle (`decision-release-bindings-in-lockstep`),
but this identity clears every registry directly, so no fallback name is
needed anywhere.

- crates.io: `redact-secret` and `redact-secret-cli` were rechecked on
  2026-09-10 and are both available; so is `redact_secret`, which crates.io
  treats as the same name as `redact-secret`. Recheck before publication with
  `python3 scripts/check-rust-workspace.py --recheck-crate-name`.
- npm: `@redact-secret/core` is the package name; the `@redact-secret`
  organization is owned by the project operator (`decision-adopt-redact-secret-naming-contract`).
- PyPI: `redact-secret` was rechecked on 2026-09-10 and is available; unlike
  the previous identity, it does not collide with an unrelated project, so no
  registry fallback is needed. Per PEP 503, `redact-secret` and the import
  name `redact_secret` normalize to the same PyPI project identity. The
  distribution name is declared in
  `[workspace.metadata.redact-secret] python-distribution` and enforced by
  `npm run python:check`. Recheck before publication with
  `python3 scripts/check-python-package.py --recheck-pypi-name`; see
  [docs/python-packaging.md](./python-packaging.md).

## Verification

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo package -p redact-secret --locked
cargo run --quiet --locked -p redact-secret-cli -- --version
cargo check -p redact-secret -p redact-secret-wasm --target wasm32-unknown-unknown --locked
cargo +1.88 check --workspace --all-targets --locked
cargo deny check
npm run rust:check
```

Toolchain setup: `rustup toolchain install 1.88 --profile minimal`,
`rustup target add wasm32-unknown-unknown`, and `cargo install cargo-deny`.
The CI jobs `rust-policy`, `rust-native`, `rust-msrv`, and `rust-wasm` run
the same commands. `cargo test --workspace` includes the doctests on the core
crate's public API; `cargo doc` fails on a broken intra-doc link because the
crate root denies `rustdoc::broken_intra_doc_links` and
`rustdoc::private_intra_doc_links`, and `missing_docs` is denied there too.

To recheck the registry names before a publication:

```bash
python3 scripts/check-rust-workspace.py --recheck-crate-name
python3 scripts/check-python-package.py --recheck-pypi-name
```

## Python packaging

The CPython distribution's identity, its abi3 contract, its wheel matrix, and
how each artifact is qualified are declared in the same
`[workspace.metadata.redact-secret]` table and documented separately in
[docs/python-packaging.md](./python-packaging.md). `npm run python:check`
enforces that contract and runs in `npm run ci`;
`.github/workflows/python-wheels.yml` builds and qualifies the artifacts.

## Cross-platform qualification

The same table also declares the rest of the supported surface —
`node-addon-targets`, `cli-release-targets` (a strict subset: the CLI ships
no musl variant), `browser-engines`, and `node-support-majors` — documented
separately in
[docs/qualification.md](./qualification.md). `npm run artifacts:check` enforces
that every manifest, qualifier script, and workflow matrix agrees with those
lists, and that every workflow job takes least-privilege permissions and pins
every third-party action; it runs in `npm run ci`.
`.github/workflows/artifact-qualification.yml` builds and qualifies every artifact from
one commit and records an inventory tied to it.
