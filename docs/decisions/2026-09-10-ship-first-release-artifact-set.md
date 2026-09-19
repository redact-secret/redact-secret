---
decision_id: decision-ship-first-release-artifact-set
status: accepted
scope: workspace
title: Ship the first release's full artifact set
decided_at: 2026-09-10
---

# Ship the first release's full artifact set

## Current application — 2026-09-19 (#443)

The npm-ships-glibc-only clause below and in the 2026-09-12 update is
superseded by
[Publish the musl Node addon packages](2026-09-19-publish-musl-node-addon-packages.md):
`node-publish-targets` now includes the two musl triples, published
alongside the six already covered here. Nothing else in this record changes;
the CLI's own musl exclusion (`cli-release-targets`) is untouched.

## Current application — 2026-09-12 (#181, #182)

The full four-surface commitment remains accepted. The
[naming contract](2026-09-10-adopt-redact-secret-naming-contract.md) and completed
release-path corrections replace the old identities and implementation states
in the historical body below with this current candidate mapping:

| Surface | Current artifact | Publication path in `release.yml` |
| --- | --- | --- |
| Rust | crates.io `redact-secret` | `publish-crates`, core before CLI |
| CLI | crates.io `redact-secret-cli`; binary `redact-secret` | `publish-crates`; six qualified non-musl binary targets |
| Python | PyPI `redact-secret`, import `redact_secret` | `publish-pypi`, qualified abi3 wheels and source distribution |
| JavaScript | npm `@redact-secret/core` from `packages/javascript` | `publish`, after runtime dependencies |
| JavaScript runtime dependencies | Six `@redact-secret/node-<platform>` packages and `@redact-secret/wasm` | `publish-native-dependencies` and `publish-wasm-dependency`, in the same release graph |

The root npm package is private tooling. Binding Cargo crates remain private;
their generated npm/PyPI artifacts are part of the public product. First and
subsequent dependency publications use the same idempotent graph, replacing
the earlier separate-cutover deferral. All version-bearing manifests,
including the private root, are enforced in lockstep.

Node support is 20/22/24; npm and CLI target Linux glibc, macOS, and Windows
on x64/arm64. Two additional musl addons are qualified but not shipped on npm.
Python ships eight CPython 3.10+ abi3 wheel targets including musllinux;
browsers are qualified on Chromium, Firefox, and WebKit. Rust, Python, CLI
stdin, and both JavaScript artifacts (Node and browser WebAssembly) support
incremental sanitization. The [qualification declaration](../qualification.md)
owns the exact target lists. This update records the implemented contract;
the original decision-time body follows unchanged. It authorizes no release.


## Decision

Branch A of `RB-9` (issue #79): the first release ships the full four-artifact
product `ARCHITECTURE.md` and `decision-release-bindings-in-lockstep` already
promise — the `secret-scan` crate on crates.io, the `secret-scan` CLI binary,
the `omiologic-secret-scan` PyPI distribution, and the `@omiologic/secret-scan`
npm package — rather than narrowing that promise for this release.

Concretely, from this decision:

- `crates/secret-scan-core/Cargo.toml` and `crates/secret-scan-cli/Cargo.toml`
  each override the workspace's `publish = false` with `publish = true`. The
  binding crates (`bindings/node`, `bindings/wasm`, `bindings/python`) keep
  `publish = false`; they are never published on their own
  (`docs/rust-workspace.md`).
- `.github/workflows/release.yml` gains `publish-crates` (`cargo publish` for
  both crates, core before CLI since the CLI's manifest depends on the core's
  registry release) and `publish-pypi` (trusted publishing via
  `pypa/gh-action-pypi-publish`, consuming the exact wheels
  `python-wheels.yml` already qualified for this commit through a
  `workflow_call`). Both run under the same `release` environment gate and
  `main`-only restriction as the existing npm job.
- `packages/javascript/package.json` declares its platform artifacts the
  N-API way: one `optionalDependencies` entry per
  `bindings/node/package.json`'s six `napi.targets`
  (`@omiologic/secret-scan-<platform>`, each a real, minimal, publishable
  package under `bindings/node/npm/<platform>/`, `os`/`cpu`/`libc`-scoped so
  npm's installer skips every non-matching one), and an ordinary `dependencies`
  entry on `@omiologic/secret-scan-wasm`
  (`bindings/wasm/npm/package.json`). `runtime/node.ts`'s `loadAddon` resolves
  the exact package for `process.platform`/`process.arch` and falls back to
  the existing fixed `INITIALIZATION_FAILED` when none matches or the
  optional dependency did not install — the "runtime fallback" the
  disposition's acceptance text names.
- `scripts/qualify-package-consumer.mjs`, run by a new `package-consumer` job
  in `artifact-qualification.yml`, packs `packages/javascript` and its native
  and WebAssembly dependencies into tarballs, installs the packed
  `@omiologic/secret-scan` tarball into a clean directory outside the
  repository (via `overrides` pointing the unpublished platform/wasm
  dependencies at local tarballs — the standard substitute for a real
  registry in this exact scenario, not a stand-in for the install mechanism
  itself), and awaits `initialize()` on both the Node runtime and a real
  headless-browser runtime. This is "Under either branch" criterion 1,
  verified locally end to end with a real compiled addon and a real
  `wasm-bindgen` build before this decision was recorded.

## Per-artifact publication-path table

| Artifact | Publication path | State after this decision |
| --- | --- | --- |
| `secret-scan` crate (crates.io) | `publish-crates` job in `release.yml`, gated by the `release` environment and `main` | Unblocked (`publish = true`); crate names `secret-scan`/`secret-scan-cli` were rechecked available 2026-09-09 (`docs/rust-workspace.md`) |
| `secret-scan` CLI binary | `cargo install secret-scan-cli` once `publish-crates` publishes it; the six-target build/smoke-test job (`cli-release-targets`, `artifact-qualification.yml`) already exists (RB-4, issue #74) | Unblocked; no new build job was needed |
| `omiologic-secret-scan` (PyPI) | New `publish-pypi` job in `release.yml`, consuming `python-wheels.yml`'s qualified wheels via `workflow_call`, publishing with PyPI trusted publishing | New CI step added by this decision; the PyPI project's trusted-publisher configuration for this repository/workflow/environment is external setup this decision does not perform |
| `@omiologic/secret-scan` (npm) | Unchanged: the existing `publish-npm` job in `release.yml`. The package it publishes is still the repository-root `package.json` (the TypeScript oracle), not `packages/javascript` — that cutover is `RB-2` (issue #72), which this decision unblocks by giving `packages/javascript` real `optionalDependencies`/`dependencies` declarations, but does not perform | Declaration ready; publication remains `RB-2`'s to execute |
| `@omiologic/secret-scan-<platform>` (×6) and `@omiologic/secret-scan-wasm` — `packages/javascript`'s own dependencies, not independently promised artifacts | Manifests exist under `bindings/node/npm/<platform>/` and `bindings/wasm/npm/`; `npm publish` for each is part of `RB-2`'s cutover (the wrapper package they support is not published before then either) | Recorded deferral to `RB-2`, not a gap: nothing depends on these being live before `packages/javascript` itself is |

No artifact `ARCHITECTURE.md`'s four-artifact table promises is left without
either a publication path or a recorded deferral to a named follow-up issue.

## Rationale

`decision-release-bindings-in-lockstep` already treats the crate, npm package,
Python package, and CLI as "one product" and states that "user-visible binding
behavior is part of the supported product contract" — a decision Branch B
would have had to reopen, not merely defer around. `RB-5` (issue #75) already
brought every version-bearing manifest into lockstep across all four artifacts
in anticipation of shipping them together, and `RB-4` (issue #74) already
built and qualifies the CLI's six-target matrix and the Node/browser
artifacts. Narrowing the promise now would discard work already committed on
the assumption of Branch A and would require reopening an accepted ADR to do
it.

## Alternatives considered

- **Branch B (narrow the promise).** Amend `ARCHITECTURE.md`, `README.md`, and
  `decision-release-bindings-in-lockstep` to ship npm only for the first
  release, deferring crates.io, PyPI, and CLI distribution. Rejected: it
  reopens an accepted ADR's "one product" framing for reasons that are about
  release-engineering sequencing, not about the product; the qualification
  work RB-4 already built for the CLI and Python wheels would sit unused
  behind a documented deferral instead of a two-job addition to `release.yml`.

## Consequences

- `CARGO_REGISTRY_TOKEN` (crates.io) and a PyPI trusted publisher configured
  for this repository's `Release` workflow and `release` environment are both
  required before `publish-crates`/`publish-pypi` can succeed for real; this
  decision adds the CI steps but does not provision either credential.
- `reconcile-release.yml` and `scripts/reconcile-guard.py` reconcile only the
  npm tag today. A partial crates.io or PyPI publication inside one dispatch
  of the now five-registry `release.yml` is not repairable by the existing
  reconcile mechanism; `record-manifest`'s per-registry `registry_state` makes
  such a partial publication visible, but closing the repair gap itself is
  not this decision's scope (`RB-7`/`RB-8`, issues #77/#78, are the natural
  place for it).
- `RB-2` (issue #72) still owns the actual npm cutover — publishing
  `packages/javascript`, its six platform packages, and its wasm package for
  the first time, and removing the root `package.json` from
  `LOCKSTEP_MANIFESTS` per `docs/rust-workspace.md`.
- This decision does not select a version or authorize any release, branch,
  tag, archive, publication, or deployment. Existing release authority
  (`AGENTS.md`, "Release authority") remains in force, and
  `decision-release-bindings-in-lockstep`'s own consequences continue to
  apply unchanged.
