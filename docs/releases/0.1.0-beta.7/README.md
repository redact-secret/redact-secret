# 0.1.0-beta.7 release evidence

Published on 2026-09-24 from `rc/0.1.0-beta.7`, using the approved and
qualified source `2b98027bbf38d63f07b75129fe2864ef32ed4732`. All ten npm
packages (including the two musl Linux Node addons), both Rust crates, and
all nine Python distribution files are published. Python spells this version
`0.1.0b7`; npm and Cargo use `0.1.0-beta.7`.

## Qualification and approval

[CI 35985834032](https://github.com/redact-secret/redact-secret/actions/runs/35985834032),
[SAST 35985834076](https://github.com/redact-secret/redact-secret/actions/runs/35985834076),
[Python wheels 35985834058](https://github.com/redact-secret/redact-secret/actions/runs/35985834058),
[Artifact qualification 35985834573](https://github.com/redact-secret/redact-secret/actions/runs/35985834573),
and [Package Release Rehearsal 35987819361](https://github.com/redact-secret/redact-secret/actions/runs/35987819361)
passed at the frozen source revision.

Detection qualification is recorded on
[#584](https://github.com/redact-secret/redact-secret/issues/584) and in
[its evidence](../../audits/evidence/584/README.md). The benchmark evaluation
was re-run on the addon and wasm files that CI built for this revision, and it
matched the recorded candidate fixture for fixture, 1,466 of 1,466. Publication
was then explicitly approved for this source revision.

## Original partial publication

[Release run 35989289538](https://github.com/redact-secret/redact-secret/actions/runs/35989289538)
re-ran qualification and produced the preserved
[artifact inventory](artifact-inventory.json). It published both crates, all
nine PyPI files, all nine npm dependency packages, and `@redact-secret/core`.
Two things in that run's record are wrong, and neither is a publication
defect.

- **The facade check compared against the wrong tarball.** *Compute the
  wrapper package identity* ran `npm pack --dry-run` before *Qualify release*
  built `packages/javascript/dist/`. The recorded shasum `f82efd6b…` therefore
  belongs to a 3-entry tarball with no `dist/`. npm published the built
  53-entry package, shasum `97fb760d…`, SHA-256
  `8b6e759b98201ebfed797a5389eca57a3aa52fef1bc96783d522c60418662520`. That
  SHA-256 is the core artifact every installed-package and clean-install
  report in the inventory installed. *Verify npm publication* failed on the
  mismatch, which skipped registry install verification and the tag. The
  cause is fixed for later releases by
  [#732](https://github.com/redact-secret/redact-secret/issues/732).
- **`node-linux-x64-gnu` was reported as `unpublished`.** npm accepted that
  publish (shasum `e1436a82…`), but the version endpoint was still
  propagating. The issue #614 path accepted it, and the leg's registry-state
  report ran during the lag.

The run's manifest is preserved verbatim as
[original-manifest.json](original-manifest.json). It records both states and
the wrapper digest error.

## Authorized recovery

- [Dry run 35991840838](https://github.com/redact-secret/redact-secret/actions/runs/35991840838)
  stopped at the guard before it planned anything. It was dispatched with
  `source_run` but without `source_commit`, and a `source_run` skips the
  manifest download. It published nothing.
- [Dry run 35992781937](https://github.com/redact-secret/redact-secret/actions/runs/35992781937)
  (`source_run` 35989289538, `source_commit` `2b98027`) confirmed the source
  is an ancestor of `rc/0.1.0-beta.7`. It content-matched all nine npm
  dependency packages, both crates, all nine PyPI files, and the rebuilt
  facade, and planned no publication.
- [Recovery run 35993751064](https://github.com/redact-secret/redact-secret/actions/runs/35993751064)
  republished nothing. It passed registry installs on all eight Node targets
  and Chromium, and created annotated tag `v0.1.0-beta.7` (object `696e19c`)
  at the frozen source revision.

## Independent verification

On 2026-09-24 the operator's agent checked every registry directly, without
relying on the workflows' own reports:

- **npm:** all ten packages are at `0.1.0-beta.7` with dist-tag `beta`. The
  `.node` and `.wasm` payload in each tarball is byte-identical to this
  inventory. The core tarball's SHA-256 equals the inventory's
  installed-package digest.
- **crates.io:** both crate checksums equal the inventory's `crate` digests.
- **PyPI:** all nine file hashes equal the inventory's Python entries.
- **Local installs from empty directories:**
  - `@redact-secret/core@0.1.0-beta.7`
  - `redact-secret==0.1.0b7`, wheel only
  - `cargo install redact-secret-cli --version 0.1.0-beta.7 --locked`

  Each redacted a synthetic `API_KEY=` value to `<SECRET_1>`.
  `@redact-secret/adapter-pino` 0.1.0 resolves core `0.1.0-beta.7`.

The release workflows did not change npm `latest`. On 2026-09-24 it was moved
outside them, from beta.1 (beta.5 for the musl addons) to beta.6 on all ten
packages; see [release status](../status.md).

## Durable record

Reconcile Release intentionally emits no replacement manifest. This
checked-in [manifest](manifest.json) is therefore marked `reconstructed`. It
combines:

- the preserved inventory;
- a summary of the original manifest, plus the verbatim file;
- final registry checksums;
- the complete run history;
- clean-install results;
- the annotated-tag object and target.

Its `artifact_digests` entry for `@redact-secret/core` is corrected to the
published and qualified `97fb760d…`, and it carries a note explaining the
original `f82efd6b…`. Qualified CLI binaries remain Actions artifacts. The
[GitHub Release page](https://github.com/redact-secret/redact-secret/releases/tag/v0.1.0-beta.7)
was created separately on 2026-09-24, as a prerelease on the existing tag.
