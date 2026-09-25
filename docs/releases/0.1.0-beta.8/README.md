# 0.1.0-beta.8 release evidence

Published on 2026-09-25 from `rc/0.1.0-beta.8`, using the approved and
qualified source `5639a0ea02e0eefbd1533bea23a05c749b529bef`. All ten npm
packages (including the two musl Linux Node addons), both Rust crates, and
all nine Python distribution files are published. Python spells this version
`0.1.0b8`; npm and Cargo use `0.1.0-beta.8`. The release workflows did not
change npm `latest`, which stays at `0.1.0-beta.7`; `beta` points to
`0.1.0-beta.8`.

## Qualification and approval

[CI 36122908789](https://github.com/redact-secret/redact-secret/actions/runs/36122908789),
[SAST 36122908837](https://github.com/redact-secret/redact-secret/actions/runs/36122908837),
[Python wheels 36122908760](https://github.com/redact-secret/redact-secret/actions/runs/36122908760),
[Artifact qualification 36122909150](https://github.com/redact-secret/redact-secret/actions/runs/36122909150),
and [Package Release Rehearsal 36122918861](https://github.com/redact-secret/redact-secret/actions/runs/36122918861)
passed at the frozen source revision.

Detection qualification is recorded on
[#731](https://github.com/redact-secret/redact-secret/issues/731) and in
[its evidence](../../audits/evidence/731/README.md). That measurement ran on
product `9d9ca8e` (declared version `0.1.0-beta.7`) against benchmarks
`cfaeac4`; the release source `5639a0e` differs from it only by the version
bump, the changelog and the evidence documents. It was authorized with two
items open, which the record states: the beta.7 stable baseline is 34 in the
issue and 51 in the beta.7 tag's matrix, and two of the 15 new families
(`openrouter:management-api-key`, `pinecone:legacy-api-key`) are
`unsupported`, not provisional or better.

## Publication

[Release run 36124378948](https://github.com/redact-secret/redact-secret/actions/runs/36124378948)
re-ran qualification, published both crates, all nine PyPI files, all nine
npm dependency packages and `@redact-secret/core`, passed registry installs on
all eight Node targets and Chromium, and created annotated tag `v0.1.0-beta.8`
(object `f7fe80fe`) at the frozen source revision. Reconcile Release was not
needed and was not run: nothing was partially published.

One job failed and is not a publication defect. `Record release manifest`
died with `python3: Argument list too long` because `release.yml` passes the
merged artifact digests to `release-manifest.py` as a single command-line
argument, which exceeded the Linux per-argument limit. No manifest artifact
was uploaded. It is tracked as
[#799](https://github.com/redact-secret/redact-secret/issues/799).

## Independent verification

On 2026-09-25 every registry was checked directly, without relying on the
workflow's own reports:

- **npm:** all ten packages are at `0.1.0-beta.8` with dist-tag `beta`. The
  core tarball's SHA-256
  `b3c2c2cdc15b048b79fa33c6748b01baae6d2e1f588222059676001a2ff0af33` equals
  the digest every installed-package and clean-install report in the inventory
  installed.
- **crates.io:** both crate checksums equal the inventory's `crate` digests.
- **PyPI:** all nine file hashes equal the inventory's Python entries.
- **Local installs from empty directories:**
  - `@redact-secret/core@0.1.0-beta.8` (addon)
  - `redact-secret==0.1.0b8`, wheel only
  - `cargo install redact-secret-cli --version 0.1.0-beta.8 --locked`

  Each redacted a synthetic `API_KEY=` value to `<SECRET_1>`.
  `@redact-secret/adapter-pino` 0.1.0 resolves core `0.1.0-beta.8`.

## Durable record

The CHANGELOG's generated `### Support status` section comes from the committed
[support-status fragment](support-status.md).

Because the run uploaded no manifest, this checked-in [manifest](manifest.json)
is marked `reconstructed` and its `original_manifest` states that none exists.
It combines the preserved [inventory](artifact-inventory.json), the native
digest artifacts the run did record, final registry checksums computed from the
registries, the complete run history, the clean-install results and the
annotated-tag object and target. Its `@redact-secret/core` digest is the
SHA-256 of the published tarball; the run did not preserve the wrapper digest
output. Qualified CLI binaries remain Actions artifacts. No GitHub Release
page has been created for this version.
