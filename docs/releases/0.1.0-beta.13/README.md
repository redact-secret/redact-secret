# 0.1.0-beta.13 release evidence

Published on 2026-10-03 from the qualified source
`66b492bdff5e6751fc6b5409266916346ed7c723` (`main`, documentation-only on top of
the frozen product candidate `401158d09a677b110fa60209256ba184b1f08f8f`). All
ten npm packages (including the two musl Linux Node addons), both Rust crates,
and all nine Python distribution files are published. Python spells this
version `0.1.0b13`; npm and Cargo use `0.1.0-beta.13`. The maintainer approved
the Release run, its `release` environment deployments and, only if needed, a
Reconcile Release; the deployments of the Release run were approved through the
GitHub API under that approval. No Reconcile Release was dispatched for this
version, and `latest` was not touched.

## Identity

- **Source revision:** `66b492bdff5e6751fc6b5409266916346ed7c723`. `git diff --stat
  401158d0..66b492bd` touches only four files under `docs/`, so the product
  source is that of the frozen candidate `401158d0`.
- **Conformance corpus identity:** tree `9b84d5f39fa5d172b83d8841a56fa74afe7edaa9`
  (`git rev-parse 66b492bd:conformance`), equal to the manifest's
  `conformance_identity` and unchanged since `0027da0b`.
- **Artifact inventory:** [artifact-inventory.json](artifact-inventory.json), the
  Release run's own `artifact-inventory` artifact, unchanged (SHA-256
  `36f67954c9474404ddb11ed5f3ca4d8c66cf86b7725bba46bac4cde5fc8056fc`, recorded as the manifest's
  `artifact_inventory_sha256`).
- **Annotated tag:** `v0.1.0-beta.13`, object
  `cd447c06ffb8ac27f3176f8560fe7af5f8e245b8`, peeled to `66b492bd`.

## Qualification and approval

At the release source `66b492bd`: [SAST 37099946921](https://github.com/redact-secret/redact-secret/actions/runs/37099946921),
[Artifact qualification 37099947242](https://github.com/redact-secret/redact-secret/actions/runs/37099947242) (push) and Scorecard
[37099946920](https://github.com/redact-secret/redact-secret/actions/runs/37099946920) passed. At the frozen candidate `401158d0` (same product
source): [Artifact qualification 37093118224](https://github.com/redact-secret/redact-secret/actions/runs/37093118224),
[SAST 37093118072](https://github.com/redact-secret/redact-secret/actions/runs/37093118072). [Package Release Rehearsal 37087510742](https://github.com/redact-secret/redact-secret/actions/runs/37087510742)
passed at `0027da0b`, which has the same product source and workflows; it was not
re-dispatched. Registry preflight, `benchmark-pins:check:ancestry` (0 errors, 2
expected warnings) and `scripts/verify-release-governance.py` passed on
2026-10-03 before dispatch. The readiness conditions and the disposition of every
blocking candidate are in the [#1071 record](../../audits/evidence/1071/README.md)
and the [readiness checklist](../release-readiness-v0.1.0.md).

### Performance evaluation

Confirming run [37099250035](https://github.com/redact-secret/redact-secret-benchmarks/actions/runs/37099250035) in `redact-secret-benchmarks`
(benchmarks `develop` at `8aeefd85`, candidate `401158d0`): acceptance accepted;
the regression budget accepted, with the browser-wasm initialization ratio
(1.2696) and the size rows carried as accepted tradeoffs. Details and the
earlier runs are in the #1071 record.

### Support status of the release

The checked-in `benchmarks/support-matrix.json` is pinned to benchmarks
`573e1288` (candidate `fe6e923`, trufflehog 3.97.4): 173 families, 144 stable.
It measures a candidate build, not the published artifacts, so the
[support-status fragment](support-status.md) states no stable delta against beta.12.

## Publication

[Release run 37100486438](https://github.com/redact-secret/redact-secret/actions/runs/37100486438), the only Release dispatch for this version,
was dispatched on 2026-10-03 from `main` at `66b492bd`. It re-ran qualification,
published both crates, all nine PyPI files and all ten npm packages (including
the facade), passed registry-install verification on all eight Node targets and
Chromium, created annotated tag `v0.1.0-beta.13` at the frozen source revision and
uploaded `release-manifest-0.1.0-beta.13`. Every job succeeded and the run reads
**success**.

Release readiness row 4 (a clean Release run: one run reaching `tag-release`,
zero `reconcile-release.yml` dispatches against this version) was met. The two
Reconcile dispatches on record near this release (37093975420, 37095965449)
were the row-5 exercises against `0.1.0-beta.12`.

Release readiness row 3 (no registry-state false negative) was **not** met on
this run: the run's registry-state snapshots for `@redact-secret/node-darwin-x64`
and `@redact-secret/node-win32-x64-msvc` read `unpublished`, and the published
digest was empty for those two packages and for three PyPI files (the
`win_arm64` and `win_amd64` wheels and the sdist). The same run's publish jobs
for these packages succeeded, and the live registries carry every one of them
(below). It is the propagation-lag false negative seen on beta.11, now in the
snapshot rather than a failed job. It did not block the tag and needed no
recovery.

## Clean-install verification

The Release run's registry-backed `Verify registry install` jobs each installed
`0.1.0-beta.13` from the public registry into a clean directory and passed:

| Lane | Result |
| --- | --- |
| `aarch64-apple-darwin` | passed |
| `x86_64-apple-darwin` | passed |
| `aarch64-unknown-linux-gnu` | passed |
| `x86_64-unknown-linux-gnu` | passed |
| `aarch64-unknown-linux-musl` | passed |
| `x86_64-unknown-linux-musl` | passed |
| `aarch64-pc-windows-msvc` | passed |
| `x86_64-pc-windows-msvc` | passed |
| Browser (Chromium) | passed |

## Registry checksums

Fetched live on 2026-10-03 from the npm registry, the crates.io API and the PyPI
JSON API.

| npm package `@0.1.0-beta.13` | shasum |
| --- | --- |
| `@redact-secret/core` | `1a3e312c8b6740582345b2561ed134bfe7ad8ddd` |
| `@redact-secret/node-darwin-arm64` | `9aabbbeac338f3af27ee356746b32e97e7b8287b` |
| `@redact-secret/node-darwin-x64` | `6abcb47d03faac144597a8a9fc22ca012ff24f97` |
| `@redact-secret/node-linux-arm64-gnu` | `9323a05fcb9bdf67757cd79a44e675876d735954` |
| `@redact-secret/node-linux-arm64-musl` | `0e6a10e959790b538d21230d25cf6f454225fd10` |
| `@redact-secret/node-linux-x64-gnu` | `4093200cb5ed40b2c4c33c448f7039e67462ccc7` |
| `@redact-secret/node-linux-x64-musl` | `357564f6309cda97dfb9a2db00efc19263fa354a` |
| `@redact-secret/node-win32-arm64-msvc` | `74a4800706ca4b345a47d0d8a2798b4f282d5444` |
| `@redact-secret/node-win32-x64-msvc` | `990c4b721955ef326d81c1e3b4cf61b3256376fe` |
| `@redact-secret/wasm` | `2868536a953a850fd194805acf3499afbb24cd83` |

The `integrity` values are in the [manifest](manifest.json).

| Crate `0.1.0-beta.13` | SHA-256 |
| --- | --- |
| `redact-secret` | `db71d5b29197e084c65ae686574488ddfa3da33adf797dd99da469d387ed3a92` |
| `redact-secret-cli` | `15ca4349039b71513ce5d46be24bf6c595d5476d5e9e29f5d9e0e3c9c6a8ec06` |

| PyPI file | SHA-256 |
| --- | --- |
| `redact_secret-0.1.0b13-cp310-abi3-macosx_10_12_x86_64.whl` | `b05dfb325b332d25a709e41acf6f91d44d33b96cd48aa83800e7dc760b773f00` |
| `redact_secret-0.1.0b13-cp310-abi3-macosx_11_0_arm64.whl` | `01766fa77d996dff06f2bf38a1b4b7bccc2afe46af85795a058cf84e805b1f9c` |
| `redact_secret-0.1.0b13-cp310-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl` | `631c5c45564bdbd5d320e9f65977314a73f9b5f53a716cd951ecad981c3d4513` |
| `redact_secret-0.1.0b13-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` | `bdb720192f608ab0b9908ca20223b209476e40fb89f3f8f7fae0343d538441f2` |
| `redact_secret-0.1.0b13-cp310-abi3-musllinux_1_2_aarch64.whl` | `2995a89013d422bfde377731c175bd976dad8636958f647aa64c98a1a02eaff3` |
| `redact_secret-0.1.0b13-cp310-abi3-musllinux_1_2_x86_64.whl` | `c37cb38c9e92633c301379285e32c0df68bd57d6b62a31740fbc5e8e9dff8854` |
| `redact_secret-0.1.0b13-cp310-abi3-win_amd64.whl` | `b1e0db809d302ace6430b2a8ddee34c354ff982da856963a2b9a963a5776df91` |
| `redact_secret-0.1.0b13-cp310-abi3-win_arm64.whl` | `1637dfbe7c6141c354377ecf41b099a2115e255e6f8734f7a2563dd7a199d4d9` |
| `redact_secret-0.1.0b13.tar.gz` | `a4f70c98b189824a00dea06328a68b79752a16fc5b4b667473c49b52e4106d7b` |

## Independent verification

On 2026-10-03 every registry was checked directly rather than through the
workflow's own reports:

- **npm:** all ten packages are at `0.1.0-beta.13`, with the shasums above. The `beta`
  dist-tag is `0.1.0-beta.13`. The publish left `latest` at `0.1.0-beta.12`, as the
  [dist-tag policy](../../releasing.md#npm-dist-tag-policy) requires; `latest`
  was not moved.
- **crates.io:** both crate checksums equal the inventory's crate digests.
  Neither version is yanked.
- **PyPI:** all nine file hashes equal the inventory's Python entries.
- **git:** `v0.1.0-beta.13` resolves on `origin` to annotated object
  `cd447c06ffb8ac27f3176f8560fe7af5f8e245b8`, peeled to `66b492bd`.

## Durable record

This checked-in [manifest](manifest.json) is marked `reconstructed`, although the
run did upload a manifest: that original is preserved verbatim in its
`original_manifest`, and the record differs from it only by the correction
described under Publication. Only the two `registry_state` entries and the empty
`published` digests were corrected, each from the live registries, after the
other published digests were checked equal to the live values. It also adds the
`release_evidence` this repository's manifest job does not itself populate (tag,
per-registry checksums, workflow run references, clean-install verification).
The preserved [inventory](artifact-inventory.json) is unchanged from the Release
run. The [support-status fragment](support-status.md) is generated, not
hand-written. No GitHub Release page has been created for this version.
