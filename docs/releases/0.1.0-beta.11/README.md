# 0.1.0-beta.11 release evidence

Published on 2026-09-29 from the qualified source
`94fc18a974f659ea882c89120dbf1adb3acf2f28` (the merge of
[#1007](https://github.com/redact-secret/redact-secret/pull/1007)). All ten npm
packages (including the two musl Linux Node addons), both Rust crates, and all
nine Python distribution files are published. Python spells this version
`0.1.0b11`; npm and Cargo use `0.1.0-beta.11`.

## Identity

- **Source revision:** `94fc18a974f659ea882c89120dbf1adb3acf2f28`.
- **Conformance corpus identity:** tree `25fbfb5130c83ab908b64c8506c5713662a9b876`
  (`git rev-parse 94fc18a:conformance`), equal to the manifest's
  `conformance_identity`.
- **Artifact inventory:** [artifact-inventory.json](artifact-inventory.json),
  the Release run's own `artifact-inventory` artifact, unchanged (SHA-256
  `8ebbccb59925d6e9e8354e0a6e50c166423c85126891919b0bd72767ee9d7446`, recorded
  as the manifest's `artifact_inventory_sha256`). This is the inventory the
  published files were built and qualified against. The pre-release
  [Artifact qualification 36606395309](https://github.com/redact-secret/redact-secret/actions/runs/36606395309)
  inventory for the same commit differs in ten digests: the eight wheels and
  the two Windows Node addons. Those builds are not byte-reproducible across
  runs, a known issue. Every registry checksum below matches the Release run's
  inventory.
- **Annotated tag:** `v0.1.0-beta.11`, object
  `eeae31a77798c2937443456ce559beef551b4c23`, targeting `94fc18a9`.

## Qualification and approval

[SAST 36606394784](https://github.com/redact-secret/redact-secret/actions/runs/36606394784),
[Artifact qualification 36606395309](https://github.com/redact-secret/redact-secret/actions/runs/36606395309),
and [Package Release Rehearsal 36606423943](https://github.com/redact-secret/redact-secret/actions/runs/36606423943)
passed at the frozen source revision. The maintainer's account approved the
Release run's `release` environment deployments.

### Performance evaluation

The first performance evaluation against this candidate,
[36606420213](https://github.com/redact-secret/redact-secret-benchmarks/actions/runs/36606420213),
failed on two kinds of finding. Neither was a code defect:

- **Size rows.** They breached only because the acceptance rows were keyed to
  the earlier candidate `8b6a5fd`. `94fc18a` is `8b6a5fd` plus version
  strings and READMEs, with no Rust, binding or package source change. The
  maintainer accepted the Beta.11 size growth on 2026-09-29, and six rows were
  re-keyed to `94fc18a` with the same rationale.
- **Browser-init row (ratio 1.286).** Paired `8b6a5fd` → `94fc18a` runs
  36609019172, 36609026856 and 36609034804 pooled to 0.971 [0.869, 1.084],
  and A/A run 36609042852 bounds the noise. The row is not recorded as a
  tradeoff.

[redact-secret-benchmarks#509](https://github.com/redact-secret/redact-secret-benchmarks/pull/509)
(merge `13fe1dbc73a1f4e610dc48d12cb5879dc464d8a7`) records this. Its run of record,
[performance evaluation 36609010314](https://github.com/redact-secret/redact-secret-benchmarks/actions/runs/36609010314),
is **ACCEPTED**: latency, initialization and memory are within budget, and the
size rows are accepted tradeoffs.

## Publication

[Release run 36610474587](https://github.com/redact-secret/redact-secret/actions/runs/36610474587)
re-ran qualification and published both crates, all nine PyPI files and all
ten npm packages (including the facade). It passed registry-install
verification on all eight Node targets and Chromium, recorded the release
manifest, and created annotated tag `v0.1.0-beta.11` at the frozen source
revision. The run succeeded end to end.

The run left one stale entry, which is not a publication defect. The
`Publish npm dependency linux-arm64-musl` job wrote its registry-state
snapshot right after its own publish, before npm had propagated the version.
So the `Record release manifest` job recorded
`npm:@redact-secret/node-linux-arm64-musl` as `unpublished`, with a null
`published` shasum. npm records that version as published at
2026-09-29T18:30:17Z. The same run's `Verify registry install
aarch64-unknown-linux-musl` job installed `0.1.0-beta.11` from the registry
and passed at 18:33:48Z. This is the npm propagation-lag false negative seen
in the beta.3, beta.5, beta.6 and beta.10 records, not a partial publication.

A [Reconcile Release dry run 36613259577](https://github.com/redact-secret/redact-secret/actions/runs/36613259577)
confirmed it. Every npm package (the musl addon at shasum
`639832a6e801b4822c29e8148b71842aaf48f5cb`), both crates, and every PyPI file
were already published with content matching this source revision. The dry run
published nothing and skipped the tag step. No real reconcile was needed or run.

## Clean-install verification

The Release run's registry-backed `Verify registry install` jobs each
installed `0.1.0-beta.11` from the public registry into a clean directory and
passed:

| Lane | Result |
| --- | --- |
| `aarch64-apple-darwin` | passed |
| `x86_64-apple-darwin` | passed |
| `aarch64-unknown-linux-gnu` | passed |
| `x86_64-unknown-linux-gnu` | passed |
| `aarch64-unknown-linux-musl` | passed (Alpine `node:22-alpine`) |
| `x86_64-unknown-linux-musl` | passed |
| `aarch64-pc-windows-msvc` | passed |
| `x86_64-pc-windows-msvc` | passed |
| Browser (Chromium) | passed |

## Registry checksums

Fetched live on 2026-09-29 from the npm registry, the crates.io API and the
PyPI JSON API.

| npm package `@0.1.0-beta.11` | shasum |
| --- | --- |
| `@redact-secret/core` | `7080134fd1a0e52adfeaf115d02620c9f65b0f55` |
| `@redact-secret/wasm` | `b68a93b16aabb541c809eb22105c0863bd8f0cb0` |
| `@redact-secret/node-darwin-arm64` | `c390434f1088879e8dd3871c57f8d1a37f98ef1b` |
| `@redact-secret/node-darwin-x64` | `df66b9a59cb21d70ac0b4a4a6cd6f4e71763bdfc` |
| `@redact-secret/node-linux-arm64-gnu` | `c854057178c214f31df197ea5dea576bf9e47db3` |
| `@redact-secret/node-linux-arm64-musl` | `639832a6e801b4822c29e8148b71842aaf48f5cb` |
| `@redact-secret/node-linux-x64-gnu` | `43a4760b2abf6f67ff978ce8073b91b5b21cffae` |
| `@redact-secret/node-linux-x64-musl` | `6c92bb8f4af0fb6e588db1297058526f63a4cc00` |
| `@redact-secret/node-win32-arm64-msvc` | `025663e2ae99b94fca55bbf87febb6ba99fe01a0` |
| `@redact-secret/node-win32-x64-msvc` | `46a712647ccd43b44045542ab18b8aae4a36cb06` |

The `integrity` values are in the [manifest](manifest.json).

| Crate `0.1.0-beta.11` | SHA-256 |
| --- | --- |
| `redact-secret` | `c38795ffe4dd62a921acec33d11e50bc1f219f6e2486f2f9604fe2613228dc40` |
| `redact-secret-cli` | `5e683fd74775fc07f01ac07a568db3b45c75659bb15df91f370963eb6d675f81` |

| PyPI file | SHA-256 |
| --- | --- |
| `redact_secret-0.1.0b11-cp310-abi3-macosx_10_12_x86_64.whl` | `aadc6343d5343163c001e7708c2797b7db4ac7ba78313ca80efbeec50a934e8c` |
| `redact_secret-0.1.0b11-cp310-abi3-macosx_11_0_arm64.whl` | `a15d9bb872b89752cfdf12d9678c27c7e60e60f1ca742ce798cb4a95a27ae5ae` |
| `redact_secret-0.1.0b11-cp310-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl` | `a7bebef8b6e8b0b6ab4606bdb4ec98bef2bf5abcbd224865947ea939c944eb36` |
| `redact_secret-0.1.0b11-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` | `80b1496a9b58b6297357daf2dd78a64db5352b22cf41dbfbcf9c27936b533fcf` |
| `redact_secret-0.1.0b11-cp310-abi3-musllinux_1_2_aarch64.whl` | `ddf824eac3fe0d81f57920fdedf9024e28181569d2c1a959946d0c063f6205fe` |
| `redact_secret-0.1.0b11-cp310-abi3-musllinux_1_2_x86_64.whl` | `ace286a8cfd9f8cb662fdcc27d63c2360cb0e252d187e5e131731545860960aa` |
| `redact_secret-0.1.0b11-cp310-abi3-win_amd64.whl` | `5410c0537d826ce4b22ce7a8ff877a1e04df2318e65b18c83574b7521a57740d` |
| `redact_secret-0.1.0b11-cp310-abi3-win_arm64.whl` | `ddfd411298550c1a024c19b57900e183e0bedee054c6e30de90a40c16bd0b3ac` |
| `redact_secret-0.1.0b11.tar.gz` | `51537150f12a25bee813874ef8d3147f8c53ec2ac3e1412fc44d365777f144ae` |

## Independent verification

On 2026-09-29 every registry was checked directly rather than through the
workflow's own reports:

- **npm:** all ten packages are at `0.1.0-beta.11`, each shasum equal to the
  manifest's published digest. The `beta` dist-tag is `0.1.0-beta.11`.
  `latest` is still `0.1.0-beta.10`, as the
  [dist-tag policy](../../releasing.md#npm-dist-tag-policy) requires. Moving
  it is a separate, explicitly approved action.
- **crates.io:** both crate checksums equal the inventory's crate digests.
  Neither version is yanked.
- **PyPI:** all nine file hashes equal the inventory's Python entries.
- **git:** `v0.1.0-beta.11` resolves locally and on `origin` to annotated
  object `eeae31a77798c2937443456ce559beef551b4c23`, targeting `94fc18a9`.

## Durable record

This checked-in [manifest](manifest.json) is marked `reconstructed`, for two
reasons. The workflow's manifest job does not populate the tag, registry and
verification evidence this record requires; that is true of every version in
this history, not a defect of this run. And its registry state for the musl
lane above was a propagation-lag artifact. The record corrects exactly one
`registry_state` entry to `published` and fills that package's `published`
shasum from the live registry. Both corrections rest on the run's own later
verification, the Reconcile dry run and the independent check above. The
original manifest job output is preserved verbatim as `original_manifest`.
The preserved [inventory](artifact-inventory.json) is unchanged from the
Release run. The [support-status fragment](support-status.md) is generated,
not hand-written. No GitHub Release page has been created for this version.
