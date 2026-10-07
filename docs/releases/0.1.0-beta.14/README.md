# 0.1.0-beta.14 release evidence

Published on 2026-10-07 (UTC) from the qualified source
`0c62fd38bca75c5b28b042dc79789b708ebf1d17` (`main`, the merge of pull request
#1271). All ten npm packages (including the two musl Linux Node addons), both
Rust crates, and all nine Python distribution files are published. Python spells
this version `0.1.0b14`; npm and Cargo use `0.1.0-beta.14`. The maintainer
approved the Release run and its three `release` environment deployments on
2026-10-07 UTC, in the GitHub deployment review of the run
(`milocosmopolitan`). No Reconcile Release was dispatched for this version, and
`latest` was not touched.

## Identity

- **Source revision:** `0c62fd38bca75c5b28b042dc79789b708ebf1d17`. Qualification,
  rehearsal, SAST and the Release run all ran on this exact commit.
- **Conformance corpus identity:** tree `07318cdbafde556bb886329dcc8f8358deab4605`
  (`git rev-parse 0c62fd38:conformance`), equal to the manifest's
  `conformance_identity`.
- **Artifact inventory:** [artifact-inventory.json](artifact-inventory.json), the
  Release run's own `artifact-inventory` artifact, byte-identical (SHA-256
  `b9e6052e3dd675db4ab84d7f19667b4777a00d99d345027df2f88a9550a2ce57`, recorded as the
  manifest's `artifact_inventory_sha256`).
- **Annotated tag:** `v0.1.0-beta.14`, object
  `db9c280bfdfa7c489da8ad767f7417259521c53d`, peeled to `0c62fd38`.
- **Release manifest:** the run's `release-manifest-0.1.0-beta.14` artifact has
  SHA-256 `5bc3ccb386934e6dfa6357ed4f3d3b2192125bebce0e61d88648d21494e66e49`; the
  checked-in [manifest](manifest.json) embeds it unchanged (see Durable record).

## Qualification and approval

At the release source `0c62fd38`: [Artifact qualification 37552318055](https://github.com/redact-secret/redact-secret/actions/runs/37552318055)
(push), [Package Release Rehearsal 37552330420](https://github.com/redact-secret/redact-secret/actions/runs/37552330420)
(workflow dispatch) and [SAST 37552317712](https://github.com/redact-secret/redact-secret/actions/runs/37552317712) passed. The Release run
re-ran qualification on the same commit and passed it too.

### Public API and compatibility review

The candidate review
[`docs/audits/beta14-candidate-public-contract-review.md`](https://github.com/redact-secret/redact-secret/blob/0c62fd38bca75c5b28b042dc79789b708ebf1d17/docs/audits/beta14-candidate-public-contract-review.md)
(owner [#1263](https://github.com/redact-secret/redact-secret/issues/1263), SHA-256
`422482156bcacf7d8f1552bbbda364885398f05cc1067efe53fa670bf030b448`, reviewed at
`2816897f96c405c3eb8c87a0c70eba5df273c121`) was bound by the artifact inventory.
Its disposition is **accepted with limitations**: the public API change since
`0.1.0-beta.13` is additive in every binding and the CLI (Rust root exports 54
to 72 names, JavaScript adds `status`, `compareActionPolicies`, `defaultPolicy`
and the `actionPolicy` option, Python `__all__` 44 to 55 names, the CLI adds
`--action-policy` and `--compare-action-policy`, finding types 141 to 157 and
detectors 110 to 118), and nothing was removed, renamed or re-signed. The review
is evidence, not release approval. It was a retained temporary unit; its body
is retired by the closeout and stays at the permalink above.

### Performance evaluation

Confirming run [37554223815](https://github.com/redact-secret/redact-secret-benchmarks/actions/runs/37554223815) in `redact-secret-benchmarks`
(benchmarks `develop` at `6494f12b`, candidate `0c62fd38`) succeeded. The
fixed-candidate acceptance of the evaluation run 37552333458 was accepted (46
checks, 0 failures) with four reviewed budget breaches, which
[benchmarks pull request #803](https://github.com/redact-secret/redact-secret-benchmarks/pull/803)
carries as accepted tradeoffs on the maintainer's approval of 2026-10-06
(the size growth of the declarative action-policy and comparison APIs, epic
[#1216](https://github.com/redact-secret/redact-secret/issues/1216), and the closeout detector fixes):

| Trigger | Baseline | Candidate | Growth over the Beta.13 accepted value |
| --- | ---: | ---: | ---: |
| `size/wasm/full/gzip` | 137,639 | 235,713 | +29,016 (+14.0%) |
| `size/wasm/common/gzip` | 100,058 | 168,891 | +26,025 (+18.2%) |
| `size/browser-bundle/quickstart/gzip` | 144,501 | 244,931 | +30,717 (+14.3%) |
| `initialization/browser-wasm/scale-logs-small-whole/initialization-ratio` | 1 | 1.3437 | below the Beta.13 accepted 1.5, above the 1.25 budget; not attributed to a Beta.14 change |

The WebAssembly size growth is a known, accepted limitation; the
[changelog](../../../CHANGELOG.md#010-beta14--2026-10-07) states it as 7.0% brotli for the `full` artifact.

### Support status of the release

The checked-in `benchmarks/support-matrix.json` is pinned to benchmarks
`573e1288` (generated 2026-10-02): 173 families, 144 stable. It was not
refreshed for this version, so the eight detectors added in beta.14
(`buildkite-token`, `fly-token`, `mapbox-token`, `pydantic-logfire-token`,
`sourcegraph-token`, `square-token`, `unkey-root-key`, `xata-api-key`) carry no
support status until their benchmarks arrival evidence lands. The Release run's
support-matrix drift report records 0 improvements, 0 regressions and 0 new or
unclassified families.

## Publication

[Release run 37554713667](https://github.com/redact-secret/redact-secret/actions/runs/37554713667), the only Release dispatch for this version,
was dispatched on 2026-10-07 from `main` at `0c62fd38`. It re-ran qualification,
published both crates, all nine PyPI files and all ten npm packages (including
the facade), passed registry-install verification on all eight Node targets and
Chromium, created annotated tag `v0.1.0-beta.14` at the release source revision
and uploaded `release-manifest-0.1.0-beta.14`. Every job succeeded and the run
reads **success**.

Release readiness rows 3 and 4 held on this run: every registry-state entry in
the run's manifest reads `published`, every comparable published digest is
present (no propagation-lag false negative, unlike beta.13), one Release run
reached `tag-release`, and no `reconcile-release.yml` was dispatched against
this version.

## Clean-install verification

The Release run's registry-backed `Verify registry install` jobs each installed
`0.1.0-beta.14` from the public registry into a clean directory and passed:

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

Fetched live on 2026-10-07 from the npm registry, the crates.io API and the PyPI
JSON API.

| npm package `@0.1.0-beta.14` | shasum |
| --- | --- |
| `@redact-secret/core` | `cb8cb61c20a2a65cfd56bbc3947d63b5bd6408c8` |
| `@redact-secret/node-darwin-arm64` | `91068c769562afc2348b9eb6e0c5bcd6a4c782de` |
| `@redact-secret/node-darwin-x64` | `b7e38b125ee7d63327dff0ea110860b0beb94ba9` |
| `@redact-secret/node-linux-arm64-gnu` | `886a5fd04083c23e47516bbfde0f64047b3d1754` |
| `@redact-secret/node-linux-arm64-musl` | `eb07bb443d1c9e9a0d0e6ec28365d05795d30386` |
| `@redact-secret/node-linux-x64-gnu` | `f4aa9bf864d2ef6eea031a2958debc62f0a9845a` |
| `@redact-secret/node-linux-x64-musl` | `78357f30b0817fc33f552dcd1d78add2748400d2` |
| `@redact-secret/node-win32-arm64-msvc` | `eae7d8139081e94966a219d80403f46cdf82039a` |
| `@redact-secret/node-win32-x64-msvc` | `731d7989a96cf6c69765cc27cda1161f258c66ff` |
| `@redact-secret/wasm` | `5428551d95cb00300b6661701691f48ee3d3e97c` |

The `integrity` values are in the [manifest](manifest.json).

| Crate `0.1.0-beta.14` | SHA-256 |
| --- | --- |
| `redact-secret` | `2b2691a3a55efa1d2cfabe8aa86b4a08c1db8de3ee32ba714f67bdf064889476` |
| `redact-secret-cli` | `cd29abae14fa1b26c8bcda2c46cafb9f5e32b3e9d5fbfcdb9547b4931bb79589` |

| PyPI file | SHA-256 |
| --- | --- |
| `redact_secret-0.1.0b14-cp310-abi3-macosx_10_12_x86_64.whl` | `8b4d984b211cc7eb6b747026f49619e74ecb107c541ef3e526b19be7f8e74e32` |
| `redact_secret-0.1.0b14-cp310-abi3-macosx_11_0_arm64.whl` | `d3279d513ed5a75f04a6e223eeec82f6d0c64d42d40e53e47726524f68008a62` |
| `redact_secret-0.1.0b14-cp310-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl` | `89818913609b915f3da0c633d74189ce4df8fa1836f5dff926056f8456d9c519` |
| `redact_secret-0.1.0b14-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` | `d8c8f18e613ab7fc31216bd048bbb3319b673bd9f0eb8aa62ba9266cf2773739` |
| `redact_secret-0.1.0b14-cp310-abi3-musllinux_1_2_aarch64.whl` | `b00611b2557bc1cce7f03b9da64cdf664e8825c8106f5a9fc09330d878e70837` |
| `redact_secret-0.1.0b14-cp310-abi3-musllinux_1_2_x86_64.whl` | `37320b343fb1f4e11589992d7c7b016412d9f2156e19dcaf53f5ed636604eb35` |
| `redact_secret-0.1.0b14-cp310-abi3-win_amd64.whl` | `27d92de3fe37ed958dc9378787abe9ce79cad0bfdec73d4fb3c4169fcbf6bf8a` |
| `redact_secret-0.1.0b14-cp310-abi3-win_arm64.whl` | `297490b25df1757c111fef75a6dc1c773c8f201149279034e999639af41bb284` |
| `redact_secret-0.1.0b14.tar.gz` | `3ccddf1694a05bc33f2e26f3b25dba5496997b938048ba0f5269722837d2a05c` |

## Independent verification

On 2026-10-07 every registry was checked directly rather than through the
workflow's own reports:

- **npm:** all ten packages are at `0.1.0-beta.14`, with the shasums above, and
  each shasum equals the manifest's `published` digest. The `beta` dist-tag is
  `0.1.0-beta.14`. The publish left `latest` at `0.1.0-beta.13`, as the
  [dist-tag policy](../../releasing.md#npm-dist-tag-policy) requires; `latest`
  was not moved.
- **crates.io:** both crate checksums equal the manifest's and the inventory's
  crate digests. Neither version is yanked.
- **PyPI:** all nine file hashes equal the manifest's and the inventory's Python
  entries; the registry holds no other file for this version.
- **git:** `v0.1.0-beta.14` resolves on `origin` to annotated object
  `db9c280bfdfa7c489da8ad767f7417259521c53d`, peeled to `0c62fd38`.

## Known limitations

- The support matrix is not refreshed for the eight new detectors (see Support
  status above).
- `SecretScanErrorCode::ALL` is `[Self; 23]` instead of `[Self; 22]` because of
  the new `INVALID_ACTION_POLICY` code. Code that indexes or iterates it is
  unaffected; code that spells the array type or destructures it by length no
  longer compiles. The enum is `#[non_exhaustive]`, so a `match` cannot break.
- The WebAssembly artifacts and the browser bundle grew (table above); the
  growth is accepted, and the decision is recorded in benchmarks pull request
  [#803](https://github.com/redact-secret/redact-secret-benchmarks/pull/803).

## Durable record

This checked-in [manifest](manifest.json) is marked `reconstructed`, as every
record since beta.2 is, although nothing in the run's manifest was wrong: the
run's original is preserved verbatim in its `original_manifest` and every
top-level field equals it (all thirteen `registry_state` entries read
`published`, every comparable digest is present, no value was corrected). The
record adds only the `release_evidence` this repository's manifest job does not
itself populate (tag, per-registry checksums, workflow run references,
clean-install verification) and `artifact_inventory_sha256`. The preserved
[inventory](artifact-inventory.json) is byte-identical to the Release run's.
No GitHub Release page has been created for this version.
