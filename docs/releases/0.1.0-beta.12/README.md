# 0.1.0-beta.12 release evidence

Published on 2026-10-01 from the qualified source
`4227160c4dac402d7add53d3f8fe990f693912c1` (main after
[#1113](https://github.com/redact-secret/redact-secret/pull/1113)). All ten npm
packages (including the two musl Linux Node addons), both Rust crates, and all
nine Python distribution files are published. Python spells this version
`0.1.0b12`; npm and Cargo use `0.1.0-beta.12`. The maintainer approved the
version and the Rehearsal, Release and Reconcile runs on 2026-09-30; the
`release` environment deployments (four on the Release run, including the
facade and the tag, and one on the Reconcile dry run) were approved through the
GitHub API under that approval.

## Identity

- **Source revision:** `4227160c4dac402d7add53d3f8fe990f693912c1`.
- **Conformance corpus identity:** tree `3abcd2462072c88efefba56e2112d94cdbc6c263`
  (`git rev-parse 4227160c:conformance`), equal to the manifest's
  `conformance_identity`.
- **Artifact inventory:** [artifact-inventory.json](artifact-inventory.json),
  the Release run's own `artifact-inventory` artifact, unchanged (SHA-256
  `ffc637183a1bebea9f913d3fd4cadb7af89d62a95a60e03073ae3a35aee3917c`, recorded as the manifest's `artifact_inventory_sha256`). This is the
  inventory the published files were built and qualified against. The
  pre-release [Artifact qualification 36805155123](https://github.com/redact-secret/redact-secret/actions/runs/36805155123) inventory
  for the same commit differs in the eight wheels, the Windows CLI executable and the
  Windows arm64 Node addon, which are not byte-reproducible across runs (a
  known issue). Every
  registry checksum below matches the Release run's inventory.
- **Annotated tag:** `v0.1.0-beta.12`, object
  `8973ab50e068058693bcac9a0b2b8343bd327e85`, peeled to `4227160c`.

## Qualification and approval

[SAST 36805154806](https://github.com/redact-secret/redact-secret/actions/runs/36805154806), [Artifact qualification 36805155123](https://github.com/redact-secret/redact-secret/actions/runs/36805155123)
(push), and [Package Release Rehearsal 36808558300](https://github.com/redact-secret/redact-secret/actions/runs/36808558300) passed at the
frozen source revision. Registry preflight and the governance check passed.

### Performance evaluation

The performance evaluation of record,
[36817086580](https://github.com/redact-secret/redact-secret-benchmarks/actions/runs/36817086580) in `redact-secret-benchmarks`, ran 14 rounds and
accepted the budgets. Two earlier 6-round runs, 36808555320 and 36812132564,
breached an initialization row (ratio 1.477 and 1.322 against a limit of 1.25);
the breach did not reproduce with 14 rounds (1.219). Three size rows are
accepted as tradeoffs, recorded in benchmarks PRs #580 and #587.

### Support status of the release

The code-candidate evidence is benchmarks `evidence/860/bfc608c/`
(benchmarks PR #586, develop `bbcf4029`): 173 families, 144 stable in candidate
mode at `bfc608c`, measured with trufflehog 3.97.4. The checked-in
`benchmarks/support-matrix.json` carries the same figures; its `sourceReport`
is run `dbbeea5b-c769-43dc-853f-4c0f5484c7c0` at `redact-secret-benchmarks`
revision `f35037073a3cd9bc1269f62e4c51b7d9f457515e`, measuring product source
`bfc608cce75f79f6a5cab037d7e558ba629777f6`. That is a candidate-build measure,
not a measure of the published artifacts, and the previous matrix (beta.11) was
also a candidate-build measure at a different revision, so the
[support-status fragment](support-status.md) states no stable delta.

## Publication

An earlier Release dispatch, [run 36841178285](https://github.com/redact-secret/redact-secret/actions/runs/36841178285), failed in CI's
`Benchmark pin drift` ancestry check before publishing anything: benchmarks
`main` did not contain the pinned `benchmarkCommit` `c1e1fb32`. Promoting
benchmarks `develop` to `main` with `npm run go-production`
([benchmarks PR #597](https://github.com/redact-secret/redact-secret-benchmarks/pull/597),
`main` at `68dacc4c`) fixed it with no source change.

[Release run 36844232498](https://github.com/redact-secret/redact-secret/actions/runs/36844232498), dispatched 2026-10-01 at about 09:12
UTC from `main`, re-ran qualification and published both crates, all nine PyPI
files and all ten npm packages (including the facade). It passed
registry-install verification on all eight Node targets and Chromium and created
annotated tag `v0.1.0-beta.12` at the frozen source revision. Every publish,
verification and `Tag verified release` job succeeded. The run itself reads
**failure** because one job did not: `Record release manifest`.

That failure is not a publication defect. Its `Build and record the manifest`
step died with `python3: Argument list too long` (exit code 126) because
`release.yml` passes the merged artifact digests to `scripts/release-manifest.py`
as one command-line argument that exceeded the Linux per-argument limit. It is
the beta.8 defect ([#799](https://github.com/redact-secret/redact-secret/issues/799))
again. The following `Upload release manifest` step then found no
`manifest.json`, so no `release-manifest-0.1.0-beta.12` artifact exists. It is
tracked as [#1115](https://github.com/redact-secret/redact-secret/issues/1115),
which first attributed it to a registry-state artifact download digest mismatch;
the job log shows the argument-length error instead.

A [Reconcile Release dry run 36847025200](https://github.com/redact-secret/redact-secret/actions/runs/36847025200) (`source_commit`
`4227160c`, `source_run` 36844232498) found every npm package already published
and matching this revision's content, PyPI state complete, and both crates
verified. It published nothing and skipped the tag step. No real reconcile was
needed or run.

## Clean-install verification

The Release run's registry-backed `Verify registry install` jobs each installed
`0.1.0-beta.12` from the public registry into a clean directory and passed:

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

Fetched live on 2026-10-01 from the npm registry, the crates.io API and the PyPI
JSON API.

| npm package `@0.1.0-beta.12` | shasum |
| --- | --- |
| `@redact-secret/core` | `8e7dd164c425eaa4850baf836ef254fd0c3eda32` |
| `@redact-secret/node-darwin-arm64` | `77674b19c3e9f1c76e4dce3df6537ac48b897fbe` |
| `@redact-secret/node-darwin-x64` | `db404c51a67c5df6d3ebcce68ecd1799e05ec812` |
| `@redact-secret/node-linux-arm64-gnu` | `e78850afefff0e835724847c8efc95a3c0bf0993` |
| `@redact-secret/node-linux-arm64-musl` | `3520c1ba26c9b1f4edb451d0d131f6cbd717d051` |
| `@redact-secret/node-linux-x64-gnu` | `943c938b46b1c43797302a8f4d8b916bbf910835` |
| `@redact-secret/node-linux-x64-musl` | `76ff6f942e2c12c89575c942ea3b1a44744ec3a9` |
| `@redact-secret/node-win32-arm64-msvc` | `481beb56e4cb3f94e7ad7e3d3606edec150af5fa` |
| `@redact-secret/node-win32-x64-msvc` | `603c97eb6acbbbc43bc83e715175a2388bfba2da` |
| `@redact-secret/wasm` | `67896b386f1141feabd29afef71c270c578a9a81` |

The `integrity` values are in the [manifest](manifest.json).

| Crate `0.1.0-beta.12` | SHA-256 |
| --- | --- |
| `redact-secret` | `2cc951e8b991e9ec27343a872627f53a25b252cc8148cb4ec7160192ed9d856d` |
| `redact-secret-cli` | `a2169c5c72002c32170e367f2cf922af9a85691c7df5d4ab04fa2b8b08a9ddb8` |

| PyPI file | SHA-256 |
| --- | --- |
| `redact_secret-0.1.0b12-cp310-abi3-macosx_10_12_x86_64.whl` | `54f9580af234bddbaab0e068cc2d89871759a5f794778f6bfd77cfc6b1e4164c` |
| `redact_secret-0.1.0b12-cp310-abi3-macosx_11_0_arm64.whl` | `294e72ec7346e7828bc2413f8de725315c6c48bd1f341c5f24ee340b1bb89b90` |
| `redact_secret-0.1.0b12-cp310-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl` | `59a2715ad809e3128568b413e626bbb3200d43cd3ba713034d16edcd11e06e79` |
| `redact_secret-0.1.0b12-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` | `a3d6f831b146636c74681f89d146987e6b1d3750effefd8e8e662054217912c8` |
| `redact_secret-0.1.0b12-cp310-abi3-musllinux_1_2_aarch64.whl` | `6e1a8aca8d221894847a10ea22c0e1875660c285c8a7c5c24c51a9167345b311` |
| `redact_secret-0.1.0b12-cp310-abi3-musllinux_1_2_x86_64.whl` | `c568eff39481a552752a1fc063193ec6cbb854ba5fba278775a237fbf4241ae2` |
| `redact_secret-0.1.0b12-cp310-abi3-win_amd64.whl` | `f7ff295ba1781fadbb4b92a1658a0ea2d33f061886ff9215234f80707dd53d97` |
| `redact_secret-0.1.0b12-cp310-abi3-win_arm64.whl` | `a46491828eedfa074b37b1ffc9f520eb1e2fef66e2aeb10b63526b8569d8976a` |
| `redact_secret-0.1.0b12.tar.gz` | `eeb7a664887d03a14b19d73143682a5943a29c42d6ba25612d4062a9a7fdeced` |

## Independent verification

On 2026-10-01 every registry was checked directly rather than through the
workflow's own reports:

- **npm:** all ten packages are at `0.1.0-beta.12`, each shasum equal to the
  `published` digest the Release run's own jobs recorded. The `beta` dist-tag is
  `0.1.0-beta.12`. The publish left `latest` at `0.1.0-beta.11`, as the
  [dist-tag policy](../../releasing.md#npm-dist-tag-policy) requires. The
  maintainer separately approved moving `latest` on 2026-10-01 and moved all
  ten packages by hand; afterwards every package was re-observed as
  `{"latest":"0.1.0-beta.12","beta":"0.1.0-beta.12"}`, and a bare
  `npm install @redact-secret/core` in a clean directory resolved
  `0.1.0-beta.12`.
- **crates.io:** both crate checksums equal the inventory's crate digests.
  Neither version is yanked.
- **PyPI:** all nine file hashes equal the inventory's Python entries.
- **git:** `v0.1.0-beta.12` resolves on `origin` to annotated object
  `8973ab50e068058693bcac9a0b2b8343bd327e85`, peeled to `4227160c`.

## Durable record

Because the run uploaded no manifest, this checked-in [manifest](manifest.json)
is marked `reconstructed` and its `original_manifest` states that none exists.
It is rebuilt with the repository's own `scripts/release-manifest.py` from
inputs the run did preserve: the registry-state and artifact-digest values
printed in the failed job's log for the core, WebAssembly, crates and PyPI
publishers, the `registry-state-native-*` and `artifact-digest-native-*` run
artifacts, and the run's `support-matrix-drift` artifact. Every `registry_state`
entry is the run's own value (all `published`); none was corrected. The record
adds the tag, per-registry checksums, workflow run references and clean-install
verification that the manifest job never populates. The npm `published` digests
in `artifact_digests` equal the live registry shasums. The preserved
[inventory](artifact-inventory.json) is unchanged from the Release run. The
[support-status fragment](support-status.md) is generated, not hand-written. No
GitHub Release page has been created for this version.
