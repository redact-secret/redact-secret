# Releasing Redact Secret

[Documentation home](README.md) · [Contribution guide](../CONTRIBUTION.md)

Use this runbook after feature work is reviewed, for candidate preparation,
qualification, publication, recovery, and closeout. It describes the workflows
in this repository; [AGENTS.md](../AGENTS.md#release-authority) remains the
release authority. A completed issue or successful build is not release approval.

The previous release is recorded in [beta.1 evidence](releases/0.1.0-beta.1/README.md).
Version `0.1.0-beta.2` was approved for candidate preparation on 2026-09-13.
The [final beta.2 code review](audits/beta2-final-code-review.md) records the
closed findings and the evidence required before publication approval.

## Product and artifact identity

All product packages share one SemVer version and source revision. Python uses
the equivalent PEP 440 spelling, for example `0.1.0-beta.2` becomes `0.1.0b2`.
The version examples here do not authorize selecting or publishing them.

| Registry or delivery surface | Artifact |
| --- | --- |
| npm | `@redact-secret/core` facade |
| npm | `@redact-secret/wasm` runtime |
| npm | Six `@redact-secret/node-<platform>` runtime packages |
| crates.io | `redact-secret` library and `redact-secret-cli` CLI crate |
| PyPI | `redact-secret` distribution: eight abi3 wheels and one sdist |
| Actions qualification artifacts | Six native CLI binaries |

There are eight npm package identities, two crate identities, and one Python
distribution across three registries. The two musl Node addons are qualified
but not published to npm. The exact matrices belong to
`Cargo.toml`'s `[workspace.metadata.redact-secret]`; see
[qualification](qualification.md) and [Python packaging](python-packaging.md).

The workflows create an annotated Git tag after verification. They do not
automatically create a GitHub Release or attach CLI binaries to one. A GitHub
Release or another distribution channel needs an explicit publication decision
and must use the qualified binaries and recorded digests.

## Prepare the candidate

1. Review the integration commit on `main`, the open defects, public exports,
   supported runtimes, compatibility changes, and `Unreleased` changelog.
2. After candidate-version approval, create `rc/<version>` from reviewed `main`.
   Prepare manifests, lockfiles, changelog, and candidate notes there. Release
   fixes use reviewed PRs targeting that RC branch.
3. Update the workspace Cargo version, every version-bearing JSON manifest,
   exact npm runtime dependencies, and Cargo/npm lockfiles together. Python
   derives its version dynamically from Cargo. Use the
   [lockstep policy](rust-workspace.md#version-lockstep) for the complete set.
   Preserve historical release records and examples intentionally pinned to them.
4. Run the local checks below, then freeze the candidate commit. Any further
   source commit requires fresh qualification. Retain the RC branch after release.

```bash
npm ci --ignore-scripts
npm run ci
npm run rust:check
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

From the prepared candidate checkout, derive the version and check the branch:

```bash
RELEASE_VERSION=$(node -p "require('./packages/javascript/package.json').version")
RC_BRANCH="rc/$RELEASE_VERSION"
test "$(git branch --show-current)" = "$RC_BRANCH"
python3 -B scripts/check-release-refs.py --candidate-ref "refs/heads/$RC_BRANCH"
git rev-parse HEAD
```

This reads an already-approved version; it does not choose one. Record the full
commit SHA alongside all subsequent workflow run IDs.

## Qualify without publication

Inspect workload inputs before expensive runs. Conformance tests use the
smallest fixtures that exercise the behavior; performance profiles measure
resource use separately. A large performance workload is not needed to prove
a lifecycle or packaging contract.

RC pushes trigger qualification. Reuse a successful full run for the frozen
revision, or dispatch it explicitly when needed:

```bash
gh workflow run artifact-qualification.yml --ref "$RC_BRANCH"
gh workflow run package-release-rehearsal.yml --ref "$RC_BRANCH"
gh run list --branch "$RC_BRANCH" --limit 20
```

`Artifact qualification` includes reusable CI and Python-wheel workflows,
native/browser/CLI qualification, installed JavaScript consumers, and an
`artifact-inventory` upload. Check the run's `headSha` against the frozen SHA,
every required job, and the inventory's source, version, corpus hashes, artifact
digests, and installed-consumer reports. A PR run that only checks changed
workflow declarations is not full candidate qualification.

`Package Release Rehearsal` packs and checks npm runtime dependencies and
records `dependency-cutover-plan`. It publishes nothing. It is an npm dependency
rehearsal, not a simulated publication to all registries. `Release` has no
`publish=false` or `dry_run` input; never dispatch it as a rehearsal.

Also require passing SAST evidence for the frozen revision. An acknowledged
baseline is not zero findings or complete parser coverage. Assessment results
remain separate from conformance: use the prepared profiles and applicable
environment in [assessment](../assessment/README.md). The manually dispatched
`complete-assessment.yml` is not wired as a Release dependency, and a threshold
measured for one host does not establish acceptance on another host.

## Review and approval

Before requesting final release approval, assemble a reviewable record of:

- Approved version, RC branch, full source SHA, public API review, compatibility
  changes, changelog, and disposition of every release-blocking issue.
- Exact-revision qualification, rehearsal, SAST, artifact inventory, and any
  applicable assessment evidence. Hashing an old review document does not make
  it a current API review.
- Live `release` environment reviewers and RC branch restrictions; repository
  review/status/tag rules; npm and crates.io publisher rights; PyPI Trusted
  Publisher identity for this repository, workflow, and environment.

`npm run registry-preflight:check` reads public registry/repository metadata.
It does not prove that publishing credentials work. The read-only
`scripts/verify-release-governance.py` can inspect the `release` environment
and branch settings; account-level publishing rights need separate verification.
Never record token values in release evidence.

Beta.1's Actions token could not create the tag reference (HTTP 403); its
[release record](releases/0.1.0-beta.1/README.md) documents the authorized recovery.
Check tag-writing authority before publication. Do not bypass repository rules
or assume `contents: write` alone proves that the tag operation is permitted.

Obtain explicit user release approval after tests, API review, and changelog
review pass. Environment approval is an additional workflow boundary.

## Publish the approved revision

After approval, confirm the remote RC tip still equals the qualified SHA and
dispatch the one product workflow:

```bash
gh workflow run release.yml --ref "$RC_BRANCH"
gh run list --workflow release.yml --branch "$RC_BRANCH" --limit 5
```

Inspect the new run's SHA before approving its protected jobs. The workflow
repeats qualification at that revision. It publishes native/Wasm npm dependencies
before the facade; publishes the core crate before the CLI crate; and uploads
the qualified Python wheel/sdist files. Prerelease npm packages use `beta`,
stable packages use `latest`.

The post-publication jobs clean-install the exact npm version on all six Node
platforms and Chromium. `tag-release` waits for publication and those install
checks, then creates annotated `v<version>` at the workflow source SHA. The
current graph has no equivalent post-publication Rust/Python clean-install
matrix: retain their registry file/checksum evidence and verify exact-version
consumer installation separately before claiming that broader verification.

`record-manifest` attempts to run even after failed publishers and uploads
`release-manifest-<version>`. It records source revision, corpus identity,
version, expected artifact identities, and observed registry states. Its success
does not establish tag or registry-install success: those jobs are separate.

## Recover a partial publication

Stop and record the exact failed run, source, version, available qualified
artifacts, manifest, and live registry state. A timeout or HTTP error does not
prove absence. Never overwrite a published version or move its tag.

With separate explicit recovery authorization, use `Reconcile Release` from
the matching RC branch. First compute a non-publishing plan:

```bash
gh workflow run reconcile-release.yml --ref "$RC_BRANCH" \
  -f version="$RELEASE_VERSION" -f dry_run=true
```

The workflow locates the latest unexpired matching release manifest. Check its
source/run identity. When the manifest upload failed, provide both
`source_commit` and `source_run` explicitly to identify the original Release
run and qualified inventory. The selected source must remain in the current
RC branch's history, including its tip. A source removed by force-push/rebase
cannot be recovered through this path.

Review the exact skip/publish/block plan and evidence before authorizing
`dry_run=false`. Existing artifacts must match the qualified content; missing
compiled artifacts come from the original run, not a new build. Expired
artifacts, content conflicts, or unknown registry state require resolution
before proceeding. A full Release retry is not a general recovery mechanism:
some publishers reject an already-published version.

Registry lookup failures remain `unknown` and block recovery planning rather
than being inferred as unpublished; [#238](https://github.com/redact-secret/redact-secret/issues/238)
records the fix and deterministic regressions. Independently verify live state
before any recovery action.
Preserve all recovery run IDs and verification outcomes; the recovery workflow
does not write a replacement durable release manifest.

## Close out

Preserve evidence under `docs/releases/<version>/`, following the
[beta.1 record](releases/0.1.0-beta.1/README.md): approved source, artifact and
corpus identity, registry file checksums, qualification/publication/recovery run
IDs, clean-install results, and annotated tag target. Label reconstructed
evidence explicitly if an automated manifest failed. Copy necessary evidence
before Actions artifacts expire.

Update the dated changelog entry and public installation guidance to reflect
what actually published. Merge release changes back into `main` through a
reviewed PR and retain the RC branch. A release is complete only when the
intended artifact set, verification, tag, and evidence agree; partial success
must remain visible as partial success.
