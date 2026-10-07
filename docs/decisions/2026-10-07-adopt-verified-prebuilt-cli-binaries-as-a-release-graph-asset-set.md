---
decision_id: decision-adopt-verified-prebuilt-cli-binaries-as-a-release-graph-asset-set
status: accepted
scope: workspace
title: Adopt verified prebuilt CLI binaries as one more asset set in the existing release graph
decided_at: 2026-10-07
spec: distribution
---

# Adopt verified prebuilt CLI binaries as one more asset set in the existing release graph

## Context

[Issue #1269](https://github.com/redact-secret/redact-secret/issues/1269),
raised by a review of #1267, observes that the only documented CLI install is
`cargo install redact-secret-cli --locked --version <v>`, which needs a Rust
toolchain and a source build. The README states that no prebuilt CLI binary is
published. The issue asks whether to publish verified prebuilt downloads and
how that fits the release workflow without a second publish path. This record
decides policy only. It chooses no version and publishes nothing.

What exists today, read from the tree at `0c313602`:

- **Qualification already builds the binaries.** The `cli` job in
  `.github/workflows/artifact-qualification.yml` builds
  `cargo build --release --locked -p redact-secret-cli --target <t>` for the
  six non-musl `cli-release-targets` on native runners, runs
  `scripts/qualify-cli-binary.mjs` (identity, exit codes, every canonical
  fixture, `--redact` over every positive fixture), and uploads
  `cli-<target>`. `release.yml` calls that workflow for the candidate.
- **The inventory records them, the manifest does not.**
  `artifact-inventory.json` carries one `family: cli` entry per target with
  `file`, `bytes` and `sha256`. The durable release manifest
  (`docs/releases/<version>/manifest.json`) carries `artifact_set`,
  `artifact_digests` and `registry_state` for the thirteen registry
  identities only (ten npm, two crates, one PyPI). No CLI binary is in
  `artifact_set`, so no publish job verifies one and the manifest can say
  nothing about its availability.
- **No lane installs the CLI the way a user would.** The clean-install lanes
  cover Node, Python and a Vite browser bundle; their reports are rejected
  unless the `.node`, `.wasm` and `.whl` digests equal the inventory's.
  `docs/qualification.md` describes the CLI path only as a binary smoke test
  on the build host.
- **The publish graph has no binary node.** `release.yml` publishes crates.io
  (core before CLI), PyPI and npm, verifies each against the qualified digest,
  and creates the annotated tag only after all of them and the
  registry-install checks succeed. `docs/releasing.md` already says a GitHub
  Release "needs an explicit publication decision and must use the qualified
  binaries and recorded digests".
- **Facts the qualification does not yet pin.** The binaries are unsigned and
  not notarized. The Linux glibc floor is whatever `ubuntu-latest` and
  `ubuntu-24.04-arm` provide, and is not recorded. Qualification artifacts are
  workflow artifacts with finite retention, not a durable address. A binary
  from `cargo install` is a different build (toolchain, environment) from the
  qualified one, so the bytes differ even for one commit.

## Decision

**Adopt**, conditionally. The project will publish verified prebuilt CLI
binaries for the six `cli-release-targets` as a **GitHub Release asset set**,
under these rules. Nothing is published by this decision: the first
publication needs the explicit release approval `AGENTS.md` already requires,
and the work below is a prerequisite.

1. **Reuse the qualified bytes; never rebuild at publish.** The published
   executable is the exact file the `cli` job built, qualified and recorded.
   The publish job downloads `cli-<target>` from the qualification run,
   re-hashes it against the inventory, and refuses on mismatch. No toolchain
   runs at publish time. Packaging (a `tar.gz` for Unix targets, a `zip` for
   Windows, each holding only the executable) is a container step done
   **inside qualification**, before the inventory closes, so the archive's
   digest and the contained executable's digest are both recorded by the run
   that qualified them.
2. **One publish path.** The asset set is a new registry node in the existing
   `release.yml` graph, with its own state beside crates.io, PyPI and npm. It
   is not a separate workflow and not a manual upload. It is created as a
   draft release by a job that depends on qualification and the
   registry-install checks, and is published only by the step that follows tag
   creation, so the release names the annotated `v{version}` tag at
   `github.sha` and the existing ordering ("tag only after every publication
   job succeeds") holds. `Reconcile Release` repairs it by the same rule as
   the other registries: verify and complete a matching published version,
   never rebuild.
3. **Per-target digests in the durable manifest.** `artifact_set`,
   `artifact_digests` and `registry_state` gain `github-release:` identities
   for the archives (one per target) and a `SHA256SUMS` file. The manifest
   validator treats them like every other registry identity. Digests come from
   the qualified inventory, never from an upload response.
4. **A CLI clean-install lane gates the publish.** A new lane, in the family of
   the existing clean-install lanes, starts in an empty directory with no Rust
   toolchain on `PATH`, installs from the candidate archive for its own native
   target, verifies the archive digest and the contained executable digest
   against the inventory, and runs the documented quickstart command. The
   `inventory` job rejects a report whose digests differ from the run's
   artifacts, as it does for the other lanes. After publication, a
   registry-install check downloads the asset from the real release and
   verifies it the same way, mirroring `verify-registry-install`.
5. **Docs follow the lane, not the reverse.** The quickstart, README and CLI
   guide add the no-toolchain install (download, verify against `SHA256SUMS`,
   run) only in the release whose lane has passed. The sentence "no prebuilt
   CLI binary is published" stays true until then. `cargo install` remains the
   source install and the path for platforms without a prebuilt binary.
6. **Honest trust statement.** The binaries are unsigned. Integrity rests on
   the digest in the release manifest, `SHA256SUMS` and, if the
   implementation adopts it, a GitHub artifact attestation bound to the same
   workflow run. Platform code signing (Apple notarization, Windows
   Authenticode) is not part of this decision, and the docs say so, including
   the macOS Gatekeeper and Windows SmartScreen behavior for a
   browser-downloaded file.
7. **Same target set.** The six `cli-release-targets` only. No static musl CLI
   binary is added; that exclusion stands until a separate decision. Because a
   glibc binary's compatibility is a claim, the implementation records the
   minimum glibc version of each Linux binary in the inventory and states it in
   the install instructions.
8. **Lockstep.** The asset set ships in the release that ships every other
   artifact, same version, never alone, per
   [Release bindings in lockstep](2026-09-09-release-bindings-in-lockstep.md).

## Alternatives considered

- **Defer.** Cheapest, and `cargo install` works. Rejected as the end state
  because the qualified binaries already exist and are digest-recorded, so the
  marginal cost is packaging, manifest and lane work, while the entry cost for
  CLI users (a toolchain plus a fat-LTO build) is the largest of the four
  bindings. Deferring becomes right if the first implementation issue shows
  the lane cannot be made hermetic.
- **Reject.** Leaves CLI users on the source-build path permanently. Rejected:
  the concern is valid and the security boundary is unaffected, since the
  binary is the same core.
- **Upload from a separate workflow or a maintainer's machine.** Rejected: a
  second publish path outside the idempotent graph, with no manifest state and
  no reconcile story.
- **Rebuild in the publish job.** Rejected: what is published would not be
  what was qualified.
- **Ship the binary inside the existing npm or PyPI packages.** Rejected: it
  changes those artifacts' contents and size for every user and widens their
  contracts to carry an executable.
- **Wait for code signing first.** Rejected as a blocker: signing needs
  external credentials and identity this repository does not provision, and
  digest verification is useful without it. It stays a separate decision.

## Consequences

- Cost: an archive family, a new manifest identity kind, one lane across six
  native runners, one publish job and one post-publish check. The release graph
  gains a registry whose partial state (draft present, not published) must be
  visible and repairable.
- Risk: a first-time `github-release:` state in the manifest and reconciler.
  The draft-then-publish ordering depends on GitHub release and tag semantics
  and on the repository's release immutability settings, which the first
  publishing issue must verify in a rehearsal before relying on them.
- The CLI crate stays the canonical source distribution; the binaries are a
  derived convenience from the same source commit and are not byte-identical to
  a `cargo install` build.
- No detection, policy, or public-API behavior changes. The core stays
  side-effect free.

## Implementation plan

Issue-sized, in dependency order. None selects a version or publishes.

1. **Package the qualified CLI binaries in qualification.** Produce the
   per-target archive and `SHA256SUMS` in the `cli` job; extend
   `record-artifact-inventory.py` and its tests to record archive and
   executable digests, and record each Linux binary's minimum glibc. Decide the
   glibc floor and, if needed, the build runner.
2. **Add the CLI clean-install lane.** Toolchain-free empty-directory install
   from the candidate archive on each native target, digest verification
   against the inventory, the documented quickstart command, and a report the
   `inventory` job cross-checks; reproduce-locally steps in
   `docs/qualification.md`.
3. **Extend the release manifest and its validators.** `github-release:`
   identities in `artifact_set`, `artifact_digests` and `registry_state`;
   `scripts/release-manifest.py`, `validate-release-records.py` and the
   reconcile artifact plan, with fixtures. Decide deliberately whether the
   site-feed package listing changes.
4. **Publish and verify in the release graph.** The draft-release job, the
   post-tag publish step, post-publish download verification, and
   `Reconcile Release` repair for the new registry. Prove ordering and
   immutability behavior in `package-release-rehearsal.yml` first. This touches
   workflows, so it needs a `ci-hardening` review.
5. **Docs and spec.** Quickstart, README, CLI guide, `docs/releasing.md` and
   the `distribution.md` row updated to present tense, landing in the release
   that first publishes the set.
6. **Optional follow-ups, each its own decision.** GitHub artifact
   attestations, platform code signing and notarization, a static musl CLI,
   and `cargo-binstall` metadata pointing at the assets.
