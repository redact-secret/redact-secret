# 0.1.0-beta.6 release retrospective

Written on 2026-09-22 against `main`, for issue
[#615](https://github.com/redact-secret/redact-secret/issues/615). It follows
the shape of the [beta.5 retrospective](beta5-release-retrospective.md)
([#531](https://github.com/redact-secret/redact-secret/issues/531)).

**Authority:** this document records what happened during the beta.6 release
and what has since been fixed. It does not select a version, create a tag,
publish a package, or deploy, and it does not approve beta.7, v0.1.0, or any
other release. The complete qualification, publication, recovery, and
verification account, with every workflow run ID, is the durable record at
[`docs/releases/0.1.0-beta.6/README.md`](../releases/0.1.0-beta.6/README.md)
(tracking [#606](https://github.com/redact-secret/redact-secret/issues/606),
merge-back [#613](https://github.com/redact-secret/redact-secret/pull/613)).
This document summarizes it only as far as needed to say what broke and what
fixed it.

## Outcome

All 13 artifacts were published and verified live from source
`079095e766e4a71e2b7e29413ed17be37bb3315d`:

- 10 npm packages, including the two musl Linux Node addons;
- 2 crates;
- the PyPI distribution: 8 abi3 wheels and the sdist.

Every registry byte matches the qualification inventory. Annotated tag
`v0.1.0-beta.6` targets `079095e`.

The release did not finish in one pass. It took 1 partial Release run and 3
Reconcile Release runs (1 dry, 2 real), with 5 separate `release` environment
approvals.

## What went well

- **The rehearsal earned its place.** Package Release Rehearsal caught
  [#608](https://github.com/redact-secret/redact-secret/pull/608), a
  digest-scope defect. Without it, every npm dependency publish leg would
  have failed its pre-publish check while the crate and PyPI legs published
  in parallel.
- **Candidate review caught a materially incomplete changelog** before
  release. Nine detector-behavior PRs had no entry, one entry described a
  state that never shipped, and a finding-type compatibility break (GitHub
  findings split into one type per token family) was not recorded. See the
  [beta.6 candidate public contract review](beta6-candidate-public-contract-review.md).
- **Build-once qualification held.** Every published byte matched the
  qualified inventory. The beta.5 Python wheel mismatch did not recur,
  because [#527](https://github.com/redact-secret/redact-secret/issues/527)
  and [#528](https://github.com/redact-secret/redact-secret/issues/528)
  build each artifact once and publish that build.
- **Reconcile Release's idempotent registry-state model worked.** It
  recovered the release twice without republishing anything, including from
  a run that had left no release manifest at all.

## What went wrong

Nothing here involved secret detection, redaction, or policy behavior. All
six items are release-engineering or process debt.

1. **Two release-path defects from #528 had never run at an unpublished
   version.** Both failed only on the freshly bumped RC:
   [#607](https://github.com/redact-secret/redact-secret/pull/607) (Cargo
   could not package `redact-secret-cli` before its exact `redact-secret`
   requirement existed on crates.io) and #608 (digest checks passed fewer
   files than the inventory records). `main` never exercises either, because
   `main`'s version is always one that is already published. Fixing them on
   the RC branch cost two extra qualification cycles.
2. **The manifest step broke on an apostrophe in a job output.**
   `release.yml` interpolated each publish job's `artifact_digest_json` into
   a single-quoted shell string. The wasm job's digest note contains
   `tarball's own shasum`, so the step failed with `own: command not found`
   and the run recorded no release manifest. The manifest was reconstructed
   by hand, and the dry-run Reconcile needed explicit `source_run` and
   `source_commit` inputs.
3. **The npm 180-second propagation window caused false failures again,
   twice.** `@redact-secret/node-darwin-arm64` in the original run and
   `@redact-secret/core` in the first recovery run were both accepted by npm
   with the qualified shasum, and both jobs reported failure because the
   version endpoint had not caught up. Beta.5 lost its clean run the same
   way. [#529](https://github.com/redact-secret/redact-secret/issues/529)'s
   bounded wait made the window longer but kept a successful `npm publish`
   followed by a slow registry as a failure.
4. **Windows addon builds were not reproducible across qualification
   runs.** The rehearsal's separate qualification build produced different
   `win32-x64-msvc` and `win32-arm64-msvc` `.node` bytes from the release's
   build of the same source. The other six native packages and the wasm
   package matched exactly. The published bytes are correct, because each
   leg checks its digest against the inventory of the run that feeds it, but
   a rehearsal's Windows digests said nothing about the release's.
5. **The changelog drifted.** Detector PRs merged to `main` without
   changelog entries, and the gap was caught only at candidate review. Beta.5
   hit the same thing in its second readiness pass. Nothing checks for it at
   PR time.
6. **The support-matrix drift gate was vacuous for this release.** The
   `support-matrix-drift` qualification job compares against the previous
   release tag's `benchmarks/support-matrix.json`, and `v0.1.0-beta.5`
   predates that file, so the job skipped by design. The #573 re-pin
   ([#580](https://github.com/redact-secret/redact-secret/pull/580)) was
   compared by hand against the pre-run pin instead.

## How each problem was resolved

- **Items 2, 3, and 4 are resolved by
  [#614](https://github.com/redact-secret/redact-secret/issues/614)
  ([#630](https://github.com/redact-secret/redact-secret/pull/630)).**
  - *Manifest quoting:* `release.yml` passes job outputs to the manifest
    step through `env:` rather than shell interpolation, and
    `scripts/tests/test_release_manifest.py` asserts that the step survives
    an apostrophe in a job output. `scripts/check-release-gate.py` documents
    the quoting rule for release workflows.
  - *npm propagation:* a publish leg whose own `npm publish` exited
    successfully now treats npm's acceptance as authoritative
    (`--publish-accepted` in `scripts/npm-registry-metadata.mjs`). A version
    that is still 404 when the window closes is reported as pending
    propagation, not as a failure. A *visible* shasum other than the expected
    one is still a hard failure. The long wait moves to the registry-install
    lane, which runs after every publish job and waits up to 20 minutes for
    each version to be installable through the packument `npm install`
    reads.
  - *Windows reproducibility:* `.cargo/config.toml` links MSVC targets with
    `/Brepro` and `/PDBALTPATH:%_PDB%`, removing the link timestamp and
    absolute PDB path. The Windows addon legs of
    `artifact-qualification.yml` now relink the addon and fail if the
    rebuild's bytes differ from the first build's. That proves
    reproducibility within one runner; whether two separate qualification
    runs agree will first show at the beta.7 rehearsal.
- **Item 1 is resolved for #607 and #608 themselves**, which were fixed on
  the RC through reviewed PRs and merged back with #613. The class of defect
  is still open; see [What remains open](#what-remains-open).
- **Item 6 resolves itself at beta.7.** `v0.1.0-beta.6` carries
  `benchmarks/support-matrix.json` and is an ancestor of `main`, so
  `git tag --list 'v*' --sort=-v:refname --merged HEAD` resolves it as the
  baseline for a beta.7 RC cut from `main`. Running
  `scripts/check-support-matrix-drift.py --baseline` against
  `v0.1.0-beta.6`'s pin on `main` at `12d9b8e` on 2026-09-22 reported 79
  families, 0 regressions, 0 improvements, 0 new families, and 0 stale
  provenance warnings. The gate is live for beta.7.

## What remains open

- **Exercise the release path at an unpublished version before an RC
  exists.** Run the rehearsal on a throwaway version bump, so that defects
  shaped like #607 and #608 appear before a candidate is cut. Package
  Release Rehearsal today qualifies whatever version the branch carries,
  which on `main` is always already published. Tracked in
  [#632](https://github.com/redact-secret/redact-secret/issues/632).
- **Enforce changelog coverage at PR time.** A change to
  `crates/secret-scan-core/src/detectors/**` or to a binding's public
  surface should need an `## Unreleased` entry in `CHANGELOG.md` (or an
  explicit waiver) before merge, not at candidate review. Tracked in
  [#633](https://github.com/redact-secret/redact-secret/issues/633).
- **Reconcile Release has still not been exercised deliberately.** Beta.6's
  three dispatches were real recoveries, like every one before them. The
  beta.5 retrospective's open item and item 5 of the
  [v0.1.0 release-readiness checklist](../releases/release-readiness-v0.1.0.md)
  stand unchanged.
