# 0.1.0-beta.10 release evidence

Published on 2026-09-28 from the qualified source
`af7f863f29f9fe482dd233c8b7bc5b77dc427314`. All ten npm packages (including
the two musl Linux Node addons), both Rust crates, and all nine Python
distribution files are published. Python spells this version `0.1.0b10`; npm
and Cargo use `0.1.0-beta.10`.

## Qualification and approval

[SAST 36370302566](https://github.com/redact-secret/redact-secret/actions/runs/36370302566),
[Artifact qualification 36370302722](https://github.com/redact-secret/redact-secret/actions/runs/36370302722),
and [Package Release Rehearsal 36370537054](https://github.com/redact-secret/redact-secret/actions/runs/36370537054)
passed at the frozen source revision.

Public API and compatibility review is recorded in
[the beta.10 candidate public-contract review](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/beta10-candidate-public-contract-review.md)
(issue [#898](https://github.com/redact-secret/redact-secret/issues/898)).
Its own status line notes two benchmarks-side qualification records were
still open at review time —
[redact-secret-benchmarks#286](https://github.com/redact-secret/redact-secret-benchmarks/issues/286)
(PII profile/runtime/artifact-size cost study) and
[redact-secret-benchmarks#287](https://github.com/redact-secret/redact-secret-benchmarks/issues/287)
(the combined credential+PII qualification record) — both tracked under
[redact-secret#579](https://github.com/redact-secret/redact-secret/issues/579).
Neither blocks this release: they are being carried forward in a separate,
already-in-progress work track rather than re-measured here.

### Performance evaluation

Performance evaluation against this exact candidate initially failed on two
findings, both investigated and resolved as accepted tradeoffs rather than
code defects, recorded in
[redact-secret-benchmarks#414](https://github.com/redact-secret/redact-secret-benchmarks/pull/414)
(merged into `accepted-regressions.json`):

- Three already-known credential-detector-pack latency regressions
  (`redact-secret#883`) re-recorded for this exact final commit, since this
  repository's acceptance ledger is candidate-SHA-scoped and the prior rows
  were bound to an earlier candidate commit.
- One new regression: `browser-wasm` initialization time on the
  `scale-logs-small-whole` profile rose 41-56% across two dispatches (25%
  budget), root-caused to the new phone-detection PII family
  (`redact-secret#895`): the added detector code grows the compiled wasm
  module by ~1.67%, which this profile's small absolute baseline amplifies
  into a large relative ratio. No fixable defect was found — no eager static
  initialization, no new dependency, and the wasm release profile already
  uses `lto = "fat"` / `codegen-units = 1` with no `wasm-opt` post-processing
  step available to add safely pre-release.

A separate, unrelated harness defect was found and filed as
[redact-secret-benchmarks#415](https://github.com/redact-secret/redact-secret-benchmarks/issues/415):
the node performance runner does not record which artifact (`node-addon` vs
`wasm`) resolved for two `scale-logs` profiles, failing a schema check
(`#405`) independently of the regression-budget judgment. This does not
implicate any redact-secret core change and is tracked separately rather than
blocking this release.

After the accepted-regressions update, [performance-evaluation run
36373147944](https://github.com/redact-secret/redact-secret-benchmarks/actions/runs/36373147944)
passed its regression-budget judgment cleanly (the schema-check failure above
is its only remaining, separately tracked, non-blocking finding).

## Publication

[Release run 36374488650](https://github.com/redact-secret/redact-secret/actions/runs/36374488650)
re-ran qualification, published both crates, all nine PyPI files, and all ten
npm packages (including the facade), passed registry-install verification on
all eight Node targets and Chromium, recorded the release manifest, and
created annotated tag `v0.1.0-beta.10` (object `f0e4b15da`) at the frozen
source revision. The run succeeded end to end; Reconcile Release was not
needed and was not run.

One transient artifact of the run is not a publication defect. The `Record
release manifest` job's registry-state snapshot ran mid-publish and recorded
three npm packages (`node-linux-x64-gnu`, `node-win32-arm64-msvc`,
`node-win32-x64-msvc`) as `unpublished` at that instant, even though the same
run's own later `Verify registry install` jobs for those exact targets
subsequently passed. This is the same npm registry propagation-lag false
negative documented in the beta.3/beta.5/beta.6 records, not a partial
publication.

## Independent verification

On 2026-09-28 every registry was checked directly, without relying on the
workflow's own reports:

- **npm:** all ten packages are at `0.1.0-beta.10`.
- **crates.io:** both crate checksums equal the inventory's crate digests.
- **PyPI:** all nine file hashes equal the inventory's Python entries.
- **git:** `v0.1.0-beta.10` resolves locally to object
  `f0e4b15da73276582531338c73a9a0f2be509817` targeting `af7f863f`.

## Durable record

This checked-in [manifest](manifest.json) is marked `reconstructed`: the
workflow's own manifest job does not populate the tag/registry/verification
evidence this record requires (true of every version in this history, not a
defect specific to this run), and its registry-state snapshot for the three
lanes above was a mid-run propagation-lag artifact, corrected here against
the same run's own later verification and the independent check above. The
original manifest job's output is preserved verbatim as `original_manifest`.
The preserved [inventory](artifact-inventory.json) is unchanged from the
release run. No GitHub Release page has been created for this version.
