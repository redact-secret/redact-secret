# 0.1.0-beta.6 release evidence

Published on 2026-09-22 from `rc/0.1.0-beta.6`, using the approved and
qualified source `079095e766e4a71e2b7e29413ed17be37bb3315d`. All ten npm
packages (including the two musl Linux Node addons), both Rust crates, and
all nine Python distribution files are published. Python spells this version
`0.1.0b6`; npm and Cargo use `0.1.0-beta.6`. Release tracking:
[#606](https://github.com/redact-secret/redact-secret/issues/606).

## Qualification and approval

The candidate was cut from reviewed `main` at `8838b91` after the beta.6
release gate (#572) closed. The first candidate, `db321fe`, failed
qualification, and two release-path defects had to be fixed on the RC
branch through reviewed PRs before the source was frozen. Both were added by
#528 after beta.5 and had never run at a version that was not yet on a
registry:

- [#607](https://github.com/redact-secret/redact-secret/pull/607): the
  artifact inventory packaged `redact-secret-cli` on its own, and Cargo
  could not resolve its exact `redact-secret` requirement before that
  version existed on crates.io. Both crates are now packaged in one
  invocation.
- [#608](https://github.com/redact-secret/redact-secret/pull/608): the npm
  dependency digest checks passed fewer files than the inventory records
  for their families (napi's generated loader for each addon, and the four
  `.d.ts` files in the wasm package). Every npm dependency publish leg would
  have failed its pre-publish check. Package Release Rehearsal caught this
  before the real release ran.

[CI 35746762806](https://github.com/redact-secret/redact-secret/actions/runs/35746762806),
[SAST 35746762866](https://github.com/redact-secret/redact-secret/actions/runs/35746762866),
and [Artifact qualification 35746763631](https://github.com/redact-secret/redact-secret/actions/runs/35746763631)
passed at the frozen source revision.
[Package Release Rehearsal 35745354042](https://github.com/redact-secret/redact-secret/actions/runs/35745354042)
passed at `0abdb7f`, the head of #608. Its only difference from the frozen
source is the `sast/baseline.json` re-key merged in the same PR. Publication
was then explicitly authorized for the frozen source revision.

The `support-matrix-drift` qualification job found no baseline:
`v0.1.0-beta.5` does not carry `benchmarks/support-matrix.json`. By design,
that job skips comparison for this release. The #573 re-pin (PR #580) was
compared against the pre-run pin with no unacknowledged regression.

## Original partial publication

[Release run 35747931840](https://github.com/redact-secret/redact-secret/actions/runs/35747931840)
re-ran qualification. That qualification produced the preserved
[artifact inventory](artifact-inventory.json), which is an unmodified copy.
The run then published:

- both crates;
- all nine PyPI files;
- all nine npm dependency packages.

`@redact-secret/node-darwin-arm64` was in fact published: npm accepted it
with the qualified shasum. Registry propagation, however, exceeded the
workflow's 180-second verification window, so the job reported failure. The
npm facade (`@redact-secret/core`), the registry-install matrix, and the tag
were therefore skipped, because they depend on every dependency job.

The run also left no release manifest. Its "Build and record the manifest"
step inserts each publish job's `artifact_digest_json` output into a
single-quoted shell string. The wasm job's digest note contains an
apostrophe (`tarball's own shasum`). That apostrophe ended the quoted
string, and the step failed with `own: command not found` (exit 127). The
run's original state is reconstructed under
`release_evidence.original_manifest` in [manifest.json](manifest.json), with
its provenance stated there:

- The eight native npm states are copied verbatim from the per-leg
  `registry-state-native-*` artifacts the run uploaded.
- The wasm, crate, and PyPI states are inferred from their jobs'
  successful post-publish verification.

## Authorized recovery

[Dry run 35749700163](https://github.com/redact-secret/redact-secret/actions/runs/35749700163)
ran with `source_run` 35747931840 and `source_commit` `079095e`, because no
manifest existed. It confirmed that the source revision is an ancestor of
`rc/0.1.0-beta.6`. It then content-matched all nine npm dependency packages,
both crates, and all nine PyPI files, and planned to publish only the
facade.

[Recovery run 35749941626](https://github.com/redact-secret/redact-secret/actions/runs/35749941626)
published `@redact-secret/core`. npm processing then exceeded the
180-second window again. Its published shasum was independently confirmed
equal to the packed tarball's before anything else was done.

[Recovery run 35750575837](https://github.com/redact-secret/redact-secret/actions/runs/35750575837)
re-verified every artifact without republishing anything. It passed clean
registry installs on all eight Node targets and Chromium, and created
annotated tag `v0.1.0-beta.6` at the frozen source revision.

## Independent verification

On 2026-09-22 the operator's agent checked every registry directly, without
relying on the workflows' self-reports:

- **npm:** all ten packages at `0.1.0-beta.6` with dist-tag `beta`. The
  agent unpacked each registry tarball. All eight native `.node` libraries
  and all eight wasm package files are byte-identical to this release's
  inventory.
- **crates.io:** both crate checksums equal the inventory's `crate`
  digests.
- **PyPI:** all nine file hashes equal the inventory's Python entries. The
  wheel mismatch recorded for beta.5 did not recur, because #527 builds each
  wheel once.
- **Local installs:** the agent installed `redact-secret-cli@0.1.0-beta.6`
  with `cargo install --locked` into an empty temporary root and ran its
  version and clean-input checks. It also installed `redact-secret==0.1.0b6`
  into a new virtual environment and exercised `scan_and_redact` on clean
  input.

## Known discrepancy: Windows addon builds differ across qualification runs

The Windows (`win32-x64-msvc`, `win32-arm64-msvc`) npm tarball shasums
differ from the ones the rehearsal's dry run reported for the same source.
The rehearsal ran its own separate qualification build, and its Windows
`.node` bytes differed. The other six native packages and the wasm package
matched exactly across the two builds. The published bytes are correct:
they match the inventory of the qualification run that fed this release,
and every leg's pre-publish digest check enforced that. The build itself is
nonetheless not reproducible across runs on Windows. Follow-up is tracked
with the other release-path issues from this release.

## Durable record

Reconcile Release intentionally emits no replacement manifest. This
checked-in manifest is therefore marked `reconstructed`. It combines:

- the preserved inventory;
- the reconstructed original state;
- final registry checksums;
- the complete run history;
- clean-install results;
- the annotated-tag object and target.

No GitHub Release was expected or created. Qualified CLI binaries remain
Actions artifacts rather than a separate distribution channel.
