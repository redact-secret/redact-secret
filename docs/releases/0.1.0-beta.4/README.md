# 0.1.0-beta.4 release evidence

Published on 2026-09-17 from `rc/0.1.0-beta.4`, using the approved and
qualified source `b4a9ae83d737d367ebc1d6d1732e634b44b2452a`. All eight npm
packages, both Rust crates, and all nine Python distribution files are
published. Python spells this version `0.1.0b4`; npm and Cargo use
`0.1.0-beta.4`.

## Qualification and approval

[CI 35241840201](https://github.com/redact-secret/redact-secret/actions/runs/35241840201),
[SAST 35241840155](https://github.com/redact-secret/redact-secret/actions/runs/35241840155),
[Artifact qualification 35241840473](https://github.com/redact-secret/redact-secret/actions/runs/35241840473),
and [Package Release Rehearsal 35241861038](https://github.com/redact-secret/redact-secret/actions/runs/35241861038)
passed at the frozen source revision. The qualification inventory records the
conformance fixture hashes and installed-candidate results. Publication was
then explicitly authorized for that source revision.

## Original partial publication

[Release run 35243359690](https://github.com/redact-secret/redact-secret/actions/runs/35243359690)
published both crates, all nine PyPI files, the WebAssembly package, and five
native npm packages. The Linux x64 package was published despite its job's
verification timeout. The Windows ARM64 job likewise did not complete, and the
npm facade, registry-install matrix, and tag remained pending. The preserved
[artifact inventory](artifact-inventory.json) is the unmodified qualification
artifact from that run. Its exact partial manifest is embedded under
`release_evidence.original_manifest` in [manifest.json](manifest.json).

## Authorized recovery

[Dry run 35245875637](https://github.com/redact-secret/redact-secret/actions/runs/35245875637)
verified the preserved manifest and inventory, observed all seven npm runtime
dependencies with matching qualified content, and planned publication only of
the facade. [Recovery run 35246240335](https://github.com/redact-secret/redact-secret/actions/runs/35246240335)
published `@redact-secret/core`, but npm processing exceeded the workflow's
one-minute metadata window. After the registry exposed the exact qualified
shasum, final [recovery run 35246692567](https://github.com/redact-secret/redact-secret/actions/runs/35246692567)
verified every registry artifact, passed clean installs on all six published
Node targets and Chromium, and created annotated tag `v0.1.0-beta.4` at the
frozen source revision.

The original Release run's successful crates.io and PyPI jobs provide the
exact-version Rust and Python publication/install evidence. The final recovery
run provides the registry-backed JavaScript install evidence. Registry
metadata was observed again for this record on 2026-09-17, and every PyPI file
hash matches the original inventory.

## Durable record

Reconcile Release intentionally emits no replacement manifest. This checked-in
manifest is therefore marked `reconstructed`: it combines the immutable
original manifest and inventory with final registry checksums, the complete
recovery history, clean-install results, and annotated-tag object and target.
No GitHub Release was expected or created, and qualified CLI binaries remain
Actions artifacts rather than a separate distribution channel.
