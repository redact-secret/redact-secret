# 0.1.0-beta.2 release evidence

Published on 2026-09-14 from `rc/0.1.0-beta.2`, using the approved and
qualified source `8cdc1b118449a15be545ecf70bb7f0df53f6126e`. All eight npm
packages, both Rust crates, and all nine Python distribution files are
published. Python spells this version `0.1.0b2`; npm and Cargo use
`0.1.0-beta.2`.

## Original partial publication

[Release run 34792026587](https://github.com/redact-secret/redact-secret/actions/runs/34792026587)
published most artifacts, then failed because delayed npm metadata prevented
immediate verification of the Windows ARM64 package. The preserved
[artifact inventory](artifact-inventory.json) is the unmodified qualification
artifact from that run; its `published: false` field correctly describes its
pre-publication origin. The run's original manifest reported the Windows ARM64
npm package as `unpublished` and the facade as `unknown`. That exact partial
state is embedded under `release_evidence.original_manifest` in
[manifest.json](manifest.json), rather than rewritten.

## Authorized recovery

[Reconciliation run 34792787564](https://github.com/redact-secret/redact-secret/actions/runs/34792787564)
failed closed when its dry run detected a repacked npm-content mismatch.
[Dry run 34794019747](https://github.com/redact-secret/redact-secret/actions/runs/34794019747)
then passed with corrected recovery tooling. Final authorized
[reconciliation run 34794379520](https://github.com/redact-secret/redact-secret/actions/runs/34794379520)
completed publication and checksum verification, passed clean registry installs
on all six published Node targets and Chromium, and created annotated tag
`v0.1.0-beta.2` at the original source revision.

Reconcile Release intentionally does not emit a replacement durable manifest.
The checked-in manifest is therefore explicitly marked `reconstructed`. It
combines the preserved original manifest and inventory with immutable npm,
crates.io, and PyPI checksums, the complete recovery-run history, successful
install results, and local annotated-tag object/target inspection. Registry
metadata was observed on 2026-09-16; every Python file hash matches the original
inventory. No GitHub Release was expected or created, and the qualified CLI
binaries remain Actions artifacts rather than a separate distribution channel.

This record repairs the missed beta.2 closeout. Release completion now also
requires the offline durable-record validator to pass in a reviewed closeout PR;
a successful publication workflow or tag alone is insufficient.
