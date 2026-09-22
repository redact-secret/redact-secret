# 0.1.0-beta.3 release evidence

Published on 2026-09-16 from `rc/0.1.0-beta.3`, using the approved and
qualified source `34ea9b92ed8879082e99f56f8f4715ee4e4f1f35`. All eight npm
packages, both Rust crates, and all nine Python distribution files are
published. Python spells this version `0.1.0b3`; npm and Cargo use
`0.1.0-beta.3`.

## Original partial publication

[Release run 35127722228](https://github.com/redact-secret/redact-secret/actions/runs/35127722228)
published both crates, all nine Python files, the WASM package, and all six
native npm packages. Two of those native packages, Linux x64 GNU and Windows
ARM64, could not be verified on the registry immediately after publishing, so
their publish jobs failed and the facade publish, install, and tag jobs were
skipped. The run's [original manifest](original-manifest.json) therefore
recorded those two packages as `unpublished` and the facade as `unknown`. It is
preserved byte for byte, and the same state is embedded under
`release_evidence.original_manifest` in [manifest.json](manifest.json), rather
than rewritten as success. The [artifact inventory](artifact-inventory.json) is
the unmodified qualification artifact from that run; its `published: false`
field correctly describes its pre-publication origin.

## Authorized recovery

[Reconciliation run 35129171906](https://github.com/redact-secret/redact-secret/actions/runs/35129171906)
found all seven npm dependency packages already published with content matching
the original source, which shows the two `unpublished` states were verification
false negatives rather than missing packages. It then published the npm facade
and failed its immediate post-publish checksum read, so install and tag jobs
were skipped. Final authorized
[reconciliation run 35129831469](https://github.com/redact-secret/redact-secret/actions/runs/35129831469)
found every artifact, the facade included, already published with matching
content. It passed clean registry installs on all six published Node targets
and Chromium, and created annotated tag `v0.1.0-beta.3` at the original source
revision.

Reconcile Release intentionally does not emit a replacement durable manifest.
The checked-in manifest is therefore explicitly marked `reconstructed`. It
combines the preserved original manifest and inventory with the npm integrity
values, crates.io checksums, PyPI file hashes, and annotated tag object in the
[2026-09-16 registry observation](../registry-observation.json), the complete
recovery-run history, and successful install results. npm `shasum` values were
read from the registry on 2026-09-22 and match the values both reconciliation
runs logged. Every Python file hash matches the original inventory.

This record is a closeout of evidence that already existed. It is not a new
qualification run, and it does not reconstruct each artifact's original
qualification chain beyond what the original run's inventory states.

## GitHub Release page

No GitHub Release page exists for `v0.1.0-beta.3`. A prerelease body targeting
the existing tag is prepared in [github-release-notes.md](github-release-notes.md).
Creating the page is a release operation that requires the explicit approval in
[`AGENTS.md`](../../../AGENTS.md#release-authority); no package republish, new
tag, or workflow dispatch is needed. Qualified CLI binaries remain Actions
artifacts rather than a separate distribution channel.
