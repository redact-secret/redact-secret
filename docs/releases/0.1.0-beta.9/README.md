# 0.1.0-beta.9 release evidence

Published on 2026-09-26 from the qualified source
`f726f2ffb0fd854cc3eeb4c35798695fde3161d3`. All ten npm packages (including
the two musl Linux Node addons), both Rust crates, and all nine Python
distribution files are published. Python spells this version `0.1.0b9`; npm
and Cargo use `0.1.0-beta.9`.

## Qualification and approval

[SAST 36255940520](https://github.com/redact-secret/redact-secret/actions/runs/36255940520),
[Artifact qualification 36255940754](https://github.com/redact-secret/redact-secret/actions/runs/36255940754),
and [Package Release Rehearsal 36256023225](https://github.com/redact-secret/redact-secret/actions/runs/36256023225)
passed at the frozen source revision.

## Publication

[Release run 36256896376](https://github.com/redact-secret/redact-secret/actions/runs/36256896376)
re-ran qualification and published both crates, all nine PyPI files, and all
nine npm dependency (addon/wasm) packages. Its `npm:@redact-secret/core`
publish job failed, but not at the actual `npm publish` step: it failed at
that job's own pre-publish `Qualify release` gate (`npm run release:check`,
which reruns the entire `npm run ci` battery), specifically in `examples:test`,
with `Error [ERR_MODULE_NOT_FOUND]: Cannot find package
'@redact-secret/adapter-ai-context'` from `examples/mcp-redact/agent-context.mjs`.
That package is an externally published sibling-repo dependency
(`@redact-secret/adapter-ai-context@0.1.0-alpha.1`, published the day before)
used only by the MCP golden-path example, not a redact-secret artifact or a
defect in the qualified core facade itself. The actual `npm publish` command
for the facade never ran in that job, so `Verify registry install` and
`Tag verified release` were skipped as a consequence.

With separate authorization, [Reconcile Release (dry-run)
36257774995](https://github.com/redact-secret/redact-secret/actions/runs/36257774995)
confirmed only `npm:@redact-secret/core` was missing, and [Reconcile Release
36257859108](https://github.com/redact-secret/redact-secret/actions/runs/36257859108)
published it from the already-qualified tarball. `Reconcile Release` does not
re-run `release:check` before publishing (it acts on the artifact the original
run already qualified and packed), which is why it did not hit the same
example-dependency failure. It then verified all eight Node install lanes and
Chromium, and created annotated tag `v0.1.0-beta.9` (object `8f1d0b985`) at the
frozen source revision.

## Independent verification

On 2026-09-28 every registry was checked directly, without relying on the
workflows' own reports:

- **npm:** all ten packages are at `0.1.0-beta.9`, including the core facade
  (shasum `c8abc79c4b`, confirming the reconcile repair).
- **crates.io:** both crate checksums equal the inventory's crate digests.
- **PyPI:** all nine file hashes equal the inventory's Python entries.
- **git:** `v0.1.0-beta.9` resolves locally to object
  `8f1d0b9851be4af6b518e5146d0434f2c1684a49` targeting `f726f2ff`.

## Durable record

This checked-in [manifest](manifest.json) is marked `reconstructed`: the
original run's manifest step ran mid-publish (before the core facade's digest
or the tag/registry/verification evidence a fully successful run assembles
existed) and is preserved verbatim as `original_manifest`. This record
combines that preserved snapshot, the reconcile run's verification and tag,
and the registry checksums independently observed above. The preserved
[inventory](artifact-inventory.json) is unchanged from the original run. No
GitHub Release page has been created for this version.
