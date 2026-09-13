# Release artifact installation and qualification

[Documentation home](../README.md) · [Audit archive](README.md)

- Issue: [#203](https://github.com/redact-secret/redact-secret/issues/203).
- Recorded on: 2026-09-13.
- Scope: release-candidate artifact identity, installed-consumer evidence,
  public API and changelog readiness, and post-publication install verification
  boundaries.
- Status: **EVIDENCE PATH RECORDED; RELEASE AUTHORITY REMAINS SEPARATE.**

This record ties issue #203 to the durable evidence that the qualification and
release workflows already produce. It does not select or change a version,
create a release-candidate branch or tag, publish any package, deploy anything,
or approve a release.

## Acceptance evidence

| Criterion | Evidence path |
| --- | --- |
| Qualify the full declared artifact set from one RC source commit and preserve artifact/corpus identity. | `.github/workflows/artifact-qualification.yml` builds the declared Node addon, browser WebAssembly, Python wheel/sdist, CLI, and Rust surfaces from one source revision. `scripts/record-artifact-inventory.py` fails unless every declared target is present, records every artifact file with SHA-256, records the conformance fixture hashes, and writes `published: false`. |
| Verify installation and execution of candidate artifacts using the existing qualification system. | The `package-consumer-node` and `package-consumer-browser` jobs install the packed wrapper, native, and Wasm packages outside the checkout. Their reports are uploaded as `installed-javascript-*` artifacts. The inventory job now requires one report per declared Node major and browser engine and validates initialize, scan, incremental, incremental-corpus, and stream outcomes plus package digests. |
| Review public API and changelog before requesting explicit release approval. | The inventory now carries a `releaseReadiness.publicApiAndChangelogReview` section with SHA-256 pointers to `docs/audits/candidate-public-contract-review.md` and `CHANGELOG.md`. A release reviewer can compare those hashes to the source revision under review before requesting approval. |
| After separately approved publication, use release workflow registry-install evidence; do not initiate publication from this issue alone. | The inventory records the post-publication boundary as `releaseReadiness.registryInstallVerification`, pointing to `.github/workflows/release.yml` and `scripts/verify-registry-install.mjs`. Those checks run only after the release workflow publishes the approved version and verify clean registry installs across the declared npm platform lanes and Chromium browser lane. |

## Authority boundary

Pre-publication package-consumer checks use packed local artifacts as registry
stand-ins. They prove the candidate packages can be installed and executed, but
they cannot prove public-registry availability. Public-registry install evidence
belongs to the release workflow after separate release approval, because only
that workflow is allowed to publish and then install the exact registry
artifacts.

The `artifact-inventory` output remains a qualification artifact, not release
approval. It intentionally records `published: false` and now states that
publication, tagging, deployment, and release approval require separate
authorization.

## Verification hooks

The deterministic regression tests are in
`scripts/tests/test_record_artifact_inventory.py`. They cover the installed
JavaScript evidence matrix, source revision precedence, safe summary rendering,
and the new release-readiness record for #203.
