# Issue #199 — public contract and cross-runtime conformance evidence

[Audit archive](../../README.md) · [Issue #199](https://github.com/redact-secret/redact-secret/issues/199) ·
[Current contract review](../../public-contract-cross-runtime-conformance.md)

Recorded 2026-09-13 at commit `5607de8973ddb83f9b61f840f67eb8534d5cea0d`,
`0.1.0-beta.1` development. This is the raw
`verification-summary.json` behind the review's own narrative — the review
document is the disposition, this folder is the evidence it cites.

## What is here

`verification-summary.json` records, per current host (macOS arm64; Rust
1.98.1; Node 22.16.0; CPython 3.14): the pinned fixture corpora and their
`sha256` (399 synchronous fixtures, 297 supported / 102 intentionally
unsupported; 16 incremental; 11 incremental-lifecycle; 6 unicode-conversion;
15 error codes), the built artifact under test on this host (Node addon,
browser WASM, Python wheel, CLI) with each artifact's own `sha256`, and the
check results (`npm run ci`, `cargo test`, `cargo clippy`, and each
artifact-qualification pass/fail).

It also records why an earlier full qualification matrix
(`9f02fc401525381a6b02b5dd514a68df9a4f9531`, 41 jobs, 43 artifact files, all
passed) is *not* treated as evidence for this revision: the synchronous
corpus hash it ran against differs from this revision's, and issue #203 owns
the formal same-revision RC run this evidence does not substitute for.

No candidate version was approved and no release was authorized from this
evidence (`candidate_version_approved: false`, `release_authorized: false`,
`published: false`); six follow-up issues (180, 200, 201, 202, 203, 224) were
opened from gaps this run found.
