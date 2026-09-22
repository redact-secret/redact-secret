# Issue #144 — candidate identity and public-contract verification

[Audit archive](../../README.md) · [Issue #144](https://github.com/redact-secret/redact-secret/issues/144) ·
[Candidate public-contract review (beta.1)](../../candidate-public-contract-review.md)

Recorded 2026-09-11 at commit `c34f4a8ad2634bc9c77cf64a9514a8ccc629d229`,
`0.1.0-beta.1` development (`0.1.0b1` on PyPI). This is the raw
`opengrep.json`/`verification-summary.json` pair behind the review's own
narrative: `candidate_version_approved: false` and `release_authorized:
false` — issue #144 explicitly records that the current manifest value does
not itself establish approval, matching the parent review's conclusion.

## What is here

`verification-summary.json` records the checks run against this revision
(`release_check`: passed; 44 Rust workspace-policy tests; 18 public-API
tests; clippy clean; the core package built and verified; the CLI's file
list inspected, with no registry-dependent standalone build available yet;
a macOS arm64 abi3 wheel and sdist built and inspected; 66 local
Markdown file/heading links passed, `git diff --check` passed) and the exact
file manifests of every package artifact built from this revision — the npm
facade, the `rust_core`/`rust_cli` crate contents, and the Python wheel and
sdist file lists.

`opengrep.json` is the raw scan report behind the summary's `opengrep` entry
(29 findings, 16 acknowledged scan errors, zero unresolved), pinned to tool
version 1.30.0 and the rules digest recorded in the summary. It also records
that an earlier full qualification matrix
(`9f02fc401525381a6b02b5dd514a68df9a4f9531`) is *not* itself evidence for
this revision (`prior_full_matrix_is_current_revision_evidence: false`).
