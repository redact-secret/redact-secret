# Issue #174 — release-qualification rehearsal evidence

[Audit archive](../../README.md) · [Issue #174](https://github.com/redact-secret/redact-secret/issues/174) ·
[Qualification follow-up](../../release-qualification-follow-up.md)

Recorded 2026-09-11T15:20–15:30 UTC. Two source revisions appear because the
rehearsal's first attempt failed and was corrected: `initial_source_revision`
`470844b9210ffad6f1646fab13940de670afdcdd` failed
`Rust native host (windows-latest)` (`an_ordinary_long_line_behaves_the_same_streamed_or_by_path`
compared an unescaped Windows path against escaped text output; fixed by
comparing parsed JSON finding arrays instead of raw text). The fix landed as
`9f02fc401525381a6b02b5dd514a68df9a4f9531`, and every result below is
against that corrected `source_revision`.

## What is here

`verification-summary.json` is the full rehearsal record: registry and
governance checks (repository visibility, the `release` environment's
required-reviewer and branch-policy settings, `main`'s branch-protection
rule, and a confirmed-absent state for every npm/crates.io/PyPI package name
this project would publish — nothing had shipped yet), the pinned SAST scan
result (29 findings, 16 acknowledged errors, 0 unresolved), a clean
`npm audit`, and the full qualification workflow run (41 jobs, all
`success`, `https://github.com/redact-secret/redact-secret/actions/runs/34615840860`).

`download_verification` records that every one of the run's 43 artifact
files, 5 conformance fixture files, and 6 declared matrices were downloaded
and verified, with the `sha256` of the two evidence files this rehearsal
itself produced.

`artifact-inventory.json` and `dependency-cutover-plan.json` are the two
files `download_verification.evidence_sha256` fixes the hashes of; edit
neither without recomputing and updating that entry, or updating this
evidence bundle to record why the two now disagree.
