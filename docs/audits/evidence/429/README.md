# Issue #429 — closing the six gates in benchmark-regressions.json

[Audit archive](../../README.md) ·
[Governance decision](https://github.com/redact-secret/redact-secret-benchmarks/blob/main/docs/decisions/2026-09-18-govern-benchmark-promotion.md) ·
[Issue #429](https://github.com/redact-secret/redact-secret/issues/429) ·
[Candidate evidence summary](candidate-evidence-summary.json)

`conformance/benchmark-regressions.json` carries a `productConformance` and a
`benchmarkRevalidation` gate on each of `benchmark-gap-292`, `-293`, and
`-294`. This records what closed, what didn't, and why.

## productConformance

Evidence: GitHub Actions run
[35439980831](https://github.com/redact-secret/redact-secret/actions/runs/35439980831)
("Artifact qualification", commit `f6769c4ceb4d93ca802875bff5df62250c4c3204`,
`main`, success). That run's `Rust` job calls `ci.yml` (`cargo test
--workspace`, which includes
`crates/secret-scan-core/tests/canonical_corpus.rs`), its `Python` job calls
`python-wheels.yml` (`scripts/qualify-python-wheel.py --conformance`,
`bindings/python/tests/test_conformance.py`'s corpus), and its `Addon
<target>` / `Browser <engine>` / `CLI <target>` jobs qualify the built N-API
addon, the WebAssembly artifact in Chromium/Firefox/WebKit, and the CLI
binary against the same canonical corpus. Every one of those jobs succeeded.

`f6769c4` is a descendant of both `benchmark-gap-293`'s fixing commit
(`a62339e7bb2de616bbc200476c9e043bfd429c30`) and `benchmark-gap-294`'s
(`49f41ea95958c87e6c132471b15cd4c50642f721`), and their canonical fixtures
(`contextual-negative-azure-keyvault-*`, `contextual-positive-nested-no-separator-*`)
were already present in `conformance/fixtures/synchronous-corpus.json` at
that commit. `productConformance` is `passed` for both records.

`benchmark-gap-292` had no canonical fixtures at all before this issue
(`canonicalFixtures.synchronous: []`). This change adds
`contextual-negative-windows-env-reference-excluded` and
`contextual-negative-sql-bind-parameter-excluded` (verified green under
`cargo test -p redact-secret --test canonical_corpus` and the
`common_profile_corpus` regeneration), but **no CI run has ever executed
them** -- they exist only on this branch. `productConformance` stays
`pending` for `benchmark-gap-292` until the pull request's own CI run is
recorded; closing it here with a fabricated or future link would not be
evidence.

## benchmarkRevalidation

Evidence: a real `npm run benchmark:candidate` rerun (candidate commit
`2545c1afd5c8875b8102fcd2ac3dd8bb6cad835b`, the commit that added
`benchmark-gap-292`'s fixtures; benchmark commit
`0fa424ae64b7c44967b146758bc035a92dd65ee8`, the revision this repository's
`benchmarks/pin-manifest.json` currently pins) -- full-suite, unfiltered,
`benchmark.dirty: false`, `status: complete`, no failures. See
[candidate-evidence-summary.json](candidate-evidence-summary.json) for the
sanitized run record (fixture ids, outcomes, and hashes only -- no fixture
input or matched value).

For `benchmark-gap-292` and `benchmark-gap-293`, both keyed to the
`reference-syntax` corpus category, the evidence's category hash
(`0fe3363d4e0aec300b81bb823929f73928c7e06eb9e1d43064cf7b5b7f0d977e`) matches
the ledger's `corpusHashes` exactly, and every named fixture
(`reference-syntax--windows-env`, `reference-syntax--sql-bind`,
`reference-syntax--azure-keyvault`) came back `clean` (no flag), the expected
direction for a `must-not-flag` regression fix. `benchmarkRevalidation` is
`passed` for both, with `benchmarkCommit` set to `0fa424ae64b7c44967b146758bc035a92dd65ee8`.

**`benchmark-gap-294` does not close.** It is keyed to the `detector-coverage`
corpus category. The ledger's `corpusHashes` names
`1012bdbabc75ab6228091cddfe9a54bb283c7c37a254c7484650bf367cfeab17`; the live
rerun measured `0d5800251b19d7ee0d2cc2ad489d09a619d7626c578bf9b28a5c9fce791610eb`
at the exact pinned commit. The three individual fixtures
(`detector-coverage--generic-token-{api-key,password,client-secret}-quoted`)
still come back `EXACT` -- the detector itself is fine -- but per
`decision-govern-benchmark-promotion`, "the evidence's corpusHash must match
the corpusHashes in the product ledger -- a mismatch means a different
corpus was measured and the gate cannot close," so the gate stays `pending`.

Checked directly against a real `redact-secret-benchmarks` checkout at commit
`0fa424ae64b7c44967b146758bc035a92dd65ee8`: that commit's own
`benchmarks/pin-manifest.json` reports `revision: f1d4fac69ae49adc91cc199f2b0550c4a48daaf4`
and `detector-coverage: 0d580025…` -- matching this rerun, not the value this
repository's committed `benchmarks/pin-manifest.json` carries under the label
`revision: 0fa424ae…`. This repository's pinned manifest copy also lists
several dozen `detector-coverage--*` fixture ids (Atlassian, Azure DevOps,
Datadog, Discord, Google, Grafana, Microsoft Entra, New Relic, Notion,
Sentry, Telegram, Twilio) that do not exist in the benchmarks tree at
`0fa424ae…` at all -- they belong to a later benchmarks-repo state. The copy
committed here (issue #427) does not actually describe the revision it
claims to. That is a pre-existing staleness bug in this repository's pinned
manifest, not something this change caused or can correct without risking
silently dropping tracked future-detector fixture ids from the pin; it needs
its own follow-up issue against #427's manifest-sync process. Until that is
fixed and a rerun is repeated against a manifest that actually matches its
claimed revision, `benchmark-gap-294`'s `benchmarkRevalidation` evidence
cannot be produced.
