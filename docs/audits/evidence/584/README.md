# Beta.7 candidate qualification (#584)

[Audit archive](../../README.md) ·
[Issue #584](https://github.com/redact-secret/redact-secret/issues/584) ·
[Epic A #575](../575/README.md) ·
[Release runbook](../../../releasing.md)

Written 2026-09-24 on branch `workbench/584-qualify-beta7-candidate`. Every
value used in detector and corpus checks was a deterministic synthetic value.
This record contains no credential value. It qualifies one candidate; it does
not choose a version, tag, publish, or approve a release.

## Result

Detection gates pass on the recorded candidate. Two items are open and are
listed under [Open items](#open-items): four provisional families carry
unresolved differential items, and the benchmarks pin manifest lags this
candidate. Neither was rewritten to fit.

## Candidate identity

| | |
| --- | --- |
| Product source commit | `6a2dca04b9f88b82f1b88a7acfeeb93a82510c21` (`main`, clean) |
| Benchmark source commit | `28fc818966d9acf7ad3f77ce38577d6b5c14ea0b` (`develop`, clean) |
| Benchmark lockfile SHA-256 | `391edc5b11bd6134af83f2e3df861cfa7e0bbb600732e19b78578e4258a781a8` |
| Corpus | `measurement-v4`, hash `29bde22bb7488be6ff18c8453d0090b6fe3403fac82de1de2540a0898068601c` |
| Candidate package | `@redact-secret/core` 0.1.0-beta.7 |
| Core artifact SHA-256 | `8b6e759b98201ebfed797a5389eca57a3aa52fef1bc96783d522c60418662520` (equal to the expected digest, and to the one CI qualified in run `35949674873`) |
| Node artifact (darwin-arm64) | `cd801afc5bc3921642e8fa18b829eb5e0585f1c4c21ae8db1e961a5f8d5ef7af` |
| WASM artifact | `2c288cb36fce4d2f176a61f4cd09efbfadf1781eb70b76aba4195630879c166c` |
| Peer scanners | trufflehog 3.97.4 (pinned; a 3.97.6 and a self-updated 3.97.8 binary were present and not used), gitleaks 8.30.1 |
| Scanner configuration hash | `92b89dd6272b5466bf1f948c8c914411dd8c5007b5805a3e485d3fa868d9b394` (adapter 1, family mapping 2, default detectors, isolated npm tarballs) |
| Runtime | Node v22.16.0, darwin arm64 |
| Evidence runs | `benchmark:candidate` run `1216cfba-fb86-45c0-83a5-cf93b44040e4`; `eval:classify` + `eval:matrix` run `d87f63dd-5d38-4cf6-a8d1-6ab28f3c7f95`, both candidate mode |

Stable counts below are candidate mode unless labelled otherwise.

## Detection gates

| Gate | Result |
| --- | --- |
| 15 existing families moved to `stable` | Pass. The beta.7-start matrix (product `50e2f4bc`, benchmarks `be5f8e6b`, trufflehog 3.97.4) had 34 `stable`; this candidate has 51, +17. The 15 Epic A families are the ones listed in [#575](../575/README.md); the other two are the #574 families `netlify:personal-access-token` and `confluent:cloud-api-secret`, which are not part of the 15. |
| No previously stable family regressed | Pass. Compared with the published beta.6 package on the same corpus and pinned peers: 43 → 51 in the 93-family matrix, 0 families left `stable`. |
| T1/T2 leaked span rate 0 | Pass. 0 of 306 T1 and 0 of 89 T2 expected spans missed; every T1/T2 must-redact row is `EXACT`. |
| Must-not-flag | 0 of 842 scored flagged, including `detector-coverage--heroku-api-key-legacy-public-id` (#714, fixed by #715). Four twin rows carry a raw finding but score `clean`: `sendgrid-regressions--base62-generic-key-twin`, `sendgrid-regressions--base62-bearer-twin` (#553) and the two `openai-token-legacy` twins. |
| Fixture completeness | `complete`, 1,466 selected / scanned / written, 0 failures; the benchmarks validator accepted the evidence. |
| #574 committed families present, registered, scored | Pass. `netlify` (stable, T1), `confluent` (stable, T1), `heroku:oauth-access-token` (stable, T1); `okta`, `mailgun`, `mailchimp`, `postman`, `databricks` are `provisional` at T2 or better. |
| Stretch-family incompleteness | Does not block. |
| Mutation and differential ledgers | **Open**, see below. |
| Matrix, README, docs, release notes agree | Pass after this change. `benchmarks/support-matrix.json` is re-vendored from run `d87f63dd` (51 stable, 21 provisional, 2 pending, 19 unsupported of 93). `docs/support-matrix.md`, the README section and the CHANGELOG entry are regenerated or updated from it. It contains all 64 finding types in `docs/coverage/detector-inventory.json`; the 8 families the pinned matrix lacked on 2026-09-23 (`okta`, `mailgun`, `mailchimp`, `heroku`, `netlify`, `postman`, `databricks`, `confluent`) are all present. |

The previous pinned matrix read 49 `stable`. `netlify` and `confluent` read
`provisional` there only because their candidate-mode differential rows were
not yet on benchmarks `main`; they are on `28fc818`.

## Adoption and packaging gates

CI `Artifact qualification` run `35949674873` on `6a2dca0` succeeded: clean
install for Node, Python and browser; installed-package runs on Node 20, 22
and 24; browser packages on Chromium, Firefox and WebKit; Node WebAssembly
fallback and Cloudflare Workers; source and wheel builds. `SAST` (run `35949674699`) also passed. The artifact inventory
records `published: false`.

Issues #585, #586, #587, #588, #589 and #590 are closed. This record did not
re-run their acceptance checks or confirm whether #588 was promoted from
stretch; it relies on the qualification run above and on their own evidence.

## Open items

1. **Unresolved differential items in four provisional families**, identical
   in the old pin and in this candidate:
   `confluent:cloud-api-secret-legacy` 6, `databricks:personal-access-token` 6,
   `discord:bot-token` 12, `okta:api-token` 9. No `stable` family has any.
   Whether these are release-blocking needs a maintainer ruling. The
   CHANGELOG entry from #574 states that Databricks and Okta have "no
   unresolved differential items"; that does not match this measurement.
2. **Benchmarks pin manifest.** `pins.redactSecretVersion` is still
   `0.1.0-beta.6`, and `crates/secret-scan-core/src/detectors` changed after
   `pins.sourceRevision` (`fdca511d`), so the detector registry snapshot
   needs a refresh (#427). Both need the benchmarks repository and, for the
   version, a published beta.7.
3. **Re-measure.** If any product commit lands after `6a2dca0`, this record
   is stale and the run must be repeated.

## Release boundary

Tagging and publication require separate explicit approval, and the version
choice belongs to the maintainer. Nothing here authorizes either.
