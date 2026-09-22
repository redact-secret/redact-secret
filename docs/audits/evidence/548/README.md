# Epic #548 — Epic D close-out: `stable` measured on a candidate of clean `main`, gate by gate

[Audit archive](../../README.md) ·
[Epic #548](https://github.com/redact-secret/redact-secret/issues/548) ·
[E4 re-pin (#573, PR #580)](https://github.com/redact-secret/redact-secret/issues/573) ·
[Beta.6 gate epic (#572)](https://github.com/redact-secret/redact-secret/issues/572) ·
[Benchmarks epic (#61)](https://github.com/redact-secret/redact-secret-benchmarks/issues/61) ·
[Benchmarks close-out (#108)](https://github.com/redact-secret/redact-secret-benchmarks/issues/108) ·
[Prior evidence: #552](../552/README.md) · [Prior evidence: #566](../566/README.md) ·
[Slack regression (#570)](https://github.com/redact-secret/redact-secret/issues/570)

Written 2026-09-22 against `main` at `b32ca088f84b9ec46e9e191edf2b84574490824e`,
on branch `workbench/548-epic-d-close-out`.

## Summary

Epic D's definition of done names one number — `eval:classify` reporting
`stable` ≥ 17 of 46 — and three zero-counts across all 46 families. Every
sub-issue (#549–#554, #569, #570) is closed. This record is the measurement
the epic asked for, taken under all four conditions #572 requires (product
clean `main`, benchmarks clean `main`, an exact immutable candidate artifact,
the pinned peer scanners), and it attributes every remaining gate failure to
either this repository or the benchmarks repository.

**Measured: `stable` 2 of 46** (`gitlab-token`, `npm-token`). The target is not
met, and the gap is not detection quality:

- **All 17 T1 + `providerSource` families clear every product-quality gate.**
  `twinFailures` 0, `benign.falseAlarms` 0, `metamorphic.criticalFailures` 0,
  `mutation.unresolvedCritical` 0, with `minimumTwinPairs` and
  `benign.minimumCases` satisfied, for all 17.
- **15 of 17 are blocked only by `differential.unresolvedContractDisagreements`**,
  a gate `benchmarks/support/evidence.ts` computes from review-queue-versus-ledger
  state, not from any scanner assertion. Every unresolved entry is one the ledger
  has never seen (status `MISSING`, not `open`), and the two mechanisms that
  produce them are both benchmarks-side bookkeeping (see
  [why the ledger does not match](#why-the-ledger-does-not-match-the-queue)).
- **3 of 17 additionally fail `benign.minimumAxes` (2 < 3)**: `aws-access-key`,
  `github-token`, `slack-token` carry `near-miss` and `placeholder` controls but
  no third axis. A fixture gap, benchmarks-side.
- **One product defect was inside the DoD's scope and is fixed on this branch**:
  `generic-token`'s two `metamorphic.criticalFailures` under `context.markdown`
  (see [the generic-token fix](#the-generic-token-fix)).
- **Two further non-T1 assertion failures are benchmarks-side**: `docker-token`
  (27 metamorphic, 3 mutation) is the stale `shape-1` fixture already dispositioned
  in [#566](../566/README.md); `discord-bot-token` (6 mutation) is the
  `lexical.prefix-change` operator applied to a family whose first byte is
  load-bearing (see [discord](#discord-bot-token-6-mutation-failures)).

Nothing in this record is an estimate. Every number below comes from the run
identified in the next section, and the per-family table is the run's own
output, not carried forward from any earlier comment on the epic.

## Evidence identity

| | |
| --- | --- |
| Product | `main` @ `b32ca088f84b9ec46e9e191edf2b84574490824e`, clean worktree |
| Candidate artifacts | `@redact-secret/core` 0.1.0-beta.5 (declared), built by `scripts/measure-candidate.sh` → `npm run benchmark:candidate` |
| Core tarball SHA-256 | `a8f7abedfff82b41f33264ff5e7f31326f8280b818d66644139a8a6ddd233ed7` |
| Node addon tarball SHA-256 | `1da93e1a6933526e2d2a50760dd23e355e0487fd7b2d613205109628ababde67` |
| WebAssembly tarball SHA-256 | `2370df44f9ec01b2b9e418e8ecaf65f465961d5573155804a9057071621b6cef` |
| Benchmarks | `redact-secret-benchmarks` `main` @ `a502fdd715c5a5882430e951d5493de32fe8621c`, clean (same revision PR #580's pin was taken at) |
| Peer scanners | gitleaks 8.30.1, trufflehog **3.97.4** — the `qualification/suite-v1.json` pin, placed first on `PATH` for the run (the machine's installed trufflehog is 3.97.5) |
| `eval:classify` run | `68680d2f-19f9-49b3-87a6-b065cb8d2e39`, 2026-09-22T00:47:44Z, 3,317 cases / 8,758 variants, 46 families |
| Candidate conformance (`eval:candidate`) | `status complete`, 0 failures, 1060/1060 fixtures, scope `full-suite`; fixed corpus 144 fixtures: 0 required-positive misses; expanded corpus 916 fixtures: 0 required-positive misses, 3 policy misses (the `docker-token` shape-1 rows of #566) |
| Distribution | `{"stable":2,"provisional":42,"pending":2,"unsupported":0}` |

`pending` is exactly `supabase-token` and `vercel-token` (T0, no cleared positive),
unchanged from every prior measurement: no family regressed from `provisional`
to `pending`.

## Per-family evidence, the 17 T1 + `providerSource` families

Straight from `support-status.json` for the run above.

| family | status | twin pairs | twin fail | benign | axes | benign FA | metamorphic | mutation | differential | blocked by |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `aws-access-key` | provisional | 6 | 0 | 5 | 2 | 0 | 0 | 0 | 13 | axes, differential |
| `cloudflare-token` | provisional | 6 | 0 | 8 | 3 | 0 | 0 | 0 | 3 | differential |
| `digitalocean-token` | provisional | 8 | 0 | 9 | 3 | 0 | 0 | 0 | 4 | differential |
| `github-token` | provisional | 42 | 0 | 5 | 2 | 0 | 0 | 0 | 5 | axes, differential |
| `gitlab-token` | **stable** | 7 | 0 | 6 | 3 | 0 | 0 | 0 | 0 | — |
| `jwt` | provisional | 7 | 0 | 5 | 4 | 0 | 0 | 0 | 4 | differential |
| `npm-token` | **stable** | 6 | 0 | 6 | 3 | 0 | 0 | 0 | 0 | — |
| `private-key` | provisional | 5 | 0 | 5 | 3 | 0 | 0 | 0 | 20 | differential |
| `pulumi-access-token` | provisional | 6 | 0 | 6 | 3 | 0 | 0 | 0 | 1 | differential |
| `pypi-token` | provisional | 9 | 0 | 8 | 6 | 0 | 0 | 0 | 4 | differential |
| `sendgrid-token` | provisional | 18 | 0 | 11 | 3 | 0 | 0 | 0 | 28 | differential |
| `shopify-token` | provisional | 6 | 0 | 5 | 3 | 0 | 0 | 0 | 6 | differential |
| `slack-token` | provisional | 6 | 0 | 11 | 2 | 0 | 0 | 0 | 32 | axes, differential |
| `stripe-token` | provisional | 6 | 0 | 5 | 3 | 0 | 0 | 0 | 20 | differential |
| `supabase-management-token` | provisional | 6 | 0 | 5 | 3 | 0 | 0 | 0 | 9 | differential |
| `terraform-cloud-token` | provisional | 6 | 0 | 6 | 3 | 0 | 0 | 0 | 6 | differential |
| `vault-token` | provisional | 6 | 0 | 5 | 3 | 0 | 0 | 0 | 18 | differential |

`pypi-token`, the last "fixture-only" family in the epic's original table, now
carries 9 twin pairs and 8 benign controls on 6 axes (benchmarks #107/#110/#117
landed); its only blocker is the same ledger gap as the other 14.

Gate counts across all 46: `positiveContract` 27, `minimumTwinPairs` 21,
`differential.unresolvedContractDisagreements` 40, `benign.minimumAxes` 7,
`mutation.unresolvedCritical` 2, `metamorphic.criticalFailures` 2, un-probeable
T0 2.

## Why the ledger does not match the queue

The review queue was dumped from the same evaluation with each entry's
`benchmarks/review-ledger.json` status attached. Every one of the 1,846 queue
entries is either `not-assertable` (all 1,403 mutation entries, D2's operator
classes) or, for the differential method, `resolved` or **absent from the
ledger altogether**. There are no `open` carry-overs: the 254 `open` ledger
entries match nothing the current queue produces.

A differential queue id is `sha256({case, source: sourceHash, ...entry})`, and
`entry.evidence.tools` carries both scanners' `{id, version, mode,
configurationHash, configuration}` (`benchmarks/engine/execution.ts:123`,
`benchmarks/methods/differential.ts:50`). Two consequences, both measured:

1. **The ledger's trufflehog-peer entries are keyed to trufflehog 3.97.5, not
   the pinned 3.97.4.** Re-running the identical evaluation with the installed
   3.97.5 first on `PATH` drops the unresolved total from **443 to 345** and
   turns every trufflehog-peer entry for `github-token` (5), `sendgrid-token`
   (28), plus 2 each for `aws-access-key`, `private-key`, `slack-token`,
   `stripe-token`, from `MISSING` to `resolved`. The D7 sweep
   (benchmarks PR #101) was triaged against the machine's 3.97.5 binary while
   `qualification/suite-v1.json` pins 3.97.4; the #573 comment that called the
   3.97.5 citations "miscitations in prose" was right about the pin and wrong
   about what the ledger was keyed against. Under the pin, `sendgrid-token`
   is not `stable`; under the installed binary it is. **The pin and the ledger
   disagree, and only one of them can be authoritative.** Benchmarks-side.
2. **`fixtures/generated/detector-coverage.mjs` was edited after the D7 sweep**
   (benchmarks `cec9bbf`, "update corpora, fixtures, and tests"), which changes
   that category's `sourceHash` and therefore re-keys every differential
   disagreement sourced from it, across every family — the blast radius
   `docs/decisions/2026-09-21-resweep-differential-mutation-queue-d7.md`
   (benchmarks) already documents. The 345 entries that stay `MISSING` even
   under 3.97.5 are this re-keying, plus `slack-token`'s genuinely new content:
   product `main` moved from the D7-measured `34dddb1` to `b32ca08` by exactly
   one detector commit, `d0b6aa5` (#571, the #570 fix), which restored
   `xapp-`/`xwfp-` detection and so created `redact-secret-only` disagreements
   (15 per peer) that did not exist when D7 ran.

Ledger notes do not name their case id, so equivalence of a re-keyed entry to
its already-resolved predecessor cannot be proved from the ledger alone; it has
to be re-triaged. That is the D7 procedure again, and it belongs in the
benchmarks repository (benchmarks #108 is the open close-out).

## Definition of done, item by item

| DoD item | state | where the remainder lives |
| --- | --- | --- |
| `eval:classify` reports `stable` ≥ 17 of 46 | **not met: 2 of 46** | benchmarks: ledger re-triage (15 families), `benign.minimumAxes` third-axis controls for `aws-access-key`, `github-token`, `slack-token` (3 families) |
| No family regresses `provisional` → `pending` | **met** (`pending` = `supabase-token`, `vercel-token`, unchanged) | — |
| `twinFailures` = 0 across all 46 | **met** | — |
| `metamorphic.criticalFailures` = 0 across all 46 | **not met on `b32ca08`: `generic-token` 2, `docker-token` 27** | `generic-token`: fixed on this branch; `docker-token`: benchmarks (#566 stale fixture) |
| `differential.unresolvedContractDisagreements` = 0 across all 46 | **not met: 443 entries, 40 families** | benchmarks (two mechanisms above) |
| A `0.1.0-beta.6` baseline recorded once, after every sub-issue lands | **not done** — requires a release, which is an explicitly approved step this branch does not take | release authority |

## The `generic-token` fix

The run's two `metamorphic.criticalFailures` on `generic-token` are one case,
`detector-coverage--generic-token-mask--metamorphic`, whose seed is the masked
assignment `password=********` (expected: nothing) under the `context.markdown`
operator, which wraps the input in backticks. Probed directly through the
candidate:

| input | findings |
| --- | --- |
| `password=********` | none |
| `` `password=********` `` | `generic-token` / `contextual_secret` / medium / `warn`, bytes 10–19 |

Bytes 10–19 are the eight asterisks **plus the closing backtick**.
`is_prefix_boundary_char` and `is_quoted_value_boundary` learned the backtick in
#552 so an assignment inside a Markdown inline-code span is found at all, but
`is_unquoted_value_boundary` did not, so an unquoted value ran through the
closing delimiter. Two effects: a masked filler picked up a ninth, different
byte and escaped the #264 repeated-character exclusion, and every unquoted
value under that envelope was scoped one byte long.

Fix (`crates/secret-scan-core/src/detectors/generic_token.rs`): the backtick
now terminates an unquoted value, except as the value's own first byte — an
unterminated template literal or command substitution that
`delimited_reference_value` has already declined still reports its interior,
which the existing `a_value_only_starting_with_an_interpolation_delimiter_is_still_detected`
test pins. Accepted false negative: a real secret containing a literal
backtick, written unquoted.

Deterministic coverage added:

- unit: `a_masked_value_wrapped_in_markdown_inline_code_stays_excluded`,
  `an_unquoted_assignment_in_markdown_inline_code_excludes_the_closing_backtick`;
- conformance: `generic-token-negative-masked-value-markdown-inline-code`,
  `generic-token-positive-unquoted-markdown-inline-code` in
  `conformance/fixtures/synchronous-corpus.json` (corpus 1,434 → 1,436), with
  `common-profile-expectations.json`, `docs/coverage/inventory-report.json` and
  `docs/coverage/coverage-declarations.json` regenerated.

### Re-measurement after the fix

The fixed commit (`b37f905292b72d5888bcf1e9e5f5c9da7ad2c2f3`, this branch's
first `wip: #548` commit, clean) was rebuilt as a candidate and run through the
identical pipeline — same benchmarks revision, same pinned scanners.

| | |
| --- | --- |
| Candidate conformance | `status complete`, 0 failures, 1060/1060; fixed corpus 0 required-positive misses; expanded corpus 0 required-positive misses, same 3 `docker-token` policy rows |
| Node addon tarball SHA-256 | `de6047e033c6f79f40cd7d81b2146f3163692f803e224db378918a34577a9cf3` |
| WebAssembly tarball SHA-256 | `bb28b62f45c896ca3ff0c2724141ba602703cc687759455ede1a3f6406d6495c` |
| Core tarball SHA-256 | `a8f7abedfff82b41f33264ff5e7f31326f8280b818d66644139a8a6ddd233ed7` — unchanged, as expected: the JavaScript façade carries no detector code; the Rust core ships in the addon and WebAssembly tarballs |
| `eval:classify` run | `bf10ac91-bd64-4cea-987c-d90db45d666d`, 2026-09-22T01:09:38Z, 3,317 cases / 8,758 variants |
| `generic-token` | `metamorphicCriticalFailures` **2 → 0**; twin 9/0, benign 75 on 4 axes, 0 false alarms |
| `metamorphic.criticalFailures` gate | blocks **2 → 1** family across the 46 (`docker-token` only, #566) |
| Distribution | `{"stable":2,"provisional":42,"pending":2,"unsupported":0}` — unchanged, since `generic-token` is T3 and the 17 T1 families' blockers are the ledger and axes gaps above |

Every other per-family number in the table above is identical between the two
runs.

## `discord-bot-token`, 6 mutation failures

`lexical.prefix-change` replaces the value's first byte with a different
uppercase letter and asserts `same-detection`. `discord-bot-token` requires its
first segment to base64-decode to ASCII digits (a snowflake user id) precisely
to tell a bot token from a JWT (`crates/secret-scan-core/src/detectors/discord.rs`).
Probed: the seed's first byte `O` and the substitutions `M`, `N` still decode to
digits and are detected; `A` and `Z` do not and are not. The property the
operator perturbs is the family's discriminator, so the expectation is not
assertable for this family; the entries belong in the ledger's operator-class
decisions, not in a detector change. T2 family, outside the DoD's zero-lists;
recorded here so the count is not mistaken for a regression.

## One gap in the pin format

`benchmarks/support-matrix.json` (PR #580) has no `product` field: the
benchmarks `generate-support-matrix.ts` projection does not carry
`support-status.json`'s candidate identity (`sourceCommit`, tarball digests)
through. A pinned matrix therefore cannot show whether it measured a candidate
or the published package, which is the distinction #572's "exact candidate
artifact" condition turns on. Benchmarks-side; noted so the next re-pin records
it explicitly in the PR instead.

## Reproduction

```sh
# product checkout, clean
./scripts/measure-candidate.sh \
  --benchmark-repo /abs/path/redact-secret-benchmarks \
  --benchmark-ref a502fdd715c5a5882430e951d5493de32fe8621c \
  --output-dir /abs/scratch/candidate
# benchmarks checkout, clean, pinned trufflehog 3.97.4 first on PATH
npm run eval:classify -- --output=/abs/scratch/support-status.json \
  --candidate-package=/abs/scratch/candidate/artifacts/redact-secret-core-0.1.0-beta.5.tgz \
  --candidate-node-package=/abs/scratch/candidate/artifacts/redact-secret-node-darwin-arm64-0.1.0-beta.5.tgz \
  --candidate-wasm-package=/abs/scratch/candidate/artifacts/redact-secret-wasm-0.1.0-beta.5.tgz \
  --candidate-source-commit=b32ca088f84b9ec46e9e191edf2b84574490824e
```
