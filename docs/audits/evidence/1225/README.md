# Evidence: #1225, Batch 2 HubSpot CLI, MyJFrog and OAuth1 secret slots

**Result:** the contract for the three G5 rows (adopted in PR #1231) was tested by
the independent benchmarks#739 round 2 against the published `0.1.0-beta.13` and
the candidate `a148dadf`. `hubspot:personal-access-key` is a reproduced gap: once
credential-evidence named the field (`personalAccessKey`, variable
`HUBSPOT_PERSONAL_ACCESS_KEY`) none of its 8 positives was read; the vocabulary
admission rule below is applied by [#1233](../1233/README.md) with exactly those
two whole names. `x:oauth1-access-token-secret` reads the secret half by the
existing grammar and reproduced one gap, the shared empty-value defect, fixed by
[#1232](../1232/README.md). `jfrog:myjfrog-api-token` is existing coverage
validated by the benchmark (an explicit Bearer carrier). The `oauth_token`
observation is recorded as the existing contract-evidence conflict and is not
changed. The independent replay of the fixed candidate is open.

Issue [#1225](https://github.com/redact-secret/redact-secret/issues/1225)
(measurement child benchmarks
[#744](https://github.com/redact-secret/redact-secret-benchmarks/issues/744)),
Batch 2 of the credential-evidence adoption inventory
([#231](https://github.com/redact-secret/credential-evidence/issues/231), handoff
[#235](https://github.com/redact-secret/credential-evidence/issues/235)). The
class rules and the legend are in the [#1223 record](../1223/README.md).

## Sources

| Role | Source |
| --- | --- |
| Provider facts (pending inputs) | The three proposed contracts of credential-evidence#235 and the [Batch 2 handoff](https://github.com/redact-secret/credential-evidence/blob/005a7331cf90403bd4ce4abcb93bd8b085d315a9/docs/handoffs/batch-2-bounded-carriers.md) (credential-evidence#248, project-authored, not independent). It records `oauth_token_secret` as the secret half issued with `oauth_token`; for HubSpot, a key kept in a local global config file with no field name; for MyJFrog, existence only. |
| Independent baseline | benchmarks#739: [round-1 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/report.md), [round-2 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/round2/report.md) and [ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/ledger.json) at merge `fe7a5d1a` of PR #761 (readiness at merge `6a1a7a64` of PR #755). Identities under "Independent measurement and dispositions". Field evidence: credential-evidence `65602481`, `docs/handoffs/batch-2-research-r3.md`. |
| Product policy (this record) | The contextual name vocabulary and its whole-name admission precedent ([#1211](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1211/README.md), [#919](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/860/fal-contextual-gap.md)), `decision-redact-provider-named-credential-assignments` (a bare `token` and a bare `_key` suffix stay unmatched) and `decision-define-fragmented-credentials-as-outside-the-raw-input-contract`. |

## Adopted contracts

| Question | `x:oauth1-access-token-secret` | `hubspot:personal-access-key` | `jfrog:myjfrog-api-token` |
| --- | --- | --- | --- |
| Layout kinds in contract | A credential field named `oauth_token_secret`: assignment, quoted assignment, form body or query parameter (the token response is form-encoded), JSON or YAML member, once a reviewed layout names it. The secret never appears in an `Authorization: OAuth` header, which carries only the signature. | None until the evidence names the exact CLI configuration field and file layout. | None until the evidence names the MyJFrog header or field. If it is an explicit `Authorization: Bearer` header the existing Bearer path applies unchanged; a field is governed by the vocabulary rule below. |
| Value admission and span | The existing field grammar: 8-byte floor, shared reference, placeholder and mask exclusions, exactly the value, ending at the form delimiter. | As the vocabulary rule. | As the vocabulary rule, or the Bearer grammar. |
| Finding type and action | `contextual_secret`, redact at high confidence, warn at medium. No X or provider attribution. | Same, with no HubSpot attribution. | Same, or `bearer_token`; no JFrog attribution. |
| Excluded | `oauth_signature` (a signing output, not the secret), `oauth_consumer_key`, `oauth_nonce`, `oauth_timestamp`, `oauth_signature_method`, `oauth_version`, ids, placeholders, references, masks. | The portal and account id; other CLI configuration values; arbitrary `*key` names. | The JFrog platform access token (a different row), public ids; arbitrary `*key` names. |
| Unsupported, stated limits | A secret in another field name; a value cut across lines; an SDK call that passes it positionally. | An SDK positional argument and any configuration nesting the evidence has not contracted. | The same. |

**Vocabulary admission rule.** A credential name is added to the contextual
vocabulary only when the evidence names the exact provider-documented field, and
then as one whole normalized name (the `mac_secret_base64`, `fal_key` and
`db_pass` mechanism: it is not a prefix or suffix rule and not a `*_key` or
`*token` rule), with the shared placeholder, reference and mask exclusions kept,
a false-positive and false-negative statement, and neighbouring-name controls
(`-Id`, `-Hint`, `Length` and prefixed lookalikes stay unmatched). A name is
never derived from a credential's label ("personal access key", "API token").
[#1233](../1233/README.md) applies the rule to the HubSpot CLI field once the evidence named it (the evidence caveat: the field name rests on HubSpot's own SDK source, and the legacy `portals` layout is unresolved).

**`oauth_token` is read by the accepted default (decided in
[#1241](../1241/README.md)).** The evidence handoff lists `oauth_token` among the
public lookalikes of the secret half. The product's accepted default reads a
prefixed `_token` name as a credential (the #702 rule, `oauth_token` named in the
`auth_token` row of the contextual spec), so a random value under `oauth_token` is
`contextual_secret`, redacted, and a low-entropy one is `warn`. [#1241](../1241/README.md)
keeps this as an intentional policy deviation from the evidence role (option A):
the evidence role is a factual claim, the redaction is a product policy, a pairing
rule would add false negatives, and the default is security first. This contract
asserts nothing for `oauth_token` as part of the secret-half row, and the expectation
for the benchmarks side is `policy: redacted`, not an expected-clean value.

## Product observations

Product observations at core `3b1a5aa9` (CLI `0.1.0-beta.13` line, debug build of
this commit, check mode, UTF-8 byte ranges), small synthetic inputs, values
invented and not shown. Not benchmark results and not coverage claims.

| Input (synthetic) | Observed finding |
| --- | --- |
| `oauth_consumer_key=<8>&oauth_token=<13, low entropy>&oauth_token_secret=<20>&oauth_signature=<20>%3D` | `contextual_secret`, medium, warn, over the 13-byte `oauth_token` value (40-53); `contextual_secret`, high, redact, over exactly the 20-byte `oauth_token_secret` value (73-93); `oauth_consumer_key` and `oauth_signature` silent |
| `oauth_token=<20>&oauth_token_secret=<20>&user_id=<5>` | two `contextual_secret`, high, redact, over each 20-byte value (12-32, 52-72); `user_id` silent |
| JSON `{"oauth_token":"<20>","oauth_token_secret":"<20>","oauth_callback_confirmed":"true"}` | two `contextual_secret`, high, redact (16-36, 60-80); `oauth_callback_confirmed` silent |
| `oauth_token_secret = "<20>"` and `access_token_secret: <20>` | two `contextual_secret`, high, redact, over the value only (22-42, 65-85) |
| `Authorization: OAuth oauth_consumer_key="..", oauth_nonce="..", oauth_signature="<20>%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="..", oauth_token="<20>", oauth_version="1.0"` | one `contextual_secret`, high, redact, over the `oauth_token` value (199-219) only; the signature, nonce, consumer key, timestamp, method and version are silent |
| `personalAccessKey: <24>` and `hubspot_personal_access_key=<24>` (illustrative names, not claimed HubSpot fields) | no finding |

The last row was the stated blind spot at `3b1a5aa9`: a value under a name outside
the vocabulary is not read, and the product did not guess HubSpot's field. Both
conditions of the rule were then met (the evidence names the exact field and a
baseline shows the miss, 8 of 8), and #1233 adds the two whole names; after it the
row reads as the contract states.

## Independent measurement and dispositions

**Independent measurement.** benchmarks
[#739](https://github.com/redact-secret/redact-secret-benchmarks/issues/739)
measured all 58 rows in two rounds (PRs
[#755](https://github.com/redact-secret/redact-secret-benchmarks/pull/755) and
[#761](https://github.com/redact-secret/redact-secret-benchmarks/pull/761), both
merged; permalinks at their merge commits `6a1a7a64` and `fe7a5d1a`): the
[readiness inventory](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/readiness.md) (first version at merge `6a1a7a64` of PR #755), the [round-1 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/report.md), the [round-2 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/round2/report.md) and the [ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/ledger.json) (58 rows, schema 4). Frozen round-2
corpus sha256 `a312308a141e3157c859f62e53c5e0762ca91c2e0083d0e02497848ebee8b921`
(1935 cases; first freeze `8e447629`, three documented errata before the
re-measurement; round 1's corpus `74fed382`, 486 cases, 30 rows, is separate).
Case ids are `<family>:r2:<layout>:<kind>` in `benchmarks/batch2/corpus-r2.mjs`
(round 1: `<family>:<layout>:<kind>` in `corpus.mjs`) and are listed per row in the
ledger. Expectations were authored from credential-evidence `65602481` and the
adopted contract (PR #1231), frozen before any scan, and were not edited.

**Identities.** Published: `@redact-secret/core`, `@redact-secret/wasm` and the
darwin-arm64 addon `0.1.0-beta.13` from npm (core integrity
`sha512-qZkqRN7CIJ+pc0IteRCXSucr1l9KtTc/nJaM5wPL0NvCiZ4AGWLCyrLy8KD95a2MBgxo8vuUJ/UaKhrny7gMJQ==`),
PyPI `redact-secret` `0.1.0b13`, crates.io `redact-secret-cli` `0.1.0-beta.13`.
Candidate: the unpublished commit `a148dadf4a43b5441ed88386d055428b2e278f25`
(core main after PR #1231, no candidate package published). Surfaces: Node, WASM,
Python and the CLI (the Rust surface; no separate Rust harness), whole and
streamed at 7-byte and 1-byte chunks, darwin-arm64, Node v22.16.0; the four
surfaces agreed on every case and stream equalled whole. Peers were not run. The
fixed candidate is **not** an identity the benchmark has measured: this change
was replayed locally on the CLI surface only (see the #1223 record).

**Result (candidate `a148dadf`; published identical).** `hubspot:personal-access-key`:
8 of 8 positives missing, 4 controls clean. `x:oauth1-access-token-secret`: all
positives pass; one control flagged (`oauth_token_secret-form-empty-null`, the
#1232 defect); `oauth_token-as-public-lookalike` is the recorded conflict case,
observed as `contextual_secret` redact, not scored. `jfrog:myjfrog-api-token`: 15
positives and 7 controls, all as expected. The carriers of the two previously
unconfirmed rows are now named by the evidence: HubSpot (the YAML config field and
the environment variable), MyJFrog (an explicit Bearer carrier, read by the
existing Bearer grammar).

**Disposition legend.** *Existing coverage, validated by the benchmark: no
code* means the row's in-contract positives and controls passed on the published
baseline and on the candidate on every surface and stream, and the record
changes nothing for it. *Reproduced gap, fixed by this PR* names the issue.
*Batch 1 fix reused* means the row fails on the published baseline and passes on
the candidate through an earlier core fix. *Accepted policy limit* and
*source-unresolved / unmeasured* are never counted as a miss, a clean result or
coverage. Variants the contract leaves unassertable (prefixed or upper-case
names, single quotes, lower-case schemes, percent values, legacy layouts) are
observed and not scored in every row. A row is not claimed covered beyond what the
ledger measured.

**Local replay of this change (CLI surface only).** The benchmark's own runner
(`scripts/measure-batch1.mjs --corpus benchmarks/batch2/corpus-r2.mjs --cli
<release build of this branch>`, 7-byte and 1-byte chunks) and scorer
(`score-r2.mjs`) were run at the merge `fe7a5d1a` of benchmarks PR #761 over all
1935 cases, whole and streamed. Result: 0 positives failing and 0 controls
flagged on every row (the candidate `a148dadf` had 8 positive cases and 16 control
cases failing). Against the
candidate's CLI observations exactly 25 cases differ: the 15 empty-form-value
controls of #1232 (now clean), the 8 HubSpot positives of #1233 (now exact), the
mongodb-atlas placeholder control of #1234 (now clean), and the unscored
`personalAccessKey-legacy-portals` observation (no finding before, a finding now:
the name is read wherever it appears; the legacy layout stays unresolved and
unasserted). Nothing else changed. This is a local diagnostic, not the
benchmark's measurement: Node, WASM and Python were not replayed with the fixed
candidate.

### G5: 3 families

| Family | Carrier layout (evidence-named, benchmark slots) | Cases r2: pos / ctl / unscored | Candidate `a148dadf` (published beta.13) | Disposition |
| --- | --- | --- | --- | --- |
| `hubspot:personal-access-key` | config field `personalAccessKey` (YAML account entry) and variable `HUBSPOT_PERSONAL_ACCESS_KEY` | 8 / 4 / 3 | pos 8 fail, ctl 0 flagged (published: 8, 0) | Reproduced gap (8 of 8 positives), fixed by this PR (#1233). |
| `jfrog:myjfrog-api-token` | explicit Bearer header | 15 / 7 / 5 | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `x:oauth1-access-token-secret` | assignment / form field `oauth_token_secret`; JSON/YAML member `oauth_token_secret` | 28 / 16 / 10 (+ 16 round-1) | pos 0 fail, ctl 1 flagged (published: 0, 1) | Reproduced gap (empty-form-value control), fixed by this PR (#1232); other cases covered. `oauth_token` as a public lookalike is the recorded contract-evidence conflict: observed (`contextual_secret`, redact), not scored, not changed. |

## Handoff

Final for the benchmarks side: the `oauth_token_secret` expectation (exactly the
value, `contextual_secret`, redact, warn at medium, no X attribution; the
signature, consumer key, nonce, timestamp, method and version silent), which holds
after #1232 for the empty-value control; the HubSpot expectation of
[#1233](../1233/README.md) (exactly the value, `contextual_secret`, redact at high
confidence and warn at medium, no HubSpot attribution; `portalId`, `authType`,
`personalAccessKeyId`, `...ExpiresAt`, placeholders, references and masks silent),
with the SDK-source caveat and the unresolved legacy `portals` layout observed and
not scored; and the MyJFrog Bearer expectation, validated. `oauth_token` is
outside the secret-half row: it is not an expected clean value. [#1241](../1241/README.md)
decided that the product keeps redacting it (`policy: redacted`), so the evidence
control that lists it as a public lookalike is a recorded policy deviation, not a
product change and not a false positive; the expectation to freeze is stated there.

**What the benchmarks side replays (open).** Build the merge commit of this
change (the maintainer names it; not chosen here) as the fixed candidate (`npm
ci`, `npm run js:build`, the napi addon, `npm run wasm:build`, `npm pack` of core,
addon and wasm, `maturin develop --release`, `cargo build --release --locked -p
redact-secret-cli`), then run the round-2 corpus `a312308a...` (all 1935 cases) on
Node, WASM, Python and the CLI, whole and at 7-byte and 1-byte chunks, with
`scripts/measure-batch1.mjs` and `scripts/report-batch2-r2.mjs`, and the Batch 1
and round-1 corpora for regression. Expected: 0 positives failing and 0 controls
flagged on all 58 rows; observations identical to `a148dadf` except the 25 cases
listed above; stream equal to whole; the four surfaces identical.

No pin, version or release changes; this record chooses none.

## Gates of the issue

| Gate | State |
| --- | --- |
| Freeze each ready row's layout, admission, span, attribution, default action and exclusions in final product evidence and spec rows | Met. The class contract and spec rows are adopted (PR #1231) and the independent measurement tested them per row; the evidence contracts of credential-evidence remain proposed or draft, which is that repository's state, not a product gap. |
| Link independent baseline case ids and identities; disposition every row | Met. Identities and permalinks are above and every row has its disposition in the per-row table, with case ids in the ledger and the corpus. |
| Repair only demonstrated gaps; add only evidenced vocabulary | Met. Two gaps were demonstrated and repaired: the HubSpot field ([#1233](../1233/README.md), two exact whole names named by the evidence) and the empty value ([#1232](../1232/README.md)). No other name was added; `oauth_token` is unchanged. |
| Deterministic conformance for changed logic | Met. `tests/batch2_gaps_1232_1234.rs` pins both fixes (the `hubspot_*` tests and the empty-value tests). |
| Shared parser fix once | Met through #1232 (the one shared fix of the batch, also serving `oauth_token_secret`). |
| Node/WASM, Python, Rust and CLI whole and stream behavior | Partly. Baseline and candidate `a148dadf` were measured by the benchmark on all four surfaces, whole and 7-byte and 1-byte streamed, identical. For this change: the Rust core under whole input, every two-chunk UTF-8 byte partition and per-line sessions (`tests/batch2_gaps_1232_1234.rs`), and the CLI replay above. Open: Node, WASM and Python with the fixed candidate, which share the Rust core and are the benchmark replay. |
| Exact candidate revision and digests to benchmarks; accept independent replay | Open. The fixed candidate does not exist as a measured identity until the change is merged and built; what to replay is stated above. Offered: the merge commit and the build recipe of the benchmark README, no pin, version or release change. |
| Record no-code conclusions for existing coverage | Met for `jfrog:myjfrog-api-token` and for the in-contract positives and controls of `x:oauth1-access-token-secret`, as the benchmark ledger measured them. The HubSpot row is not a no-code row. |

## Tradeoffs

* A bounded whole-name entry (now made for HubSpot) is the cheapest repair for a missing documented
  field and its cost is the contextual one: a non-secret literal of 8 or more
  bytes in the exact slot is redacted. Waiting for the evidence to name the field
  leaves a real HubSpot or MyJFrog value unread meanwhile, stated above as a
  blind spot, instead of broadening to `*key` and redacting benign configuration.
* Reading `oauth_token` as a credential redacts a value the provider may treat
  as public. That is the security-first default of the prefixed `_token` rule and
  is kept by decision ([#1241](../1241/README.md)).
* The secret half is read by name only; the same bytes in another field, an SDK
  positional argument or a split literal are not read.

## Tests

`crates/secret-scan-core/tests/batch2_gaps_1232_1234.rs` pins #1232 and #1233 (see
[#1232](../1232/README.md#tests) and [#1233](../1233/README.md#tests)); the field
grammar is also pinned by the `generic_token` unit tests and
`batch1_credential_slots_1209_1213.rs`. The observations above are pinned by this
record only. The independent measurement is the benchmarks side's.


## Final state at 4e004108 / replay accepted (2026-10-06)

Addendum. The text above is kept as written; the statements below are superseded
and this section is the current state. Replay facts shared by all Batch 2 records
(candidate, corpus digests, results, the 25 differing cases) are in the
[#1223 record](../1223/README.md).

The accepted replay is benchmarks
[#771](https://github.com/redact-secret/redact-secret-benchmarks/pull/771)
(merge `74c88531f7f185e687eabe6477fff5b06f54e2e9`) of the exact candidate
`4e0041081aad22d0101bd52db52017b67b5bd3db` on the frozen round-2 corpus
`sha256:a312308a141e3157c859f62e53c5e0762ca91c2e0083d0e02497848ebee8b921` (1935
cases), with round 1 `74fed382...` and Batch 1 as regression, on Node, WASM,
Python and the CLI, whole and at 7-byte and 1-byte chunks
([round-3 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/74c88531f7f185e687eabe6477fff5b06f54e2e9/evidence/739/round3/report.md),
[ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/74c88531f7f185e687eabe6477fff5b06f54e2e9/evidence/739/ledger.json)).

| Earlier statement (in this record) | State now |
| --- | --- |
| "The independent replay of the fixed candidate is open" (Result, Handoff) | Done and accepted: benchmarks #771. |
| "The fixed candidate does not exist as a measured identity" (Identities, Gates) | It does: `4e0041081aad22d0101bd52db52017b67b5bd3db`. |
| Gates "Node/WASM, Python, Rust and CLI ...: Partly" and "Exact candidate revision ...; accept independent replay: Open" | Met, see below. |
| "Open: Node, WASM and Python with the fixed candidate" | Replayed by the benchmark, identical to the CLI. |

### Dispositions at `4e004108`

| Row | Ledger disposition | Positives failing / controls flagged | Whole equals stream (7-byte, 1-byte), four surfaces identical |
| --- | --- | --- | --- |
| `hubspot:personal-access-key` | fixed by candidate `4e004108`, replay verified ([#1233](../1233/README.md)); the 8 positives now pass | 0 / 0 | 60/60, 60/60; 15/15 cases |
| `x:oauth1-access-token-secret` | fixed by candidate `4e004108`, replay verified ([#1232](../1232/README.md)); the `oauth_token_secret-form-empty-null` control is clean | 0 / 0 | 220/220, 220/220; 55/55 cases |
| `jfrog:myjfrog-api-token` | already-covered / no-code | 0 / 0 | 108/108, 108/108; 27/27 cases |

The unscored HubSpot `personalAccessKey-legacy-portals` observation changed from
no finding to a `contextual_secret` / `redact` finding at 55-91 (the name is read
wherever it appears); the legacy layout stays unresolved and is not scored.

`oauth_token` is unchanged: the round-3 report still lists
`x:oauth1-access-token-secret` as a contract-evidence conflict between the
evidence's public-lookalike role and the product default, with the candidate
observation unchanged and "owners decide". The product decision is
[#1241](../1241/README.md) (default kept, a deliberate deviation from the
evidence role). Whether the benchmarks ledger records it as a resolved policy
deviation is the benchmarks side's step and is not shown by the round-3 report.

### Gates of the issue at `4e004108`

| Gate | State |
| --- | --- |
| Node/WASM, Python, Rust and CLI whole and stream behavior | **Met.** Replayed by the benchmark on all four surfaces, whole and 7-byte and 1-byte streamed, identical (the CLI is the Rust surface). |
| Exact candidate revision and digests to benchmarks; accept independent replay | **Met.** Candidate `4e0041081aad22d0101bd52db52017b67b5bd3db`, accepted as benchmarks #771. No candidate package was published, so no package digest is claimed. |
| All other gates | Met, unchanged. |

The figures are read from the merged report and ledger; the harness was not
re-run for this addendum.

## Closure statement (2026-10-06)

What this issue can honestly claim after the Groups C, D and E measurement rounds.

No scored case of Groups C, D or E exercises this issue, so the group measurement adds no row claim to it. The HubSpot `query-prefixed-name:unsupported` case is flagged on rounds 2 and
3 (observed only); the report cannot attribute that to this issue rather than to
the #1230 `hapikey` rule, so no claim is made from it. The claims of this issue stay the ones in the records above, which cite the Batch 2 evidence; do not cite the Groups C-E report for a row claim here.

The closeout also added tracked policies that these records do not claim as covered:
the `curl -u` password slot ([redact-secret#1247](https://github.com/redact-secret/redact-secret/issues/1247)), the JFrog `AKCp` bare
reader, deferred ([redact-secret#1248](https://github.com/redact-secret/redact-secret/issues/1248)), the bare `token` member
([redact-secret#1256](https://github.com/redact-secret/redact-secret/issues/1256), rule [#1241](../1241/README.md)), the existing Case
contradictions ([credential-evidence#264](https://github.com/redact-secret/credential-evidence/issues/264)) and the percent-escaped X layout
confirmation ([credential-evidence#265](https://github.com/redact-secret/credential-evidence/issues/265)).

Source: the [round-3 report of Groups C, D and E](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/report.md) (section 7, [dispositions](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/report.md#6-final-disposition-of-all-43-rows)),
its [scores](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/scores.json) and
[identity](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/identity.json), at benchmarks commit
`c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291`, measuring candidate
`c6dd685974b8df6a84514e07e41e35afa711a2ac` (unpublished, 0.1.0-beta.14) on one
host. Project-authored, maintainer-only evidence, not independent validation;
the fixes target measured failures and no generalisation is claimed.
